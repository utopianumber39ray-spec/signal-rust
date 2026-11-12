use crate::models::{
    BundleResponse, PreKeyUpload, QueuedMessage, RegistrationRequest, RegistrationResponse,
};
use crate::{ApiError, ApiResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use crypto_core::{EncryptedMessage, IdentityPublic, PublicOneTimePreKey, SignedPreKeyPublic};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn connect(url: &str) -> ApiResult<Self> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|error| ApiError::Internal(error.to_string()))?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(if url.contains(":memory:") { 1 } else { 8 })
            .connect_with(options)
            .await?;
        let database = Self { pool };
        database.migrate().await?;
        Ok(database)
    }

    pub async fn in_memory() -> ApiResult<Self> {
        Self::connect("sqlite::memory:").await
    }

    pub async fn migrate(&self) -> ApiResult<()> {
        for statement in [
            "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, identity_dh BLOB NOT NULL, identity_sig BLOB NOT NULL, token_hash BLOB NOT NULL, created_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS signed_prekeys (user_id TEXT NOT NULL, id INTEGER NOT NULL, public_key BLOB NOT NULL, signature BLOB NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(user_id,id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS one_time_prekeys (user_id TEXT NOT NULL, id INTEGER NOT NULL, public_key BLOB NOT NULL, consumed_at INTEGER, PRIMARY KEY(user_id,id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL, payload BLOB NOT NULL, created_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS messages_recipient_idx ON messages(recipient_id, created_at)",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn register(&self, request: RegistrationRequest) -> ApiResult<RegistrationResponse> {
        validate_username(&request.username)?;
        request
            .identity
            .verify_signed_prekey(&request.signed_prekey)
            .map_err(|_| ApiError::BadRequest("invalid signed pre-key signature".into()))?;
        validate_prekeys(&request.one_time_prekeys)?;
        let user_id = Uuid::new_v4();
        let mut token_bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO users(id,username,identity_dh,identity_sig,token_hash,created_at) VALUES(?,?,?,?,?,?)")
            .bind(user_id.to_string())
            .bind(&request.username)
            .bind(request.identity.dh.as_slice())
            .bind(request.identity.signing.as_slice())
            .bind(token_hash)
            .bind(Utc::now().timestamp_millis())
            .execute(&mut *transaction)
            .await
            .map_err(|error| ApiError::from_sqlx(error, "username already registered"))?;
        insert_signed_prekey(
            &mut transaction,
            &user_id.to_string(),
            &request.signed_prekey,
        )
        .await?;
        insert_prekeys(
            &mut transaction,
            &user_id.to_string(),
            &request.one_time_prekeys,
        )
        .await?;
        transaction.commit().await?;
        Ok(RegistrationResponse {
            user_id,
            username: request.username,
            token,
        })
    }

    pub async fn upload_prekeys(&self, user_id: Uuid, upload: PreKeyUpload) -> ApiResult<()> {
        let identity = self.identity_for(user_id).await?;
        identity
            .verify_signed_prekey(&upload.signed_prekey)
            .map_err(|_| ApiError::BadRequest("invalid signed pre-key signature".into()))?;
        validate_prekeys(&upload.one_time_prekeys)?;
        let mut transaction = self.pool.begin().await?;
        insert_signed_prekey(
            &mut transaction,
            &user_id.to_string(),
            &upload.signed_prekey,
        )
        .await?;
        for prekey in &upload.one_time_prekeys {
            insert_one_time(&mut transaction, user_id, prekey).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn bundle_for(&self, username: &str) -> ApiResult<BundleResponse> {
        let mut transaction = self.pool.begin().await?;
        let user = sqlx::query("SELECT id,identity_dh,identity_sig FROM users WHERE username=?")
            .bind(username)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApiError::NotFound)?;
        let id_text: String = user.try_get("id")?;
        let user_id = Uuid::parse_str(&id_text).map_err(|e| ApiError::Internal(e.to_string()))?;
        let identity = IdentityPublic {
            dh: fixed_array(user.try_get("identity_dh")?)?,
            signing: fixed_array(user.try_get("identity_sig")?)?,
        };
        let signed = sqlx::query("SELECT id,public_key,signature FROM signed_prekeys WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT 1")
            .bind(&id_text)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApiError::NotFound)?;
        let one_time = sqlx::query("UPDATE one_time_prekeys SET consumed_at=? WHERE user_id=? AND id=(SELECT id FROM one_time_prekeys WHERE user_id=? AND consumed_at IS NULL ORDER BY id LIMIT 1) AND consumed_at IS NULL RETURNING id,public_key")
            .bind(Utc::now().timestamp_millis())
            .bind(&id_text)
            .bind(&id_text)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<_, ApiError>(PublicOneTimePreKey {
                    id: u32::try_from(row.try_get::<i64,_>("id")?).map_err(|_| ApiError::Internal("invalid pre-key id".into()))?,
                    public_key: fixed_array(row.try_get("public_key")?)?,
                })
            })
            .transpose()?;
        let signed_prekey = SignedPreKeyPublic {
            id: u32::try_from(signed.try_get::<i64, _>("id")?)
                .map_err(|_| ApiError::Internal("invalid signed pre-key id".into()))?,
            public_key: fixed_array(signed.try_get("public_key")?)?,
            signature: signed.try_get("signature")?,
        };
        transaction.commit().await?;
        Ok(BundleResponse {
            user_id,
            username: username.to_owned(),
            identity,
            signed_prekey,
            one_time_prekey: one_time,
        })
    }

    pub async fn authenticate(&self, token: &str) -> ApiResult<Uuid> {
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let row = sqlx::query("SELECT id FROM users WHERE token_hash=?")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        let id: String = row.try_get("id")?;
        Uuid::parse_str(&id).map_err(|error| ApiError::Internal(error.to_string()))
    }

    pub async fn enqueue(
        &self,
        sender_id: Uuid,
        recipient_id: Uuid,
        message: EncryptedMessage,
    ) -> ApiResult<Uuid> {
        if message.ciphertext.len() > 256 * 1024 {
            return Err(ApiError::PayloadTooLarge);
        }
        let payload = serde_json::to_vec(&message)?;
        if self
            .queued_message_matches(message.id, sender_id, recipient_id, &payload)
            .await?
        {
            return Ok(message.id);
        }
        if self.message_exists(message.id).await? {
            return Err(ApiError::Conflict);
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE recipient_id=?")
            .bind(recipient_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        if count >= 1000 {
            return Err(ApiError::PayloadTooLarge);
        }
        let inserted = sqlx::query("INSERT INTO messages(id,sender_id,recipient_id,payload,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING")
            .bind(message.id.to_string())
            .bind(sender_id.to_string())
            .bind(recipient_id.to_string())
            .bind(&payload)
            .bind(Utc::now().timestamp_millis())
            .execute(&self.pool)
            .await?;
        if inserted.rows_affected() == 1 {
            return Ok(message.id);
        }
        if self
            .queued_message_matches(message.id, sender_id, recipient_id, &payload)
            .await?
        {
            Ok(message.id)
        } else {
            Err(ApiError::Conflict)
        }
    }

    async fn message_exists(&self, message_id: Uuid) -> ApiResult<bool> {
        let row = sqlx::query("SELECT id FROM messages WHERE id=?")
            .bind(message_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn queued_message_matches(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        recipient_id: Uuid,
        payload: &[u8],
    ) -> ApiResult<bool> {
        let row = sqlx::query("SELECT sender_id,recipient_id,payload FROM messages WHERE id=?")
            .bind(message_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        Ok(
            row.try_get::<String, _>("sender_id")? == sender_id.to_string()
                && row.try_get::<String, _>("recipient_id")? == recipient_id.to_string()
                && row.try_get::<Vec<u8>, _>("payload")? == payload,
        )
    }

    pub async fn pending_messages(
        &self,
        recipient_id: Uuid,
        limit: i64,
    ) -> ApiResult<Vec<QueuedMessage>> {
        let rows = sqlx::query("SELECT id,sender_id,recipient_id,payload,created_at FROM messages WHERE recipient_id=? ORDER BY created_at,id LIMIT ?")
            .bind(recipient_id.to_string())
            .bind(limit.clamp(1, 100))
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let payload: Vec<u8> = row.try_get("payload")?;
                Ok(QueuedMessage {
                    id: Uuid::parse_str(&row.try_get::<String, _>("id")?)
                        .map_err(|e| ApiError::Internal(e.to_string()))?,
                    sender_id: Uuid::parse_str(&row.try_get::<String, _>("sender_id")?)
                        .map_err(|e| ApiError::Internal(e.to_string()))?,
                    recipient_id: Uuid::parse_str(&row.try_get::<String, _>("recipient_id")?)
                        .map_err(|e| ApiError::Internal(e.to_string()))?,
                    payload: serde_json::from_slice(&payload)?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn acknowledge(&self, recipient_id: Uuid, message_id: Uuid) -> ApiResult<bool> {
        let result = sqlx::query("DELETE FROM messages WHERE id=? AND recipient_id=?")
            .bind(message_id.to_string())
            .bind(recipient_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

async fn insert_signed_prekey(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
    prekey: &SignedPreKeyPublic,
) -> ApiResult<()> {
    sqlx::query("INSERT OR REPLACE INTO signed_prekeys(user_id,id,public_key,signature,created_at) VALUES(?,?,?,?,?)")
        .bind(user_id)
        .bind(i64::from(prekey.id))
        .bind(prekey.public_key.as_slice())
        .bind(&prekey.signature)
        .bind(Utc::now().timestamp_millis())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn validate_username(username: &str) -> ApiResult<()> {
    if username.len() < 3
        || username.len() > 32
        || !username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Err(ApiError::BadRequest(
            "username must be 3-32 lowercase ASCII letters, digits, underscores, or hyphens".into(),
        ));
    }
    Ok(())
}

fn validate_prekeys(prekeys: &[PublicOneTimePreKey]) -> ApiResult<()> {
    if prekeys.is_empty() || prekeys.len() > 100 {
        return Err(ApiError::BadRequest(
            "between 1 and 100 one-time pre-keys are required".into(),
        ));
    }
    let mut ids = HashSet::new();
    for prekey in prekeys {
        if prekey.id == 0 || !ids.insert(prekey.id) {
            return Err(ApiError::BadRequest(
                "one-time pre-key ids must be unique and nonzero".into(),
            ));
        }
    }
    Ok(())
}

async fn insert_one_time(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: Uuid,
    prekey: &PublicOneTimePreKey,
) -> ApiResult<()> {
    sqlx::query("INSERT OR IGNORE INTO one_time_prekeys(user_id,id,public_key) VALUES(?,?,?)")
        .bind(user_id.to_string())
        .bind(i64::from(prekey.id))
        .bind(prekey.public_key.as_slice())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn fixed_array(bytes: Vec<u8>) -> ApiResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| ApiError::Internal("invalid key length in database".into()))
}

impl Database {
    async fn identity_for(&self, user_id: Uuid) -> ApiResult<IdentityPublic> {
        let row = sqlx::query("SELECT identity_dh,identity_sig FROM users WHERE id=?")
            .bind(user_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(IdentityPublic {
            dh: fixed_array(row.try_get("identity_dh")?)?,
            signing: fixed_array(row.try_get("identity_sig")?)?,
        })
    }
}

async fn insert_prekeys(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
    prekeys: &[PublicOneTimePreKey],
) -> ApiResult<()> {
    for prekey in prekeys {
        sqlx::query("INSERT OR IGNORE INTO one_time_prekeys(user_id,id,public_key) VALUES(?,?,?)")
            .bind(user_id)
            .bind(i64::from(prekey.id))
            .bind(prekey.public_key.as_slice())
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}
