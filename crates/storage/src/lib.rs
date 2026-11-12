#![forbid(unsafe_code)]

mod error;
mod models;

pub use error::{Result, StorageError};
pub use models::{
    Contact, DeliveryState, Direction, MediaMetadata, MessageContent, MessageRecord,
    PreKeyMaterial, StoredAccount,
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const VAULT_AAD: &[u8] = b"signal-rust/local-vault/v1";
const CHECK_NAMESPACE: &str = "vault";
const CHECK_KEY: &str = "key-check";

pub struct Store {
    connection: Connection,
    encryption_key: [u8; 32],
    index_key: [u8; 32],
}

impl Drop for Store {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.index_key.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    namespace: String,
    key: String,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredSession {
    state: Vec<u8>,
    initial: Option<crypto_core::InitialHeader>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingMessage {
    pub peer_id: Uuid,
    pub message: crypto_core::EncryptedMessage,
}

impl Store {
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", "5000")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                name TEXT PRIMARY KEY,
                value BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS vault_records (
                 lookup BLOB PRIMARY KEY,
                 nonce BLOB NOT NULL,
                 ciphertext BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );",
        )?;
        let existing_salt: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM vault_meta WHERE name='kdf_salt'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let initialized = existing_salt.is_some();
        let salt = match existing_salt {
            Some(bytes) => bytes,
            None => {
                let mut salt = [0_u8; 16];
                OsRng.fill_bytes(&mut salt);
                connection.execute(
                    "INSERT INTO vault_meta(name,value) VALUES('kdf_salt',?1)",
                    [&salt[..]],
                )?;
                salt.to_vec()
            }
        };
        if salt.len() != 16 {
            return Err(StorageError::InvalidData("invalid salt length".to_owned()));
        }
        let mut encryption_key = [0_u8; 32];
        let mut index_key = [0_u8; 32];
        derive_keys(
            passphrase.as_bytes(),
            &salt,
            &mut encryption_key,
            &mut index_key,
        )?;
        let store = Self {
            connection,
            encryption_key,
            index_key,
        };
        match store.get::<String>(CHECK_NAMESPACE, CHECK_KEY) {
            Ok(Some(value)) if value == "signal-rust-vault-v1" => Ok(store),
            Ok(Some(_)) => Err(StorageError::InvalidData("invalid key check".to_owned())),
            Ok(None) if !initialized => {
                store.put(CHECK_NAMESPACE, CHECK_KEY, "signal-rust-vault-v1")?;
                Ok(store)
            }
            Ok(None) => Err(StorageError::WrongPassphrase),
            Err(StorageError::Authentication) | Err(StorageError::Serialization(_)) => {
                Err(StorageError::WrongPassphrase)
            }
            Err(error) => Err(error),
        }
    }

    pub fn save_account(&self, account: &StoredAccount) -> Result<()> {
        self.put("account", "primary", account)
    }

    pub fn account(&self) -> Result<StoredAccount> {
        self.get("account", "primary")?
            .ok_or(StorageError::NotFound)
    }

    pub fn save_session(&self, peer_id: Uuid, session: &crypto_core::DoubleRatchet) -> Result<()> {
        let initial = self
            .get::<StoredSession>("session", &peer_id.to_string())?
            .and_then(|record| record.initial);
        self.write_session(peer_id, session, initial)
    }

    pub fn create_session(
        &self,
        peer_id: Uuid,
        session: &crypto_core::DoubleRatchet,
        initial: &crypto_core::InitialHeader,
    ) -> Result<()> {
        self.write_session(peer_id, session, Some(initial.clone()))
    }

    pub fn pending_initial(&self, peer_id: Uuid) -> Result<Option<crypto_core::InitialHeader>> {
        Ok(self
            .get::<StoredSession>("session", &peer_id.to_string())?
            .and_then(|record| record.initial))
    }

    pub fn clear_pending_initial(&self, peer_id: Uuid) -> Result<()> {
        let key = peer_id.to_string();
        if let Some(record) = self.get::<StoredSession>("session", &key)? {
            self.put(
                "session",
                &key,
                &StoredSession {
                    state: record.state,
                    initial: None,
                },
            )?;
        }
        Ok(())
    }

    pub fn load_session(&self, peer_id: Uuid) -> Result<Option<crypto_core::DoubleRatchet>> {
        let Some(record) = self.get::<StoredSession>("session", &peer_id.to_string())? else {
            return Ok(None);
        };
        crypto_core::DoubleRatchet::from_bytes(&record.state)
            .map(Some)
            .map_err(|error| StorageError::InvalidData(error.to_string()))
    }

    pub fn save_outgoing(&self, message: &OutgoingMessage) -> Result<()> {
        self.put("outbox", &message.message.id.to_string(), message)
    }

    pub fn outbox(&self) -> Result<Vec<OutgoingMessage>> {
        self.get_all("outbox")
    }

    pub fn delete_outgoing(&self, message_id: Uuid) -> Result<()> {
        self.delete("outbox", &message_id.to_string())
    }

    pub fn save_seen(&self, message_id: Uuid, digest: [u8; 32]) -> Result<()> {
        self.put("seen", &message_id.to_string(), &digest)
    }

    pub fn seen(&self, message_id: Uuid) -> Result<Option<[u8; 32]>> {
        self.get("seen", &message_id.to_string())
    }

    fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let lookup = self.lookup(namespace, key)?;
        self.connection
            .execute("DELETE FROM vault_records WHERE lookup=?1", [&lookup])?;
        Ok(())
    }

    fn write_session(
        &self,
        peer_id: Uuid,
        session: &crypto_core::DoubleRatchet,
        initial: Option<crypto_core::InitialHeader>,
    ) -> Result<()> {
        let state = session
            .to_bytes()
            .map_err(|error| StorageError::InvalidData(error.to_string()))?;
        self.put(
            "session",
            &peer_id.to_string(),
            &StoredSession { state, initial },
        )
    }

    pub fn delete_session(&self, peer_id: Uuid) -> Result<()> {
        let lookup = self.lookup("session", &peer_id.to_string())?;
        self.connection
            .execute("DELETE FROM vault_records WHERE lookup=?1", [&lookup])?;
        Ok(())
    }

    pub fn save_contact(&self, contact: &Contact) -> Result<()> {
        self.put("contact", &contact.user_id.to_string(), contact)
    }

    pub fn contact(&self, user_id: Uuid) -> Result<Option<Contact>> {
        self.get("contact", &user_id.to_string())
    }

    pub fn contacts(&self) -> Result<Vec<Contact>> {
        self.get_all("contact")
    }

    pub fn set_contact_verified(&self, user_id: Uuid, verified: bool) -> Result<()> {
        let key = user_id.to_string();
        let mut contact: Contact = self.get("contact", &key)?.ok_or(StorageError::NotFound)?;
        contact.verified = verified;
        self.put("contact", &key, &contact)
    }

    pub fn save_message(&self, message: &MessageRecord) -> Result<()> {
        self.put("message", &message.id.to_string(), message)
    }

    pub fn message(&self, message_id: Uuid) -> Result<Option<MessageRecord>> {
        self.get("message", &message_id.to_string())
    }

    pub fn messages(&self, peer_id: Uuid) -> Result<Vec<MessageRecord>> {
        let mut messages: Vec<MessageRecord> = self
            .get_all::<MessageRecord>("message")?
            .into_iter()
            .filter(|message| message.peer_id == peer_id)
            .collect();
        messages.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(messages)
    }

    pub fn mark_delivered(&self, message_id: Uuid) -> Result<bool> {
        self.mark_receipt(message_id, DeliveryState::Delivered)
    }

    pub fn mark_read(&self, message_id: Uuid) -> Result<bool> {
        self.mark_receipt(message_id, DeliveryState::Read)
    }

    pub fn mark_receipt(&self, message_id: Uuid, state: DeliveryState) -> Result<bool> {
        if state == DeliveryState::Queued || state == DeliveryState::Sent {
            return Err(StorageError::InvalidData(
                "receipt state must be delivered or read".to_owned(),
            ));
        }
        let Some(mut record) = self.message(message_id)? else {
            return Ok(false);
        };
        if record.direction != Direction::Outgoing {
            return Ok(false);
        }
        if record.state == DeliveryState::Read && state == DeliveryState::Delivered {
            return Ok(true);
        }
        record.state = state;
        self.save_message(&record)?;
        Ok(true)
    }

    pub fn mark_local_read(&self, message_id: Uuid) -> Result<bool> {
        let Some(mut record) = self.message(message_id)? else {
            return Ok(false);
        };
        if record.direction != Direction::Incoming {
            return Ok(false);
        }
        record.state = DeliveryState::Read;
        self.save_message(&record)?;
        Ok(true)
    }

    pub fn read_all_messages(&self) -> Result<Vec<MessageRecord>> {
        self.get_all("message")
    }

    fn lookup(&self, namespace: &str, key: &str) -> Result<Vec<u8>> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.index_key)
            .map_err(|_| StorageError::KeyDerivation)?;
        mac.update(VAULT_AAD);
        mac.update(&(namespace.len() as u64).to_be_bytes());
        mac.update(namespace.as_bytes());
        mac.update(&(key.len() as u64).to_be_bytes());
        mac.update(key.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn get<T: DeserializeOwned>(&self, namespace: &str, key: &str) -> Result<Option<T>> {
        let lookup = self.lookup(namespace, key)?;
        let row = self
            .connection
            .query_row(
                "SELECT nonce,ciphertext FROM vault_records WHERE lookup=?1",
                [&lookup],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((nonce, ciphertext)) = row else {
            return Ok(None);
        };
        let envelope = self.decrypt(&lookup, &nonce, &ciphertext)?;
        if envelope.namespace != namespace || envelope.key != key {
            return Err(StorageError::Authentication);
        }
        Ok(Some(serde_json::from_slice(&envelope.payload)?))
    }

    fn get_all<T: DeserializeOwned>(&self, namespace: &str) -> Result<Vec<T>> {
        let mut statement = self
            .connection
            .prepare("SELECT lookup,nonce,ciphertext FROM vault_records")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut values = Vec::new();
        for row in rows {
            let (lookup, nonce, ciphertext) = row?;
            let envelope = self.decrypt(&lookup, &nonce, &ciphertext)?;
            if envelope.namespace == namespace {
                values.push(serde_json::from_slice(&envelope.payload)?);
            }
        }
        Ok(values)
    }

    fn put<T: Serialize + ?Sized>(&self, namespace: &str, key: &str, value: &T) -> Result<()> {
        let payload = Zeroizing::new(serde_json::to_vec(value)?);
        let envelope = Envelope {
            namespace: namespace.to_owned(),
            key: key.to_owned(),
            payload: payload.to_vec(),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&envelope)?);
        let lookup = self.lookup(namespace, key)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|_| StorageError::InvalidData("invalid vault key length".to_owned()))?;
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &lookup,
                },
            )
            .map_err(|_| StorageError::Encryption)?;
        self.connection.execute(
            "INSERT INTO vault_records(lookup,nonce,ciphertext,updated_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(lookup) DO UPDATE SET nonce=excluded.nonce,
                 ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
            params![lookup, &nonce[..], ciphertext, timestamp()?],
        )?;
        Ok(())
    }

    fn decrypt(&self, lookup: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Envelope> {
        if nonce.len() != 12 {
            return Err(StorageError::InvalidData("invalid nonce length".to_owned()));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|_| StorageError::InvalidData("invalid vault key length".to_owned()))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: lookup,
                    },
                )
                .map_err(|_| StorageError::Authentication)?,
        );
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

fn derive_keys(
    passphrase: &[u8],
    salt: &[u8],
    encryption_key: &mut [u8; 32],
    index_key: &mut [u8; 32],
) -> Result<()> {
    let params = Params::new(19 * 1024, 2, 1, Some(64)).map_err(|_| StorageError::KeyDerivation)?;
    let mut derived = Zeroizing::new([0_u8; 64]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut derived[..])
        .map_err(|_| StorageError::KeyDerivation)?;
    encryption_key.copy_from_slice(&derived[..32]);
    index_key.copy_from_slice(&derived[32..]);
    Ok(())
}

fn timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| StorageError::InvalidData("timestamp out of range".to_owned()))
}
