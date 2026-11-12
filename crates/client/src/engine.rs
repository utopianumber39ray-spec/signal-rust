use crate::net::post_unauthenticated;
use crate::{ClientError, Result};
use crypto_core::{
    DoubleRatchet, OneTimePreKey, PublicOneTimePreKey, RatchetKeyPair, SignedPreKeyPublic,
};
use signal_server::{BundleResponse, PreKeyUpload, RegistrationRequest, RegistrationResponse};
use signal_storage::{
    Contact, MessageContent, MessageRecord, PreKeyMaterial, Store, StoredAccount,
};
use uuid::Uuid;

const INITIAL_PREKEYS: u32 = 20;

pub struct Client {
    pub(crate) store: Store,
    pub(crate) account: StoredAccount,
    pub(crate) http: reqwest::Client,
    pub(crate) server: String,
}

#[derive(Clone, Debug)]
pub struct ReceivedEvent {
    pub peer_id: Uuid,
    pub message_id: Uuid,
    pub content: MessageContent,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct PollReport {
    pub events: Vec<ReceivedEvent>,
    pub warnings: Vec<String>,
}

impl Client {
    pub fn open(store: Store, server: &str) -> Result<Self> {
        validate_server(server)?;
        Ok(Self {
            account: store.account()?,
            store,
            http: crate::net::http_client()?,
            server: server.trim_end_matches('/').to_owned(),
        })
    }

    pub async fn register(store: Store, server: &str, username: &str) -> Result<Self> {
        validate_server(server)?;
        let server = server.trim_end_matches('/');
        if !valid_username(username) {
            return Err(ClientError::InvalidInput("invalid username".to_owned()));
        }
        match store.account() {
            Ok(_) => {
                return Err(ClientError::InvalidInput(
                    "account already registered".into(),
                ))
            }
            Err(signal_storage::StorageError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let identity = crypto_core::IdentityKeyPair::generate();
        let signed = RatchetKeyPair::generate();
        let keys: Vec<OneTimePreKey> = (1..=INITIAL_PREKEYS).map(OneTimePreKey::generate).collect();
        let request = RegistrationRequest {
            username: username.to_owned(),
            identity: identity.public(),
            signed_prekey: SignedPreKeyPublic::new(&identity, 1, &signed),
            one_time_prekeys: keys.iter().map(OneTimePreKey::public).collect(),
        };
        let registration: RegistrationResponse =
            post_unauthenticated(server, "/v1/users/register", &request).await?;
        let account = StoredAccount {
            user_id: registration.user_id,
            username: registration.username,
            token: registration.token,
            identity_dh: identity.dh_secret_bytes(),
            identity_signing: identity.signing_bytes(),
            signed_prekeys: vec![PreKeyMaterial {
                id: 1,
                secret: signed.secret_bytes(),
            }],
            one_time_prekeys: keys
                .iter()
                .map(|key| PreKeyMaterial {
                    id: key.id,
                    secret: key.key.secret_bytes(),
                })
                .collect(),
            next_prekey_id: INITIAL_PREKEYS + 1,
        };
        store.save_account(&account)?;
        Self::open(store, server)
    }

    pub fn user_id(&self) -> Uuid {
        self.account.user_id
    }

    pub fn username(&self) -> &str {
        &self.account.username
    }

    pub fn contacts(&self) -> Result<Vec<Contact>> {
        Ok(self.store.contacts()?)
    }

    pub fn contact(&self, username: &str) -> Result<Contact> {
        self.store
            .contacts()?
            .into_iter()
            .find(|contact| contact.username == username)
            .ok_or(ClientError::UnknownContact)
    }

    pub fn history(&self, peer_id: Uuid) -> Result<Vec<MessageRecord>> {
        Ok(self.store.messages(peer_id)?)
    }

    pub fn fingerprint(&self, peer_id: Uuid) -> Result<String> {
        Ok(self
            .store
            .contact(peer_id)?
            .ok_or(ClientError::UnknownContact)?
            .fingerprint)
    }

    pub fn verify_contact(&self, peer_id: Uuid) -> Result<()> {
        self.store.set_contact_verified(peer_id, true)?;
        Ok(())
    }

    pub async fn add_contact(&mut self, username: &str) -> Result<Contact> {
        let bundle = self.bundle(username).await?;
        self.pin_contact(&bundle)
    }

    pub async fn start_session(&mut self, username: &str) -> Result<Contact> {
        if let Ok(contact) = self.contact(username) {
            if self.store.load_session(contact.user_id)?.is_some() {
                return Ok(contact);
            }
        }
        let bundle = self.bundle(username).await?;
        let contact = self.pin_contact(&bundle)?;
        let (session, initial) =
            DoubleRatchet::new_initiator(&self.account.identity(), &bundle.bundle())?;
        self.store
            .create_session(bundle.user_id, &session, &initial)?;
        Ok(contact)
    }

    pub async fn rotate_prekeys(&mut self) -> Result<()> {
        let signed_id = self
            .account
            .signed_prekeys
            .iter()
            .map(|key| key.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ClientError::InvalidInput("signed pre-key id exhausted".into()))?;
        let first_id = self.account.next_prekey_id;
        let next_id = first_id
            .checked_add(20)
            .ok_or_else(|| ClientError::InvalidInput("pre-key id exhausted".into()))?;
        let signed = RatchetKeyPair::generate();
        let mut new_keys = Vec::with_capacity(20);
        let mut public_keys = Vec::with_capacity(20);
        for offset in 0..20 {
            let id = first_id
                .checked_add(offset)
                .ok_or_else(|| ClientError::InvalidInput("pre-key id exhausted".into()))?;
            let key = RatchetKeyPair::generate();
            new_keys.push(PreKeyMaterial {
                id,
                secret: key.secret_bytes(),
            });
            public_keys.push(PublicOneTimePreKey {
                id,
                public_key: key.public_bytes(),
            });
        }
        let upload = PreKeyUpload {
            signed_prekey: SignedPreKeyPublic::new(&self.account.identity(), signed_id, &signed),
            one_time_prekeys: public_keys,
        };
        self.account.next_prekey_id = next_id;
        self.account.one_time_prekeys.extend(new_keys);
        self.account.signed_prekeys.push(PreKeyMaterial {
            id: signed_id,
            secret: signed.secret_bytes(),
        });
        if self.account.signed_prekeys.len() > 3 {
            self.account.signed_prekeys.remove(0);
        }
        self.store.save_account(&self.account)?;
        self.post_no_content("/v1/users/me/prekeys", &upload).await
    }

    pub(crate) async fn bundle(&self, username: &str) -> Result<BundleResponse> {
        if !valid_username(username) {
            return Err(ClientError::InvalidInput("invalid username".to_owned()));
        }
        crate::net::request_json(
            &self.http,
            &self.server,
            Some(&self.account.token),
            reqwest::Method::GET,
            &format!("/v1/users/{username}/bundle"),
            None::<&()>,
        )
        .await
    }

    pub(crate) async fn post_no_content<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<()> {
        crate::net::request_json::<serde_json::Value, B>(
            &self.http,
            &self.server,
            Some(&self.account.token),
            reqwest::Method::POST,
            path,
            Some(body),
        )
        .await?;
        Ok(())
    }

    fn pin_contact(&self, bundle: &BundleResponse) -> Result<Contact> {
        if bundle.user_id == self.account.user_id {
            return Err(ClientError::InvalidInput(
                "cannot add the local account as a contact".to_owned(),
            ));
        }
        bundle.bundle().verify()?;
        if self
            .store
            .contacts()?
            .iter()
            .any(|contact| contact.username == bundle.username && contact.user_id != bundle.user_id)
        {
            return Err(ClientError::IdentityChanged);
        }
        let mut contact = Contact::new(
            bundle.user_id,
            bundle.username.clone(),
            bundle.identity.clone(),
        );
        if let Some(existing) = self.store.contact(bundle.user_id)? {
            if existing.identity != bundle.identity {
                return Err(ClientError::IdentityChanged);
            }
            contact.verified = existing.verified;
        }
        self.store.save_contact(&contact)?;
        Ok(contact)
    }
}

fn valid_username(username: &str) -> bool {
    (3..=32).contains(&username.len())
        && username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn validate_server(server: &str) -> Result<()> {
    let url = reqwest::Url::parse(server)
        .map_err(|_| ClientError::InvalidInput("invalid server URL".to_owned()))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::InvalidInput(
            "server URL must not contain credentials, a query, or a fragment".to_owned(),
        ));
    }
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    );
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ClientError::InvalidInput(
            "server must use HTTPS, except on a loopback interface".to_owned(),
        ));
    }
    Ok(())
}
