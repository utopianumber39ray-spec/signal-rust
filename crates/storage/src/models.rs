use crypto_core::{IdentityKeyPair, IdentityPublic, OneTimePreKey, RatchetKeyPair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyMaterial {
    pub id: u32,
    pub secret: [u8; 32],
}

impl PreKeyMaterial {
    pub fn ratchet_key(&self) -> RatchetKeyPair {
        RatchetKeyPair::from_bytes(self.secret)
    }

    pub fn one_time_key(&self) -> OneTimePreKey {
        OneTimePreKey {
            id: self.id,
            key: RatchetKeyPair::from_bytes(self.secret),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredAccount {
    pub user_id: Uuid,
    pub username: String,
    pub token: String,
    pub identity_dh: [u8; 32],
    pub identity_signing: [u8; 32],
    pub signed_prekeys: Vec<PreKeyMaterial>,
    pub one_time_prekeys: Vec<PreKeyMaterial>,
    pub next_prekey_id: u32,
}

impl Drop for StoredAccount {
    fn drop(&mut self) {
        self.token.zeroize();
        self.identity_dh.zeroize();
        self.identity_signing.zeroize();
        self.signed_prekeys.zeroize();
        self.one_time_prekeys.zeroize();
    }
}

impl StoredAccount {
    pub fn identity(&self) -> IdentityKeyPair {
        IdentityKeyPair::from_bytes(self.identity_dh, self.identity_signing)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub user_id: Uuid,
    pub username: String,
    pub identity: IdentityPublic,
    pub fingerprint: String,
    pub verified: bool,
}

impl Contact {
    pub fn new(user_id: Uuid, username: String, identity: IdentityPublic) -> Self {
        let fingerprint = identity.fingerprint();
        Self {
            user_id,
            username,
            identity,
            fingerprint,
            verified: false,
        }
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaMetadata {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum MessageContent {
    Text { text: String },
    Media(MediaMetadata),
    DeliveryReceipt { message_id: Uuid },
    ReadReceipt { message_ids: Vec<Uuid> },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryState {
    Queued,
    Sent,
    Delivered,
    Read,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: Uuid,
    pub peer_id: Uuid,
    pub direction: Direction,
    pub content: MessageContent,
    pub state: DeliveryState,
    pub created_at: i64,
}
