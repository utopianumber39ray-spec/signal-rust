use crypto_core::{
    EncryptedMessage, IdentityPublic, PreKeyBundle, PublicOneTimePreKey, SignedPreKeyPublic,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekeys: Vec<PublicOneTimePreKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub user_id: Uuid,
    pub username: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeyUpload {
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekeys: Vec<PublicOneTimePreKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleResponse {
    pub user_id: Uuid,
    pub username: String,
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

impl BundleResponse {
    pub fn bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity: self.identity.clone(),
            signed_prekey: self.signed_prekey.clone(),
            one_time_prekey: self.one_time_prekey.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_id: Uuid,
    pub message: EncryptedMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub payload: EncryptedMessage,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
