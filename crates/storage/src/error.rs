use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("local database error")]
    Database(#[from] rusqlite::Error),
    #[error("local record authentication failed")]
    Authentication,
    #[error("incorrect passphrase")]
    WrongPassphrase,
    #[error("local record not found")]
    NotFound,
    #[error("invalid local data: {0}")]
    InvalidData(String),
    #[error("local serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("local encryption failed")]
    Encryption,
    #[error("key derivation failed")]
    KeyDerivation,
}

pub type Result<T> = std::result::Result<T, StorageError>;
