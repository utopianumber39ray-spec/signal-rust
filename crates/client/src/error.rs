use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("local storage: {0}")]
    Storage(#[from] signal_storage::StorageError),
    #[error("protocol failure: {0}")]
    Protocol(#[from] crypto_core::Error),
    #[error("network request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("server rejected request ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("contact not found")]
    UnknownContact,
    #[error("contact identity key changed; inspect the new fingerprint before trusting it")]
    IdentityChanged,
    #[error("message is not available to this client")]
    NoSession,
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;
