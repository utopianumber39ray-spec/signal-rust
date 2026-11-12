use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("signed pre-key signature is invalid")]
    InvalidSignedPreKey,
    #[error("initial header authentication failed")]
    InvalidInitialAuthentication,
    #[error("one-time pre-key {0} is unavailable")]
    MissingOneTimePreKey(u32),
    #[error("AEAD authentication failed")]
    Authentication,
    #[error("message key was already consumed or is unavailable")]
    MessageKeyUnavailable,
    #[error("message key skip limit exceeded")]
    TooManySkippedKeys,
    #[error("invalid ratchet state: {0}")]
    InvalidState(&'static str),
    #[error("cryptographic output length is invalid")]
    InvalidLength,
    #[error("signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error(transparent)]
    Serialization(#[from] bincode::Error),
}
