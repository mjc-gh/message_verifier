/// Errors from message authentication, serialization, and configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid message signature")]
    InvalidSignature,
    #[error("invalid message encoding or format")]
    InvalidMessage,
    #[error("message has expired")]
    Expired,
    #[error("message purpose does not match")]
    PurposeMismatch,
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("PBKDF2 iterations and output length must be greater than zero")]
    InvalidKeyDerivation,
    #[error("invalid or out-of-range expiration timestamp")]
    InvalidTimestamp,
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("secure random number generation failed")]
    Randomness,
}

impl Error {
    pub(crate) fn is_content(&self) -> bool {
        matches!(self, Self::Expired | Self::PurposeMismatch)
    }

    pub(crate) fn is_rejected(&self) -> bool {
        self.is_content() || matches!(self, Self::InvalidSignature | Self::InvalidMessage)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
