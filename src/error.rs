use thiserror::Error;

/// Core error types for KREL encryption engine
#[derive(Debug, Error)]
pub enum KrelError {
    /// Container format error (e.g., wrong magic bytes)
    #[error("Container format error: {0}")]
    ContainerError(String),

    /// Integrity check failure (e.g., hash mismatch)
    #[error("Integrity verification failed: {0}")]
    IntegrityError(String),

    /// Authentication error (e.g., wrong password, invalid AEAD tag)
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// I/O operation error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Invalid parameter or state
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

pub type Result<T> = std::result::Result<T, KrelError>;
