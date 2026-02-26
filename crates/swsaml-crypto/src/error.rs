// swsaml-crypto error types

use thiserror::Error;

/// Errors that occur during SAML cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The underlying bergshamra library returned an error.
    #[error("XML security error: {0}")]
    BergshamraError(#[from] bergshamra_core::Error),

    /// A required key was not found in the keys manager.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// The signature contains a ds:Object element, which is rejected per E91.
    #[error("Signature contains ds:Object element (rejected per SAML errata E91)")]
    SignatureContainsDsObject,

    /// An unsupported algorithm was requested.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// Certificate validation failed.
    #[error("Certificate validation error: {0}")]
    CertificateError(String),

    /// Encryption failed.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption failed.
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// An invalid configuration was provided.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
