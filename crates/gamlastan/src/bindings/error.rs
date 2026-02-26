// Binding-level errors for SAML 2.0 protocol bindings.

use thiserror::Error;

/// Errors that can occur during SAML binding operations.
#[derive(Debug, Error)]
pub enum BindingError {
    /// Base64 decode error.
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// DEFLATE decompression error.
    #[error("DEFLATE decompression error: {0}")]
    DeflateError(String),

    /// URL decoding error.
    #[error("URL decode error: {0}")]
    UrlDecodeError(String),

    /// Required SAML parameter missing from the request.
    #[error("missing SAML parameter: {0}")]
    MissingSamlParam(&'static str),

    /// Invalid artifact format.
    #[error("invalid artifact: {0}")]
    InvalidArtifact(String),

    /// Artifact has already been consumed (one-time-use violation).
    #[error("artifact already consumed")]
    ArtifactAlreadyConsumed,

    /// Artifact not found in the store.
    #[error("artifact not found")]
    ArtifactNotFound,

    /// RelayState exceeds 80-byte limit.
    #[error("RelayState exceeds 80-byte limit (got {0} bytes)")]
    RelayStateTooLong(usize),

    /// RelayState failed E90 sanitization (XSS/CSRF).
    #[error("RelayState failed sanitization: {0}")]
    RelayStateUnsafe(String),

    /// Signature verification failed for the binding.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Destination attribute mismatch.
    #[error("destination mismatch: expected {expected}, got {actual}")]
    DestinationMismatch { expected: String, actual: String },

    /// SOAP fault received.
    #[error("SOAP fault: {faultcode} - {faultstring}")]
    SoapFault {
        faultcode: String,
        faultstring: String,
        detail: Option<String>,
    },

    /// HTTP-level error.
    #[error("HTTP error: status {0}")]
    HttpError(u16),

    /// XML processing error.
    #[error("XML error: {0}")]
    XmlError(#[from] crate::xml::error::XmlError),

    /// Crypto error (from gamlastan crypto).
    #[error("crypto error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Message too large.
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    /// Invalid SOAP envelope.
    #[error("invalid SOAP envelope: {0}")]
    InvalidSoapEnvelope(String),
}
