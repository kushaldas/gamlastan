// Metadata error types

use thiserror::Error;

/// Errors specific to SAML metadata processing.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum MetadataError {
    /// Invalid metadata structure or content.
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Metadata signature is invalid.
    #[error("Metadata signature invalid: {0}")]
    SignatureInvalid(String),

    /// A required endpoint is missing.
    #[error("Missing required endpoint: {0}")]
    MissingRequiredEndpoint(String),

    /// Metadata violates the schema.
    #[error("Schema violation: {0}")]
    SchemaViolation(String),

    /// Metadata has expired (validUntil has passed).
    #[error("Metadata expired: validUntil {0}")]
    Expired(String),

    /// A core SAML error occurred.
    #[error("Core error: {0}")]
    Core(#[from] swsaml_core::error::CoreError),

    /// An XML parsing/serialization error occurred.
    #[error("XML error: {0}")]
    Xml(String),
}

impl From<swsaml_xml::XmlError> for MetadataError {
    fn from(e: swsaml_xml::XmlError) -> Self {
        MetadataError::Xml(e.to_string())
    }
}
