// SAML 2.0 Error types

use thiserror::Error;

/// Core SAML errors for type construction and basic validation.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CoreError {
    /// Entity ID exceeds maximum length of 1024 characters.
    #[error("Entity ID too long: {0} characters (max 1024)")]
    EntityIdTooLong(usize),

    /// Entity ID is empty.
    #[error("Entity ID must not be empty")]
    EntityIdEmpty,

    /// A required XML element is missing.
    #[error("Missing required element: {0}")]
    MissingRequiredElement(String),

    /// A required XML attribute is missing.
    #[error("Missing required attribute: {element}.{attribute}")]
    MissingRequiredAttribute {
        /// The element name containing the missing attribute.
        element: String,
        /// The missing attribute name.
        attribute: String,
    },

    /// An invalid datetime string was encountered.
    #[error("Invalid datetime: {0}")]
    InvalidDateTime(String),

    /// An invalid URI was encountered.
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// An invalid SAML version was encountered.
    #[error("Invalid SAML version: {0}")]
    InvalidVersion(String),

    /// An invalid SAML ID was encountered.
    #[error("Invalid SAML ID: {0}")]
    InvalidId(String),

    /// An invalid enum value was encountered.
    #[error("Invalid value for {field}: {value}")]
    InvalidValue {
        /// The field name.
        field: String,
        /// The invalid value.
        value: String,
    },

    /// An unexpected element was encountered.
    #[error("Unexpected element: {0}")]
    UnexpectedElement(String),

    /// An unexpected attribute was encountered.
    #[error("Unexpected attribute: {0}")]
    UnexpectedAttribute(String),
}
