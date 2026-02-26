// gamlastan xml error types

use thiserror::Error;

/// Errors that occur during SAML XML deserialization or serialization.
#[derive(Debug, Error)]
pub enum XmlError {
    /// The XML document could not be parsed.
    #[error("XML parse error: {0}")]
    ParseError(#[from] uppsala::XmlError),

    /// The document is empty (no root element).
    #[error("Empty XML document: no root element")]
    EmptyDocument,

    /// A node is not an element when one was expected.
    #[error("Expected an element node")]
    NotAnElement,

    /// A required XML element is missing.
    #[error("Missing required element: {element} in {parent}")]
    MissingElement {
        /// The parent element context.
        parent: String,
        /// The missing child element name.
        element: String,
    },

    /// A required XML attribute is missing.
    #[error("Missing required attribute: {attribute} on {element}")]
    MissingAttribute {
        /// The element name.
        element: String,
        /// The missing attribute name.
        attribute: String,
    },

    /// An unexpected XML element was encountered.
    #[error("Unexpected element: {0}")]
    UnexpectedElement(String),

    /// An unexpected namespace was found on an element.
    #[error("Unexpected namespace on {element}: expected {expected}, found {found}")]
    UnexpectedNamespace {
        /// The element name.
        element: String,
        /// The expected namespace URI.
        expected: String,
        /// The found namespace URI.
        found: String,
    },

    /// An invalid attribute value was encountered.
    #[error("Invalid attribute value for {attribute} on {element}: {value}")]
    InvalidAttributeValue {
        /// The element name.
        element: String,
        /// The attribute name.
        attribute: String,
        /// The invalid value.
        value: String,
    },

    /// A datetime string could not be parsed.
    #[error("Invalid datetime: {0}")]
    InvalidDateTime(String),

    /// A boolean value could not be parsed.
    #[error("Invalid boolean value: {0}")]
    InvalidBoolean(String),

    /// An integer value could not be parsed.
    #[error("Invalid integer value: {0}")]
    InvalidInteger(String),

    /// A base64-encoded value could not be decoded.
    #[error("Invalid base64 value: {0}")]
    InvalidBase64(String),

    /// A core type validation error occurred.
    #[error("Core validation error: {0}")]
    CoreError(#[from] crate::core::CoreError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}
