//! Error type for the MDQ client.

use gamlastan::metadata::MetadataError;
use gamlastan::xml::XmlError;

use crate::client::RequiredRole;

/// Errors produced while fetching, verifying, or resolving metadata via MDQ.
#[derive(Debug, thiserror::Error)]
pub enum MdqError {
    /// The MDQ server returned a non-success HTTP status.
    #[error("MDQ server returned status {status}: {body}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The (possibly truncated) response body.
        body: String,
    },

    /// The HTTP transport failed (connection, timeout, TLS, ...).
    #[error("MDQ transport error: {0}")]
    Transport(String),

    /// The response body was not valid UTF-8 text.
    #[error("metadata response was not valid UTF-8: {0}")]
    NotUtf8(String),

    /// The metadata XML could not be parsed.
    #[error("failed to parse metadata: {0}")]
    Parse(#[from] XmlError),

    /// A metadata-layer error (validation, signing profile, ...).
    #[error(transparent)]
    Metadata(#[from] MetadataError),

    /// A configured signing certificate could not be loaded.
    #[error("invalid signing certificate: {0}")]
    Cert(String),

    /// Signature verification failed, or the signing profile was violated.
    #[error("metadata signature verification failed: {0}")]
    SignatureInvalid(String),

    /// A signing certificate is configured but the document is not signed.
    #[error("metadata is not signed but a signing certificate is configured")]
    Unsigned,

    /// The signature verified, but none of its verified XML-DSig references
    /// covered the metadata element being trusted. A valid signature over a
    /// sibling object in the same document (XML Signature Wrapping) must not be
    /// treated as protecting the EntityDescriptor/EntitiesDescriptor whose keys
    /// and endpoints are later consumed.
    #[error(
        "metadata signature did not reference the trusted metadata element \
         (XML Signature Wrapping); element ID {0:?}"
    )]
    SignatureNotBound(String),

    /// No signing certificate is configured and unverified operation was not
    /// explicitly allowed. The MDQ server is untrusted, so metadata that cannot
    /// be signature-verified must not be accepted by default.
    #[error(
        "no signing certificate configured; refusing to accept unverified metadata \
         (call `allow_unverified()` to opt in to insecure operation)"
    )]
    VerificationNotConfigured,

    /// The returned metadata is for a different entity than was requested. The
    /// signature only attests that the federation vouches for the document, not
    /// that it answers the query, so request/response entityIDs must match.
    #[error("MDQ returned metadata for entityID {returned:?} but {requested:?} was requested")]
    EntityIdMismatch {
        /// The entityID that was requested.
        requested: String,
        /// The entityID actually present in the returned metadata.
        returned: String,
    },

    /// The fetched metadata does not contain the required role descriptor.
    #[error("metadata does not contain the required {0:?} role")]
    RoleMissing(RequiredRole),

    /// An aggregate (EntitiesDescriptor) did not contain the requested entityID.
    #[error("entityID {0:?} not found in aggregate metadata")]
    EntityNotFound(String),

    /// The metadata root element was neither EntityDescriptor nor EntitiesDescriptor.
    #[error("unexpected metadata root element (expected EntityDescriptor or EntitiesDescriptor)")]
    UnexpectedRoot,

    /// Static metadata is not (yet) available; includes the next-retry hint.
    #[error("static metadata not available: {0}")]
    StaticUnavailable(String),

    /// A `cacheDuration` value could not be parsed as an xs:duration.
    #[error("invalid cacheDuration {0:?}")]
    BadDuration(String),

    /// An I/O error reading static metadata from a file.
    #[error("failed to read metadata file: {0}")]
    Io(String),
}
