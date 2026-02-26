//! # swsaml-bindings
//!
//! SAML 2.0 protocol bindings implementation.
//!
//! This crate implements the SAML 2.0 protocol bindings defined in
//! `saml-bindings-2.0-os`:
//!
//! - **HTTP Redirect** (Section 3.4) - DEFLATE + query string encoding, detached signatures
//! - **HTTP POST** (Section 3.5) - Base64 form encoding, XHTML auto-submit
//! - **HTTP Artifact** (Section 3.6) - Type 0x0004 artifacts, one-time-use enforcement
//! - **SOAP** (Section 3.2) - SOAP 1.1 envelope wrapping/unwrapping
//! - **PAOS** (Section 3.3) - Reverse SOAP for ECP profile
//! - **URI** (Section 3.7) - Simple GET with assertion ID
//!
//! ## Design
//!
//! The bindings are framework-agnostic, using traits (`HttpRequest`,
//! `HttpResponseBuilder`, `SoapTransport`) that can be implemented for
//! any web framework (actix-web, axum, etc.).
//!
//! ## Errata Compliance
//!
//! - **E1**: RelayState covered by redirect signature
//! - **E4**: SAML V1.1 artifacts rejected
//! - **E90**: RelayState XSS/CSRF sanitization
//! - **E91**: ds:Object rejection delegated to swsaml-crypto

pub mod artifact;
pub mod caching;
pub mod deflate;
pub mod encoding;
pub mod error;
pub mod paos;
pub mod post;
pub mod redirect;
pub mod relay_state;
pub mod soap;
pub mod traits;
pub mod uri;

// Re-exports for convenience.
pub use artifact::SamlArtifact;
pub use error::BindingError;
pub use redirect::{redirect_decode, redirect_encode, RedirectDecoded, RedirectEncodeParams};
pub use relay_state::RelayState;
pub use traits::{ArtifactStore, HttpRequest, HttpResponseBuilder, SoapTransport};

use std::borrow::Cow;

/// Decoded SAML message from any binding.
///
/// Uses `Cow` for zero-copy where possible:
/// - SOAP: body can be borrowed directly as `&[u8]`
/// - HTTP POST: base64 decode requires allocation (`Cow::Owned`)
/// - HTTP Redirect: DEFLATE decompression requires allocation (`Cow::Owned`)
/// - HTTP Artifact: artifact string is small, borrowed from query/form param
#[derive(Debug)]
pub struct DecodedMessage<'a> {
    /// The SAML XML message bytes.
    ///
    /// For HTTP POST: base64-decoded bytes (allocated).
    /// For HTTP Redirect: DEFLATE-decompressed bytes (allocated).
    /// For SOAP: slice of request body (zero-copy when possible).
    pub saml_xml: Cow<'a, [u8]>,

    /// RelayState, if present.
    pub relay_state: Option<&'a str>,

    /// Whether this is a SAMLRequest (true) or SAMLResponse (false).
    pub is_request: bool,

    /// Whether the message's signature has been verified.
    /// `None` means no signature was present/checked.
    pub signature_valid: Option<bool>,
}
