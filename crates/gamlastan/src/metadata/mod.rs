//! SAML 2.0 metadata types, caching, validation, signing, and endpoint
//! resolution.
//!
//! Metadata tells a peer what entityID it has, which roles it supports, where
//! protocol messages should be sent, which certificates are trust anchors, and
//! what attributes or profile extensions it advertises. Use this module when
//! loading federation metadata, publishing local metadata, selecting endpoints,
//! or extracting signing/encryption certificates.
//!
//! # Main Concepts
//!
//! - [`EntityDescriptor`] and [`EntitiesDescriptor`] are the top-level metadata
//!   documents.
//! - Role descriptors such as [`SpSsoDescriptor`] and [`IdpSsoDescriptor`]
//!   contain endpoints and key descriptors for a specific SAML role.
//! - [`Endpoint`] and [`IndexedEndpoint`] model SAML binding endpoints such as
//!   SingleSignOnService and AssertionConsumerService.
//! - [`MetadataValidator`] checks structural requirements that the type system
//!   alone cannot enforce.
//! - Endpoint resolver helpers choose the endpoint matching a binding or a
//!   preference order.
//!
//! # Endpoint Selection Example
//!
//! ```
//! use gamlastan::core::constants::{BINDING_HTTP_POST, BINDING_HTTP_REDIRECT};
//! use gamlastan::metadata::{
//!     resolve_default_indexed_endpoint, Endpoint, IndexedEndpoint,
//! };
//!
//! let endpoints = vec![
//!     IndexedEndpoint::new(
//!         Endpoint::new(BINDING_HTTP_REDIRECT, "https://sp.example.org/acs/redirect"),
//!         0,
//!     ),
//!     IndexedEndpoint::new_default(
//!         Endpoint::new(BINDING_HTTP_POST, "https://sp.example.org/acs/post"),
//!         1,
//!     ),
//! ];
//!
//! let selected = resolve_default_indexed_endpoint(&endpoints).unwrap();
//! assert_eq!(selected.index, 1);
//! assert_eq!(selected.endpoint.binding, BINDING_HTTP_POST);
//! ```
//!
//! # Security Notes
//!
//! Signature verification and certificate extraction must be fail-closed. An
//! empty certificate list from a descriptor means no usable trust anchor was
//! extracted; it must not be interpreted as permission to skip signature
//! verification. Metadata parsed from remote sources should go through
//! [`crate::xml::parse_secure`] and, where signatures are expected, the
//! metadata signing helpers in this module.
//!
//! References: `saml-metadata-2.0-os` and SAML errata E62, E68, E69, E76, E91,
//! and E94.

pub mod types;

mod cache;
mod deserialize;
mod error;
mod serialize;
mod signing;
mod validation;

pub use cache::{CachedMetadata, MetadataCache, MetadataStore};
pub use error::MetadataError;
pub use signing::MetadataSigningProfile;
pub use types::*;
pub use validation::{
    binding_preferences, negotiate_endpoint_by_preference,
    negotiate_indexed_endpoint_by_preference, resolve_default_indexed_endpoint,
    resolve_endpoint_by_binding, resolve_indexed_endpoint_by_binding, MetadataValidator,
};
