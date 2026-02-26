// SAML 2.0 Metadata types, caching, validation, and endpoint resolution.
//
// References:
// - saml-metadata-2.0-os
// - saml-v2.0-errata05 (E62, E68, E69, E76, E91, E94)

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
    resolve_default_indexed_endpoint, resolve_endpoint_by_binding,
    resolve_indexed_endpoint_by_binding, MetadataValidator,
};
