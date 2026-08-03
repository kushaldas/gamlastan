//! # gamlastan-mdq
//!
//! A client for the SAML **Metadata Query Protocol (MDQ)** — fetch entity
//! metadata on demand by `entityID` instead of loading every metadata file at
//! startup.
//!
//! It is a thin async layer over the pure metadata/crypto building blocks in
//! [`gamlastan`]: parsing, the E94-aware [`MetadataCache`], the metadata signing
//! profile, and XML-DSig verification.
//!
//! ## Modes
//!
//! - **Dynamic** ([`MdqClient::new`]): query `server_url + transform(entityID)`,
//!   verify (when signing certs are configured), and cache per the document's
//!   `validUntil`/`cacheDuration` with a fallback TTL.
//! - **Static** ([`MdqClient::into_static_file`] / [`MdqClient::into_static_url`]):
//!   serve a single entity loaded from a file or URL; URL failures retry lazily
//!   with exponential backoff.
//!
//! ## Features
//!
//! - Role-agnostic with an optional [`RequiredRole`] gate (`Any` / `Idp` / `Sp`).
//! - Both [`MdqTransform::UrlEncoded`] and [`MdqTransform::Sha1`] request paths.
//! - Zero or more federation signing certs (rollover); unsigned-but-configured
//!   metadata is rejected. A client with no certs refuses metadata by default
//!   (the MDQ server is untrusted); call [`MdqClient::allow_unverified`] to opt
//!   into accepting unverified metadata.
//! - The resolved entity's `entityID` is checked against the requested one, so
//!   an untrusted server cannot substitute a different (but validly signed)
//!   entity.
//! - Single `<EntityDescriptor>` and `<EntitiesDescriptor>` aggregate responses.
//! - Pluggable transport via [`MetadataFetcher`] for deterministic testing.
//!
//! ## Resource limits
//!
//! The MDQ server is untrusted, so buffering is bounded by default:
//!
//! - [`ReqwestFetcher`] accepts at most **10 MiB per response body**
//!   ([`fetch::MAX_BODY_BYTES`]) and buffers at most **8 bodies concurrently**
//!   ([`fetch::MAX_CONCURRENT_FETCHES`]). These defaults are sized for
//!   per-entity MDQ lookups; fetching a large federation *aggregate* (e.g.
//!   eduGAIN, on the order of 100 MiB) requires a deliberate opt-in via
//!   [`ReqwestFetcher::with_limits`] or
//!   [`ReqwestFetcher::from_client_with_limits`].
//! - Dynamically fetched metadata is cached with a **1024-entry bound** by
//!   default ([`MdqClient::with_cache_capacity`]). Expired entries are purged
//!   first; at capacity the entry with the oldest fetch time is evicted, so
//!   attacker-chosen `entityID`s can thrash the cache but cannot grow memory
//!   without bound. A capacity of zero disables caching.
//!
//! ```no_run
//! use gamlastan_mdq::{MdqClient, MdqTransform, RequiredRole};
//!
//! # async fn run(federation_cert_pem: &[u8]) -> Result<(), gamlastan_mdq::MdqError> {
//! let client = MdqClient::new("https://mdq.example.org/")
//!     .with_transform(MdqTransform::Sha1)
//!     .require_role(RequiredRole::Idp)
//!     .add_signing_cert_pem(federation_cert_pem)?;
//! let idp = client.get("https://idp.example.com/idp").await?;
//! println!("{}", idp.entity_id);
//! # Ok(())
//! # }
//! ```
//!
//! [`MetadataCache`]: gamlastan::metadata::MetadataCache

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod fetch;
pub mod transform;
mod verify;

pub use client::{MdqClient, RequiredRole};
pub use error::MdqError;
pub use fetch::{MetadataFetcher, ReqwestFetcher, SAML_METADATA_MIME};
pub use transform::{parse_xs_duration, request_path, MdqTransform};

// Re-export the metadata type the client yields, for caller convenience.
pub use gamlastan::metadata::EntityDescriptor;
