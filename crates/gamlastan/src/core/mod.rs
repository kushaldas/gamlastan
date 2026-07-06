//! # gamlastan::core
//!
//! Core SAML 2.0 types, constants, and identifiers for the gamlastan library.
//!
//! This module provides the foundational data types used by all other modules:
//! assertions, protocol messages, constants, entity IDs, SAML IDs, status codes,
//! NameID formats, and time helpers.
//!
//! ## Borrowed and Owned Types
//!
//! Most parsed XML types follow a dual-type pattern:
//!
//! - `FooRef<'a>` borrows strings and child values from the parsed XML document;
//! - `Foo` owns its data and is suitable for construction, storage, and
//!   crossing async/thread/lifetime boundaries;
//! - `FooRef::to_owned()` converts from borrowed to owned.
//!
//! Prefer borrowed types when immediately validating or inspecting incoming XML.
//! Prefer owned types when constructing messages or storing parsed data.
//!
//! ## Example: Construct a NameID and Attribute
//!
//! ```
//! use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
//! use gamlastan::core::assertion::name_id::NameId;
//! use gamlastan::core::constants::{ATTRNAME_FORMAT_URI, NAMEID_PERSISTENT};
//!
//! let name_id = NameId {
//!     value: "opaque-id".to_string(),
//!     format: Some(NAMEID_PERSISTENT.to_string()),
//!     name_qualifier: Some("https://idp.example.org/metadata".to_string()),
//!     sp_name_qualifier: Some("https://sp.example.org/metadata".to_string()),
//!     sp_provided_id: None,
//! };
//!
//! let attr = Attribute {
//!     name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
//!     name_format: Some(ATTRNAME_FORMAT_URI.to_string()),
//!     friendly_name: Some("mail".to_string()),
//!     values: vec![AttributeValue::String("alice@example.org".to_string())],
//! };
//!
//! assert_eq!(name_id.format.as_deref(), Some(NAMEID_PERSISTENT));
//! assert_eq!(attr.friendly_name.as_deref(), Some("mail"));
//! ```
//!
//! ## Modules
//!
//! - [`namespace`] - All SAML/XML namespace URI constants
//! - [`constants`] - Binding URIs, NameID formats, status codes, authn context classes
//! - [`identifiers`] - EntityId, SamlId, SamlVersion
//! - [`time`] - DateTime wrappers and validity window helpers
//! - [`assertion`] - SAML assertion types (NameId, Subject, Conditions, Statements, etc.)
//! - [`protocol`] - SAML protocol types (AuthnRequest, Response, Status, LogoutRequest, etc.)
//! - [`error`] - Core error types

pub mod assertion;
pub mod constants;
pub mod error;
pub mod identifiers;
pub mod namespace;
pub mod protocol;
pub mod time;

// Re-export commonly used types at crate root for convenience.
pub use error::CoreError;
pub use identifiers::{EntityId, EntityIdRef, SamlId, SamlIdRef, SamlVersion};
pub use time::{SamlDateTime, SamlDateTimeRef};
