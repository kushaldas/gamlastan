//! # swsaml-core
//!
//! Core SAML 2.0 types, constants, and identifiers for the swsaml library.
//!
//! This crate provides the foundational data types used across all other swsaml crates,
//! following a zero-copy dual-type pattern: `FooRef<'a>` (borrowed, for parsing) and
//! `Foo` (owned, for construction/storage), with `.to_owned()` conversion.
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
