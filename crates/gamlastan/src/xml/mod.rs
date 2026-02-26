//! # gamlastan::xml
//!
//! XML layer for SAML 2.0 - backed by the `uppsala` XML parser.
//!
//! This crate provides:
//!
//! - [`SamlDeserialize`] trait for zero-copy deserialization from XML into borrowed SAML types
//! - [`SamlSerialize`] trait for serialization of owned SAML types to XML
//! - [`helpers`] module with utility functions for XML element navigation and attribute access
//! - [`XmlError`] error types for XML-related operations
//!
//! ## Zero-Copy Parsing Flow
//!
//! ```text
//! XML string ──→ uppsala::parse() ──→ Document<'a> ──→ SamlDeserialize::from_xml()
//!                                                         │
//!                                                         ▼
//!                                                    ResponseRef<'a>  (borrows from XML string)
//!                                                         │
//!                                                         ▼ .to_owned()
//!                                                    Response         (owned, for storage)
//! ```
//!
//! ## Re-exports
//!
//! This crate re-exports key `uppsala` types for convenience.

pub mod assertion;
pub mod deserialize;
pub mod error;
pub mod helpers;
pub mod protocol;
pub mod serialize;

// Re-export the core traits.
pub use deserialize::{parse_saml, SamlDeserialize};
pub use error::XmlError;
pub use serialize::SamlSerialize;

// Re-export commonly used uppsala types for consumers of this crate.
pub use uppsala::{self, Document, NodeId, XmlWriter};
