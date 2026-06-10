//! # gamlastan
//!
//! A comprehensive SAML 2.0 library implementing types, XML parsing/serialization,
//! cryptographic operations, metadata handling, protocol bindings, security validation,
//! and profile implementations.
//!
//! ## Modules
//!
//! - [`core`] - Core SAML 2.0 types, constants, and identifiers
//! - [`xml`] - XML layer (uppsala integration, deserialization, serialization)
//! - [`crypto`] - Cryptographic operations (signing, verification, encryption, decryption)
//! - [`metadata`] - Metadata types, caching, validation, and endpoint resolution
//! - [`bindings`] - Protocol bindings (HTTP Redirect, POST, Artifact, SOAP, PAOS, URI)
//! - [`security`] - Security validation (assertion validator, replay cache, clock skew)
//! - [`profiles`] - Profile implementations (Web Browser SSO, SLO, ECP, etc.)
//! - [`attribute_map`] - Attribute name conversion (wire <-> local) with shipped maps
//! - [`idp`] - IdP-side infrastructure (release policy, identity DB, AuthnBroker, assertion store)

pub mod attribute_map;
pub mod bindings;
pub mod core;
pub mod crypto;
pub mod idp;
pub mod metadata;
pub mod profiles;
pub mod security;
pub mod xml;
