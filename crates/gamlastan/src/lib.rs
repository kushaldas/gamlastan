//! # gamlastan
//!
//! gamlastan is a layered SAML 2.0 library. It provides the protocol data
//! model, hardened XML parsing, XML Digital Signature and XML Encryption
//! wrappers, metadata helpers, protocol bindings, Web SSO profile operations,
//! and IdP-side policy/identifier infrastructure.
//!
//! The crate is intentionally split by responsibility. A web application or
//! proxy normally uses the high-level profile and binding modules first, while
//! lower-level modules remain available when an integration needs direct access
//! to metadata, XML, crypto, or validation primitives.
//!
//! ## Common Workflows
//!
//! ### Create an SP AuthnRequest
//!
//! Use [`profiles::sso::sp::create_authn_request`] to build the typed request,
//! [`xml::SamlSerialize`] to serialize it, then one of the binding helpers to
//! send it to the IdP.
//!
//! ```
//! use gamlastan::core::constants::{BINDING_HTTP_POST, NAMEID_PERSISTENT};
//! use gamlastan::profiles::sso::sp::create_authn_request;
//! use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
//! use gamlastan::xml::SamlSerialize;
//!
//! let request = create_authn_request(&AuthnRequestOptions {
//!     sp_entity_id: "https://sp.example.org/metadata".to_string(),
//!     destination: Some("https://idp.example.org/sso".to_string()),
//!     acs_url: Some("https://sp.example.org/acs".to_string()),
//!     protocol_binding: Some(BINDING_HTTP_POST.to_string()),
//!     name_id_format: Some(NAMEID_PERSISTENT.to_string()),
//!     allow_create: true,
//!     ..Default::default()
//! })?;
//!
//! let xml = request.to_xml_string()?;
//! assert!(xml.contains("AuthnRequest"));
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Parse Typed SAML XML
//!
//! Parse untrusted XML through [`xml::parse_secure`], then deserialize the
//! document root into a borrowed SAML type. Borrowed `*Ref<'a>` values point into
//! the parsed XML buffer; call `to_owned()` when data must outlive the document.
//!
//! ```
//! use gamlastan::core::protocol::AuthnRequestRef;
//! use gamlastan::profiles::sso::sp::create_authn_request;
//! use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
//! use gamlastan::xml::{parse_saml, parse_secure, SamlSerialize};
//!
//! let request = create_authn_request(&AuthnRequestOptions {
//!     sp_entity_id: "https://sp.example.org/metadata".to_string(),
//!     ..Default::default()
//! })?;
//! let xml = request.to_xml_string()?;
//!
//! let doc = parse_secure(&xml)?;
//! let parsed = parse_saml::<AuthnRequestRef<'_>>(&doc)?;
//! assert_eq!(
//!     parsed.base.issuer.unwrap().value,
//!     "https://sp.example.org/metadata"
//! );
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Convert Attributes Between Wire and Local Names
//!
//! Use [`attribute_map::AttributeConverterSet`] when code wants local names
//! such as `mail` and `givenName`, while SAML XML carries OIDs and NameFormats.
//!
//! ```
//! use gamlastan::attribute_map::{AttributeConverterSet, LocalAttribute};
//! use gamlastan::core::constants::ATTRNAME_FORMAT_URI;
//!
//! let converters = AttributeConverterSet::with_default_maps();
//! let wire = converters.from_local(
//!     &[LocalAttribute::from_strings("mail", &["alice@example.org"])],
//!     ATTRNAME_FORMAT_URI,
//! );
//!
//! assert_eq!(wire[0].name, "urn:oid:0.9.2342.19200300.100.1.3");
//! assert_eq!(wire[0].friendly_name.as_deref(), Some("mail"));
//! ```
//!
//! ## Modules
//!
//! - [`core`] - SAML data structures, constants, identifiers, and time helpers.
//!   Use this when constructing or inspecting protocol/assertion values.
//! - [`xml`] - Secure parsing plus serialization/deserialization traits. Use
//!   this at every XML trust boundary.
//! - [`bindings`] - HTTP Redirect, HTTP POST, SOAP, PAOS, Artifact, and URI
//!   binding helpers. Use this at the HTTP edge of an SP, IdP, or proxy.
//! - [`profiles`] - Web Browser SSO, ECP, logout, artifact resolution,
//!   NameID management, Sweden Connect, and related profile logic. Start here
//!   for high-level protocol operations.
//! - [`metadata`] - Metadata types, endpoint selection, validation, cache, and
//!   signing profile helpers. Use this when loading or publishing federation
//!   metadata.
//! - [`security`] - Validation configuration, assertion/response validation,
//!   replay cache traits, and errata checks. Use this before consuming claims.
//! - [`crypto`] - SAML-focused wrappers around `bergshamra` for XML-DSig,
//!   XML-Enc, canonicalization, key handling, and digests.
//! - [`attribute_map`] - PySAML2-compatible attribute conversion between wire
//!   names/OIDs and local names.
//! - [`idp`] - IdP-side policy, NameID storage, EPTID generation,
//!   authentication-context matching, and issued-assertion stores.
//!
//! ## Layering Model
//!
//! The lower layers do not know about your web framework or storage backend:
//!
//! ```text
//! HTTP framework adapter
//!     -> bindings
//!     -> profiles
//!     -> security / metadata / idp
//!     -> core / xml / crypto / attribute_map
//! ```
//!
//! Framework-specific crates can implement [`bindings::HttpRequest`],
//! [`bindings::HttpResponseBuilder`], [`bindings::SoapTransport`], and the
//! storage traits in [`idp`] or [`security`] without changing the protocol code.
//!
//! ## PySAML2 Compatibility and Legacy Identifiers
//!
//! gamlastan deliberately uses SHA-256 for newly generated
//! `eduPersonTargetedID` values. Stock PySAML2 used MD5 in
//! `saml2.eptid.Eptid`, so the same IdP entityID, SP entityID, user identifier,
//! and secret produce a different EPTID when moving to gamlastan.
//!
//! For migrations where an SP already stores the stock PySAML2 EPTID as its
//! account key, [`idp::eptid`] exposes a guarded legacy mode. The compatibility
//! mode is not used by default; callers must select
//! [`idp::eptid::EptidDigest::Pysaml2Md5Legacy`] through
//! [`idp::eptid::EptidOptions`] and set `allow_legacy_md5 = true`.
//!
//! See [`idp::eptid`] for the exact formula, when to import old mappings
//! instead of recomputing, and examples for enabling the compatibility path.

pub mod attribute_map;
pub mod bindings;
pub mod core;
pub mod crypto;
pub mod idp;
pub mod metadata;
pub mod profiles;
pub mod security;
pub mod xml;
