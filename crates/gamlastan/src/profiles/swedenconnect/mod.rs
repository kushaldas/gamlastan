//! # Deployment Profile for the Swedish eID Framework
//!
//! An implementation of the
//! [Deployment Profile for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html)
//! (Sweden Connect / DIGG), layered on the SAML V2.0 Web Browser SSO Profile
//! that lives in [`crate::profiles::sso`].
//!
//! The profile is a *restriction and extension* of Web Browser SSO. This module
//! provides:
//!
//! - [`constants`] — Levels of Assurance, entity categories, status codes,
//!   attribute OIDs, namespaces and the section 8 cryptographic algorithm URIs.
//! - [`config::SwedenConnectConfig`] — a deployment configuration that yields a
//!   profile-correct [`crate::security::config::SecurityConfig`] (≤ 1 minute
//!   clock skew, signed + encrypted responses, Destination/Recipient checks).
//! - [`authn_context`] — the [`authn_context::LevelOfAssurance`] enum, the
//!   exact-comparison `RequestedAuthnContext` builder, and the section 6.3.4
//!   LoA matching check.
//! - [`metadata`] — builders/readers for the `<mdui:UIInfo>`,
//!   `<mdattr:EntityAttributes>` (entity categories + assurance certification),
//!   `<shibmd:Scope>` and `<idpdisc:DiscoveryResponse>` extensions.
//! - [`principal_selection`] — the `<psc:PrincipalSelection>` request extension
//!   and the `<psc:RequestedPrincipalSelection>` metadata extension.
//! - [`sign_message`] — the `<csig:SignMessage>` and `<sap:SADRequest>` request
//!   extensions for "Authentication for Signature" (section 7).
//! - [`request`] — SP-side AuthnRequest construction applying every section 5
//!   constraint.
//! - [`response`] — SP-side Response processing (decrypt, signature, LoA match,
//!   structural checks) per section 6.
//! - [`idp`] — IdP-side Response/error construction per sections 6 and 6.4.
//!
//! ## Scope
//!
//! The ordinary Web Browser SSO Profile is fully covered. The Holder-of-key Web
//! Browser SSO Profile is supported at the metadata/constant and
//! SubjectConfirmation-method level ([`constants::CM_HOLDER_OF_KEY`],
//! [`constants::BINDING_HOK_BROWSER`]); the mutual-TLS transport requirement
//! (section 5.2/6.1) is a deployment concern outside this library. The DSS/SAP
//! signing protocols are referenced only as far as the SAML authentication
//! phase: the `SignMessage` and `SADRequest` request extensions and the
//! `signMessageDigest` response attribute are modelled here, while the DSS
//! `SignRequest`/`SignResponse` envelope and SAD verification are out of scope.

pub mod authn_context;
pub mod config;
pub mod constants;
pub mod error;
pub mod idp;
pub mod metadata;
pub mod principal_selection;
pub mod request;
pub mod response;
pub mod sign_message;

// Re-export the most commonly used items at the module root.
pub use authn_context::{requested_authn_context, validate_authn_context, LevelOfAssurance};
pub use config::{SwedenConnectConfig, SwedenConnectRole, MAX_CLOCK_SKEW_SECONDS};
pub use error::SwedenConnectError;
pub use principal_selection::{MatchValue, PrincipalSelection, RequestedPrincipalSelection};
pub use request::{
    build_authn_request, request_extensions_xml, SwedenConnectAuthnOptions,
    SwedenConnectAuthnRequest,
};
pub use response::{
    decrypt_response, process_response, verify_and_process_response, SwedenConnectAuthnResult,
    SwedenConnectResponseParams,
};
pub use sign_message::{SadRequest, SignMessage, SignMessageMimeType};
