//! SAML 2.0 Single Sign-On profiles.
//!
//! The SSO modules cover the common front-channel login flow and the Enhanced
//! Client or Proxy profile:
//!
//! - [`web_browser`] - shared request/response option structs and extraction
//!   helpers;
//! - [`sp`] - SP-side AuthnRequest creation and Response processing;
//! - [`idp`] - IdP-side AuthnRequest processing and Response/error creation;
//! - [`ecp`] - SOAP/PAOS helpers for non-browser ECP clients.
//!
//! Use [`sp::create_authn_request`] on the SP before handing the serialized
//! request to [`crate::bindings`]. Use [`idp::process_authn_request`] and
//! [`idp::create_response`] after your IdP has authenticated the principal and
//! selected attributes to release.

pub mod ecp;
pub mod idp;
pub mod sp;
pub mod web_browser;
