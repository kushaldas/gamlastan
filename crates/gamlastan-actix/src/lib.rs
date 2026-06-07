//! # gamlastan-actix
//!
//! SAML 2.0 integration for actix-web.
//!
//! This crate provides ready-to-use extractors, responders, handlers,
//! and middleware for implementing SAML SP and IdP endpoints with actix-web.
//!
//! ## Architecture
//!
//! The crate has three layers of abstraction:
//!
//! 1. **Adapters** (`request_adapter`, `response_adapter`) - Low-level bridges
//!    between actix-web and `gamlastan::bindings` framework-agnostic traits.
//!
//! 2. **Extractors & Responders** (`extractors`, `responders`) - `FromRequest`
//!    and `Responder` implementations for use in handler signatures.
//!
//! 3. **Handlers** (`sp`, `idp`) - Ready-to-use SP and IdP route handlers
//!    that can be registered with `configure_sp()` / `configure_idp()`.
//!
//! ## Quick Start (SP)
//!
//! ```rust,no_run
//! use actix_web::{web, App, HttpServer};
//! use gamlastan_actix::{SpConfig, sp::configure_sp};
//!
//! // 1. Build SpConfig with your entity ID, ACS URL, and IdP metadata
//! // 2. Register routes with configure_sp()
//! // 3. The library handles AuthnRequest creation, Response validation,
//! //    LogoutRequest/Response, and metadata generation.
//! ```

pub mod config;
pub mod error;
pub mod extractors;
pub mod idp;
pub mod middleware;
pub mod request_adapter;
pub mod responders;
pub mod response_adapter;
pub mod sp;

// Re-exports for convenience.
pub use config::{IdpConfig, InMemoryRequestIdTracker, RequestIdTracker, SpConfig};
pub use error::SamlActixError;
pub use extractors::{SamlBinding, SamlMessage};
pub use idp::{AuthnCallback, AuthnCallbackResult, IdpSigningContext};
pub use request_adapter::ActixHttpRequest;
pub use response_adapter::{
    metadata_response, post_binding_response, redirect_binding_response, ActixResponseBuilder,
};
pub use sp::SpSigningContext;
