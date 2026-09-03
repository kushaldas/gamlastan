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
//! use gamlastan_actix::{SloCallback, SpConfig, sp::configure_sp};
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Load IdP metadata (from file, URL, etc.).
//!     let idp_metadata = todo!("parse IdP metadata XML");
//!
//!     let config = web::Data::new(SpConfig::new(
//!         "https://sp.example.com",
//!         "https://sp.example.com/acs",
//!         idp_metadata,
//!     ));
//!
//!     let slo_callback: SloCallback = Box::new(|event, request| Box::pin(async move {
//!         let _ = (event, request);
//!         // Await durable local-session invalidation and return its Result.
//!         // Never return Ok(()) while the local session is still valid.
//!         todo!("invalidate the local application session")
//!     }));
//!     let slo_callback = web::Data::new(slo_callback);
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .app_data(config.clone())
//!             .app_data(slo_callback.clone())
//!             .configure(configure_sp)
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
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
pub use config::{
    IdpConfig, InMemoryRequestIdTracker, RequestIdTracker, ResolveSpFuture, SpConfig, TrustedSp,
    TrustedSpResolver,
};
pub use error::SamlActixError;
pub use extractors::{SamlBinding, SamlMessage};
pub use idp::{AuthnCallback, AuthnCallbackResult, IdpSigningContext};
pub use request_adapter::ActixHttpRequest;
pub use response_adapter::{
    metadata_response, post_binding_response, redirect_binding_response, ActixResponseBuilder,
};
pub use sp::{SloCallback, SloCallbackFuture, SpLogoutEvent, SpSigningContext};
