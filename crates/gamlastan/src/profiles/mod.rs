//! SAML 2.0 profile implementations.
//!
//! Profiles combine the core SAML data model, bindings, metadata, crypto, and
//! security validation into concrete protocol flows. Start here when you want to
//! perform an SP or IdP operation instead of manually assembling protocol
//! structs.
//!
//! Implemented profile areas include:
//!
//! - [`sso`] - Web Browser SSO on both SP and IdP sides, plus ECP helpers;
//! - [`logout`] - Single Logout request/response creation and orchestration;
//! - [`artifact_resolution`] - artifact resolve/request response helpers;
//! - [`name_id_mgmt`] and [`name_id_mapping`] - NameID lifecycle profiles;
//! - [`assertion_query`] - AssertionIDRequest, AuthnQuery, AttributeQuery, and
//!   AuthzDecisionQuery support;
//! - [`idp_discovery`] - Identity Provider Discovery/Common Domain Cookie;
//! - [`attribute`] - SAML attribute profile helpers;
//! - [`swedenconnect`] - Sweden Connect deployment profile additions.
//!
//! # Choosing a Layer
//!
//! Use this module when a profile defines the behavior you need, for example
//! creating an AuthnRequest or processing a SAML Response. Use [`crate::core`]
//! directly only when you are building custom profile behavior. Use
//! [`crate::bindings`] when the typed message is ready to send over HTTP.
//!
//! # Example: SP AuthnRequest
//!
//! ```
//! use gamlastan::core::constants::{BINDING_HTTP_POST, NAMEID_TRANSIENT};
//! use gamlastan::profiles::sso::sp::create_authn_request;
//! use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
//!
//! let request = create_authn_request(&AuthnRequestOptions {
//!     sp_entity_id: "https://sp.example.org/metadata".to_string(),
//!     acs_url: Some("https://sp.example.org/acs".to_string()),
//!     protocol_binding: Some(BINDING_HTTP_POST.to_string()),
//!     name_id_format: Some(NAMEID_TRANSIENT.to_string()),
//!     ..Default::default()
//! })?;
//!
//! assert_eq!(
//!     request.base.issuer.as_ref().unwrap().value,
//!     "https://sp.example.org/metadata"
//! );
//! assert_eq!(
//!     request.protocol_binding.as_deref(),
//!     Some(BINDING_HTTP_POST)
//! );
//!
//! # Ok::<(), gamlastan::profiles::ProfileError>(())
//! ```

pub mod artifact_resolution;
pub mod assertion_query;
pub mod attribute;
pub mod confirmation;
pub mod error;
pub mod idp_discovery;
pub mod logout;
pub mod name_id_mapping;
pub mod name_id_mgmt;
pub mod pefim;
pub mod session;
pub mod sso;
pub mod swedenconnect;

// Re-export key types for convenience
pub use error::ProfileError;
pub use session::{InMemorySessionStore, SamlSession, SessionParticipant, SessionStore};
pub use sso::web_browser::{AuthnRequestOptions, AuthnResult, ResponseOptions};
