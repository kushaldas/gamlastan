// SAML 2.0 Profiles
//
// This crate implements the SAML 2.0 profile specifications:
// - Web Browser SSO (SP and IdP sides)
// - Enhanced Client or Proxy (ECP)
// - Single Logout (SLO)
// - Artifact Resolution
// - Name Identifier Management
// - Name Identifier Mapping
// - Assertion Query/Request
// - Identity Provider Discovery (Common Domain Cookie)
// - Attribute Profiles (Basic, X.500/LDAP, UUID, DCE PAC)
// - Subject Confirmation Methods (Bearer, Holder-of-Key, Sender-Vouches)

pub mod artifact_resolution;
pub mod assertion_query;
pub mod attribute;
pub mod confirmation;
pub mod error;
pub mod idp_discovery;
pub mod logout;
pub mod name_id_mapping;
pub mod name_id_mgmt;
pub mod session;
pub mod sso;

// Re-export key types for convenience
pub use error::ProfileError;
pub use session::{InMemorySessionStore, SamlSession, SessionParticipant, SessionStore};
pub use sso::web_browser::{AuthnRequestOptions, AuthnResult, ResponseOptions};
