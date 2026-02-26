// SAML 2.0 Metadata type definitions
//
// All types follow the dual Ref<'a>/Owned pattern from swsaml-core.

pub mod additional;
pub mod affiliation;
pub mod attr_authority;
pub mod authn_authority;
pub mod contact;
pub mod endpoint;
pub mod entity_descriptor;
pub mod extensions;
pub mod idp;
pub mod key_descriptor;
pub mod localized;
pub mod organization;
pub mod pdp;
pub mod role_descriptor;
pub mod sp;
pub mod spid;

// Re-export all types for convenience
pub use additional::*;
pub use affiliation::*;
pub use attr_authority::*;
pub use authn_authority::*;
pub use contact::*;
pub use endpoint::*;
pub use entity_descriptor::*;
pub use extensions::*;
pub use idp::*;
pub use key_descriptor::*;
pub use localized::*;
pub use organization::*;
pub use pdp::*;
pub use role_descriptor::*;
pub use sp::*;
pub use spid::*;
