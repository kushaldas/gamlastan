// SAML 2.0 Single Sign-On profiles
//
// Submodules:
// - web_browser: Common types for Web Browser SSO
// - sp: SP-side operations (create AuthnRequest, process Response)
// - idp: IdP-side operations (process AuthnRequest, create Response)
// - ecp: Enhanced Client or Proxy profile

pub mod ecp;
pub mod idp;
pub mod sp;
pub mod web_browser;
