// SAML 2.0 actix-web configuration.
//
// Provides SpConfig and IdpConfig for registering SAML endpoints.

use std::sync::Arc;

use swsaml_metadata::types::entity_descriptor::EntityDescriptor;
use swsaml_security::config::SecurityConfig;
use swsaml_security::replay::{InMemoryReplayCache, ReplayCache};

/// Service Provider configuration for SAML integration.
///
/// Holds the SP's identity, endpoints, partner IdP metadata,
/// security settings, and replay cache. Pass this via `actix_web::web::Data`.
#[derive(Clone)]
pub struct SpConfig {
    /// SP entity ID (the Issuer in AuthnRequests).
    pub entity_id: String,

    /// Assertion Consumer Service URL (where the IdP sends responses).
    pub acs_url: String,

    /// Single Logout URL.
    pub slo_url: String,

    /// SP metadata URL.
    pub metadata_url: String,

    /// Partner IdP metadata (for endpoint discovery and verification).
    pub idp_metadata: EntityDescriptor,

    /// Security configuration (clock skew, signature requirements, etc.).
    pub security: SecurityConfig,

    /// Replay cache for one-time-use assertion ID enforcement.
    pub replay_cache: Arc<dyn ReplayCache>,

    /// Whether to require signed assertions.
    pub want_assertions_signed: bool,

    /// NameID format to request (None = let IdP decide).
    pub name_id_format: Option<String>,

    /// Whether to allow the IdP to create new identifiers (E14).
    pub allow_create: bool,

    /// ForceAuthn default (None = don't include).
    pub force_authn: Option<bool>,

    /// IsPassive default (None = don't include).
    pub is_passive: Option<bool>,

    /// Protocol binding to request for the response.
    pub protocol_binding: Option<String>,
}

impl SpConfig {
    /// Create a minimal SP configuration.
    pub fn new(
        entity_id: impl Into<String>,
        acs_url: impl Into<String>,
        idp_metadata: EntityDescriptor,
    ) -> Self {
        let entity_id = entity_id.into();
        let acs_url = acs_url.into();
        Self {
            slo_url: String::new(),
            metadata_url: String::new(),
            idp_metadata,
            security: SecurityConfig::default(),
            replay_cache: Arc::new(InMemoryReplayCache::new()),
            want_assertions_signed: true,
            name_id_format: None,
            allow_create: false,
            force_authn: None,
            is_passive: None,
            protocol_binding: None,
            entity_id,
            acs_url,
        }
    }

    /// Set the SLO URL.
    pub fn with_slo_url(mut self, url: impl Into<String>) -> Self {
        self.slo_url = url.into();
        self
    }

    /// Set the metadata URL.
    pub fn with_metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = url.into();
        self
    }

    /// Set the security configuration.
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Set a custom replay cache.
    pub fn with_replay_cache(mut self, cache: Arc<dyn ReplayCache>) -> Self {
        self.replay_cache = cache;
        self
    }
}

/// Identity Provider configuration for SAML integration.
///
/// Holds the IdP's identity, signing config, and partner SP metadata.
/// Pass this via `actix_web::web::Data`.
#[derive(Clone)]
pub struct IdpConfig {
    /// IdP entity ID (the Issuer in Responses/Assertions).
    pub entity_id: String,

    /// SSO service URL (where SPs send AuthnRequests).
    pub sso_url: String,

    /// Single Logout URL.
    pub slo_url: String,

    /// IdP metadata URL.
    pub metadata_url: String,

    /// Security configuration.
    pub security: SecurityConfig,

    /// Default assertion lifetime in seconds.
    pub assertion_lifetime_seconds: u64,

    /// Default session lifetime in seconds.
    pub session_lifetime_seconds: u64,

    /// Whether to sign responses.
    pub sign_responses: bool,

    /// Whether to sign assertions.
    pub sign_assertions: bool,

    /// Base64-encoded DER signing certificate for KeyDescriptor and KeyInfo.
    /// Required for metadata KeyDescriptor and response/assertion signing.
    pub signing_cert_b64: Option<String>,
}

impl IdpConfig {
    /// Create a minimal IdP configuration.
    pub fn new(entity_id: impl Into<String>, sso_url: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            sso_url: sso_url.into(),
            slo_url: String::new(),
            metadata_url: String::new(),
            security: SecurityConfig::default(),
            assertion_lifetime_seconds: 300,
            session_lifetime_seconds: 28800, // 8 hours
            sign_responses: true,
            sign_assertions: true,
            signing_cert_b64: None,
        }
    }

    /// Set the SLO URL.
    pub fn with_slo_url(mut self, url: impl Into<String>) -> Self {
        self.slo_url = url.into();
        self
    }

    /// Set the metadata URL.
    pub fn with_metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = url.into();
        self
    }

    /// Set the security configuration.
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Set the signing certificate (base64-encoded DER).
    pub fn with_signing_cert(mut self, cert_b64: impl Into<String>) -> Self {
        self.signing_cert_b64 = Some(cert_b64.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swsaml_metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};

    fn make_dummy_entity_descriptor() -> EntityDescriptor {
        EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        }
    }

    #[test]
    fn test_sp_config_new() {
        let config = SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            make_dummy_entity_descriptor(),
        );
        assert_eq!(config.entity_id, "https://sp.example.com");
        assert_eq!(config.acs_url, "https://sp.example.com/acs");
        assert!(config.want_assertions_signed);
        assert!(config.slo_url.is_empty());
    }

    #[test]
    fn test_sp_config_builder() {
        let config = SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            make_dummy_entity_descriptor(),
        )
        .with_slo_url("https://sp.example.com/slo")
        .with_metadata_url("https://sp.example.com/metadata");

        assert_eq!(config.slo_url, "https://sp.example.com/slo");
        assert_eq!(config.metadata_url, "https://sp.example.com/metadata");
    }

    #[test]
    fn test_idp_config_new() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        assert_eq!(config.entity_id, "https://idp.example.com");
        assert_eq!(config.sso_url, "https://idp.example.com/sso");
        assert_eq!(config.assertion_lifetime_seconds, 300);
        assert!(config.sign_responses);
    }

    #[test]
    fn test_idp_config_builder() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_slo_url("https://idp.example.com/slo")
            .with_metadata_url("https://idp.example.com/metadata");

        assert_eq!(config.slo_url, "https://idp.example.com/slo");
        assert_eq!(config.metadata_url, "https://idp.example.com/metadata");
    }
}
