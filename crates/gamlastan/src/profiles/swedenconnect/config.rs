// Deployment configuration for the Swedish eID Framework profile.

use crate::security::config::SecurityConfig;

use super::constants;
use super::error::SwedenConnectError;

/// The role an entity plays in the federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwedenConnectRole {
    /// An ordinary Service Provider.
    ServiceProvider,
    /// An Identity Provider.
    IdentityProvider,
    /// A Signature Service (a Service Provider with the `sigservice` service
    /// type entity category, section 2.1.4).
    SignatureService,
}

/// The maximum clock skew permitted by the profile, in seconds (section 6.3.5:
/// "SHOULD NOT exceed 1 minute in either direction").
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

/// Deployment configuration for an entity conformant to the
/// "Deployment Profile for the Swedish eID Framework".
#[derive(Debug, Clone)]
pub struct SwedenConnectConfig {
    /// This entity's `entityID`.
    pub entity_id: String,

    /// The role this entity plays.
    pub role: SwedenConnectRole,

    /// The Level of Assurance authentication context URIs this SP requests
    /// (section 5.3.1). For an IdP this is the set of LoAs it can issue.
    pub requested_loas: Vec<String>,

    /// Clock skew tolerance in seconds. Clamped to [`MAX_CLOCK_SKEW_SECONDS`].
    pub clock_skew_seconds: u64,

    /// Whether the deployment accepts unsolicited (IdP-initiated) responses.
    /// The profile says SPs SHOULD NOT accept these (section 6.1); default false.
    pub accept_unsolicited: bool,

    /// The NameID format to request. Defaults to `persistent` (section 3).
    pub name_id_format: String,

    /// Whether the SP wants the assertion (inside the EncryptedAssertion) to
    /// also carry its own signature (`WantAssertionsSigned`, section 2.1.2).
    pub want_assertions_signed: bool,
}

impl SwedenConnectConfig {
    /// Create a configuration for a Service Provider requesting the given LoAs.
    pub fn service_provider(entity_id: impl Into<String>, requested_loas: Vec<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            role: SwedenConnectRole::ServiceProvider,
            requested_loas,
            clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
            accept_unsolicited: false,
            name_id_format: constants::NAMEID_PERSISTENT.to_string(),
            want_assertions_signed: false,
        }
    }

    /// Create a configuration for an Identity Provider that can issue the given
    /// LoAs.
    pub fn identity_provider(entity_id: impl Into<String>, issuable_loas: Vec<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            role: SwedenConnectRole::IdentityProvider,
            requested_loas: issuable_loas,
            clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
            accept_unsolicited: false,
            name_id_format: constants::NAMEID_PERSISTENT.to_string(),
            want_assertions_signed: false,
        }
    }

    /// Create a configuration for a Signature Service (section 2.1.4 / 7).
    pub fn signature_service(entity_id: impl Into<String>, requested_loas: Vec<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            role: SwedenConnectRole::SignatureService,
            requested_loas,
            clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
            accept_unsolicited: false,
            name_id_format: constants::NAMEID_PERSISTENT.to_string(),
            want_assertions_signed: false,
        }
    }

    /// Whether this entity is a Signature Service.
    pub fn is_signature_service(&self) -> bool {
        self.role == SwedenConnectRole::SignatureService
    }

    /// Validate the configuration against the profile's hard requirements.
    pub fn validate(&self) -> Result<(), SwedenConnectError> {
        if self.clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(SwedenConnectError::ClockSkewTooLarge(
                self.clock_skew_seconds,
            ));
        }
        Ok(())
    }

    /// The effective clock skew, clamped to the profile maximum.
    pub fn effective_clock_skew(&self) -> u64 {
        self.clock_skew_seconds.min(MAX_CLOCK_SKEW_SECONDS)
    }

    /// Build a [`SecurityConfig`] that enforces this profile's hard
    /// requirements for response/assertion processing:
    ///
    /// - clock skew clamped to ≤ 1 minute (section 6.3.5),
    /// - the `<saml2p:Response>` MUST be signed (section 6.1),
    /// - the assertion MUST arrive encrypted (section 6.1),
    /// - Destination and Recipient MUST be verified (sections 5.4.1, 6.3.2),
    /// - errata defences (E78/E90/E91/E93) stay on.
    pub fn security_config(&self) -> SecurityConfig {
        SecurityConfig {
            clock_skew_seconds: self.effective_clock_skew(),
            // The Response is always signed; assertion signatures are optional
            // unless the SP requested them via WantAssertionsSigned.
            require_signed_assertions: self.want_assertions_signed,
            require_signed_responses: true,
            require_encrypted_assertions: true,
            // Tight assertion lifetime — stolen-assertion window (section 6.3.5).
            max_assertion_age_seconds: 300,
            reject_signatures_with_ds_object: true,
            enforce_persistent_id_uniqueness: true,
            sanitize_relay_state: true,
            require_integrity_with_cbc: true,
            verify_destination: true,
            verify_recipient: true,
            // The Address check is optional per section 6.3.2.
            check_client_address: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp_defaults() {
        let cfg = SwedenConnectConfig::service_provider(
            "https://sp.example.se",
            vec![constants::LOA3.into()],
        );
        assert_eq!(cfg.role, SwedenConnectRole::ServiceProvider);
        assert_eq!(cfg.name_id_format, constants::NAMEID_PERSISTENT);
        assert!(!cfg.accept_unsolicited);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_security_config_is_strict() {
        let cfg = SwedenConnectConfig::service_provider(
            "https://sp.example.se",
            vec![constants::LOA3.into()],
        );
        let sec = cfg.security_config();
        assert!(sec.require_signed_responses);
        assert!(sec.require_encrypted_assertions);
        assert!(sec.verify_destination);
        assert!(sec.verify_recipient);
        assert_eq!(sec.clock_skew_seconds, MAX_CLOCK_SKEW_SECONDS);
    }

    #[test]
    fn test_clock_skew_clamped() {
        let mut cfg = SwedenConnectConfig::service_provider(
            "https://sp.example.se",
            vec![constants::LOA3.into()],
        );
        cfg.clock_skew_seconds = 600;
        assert_eq!(cfg.effective_clock_skew(), MAX_CLOCK_SKEW_SECONDS);
        assert!(matches!(
            cfg.validate(),
            Err(SwedenConnectError::ClockSkewTooLarge(600))
        ));
        assert_eq!(
            cfg.security_config().clock_skew_seconds,
            MAX_CLOCK_SKEW_SECONDS
        );
    }

    #[test]
    fn test_signature_service_flag() {
        let cfg = SwedenConnectConfig::signature_service(
            "https://sign.example.se",
            vec![constants::LOA3.into()],
        );
        assert!(cfg.is_signature_service());
    }
}
