// SAML 2.0 Security configuration
//
// Configurable parameters for the security validation engine.
// Per Errata:
// - E91: reject ds:Object in signatures (default true)
// - E92: clock skew tolerance 3-5 minutes (default 180 seconds)
// - E93: CBC mode requires integrity (default true)
// - E90: sanitize RelayState (default true)
// - E78: persistent ID uniqueness enforcement (default true)

/// Security configuration for SAML validation.
///
/// All boolean options default to the most secure setting.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Clock skew tolerance in seconds (E92: default 180 = 3 minutes, recommended 180-300).
    pub clock_skew_seconds: u64,

    /// Whether signed assertions are required (true for HTTP POST binding).
    pub require_signed_assertions: bool,

    /// Whether signed responses are required.
    pub require_signed_responses: bool,

    /// Whether encrypted assertions are required.
    pub require_encrypted_assertions: bool,

    /// Maximum assertion age in seconds. Short validity windows reduce risk.
    pub max_assertion_age_seconds: u64,

    /// Reject signatures containing ds:Object elements (E91: default true).
    pub reject_signatures_with_ds_object: bool,

    /// Enforce persistent identifier uniqueness (E78: default true).
    /// When true, persistent IDs must never be reassigned to different principals.
    pub enforce_persistent_id_uniqueness: bool,

    /// Sanitize RelayState for XSS/CSRF (E90: default true).
    pub sanitize_relay_state: bool,

    /// Require integrity protection when using CBC-mode encryption (E93: default true).
    pub require_integrity_with_cbc: bool,

    /// Verify the Destination attribute matches the received URL (default true).
    pub verify_destination: bool,

    /// Verify the Recipient attribute matches the ACS URL (default true).
    pub verify_recipient: bool,

    /// Check that the client IP address matches the SubjectConfirmationData Address
    /// (optional, default false).
    pub check_client_address: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            clock_skew_seconds: 180,                // E92: 3 minutes
            require_signed_assertions: true,        // secure default for POST
            require_signed_responses: false,        // not always required
            require_encrypted_assertions: false,    // not always required
            max_assertion_age_seconds: 300,         // 5 minutes
            reject_signatures_with_ds_object: true, // E91
            enforce_persistent_id_uniqueness: true, // E78
            sanitize_relay_state: true,             // E90
            require_integrity_with_cbc: true,       // E93
            verify_destination: true,
            verify_recipient: true,
            check_client_address: false, // optional, off by default
        }
    }
}

impl SecurityConfig {
    /// Create a new SecurityConfig with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive configuration for testing (NOT for production).
    ///
    /// Disables most security checks. Only use in development/testing scenarios.
    pub fn permissive() -> Self {
        Self {
            clock_skew_seconds: 600, // 10 minutes
            require_signed_assertions: false,
            require_signed_responses: false,
            require_encrypted_assertions: false,
            max_assertion_age_seconds: 3600, // 1 hour
            reject_signatures_with_ds_object: false,
            enforce_persistent_id_uniqueness: false,
            sanitize_relay_state: false,
            require_integrity_with_cbc: false,
            verify_destination: false,
            verify_recipient: false,
            check_client_address: false,
        }
    }

    /// Create a strict configuration for production use.
    ///
    /// Enables all security checks including optional ones.
    pub fn strict() -> Self {
        Self {
            clock_skew_seconds: 180, // E92: 3 minutes (tight)
            require_signed_assertions: true,
            require_signed_responses: true,
            require_encrypted_assertions: true,
            max_assertion_age_seconds: 180, // 3 minutes
            reject_signatures_with_ds_object: true,
            enforce_persistent_id_uniqueness: true,
            sanitize_relay_state: true,
            require_integrity_with_cbc: true,
            verify_destination: true,
            verify_recipient: true,
            check_client_address: true, // enable address check
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.clock_skew_seconds, 180);
        assert!(config.require_signed_assertions);
        assert!(!config.require_signed_responses);
        assert!(!config.require_encrypted_assertions);
        assert_eq!(config.max_assertion_age_seconds, 300);
        assert!(config.reject_signatures_with_ds_object);
        assert!(config.enforce_persistent_id_uniqueness);
        assert!(config.sanitize_relay_state);
        assert!(config.require_integrity_with_cbc);
        assert!(config.verify_destination);
        assert!(config.verify_recipient);
        assert!(!config.check_client_address);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert_eq!(config.clock_skew_seconds, 600);
        assert!(!config.require_signed_assertions);
        assert!(!config.verify_destination);
        assert!(!config.verify_recipient);
        assert!(!config.check_client_address);
    }

    #[test]
    fn test_strict_config() {
        let config = SecurityConfig::strict();
        assert_eq!(config.clock_skew_seconds, 180);
        assert!(config.require_signed_assertions);
        assert!(config.require_signed_responses);
        assert!(config.require_encrypted_assertions);
        assert!(config.verify_destination);
        assert!(config.verify_recipient);
        assert!(config.check_client_address);
    }

    #[test]
    fn test_config_clone() {
        let config = SecurityConfig::new();
        let cloned = config.clone();
        assert_eq!(config.clock_skew_seconds, cloned.clock_skew_seconds);
        assert_eq!(
            config.require_signed_assertions,
            cloned.require_signed_assertions
        );
    }
}
