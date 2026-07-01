// SAML 2.0 Security error types

use thiserror::Error;

/// Errors from security validation operations.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// Signature is invalid or could not be verified.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Signature contains a ds:Object element (E91).
    #[error("signature contains ds:Object element (rejected per E91)")]
    SignatureContainsDsObject,

    /// Certificate has expired or is not yet valid.
    #[error("certificate error: {0}")]
    CertificateError(String),

    /// Clock skew exceeded the configured tolerance (E92).
    #[error("clock skew exceeded: difference {difference_seconds}s exceeds tolerance {tolerance_seconds}s")]
    ClockSkewExceeded {
        difference_seconds: i64,
        tolerance_seconds: u64,
    },

    /// Assertion has been replayed (duplicate ID).
    #[error("assertion replay detected: ID '{0}'")]
    ReplayDetected(String),

    /// Destination URL does not match.
    #[error("destination mismatch: expected '{expected}', got '{actual}'")]
    DestinationMismatch { expected: String, actual: String },

    /// Recipient URL does not match.
    #[error("recipient mismatch: expected '{expected}', got '{actual}'")]
    RecipientMismatch { expected: String, actual: String },

    /// Audience restriction not satisfied (E46).
    #[error("audience restriction not satisfied for entity '{0}'")]
    AudienceRestrictionFailed(String),

    /// Assertion conditions not met (NotBefore/NotOnOrAfter).
    #[error("condition not met: {0}")]
    ConditionNotMet(String),

    /// OneTimeUse condition violated.
    #[error("one-time-use condition violated for assertion '{0}'")]
    OneTimeUseViolated(String),

    /// Proxy restriction exceeded.
    #[error("proxy restriction exceeded: count {count}, limit {limit}")]
    ProxyRestrictionExceeded { count: u32, limit: u32 },

    /// Required element is missing.
    #[error("missing required element: {0}")]
    MissingRequired(String),

    /// Issuer mismatch.
    #[error("issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch { expected: String, actual: String },

    /// Issuer format invalid (must be entity or omitted).
    #[error("issuer format invalid: '{0}' (must be entity format or omitted)")]
    IssuerFormatInvalid(String),

    /// InResponseTo mismatch.
    #[error("InResponseTo mismatch: expected '{expected}', got '{actual}'")]
    InResponseToMismatch { expected: String, actual: String },

    /// SubjectConfirmation method not acceptable.
    #[error("subject confirmation method not acceptable: {0}")]
    SubjectConfirmationInvalid(String),

    /// NotBefore is present in bearer SubjectConfirmationData (forbidden per profiles).
    #[error("NotBefore present in bearer SubjectConfirmationData (forbidden)")]
    BearerNotBeforePresent,

    /// Session expired (SessionNotOnOrAfter, E79).
    #[error("session expired: SessionNotOnOrAfter has passed")]
    SessionExpired,

    /// RelayState exceeds 80-byte limit.
    #[error("RelayState exceeds 80-byte limit: {0} bytes")]
    RelayStateTooLong(usize),

    /// RelayState contains potentially dangerous content (E90).
    #[error("RelayState contains unsafe content: {0}")]
    RelayStateUnsafe(String),

    /// CBC encryption without integrity protection (E93).
    #[error("CBC-mode encryption requires separate integrity protection (E93)")]
    CbcWithoutIntegrity,

    /// Persistent ID was reassigned (E78).
    #[error(
        "persistent identifier reassigned: '{0}' was previously assigned to a different principal"
    )]
    PersistentIdReassigned(String),

    /// Client address mismatch.
    #[error("client address mismatch: expected '{expected}', got '{actual}'")]
    AddressMismatch { expected: String, actual: String },

    /// Assertion is too old.
    #[error("assertion too old: age {age_seconds}s exceeds maximum {max_seconds}s")]
    AssertionTooOld { age_seconds: u64, max_seconds: u64 },

    /// Response status is not success.
    #[error("response status is not success: {0}")]
    ResponseNotSuccess(String),
}

/// A single validation check result.
#[derive(Debug, Clone)]
pub struct ValidationCheck {
    /// The check number. Checks 1-32 map to the Section 7.2 checklist; checks
    /// 33-34 are additional response-envelope checks (status is Success, at
    /// least one assertion present). All checks run and are recorded; a failure
    /// (including 33-34) marks the result invalid but does not short-circuit
    /// the remaining checks.
    pub check_number: u32,
    /// Human-readable name of the check.
    pub check_name: &'static str,
    /// Whether the check passed.
    pub passed: bool,
    /// Optional detail message on failure.
    pub detail: Option<String>,
}

impl ValidationCheck {
    /// Create a passing check.
    pub fn pass(check_number: u32, check_name: &'static str) -> Self {
        Self {
            check_number,
            check_name,
            passed: true,
            detail: None,
        }
    }

    /// Create a failing check with detail.
    pub fn fail(check_number: u32, check_name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check_number,
            check_name,
            passed: false,
            detail: Some(detail.into()),
        }
    }
}

/// Aggregated validation result containing all check outcomes.
#[derive(Debug)]
pub struct ValidationResult {
    /// All checks that were performed.
    pub checks: Vec<ValidationCheck>,
}

impl ValidationResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Add a check result.
    pub fn add(&mut self, check: ValidationCheck) {
        self.checks.push(check);
    }

    /// Whether all checks passed.
    pub fn is_valid(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// Get all failed checks.
    pub fn failures(&self) -> Vec<&ValidationCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Get all passed checks.
    pub fn passes(&self) -> Vec<&ValidationCheck> {
        self.checks.iter().filter(|c| c.passed).collect()
    }

    /// Total number of checks performed.
    pub fn total_checks(&self) -> usize {
        self.checks.len()
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_check_pass() {
        let check = ValidationCheck::pass(1, "Destination matches URL");
        assert!(check.passed);
        assert_eq!(check.check_number, 1);
        assert!(check.detail.is_none());
    }

    #[test]
    fn test_validation_check_fail() {
        let check = ValidationCheck::fail(1, "Destination matches URL", "URL mismatch");
        assert!(!check.passed);
        assert_eq!(check.detail.as_deref(), Some("URL mismatch"));
    }

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();
        result.add(ValidationCheck::pass(1, "Check 1"));
        result.add(ValidationCheck::fail(2, "Check 2", "failed"));
        result.add(ValidationCheck::pass(3, "Check 3"));

        assert!(!result.is_valid());
        assert_eq!(result.total_checks(), 3);
        assert_eq!(result.failures().len(), 1);
        assert_eq!(result.passes().len(), 2);
    }

    #[test]
    fn test_validation_result_all_pass() {
        let mut result = ValidationResult::new();
        result.add(ValidationCheck::pass(1, "Check 1"));
        result.add(ValidationCheck::pass(2, "Check 2"));
        assert!(result.is_valid());
    }

    #[test]
    fn test_security_error_display() {
        let err = SecurityError::DestinationMismatch {
            expected: "https://sp.example.com/acs".to_string(),
            actual: "https://evil.com/acs".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("https://sp.example.com/acs"));
        assert!(msg.contains("https://evil.com/acs"));
    }

    #[test]
    fn test_security_error_ds_object() {
        let err = SecurityError::SignatureContainsDsObject;
        assert!(err.to_string().contains("ds:Object"));
    }
}
