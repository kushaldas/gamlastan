// RelayState handling for SAML 2.0 protocol bindings.
//
// Per SAML Bindings spec:
// - Max 80 bytes
// - If present in request, MUST be echoed exactly in response
// - SHOULD be integrity-protected independently
//
// Per Erratum E90:
// - Sanitize for XSS/CSRF: reject javascript:, data:, HTML tags, null bytes

use crate::error::BindingError;

/// Maximum length of RelayState in bytes.
pub const RELAY_STATE_MAX_BYTES: usize = 80;

/// Validated RelayState value.
///
/// Enforces the 80-byte limit and E90 sanitization on construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayState(String);

impl RelayState {
    /// Create a new RelayState after validation.
    ///
    /// Enforces:
    /// - Maximum 80 bytes (per SAML Bindings spec)
    /// - E90 sanitization: rejects `javascript:`, `data:`, `vbscript:` URIs,
    ///   HTML tags, null bytes, and other potentially dangerous content.
    pub fn new(value: &str) -> Result<Self, BindingError> {
        validate_relay_state(value)?;
        Ok(RelayState(value.to_string()))
    }

    /// Create a RelayState without validation (for echoing back received values).
    ///
    /// Per spec: RelayState from the request MUST be echoed exactly in the response.
    /// Use this only when reflecting a RelayState received from a peer.
    pub fn echo(value: &str) -> Self {
        RelayState(value.to_string())
    }

    /// Get the RelayState value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate a RelayState value.
///
/// Checks:
/// 1. Length <= 80 bytes
/// 2. E90: No dangerous URI schemes (javascript:, data:, vbscript:)
/// 3. E90: No HTML tags
/// 4. E90: No null bytes
pub fn validate_relay_state(value: &str) -> Result<(), BindingError> {
    // Check length
    if value.len() > RELAY_STATE_MAX_BYTES {
        return Err(BindingError::RelayStateTooLong(value.len()));
    }

    // E90: Check for null bytes
    if value.contains('\0') {
        return Err(BindingError::RelayStateUnsafe(
            "contains null bytes".to_string(),
        ));
    }

    // E90: Check for dangerous URI schemes (case-insensitive)
    let lower = value.to_ascii_lowercase();
    let trimmed = lower.trim();
    for scheme in &["javascript:", "data:", "vbscript:"] {
        if trimmed.starts_with(scheme) {
            return Err(BindingError::RelayStateUnsafe(format!(
                "dangerous URI scheme: {}",
                scheme
            )));
        }
    }

    // E90: Check for HTML tags (basic check for < followed by alpha or /)
    if contains_html_tags(value) {
        return Err(BindingError::RelayStateUnsafe(
            "contains HTML tags".to_string(),
        ));
    }

    Ok(())
}

/// Basic check for HTML tags: `<` followed by letter or `/`.
fn contains_html_tags(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'<' {
            let next = bytes[i + 1];
            if next.is_ascii_alphabetic() || next == b'/' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_relay_state() {
        let rs = RelayState::new("abc123").unwrap();
        assert_eq!(rs.as_str(), "abc123");
    }

    #[test]
    fn test_relay_state_max_length() {
        let long = "a".repeat(80);
        assert!(RelayState::new(&long).is_ok());

        let too_long = "a".repeat(81);
        assert!(matches!(
            RelayState::new(&too_long),
            Err(BindingError::RelayStateTooLong(81))
        ));
    }

    #[test]
    fn test_relay_state_javascript_xss() {
        assert!(RelayState::new("javascript:alert(1)").is_err());
        assert!(RelayState::new("JAVASCRIPT:alert(1)").is_err());
        assert!(RelayState::new("  javascript:alert(1)").is_err());
    }

    #[test]
    fn test_relay_state_data_uri() {
        assert!(RelayState::new("data:text/html,<script>").is_err());
    }

    #[test]
    fn test_relay_state_vbscript() {
        assert!(RelayState::new("vbscript:msgbox").is_err());
    }

    #[test]
    fn test_relay_state_html_tags() {
        assert!(RelayState::new("<script>alert(1)</script>").is_err());
        assert!(RelayState::new("<img src=x onerror=alert(1)>").is_err());
    }

    #[test]
    fn test_relay_state_null_bytes() {
        assert!(RelayState::new("abc\0def").is_err());
    }

    #[test]
    fn test_relay_state_echo_no_validation() {
        // echo() skips validation for reflecting received values
        let rs = RelayState::echo("javascript:alert(1)");
        assert_eq!(rs.as_str(), "javascript:alert(1)");
    }

    #[test]
    fn test_relay_state_url_safe_token() {
        // Typical relay state: a pseudo-random token
        let rs = RelayState::new("ss:mem:6a25b4c3e2d1f0a9b8c7d6e5f4a3b2c1").unwrap();
        assert_eq!(rs.as_str(), "ss:mem:6a25b4c3e2d1f0a9b8c7d6e5f4a3b2c1");
    }

    #[test]
    fn test_relay_state_less_than_not_tag() {
        // < followed by non-alpha/non-slash is OK (e.g., math)
        assert!(RelayState::new("a < 5").is_ok());
        assert!(RelayState::new("a<5").is_ok());
    }

    #[test]
    fn test_relay_state_display() {
        let rs = RelayState::new("token123").unwrap();
        assert_eq!(format!("{}", rs), "token123");
    }

    #[test]
    fn test_relay_state_into_string() {
        let rs = RelayState::new("token123").unwrap();
        assert_eq!(rs.into_string(), "token123");
    }
}
