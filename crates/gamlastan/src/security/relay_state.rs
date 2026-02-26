// SAML 2.0 RelayState security validation
//
// Per Errata E90: RelayState must be sanitized for XSS/CSRF.
// - Reject javascript:, data:, vbscript: URIs
// - Reject HTML tags
// - Reject null bytes
// - Max 80 bytes

/// Maximum allowed RelayState length in bytes.
pub const MAX_RELAY_STATE_BYTES: usize = 80;

/// Validate a RelayState value for security.
///
/// Per E90: sanitize for XSS/CSRF attacks. Checks:
/// 1. Length <= 80 bytes
/// 2. No dangerous URI schemes (javascript:, data:, vbscript:)
/// 3. No HTML tags
/// 4. No null bytes
///
/// Returns `Ok(())` if the RelayState is safe, or an error description.
pub fn validate_relay_state(relay_state: &str) -> Result<(), String> {
    // Check 31: Max 80 bytes
    if relay_state.len() > MAX_RELAY_STATE_BYTES {
        return Err(format!(
            "RelayState exceeds 80-byte limit: {} bytes",
            relay_state.len()
        ));
    }

    // Check 32: XSS/CSRF sanitization (E90)
    validate_relay_state_content(relay_state)
}

/// Validate RelayState content for potentially dangerous patterns (E90).
///
/// Does not check length (use `validate_relay_state` for full validation).
pub fn validate_relay_state_content(relay_state: &str) -> Result<(), String> {
    let lower = relay_state.to_lowercase();

    // Reject dangerous URI schemes
    if lower.starts_with("javascript:") {
        return Err("RelayState contains javascript: URI scheme".to_string());
    }
    if lower.starts_with("data:") {
        return Err("RelayState contains data: URI scheme".to_string());
    }
    if lower.starts_with("vbscript:") {
        return Err("RelayState contains vbscript: URI scheme".to_string());
    }

    // Reject HTML tags
    if relay_state.contains('<') || relay_state.contains('>') {
        return Err("RelayState contains HTML angle brackets".to_string());
    }

    // Reject null bytes
    if relay_state.contains('\0') {
        return Err("RelayState contains null bytes".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_relay_state() {
        assert!(validate_relay_state("abc123").is_ok());
    }

    #[test]
    fn test_valid_relay_state_url() {
        assert!(validate_relay_state("https://sp.example.com/return").is_ok());
    }

    #[test]
    fn test_relay_state_too_long() {
        let long = "a".repeat(81);
        let result = validate_relay_state(&long);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("80-byte limit"));
    }

    #[test]
    fn test_relay_state_exactly_80() {
        let exact = "a".repeat(80);
        assert!(validate_relay_state(&exact).is_ok());
    }

    #[test]
    fn test_relay_state_javascript() {
        let result = validate_relay_state("javascript:alert(1)");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("javascript:"));
    }

    #[test]
    fn test_relay_state_javascript_mixed_case() {
        let result = validate_relay_state("JavaScript:alert(1)");
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_state_data_uri() {
        let result = validate_relay_state("data:text/html,<script>alert(1)</script>");
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_state_vbscript() {
        let result = validate_relay_state("vbscript:MsgBox(1)");
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_state_html_tags() {
        let result = validate_relay_state("<script>alert(1)</script>");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("angle brackets"));
    }

    #[test]
    fn test_relay_state_null_byte() {
        let result = validate_relay_state("abc\0def");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("null bytes"));
    }

    #[test]
    fn test_content_only_validation() {
        // validate_relay_state_content doesn't check length
        let long_but_safe = "a".repeat(200);
        assert!(validate_relay_state_content(&long_but_safe).is_ok());
    }

    #[test]
    fn test_empty_relay_state() {
        assert!(validate_relay_state("").is_ok());
    }
}
