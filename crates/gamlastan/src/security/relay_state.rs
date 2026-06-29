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
/// 2. No null bytes
/// 3. No control characters (C0/C1, TAB/CR/LF, DEL)
/// 4. No dangerous URI schemes (javascript:, data:, vbscript:), matched after
///    trimming surrounding whitespace
/// 5. No HTML angle brackets
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
/// Rejects, in order: null bytes; any control character (C0/C1, including
/// TAB/CR/LF and DEL); a dangerous URI scheme (`javascript:`, `data:`,
/// `vbscript:`) matched case-insensitively *after* trimming surrounding
/// whitespace, so a leading space cannot bypass the prefix check; and HTML
/// angle brackets. Rejecting control characters and trimming before the scheme
/// check close obfuscation vectors such as `java\tscript:` and ` javascript:`.
///
/// Does not check length (use `validate_relay_state` for full validation).
pub fn validate_relay_state_content(relay_state: &str) -> Result<(), String> {
    // Reject null bytes (kept as a distinct message for clarity).
    if relay_state.contains('\0') {
        return Err("RelayState contains null bytes".to_string());
    }

    // Reject ALL control characters (C0/C1, including TAB/CR/LF and DEL). Besides
    // being illegitimate in a RelayState, they are used to smuggle dangerous URI
    // schemes past a naive prefix check, e.g. "java\tscript:alert(1)" which some
    // browsers normalize back to "javascript:". Rejecting them outright closes
    // that obfuscation vector before scheme parsing.
    if relay_state.chars().any(char::is_control) {
        return Err("RelayState contains control characters".to_string());
    }

    // Normalize surrounding ASCII whitespace before scheme parsing: a leading
    // space (" javascript:...") is otherwise missed by `starts_with` even though
    // URL parsers and browsers ignore it.
    let normalized = relay_state.trim();
    let lower = normalized.to_ascii_lowercase();

    // Reject dangerous URI schemes.
    for scheme in ["javascript:", "data:", "vbscript:"] {
        if lower.starts_with(scheme) {
            return Err(format!("RelayState contains {scheme} URI scheme"));
        }
    }

    // Reject HTML tags.
    if relay_state.contains('<') || relay_state.contains('>') {
        return Err("RelayState contains HTML angle brackets".to_string());
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
    fn test_relay_state_leading_whitespace_scheme() {
        // Finding #14 regression: a leading space must not let a dangerous scheme
        // slip past the prefix check.
        assert!(validate_relay_state(" javascript:alert(1)").is_err());
        assert!(validate_relay_state("\tjavascript:alert(1)").is_err());
    }

    #[test]
    fn test_relay_state_embedded_control_char_scheme() {
        // Finding #14 regression: a control char embedded in the scheme (which
        // browsers may strip) must be rejected.
        assert!(validate_relay_state("java\tscript:alert(1)").is_err());
        assert!(validate_relay_state("java\u{0001}script:alert(1)").is_err());
    }

    #[test]
    fn test_relay_state_control_chars_rejected() {
        assert!(validate_relay_state("abc\rdef").is_err());
        assert!(validate_relay_state("abc\ndef").is_err());
        assert!(validate_relay_state("abc\u{007f}def").is_err());
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
