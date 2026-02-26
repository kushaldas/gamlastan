// SAML 2.0 Destination URL verification
//
// Per Bindings 3.4.5.2 and 3.5.5.2:
// - When a message is signed, the Destination attribute MUST be present and
//   must match the URL at which the message was received.
// - URL comparison should be exact string match after normalization.

/// Verify that the Destination attribute matches the expected URL.
///
/// Per the SAML bindings specification:
/// - If the message is signed, Destination MUST be present and MUST match.
/// - If the message is not signed, Destination is optional but if present MUST match.
///
/// # Arguments
/// * `destination` - The Destination attribute from the SAML message (may be None).
/// * `expected_url` - The URL where the message was received.
/// * `is_signed` - Whether the message or an assertion within it is signed.
///
/// Returns `Ok(())` if valid, or an error description.
pub fn verify_destination(
    destination: Option<&str>,
    expected_url: &str,
    is_signed: bool,
) -> Result<(), String> {
    match destination {
        Some(dest) => {
            if urls_match(dest, expected_url) {
                Ok(())
            } else {
                Err(format!(
                    "Destination '{}' does not match expected URL '{}'",
                    dest, expected_url
                ))
            }
        }
        None => {
            if is_signed {
                Err("Destination is required when message is signed, but was absent".to_string())
            } else {
                // Destination is optional for unsigned messages
                Ok(())
            }
        }
    }
}

/// Compare two URLs for SAML Destination matching.
///
/// The comparison is case-sensitive for the path component, but normalizes
/// trailing slashes and handles common URL variations.
fn urls_match(url_a: &str, url_b: &str) -> bool {
    // Strip trailing slashes for comparison
    let a = url_a.trim_end_matches('/');
    let b = url_b.trim_end_matches('/');
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matching_destination() {
        assert!(verify_destination(
            Some("https://sp.example.com/acs"),
            "https://sp.example.com/acs",
            true,
        )
        .is_ok());
    }

    #[test]
    fn test_mismatching_destination() {
        let result = verify_destination(
            Some("https://sp.example.com/acs"),
            "https://evil.example.com/acs",
            true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match"));
    }

    #[test]
    fn test_absent_destination_signed() {
        let result = verify_destination(None, "https://sp.example.com/acs", true);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("required when message is signed"));
    }

    #[test]
    fn test_absent_destination_unsigned() {
        assert!(verify_destination(None, "https://sp.example.com/acs", false).is_ok());
    }

    #[test]
    fn test_trailing_slash_normalization() {
        assert!(verify_destination(
            Some("https://sp.example.com/acs/"),
            "https://sp.example.com/acs",
            true,
        )
        .is_ok());
    }

    #[test]
    fn test_case_sensitive_path() {
        let result = verify_destination(
            Some("https://sp.example.com/ACS"),
            "https://sp.example.com/acs",
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_present_destination_matches_unsigned() {
        // Even unsigned, if Destination is present it must match
        assert!(verify_destination(
            Some("https://sp.example.com/acs"),
            "https://sp.example.com/acs",
            false,
        )
        .is_ok());
    }

    #[test]
    fn test_present_destination_mismatch_unsigned() {
        let result = verify_destination(
            Some("https://evil.com/acs"),
            "https://sp.example.com/acs",
            false,
        );
        assert!(result.is_err());
    }
}
