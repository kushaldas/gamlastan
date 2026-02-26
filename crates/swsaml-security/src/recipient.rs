// SAML 2.0 Recipient attribute matching
//
// Per Profiles 4.1.4.3:
// - The Recipient attribute in SubjectConfirmationData MUST match the
//   assertion consumer service URL to which the assertion was delivered.
// - This prevents assertion substitution attacks.

/// Verify that the Recipient attribute matches the expected ACS URL.
///
/// # Arguments
/// * `recipient` - The Recipient attribute from SubjectConfirmationData (may be None).
/// * `expected_acs_url` - The ACS URL where the response was received.
///
/// Returns `Ok(())` if valid, or an error description.
pub fn verify_recipient(recipient: Option<&str>, expected_acs_url: &str) -> Result<(), String> {
    match recipient {
        Some(r) => {
            if urls_match(r, expected_acs_url) {
                Ok(())
            } else {
                Err(format!(
                    "Recipient '{}' does not match expected ACS URL '{}'",
                    r, expected_acs_url
                ))
            }
        }
        None => {
            // Recipient is required for bearer confirmation per profiles
            Err(
                "Recipient is required in SubjectConfirmationData for bearer confirmation"
                    .to_string(),
            )
        }
    }
}

/// Compare two URLs for SAML Recipient matching.
///
/// Uses the same normalization as destination matching.
fn urls_match(url_a: &str, url_b: &str) -> bool {
    let a = url_a.trim_end_matches('/');
    let b = url_b.trim_end_matches('/');
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matching_recipient() {
        assert!(verify_recipient(
            Some("https://sp.example.com/acs"),
            "https://sp.example.com/acs",
        )
        .is_ok());
    }

    #[test]
    fn test_mismatching_recipient() {
        let result = verify_recipient(
            Some("https://sp.example.com/acs"),
            "https://other.example.com/acs",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match"));
    }

    #[test]
    fn test_absent_recipient() {
        let result = verify_recipient(None, "https://sp.example.com/acs");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("required"));
    }

    #[test]
    fn test_trailing_slash() {
        assert!(verify_recipient(
            Some("https://sp.example.com/acs/"),
            "https://sp.example.com/acs",
        )
        .is_ok());
    }
}
