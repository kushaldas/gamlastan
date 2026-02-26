// SAML 2.0 Identity Provider Discovery Profile
//
// SAML Profiles Section 4.3 (Common Domain Cookie)
//
// Uses a cookie (_saml_idp) in a common domain to store the list
// of IdPs that have authenticated the user.

use crate::error::ProfileError;

/// The standard cookie name for SAML IdP Discovery.
pub const COMMON_DOMAIN_COOKIE_NAME: &str = "_saml_idp";

/// Encode an IdP entity ID for inclusion in the Common Domain Cookie.
///
/// The value is base64url-encoded (no padding) per the SAML profiles spec.
pub fn encode_idp_entity_id(entity_id: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(entity_id.as_bytes())
}

/// Decode an IdP entity ID from the Common Domain Cookie.
pub fn decode_idp_entity_id(encoded: &str) -> Result<String, ProfileError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProfileError::InvalidCommonDomainCookie)?;
    String::from_utf8(bytes).map_err(|_| ProfileError::InvalidCommonDomainCookie)
}

/// Build the cookie value from a list of IdP entity IDs.
///
/// Each entity ID is base64url-encoded and separated by spaces.
pub fn build_cookie_value(idp_entity_ids: &[&str]) -> String {
    idp_entity_ids
        .iter()
        .map(|id| encode_idp_entity_id(id))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse the cookie value to extract the list of IdP entity IDs.
pub fn parse_cookie_value(cookie_value: &str) -> Result<Vec<String>, ProfileError> {
    if cookie_value.is_empty() {
        return Ok(vec![]);
    }
    cookie_value
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(decode_idp_entity_id)
        .collect()
}

/// Get the most recently used IdP entity ID from the cookie.
///
/// The most recent IdP is the last entry in the cookie.
pub fn most_recent_idp(cookie_value: &str) -> Result<Option<String>, ProfileError> {
    let idps = parse_cookie_value(cookie_value)?;
    Ok(idps.into_iter().last())
}

/// Add an IdP to the cookie value. If the IdP is already present,
/// move it to the end (most recent position).
pub fn add_idp_to_cookie(
    current_cookie: Option<&str>,
    idp_entity_id: &str,
) -> Result<String, ProfileError> {
    let mut idps = match current_cookie {
        Some(v) if !v.is_empty() => parse_cookie_value(v)?,
        _ => vec![],
    };

    // Remove if already present (to re-add at end)
    idps.retain(|id| id != idp_entity_id);
    idps.push(idp_entity_id.to_string());

    let refs: Vec<&str> = idps.iter().map(|s| s.as_str()).collect();
    Ok(build_cookie_value(&refs))
}

/// Build the discovery service return URL.
///
/// The discovery service redirects back to the SP with the selected IdP
/// entity ID as a query parameter.
pub fn build_return_url(sp_return_url: &str, idp_entity_id: &str, return_param: &str) -> String {
    let separator = if sp_return_url.contains('?') {
        "&"
    } else {
        "?"
    };
    format!(
        "{sp_return_url}{separator}{return_param}={}",
        url_encode(idp_entity_id)
    )
}

/// Simple URL encoding for the entity ID.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let entity_id = "https://idp.example.com";
        let encoded = encode_idp_entity_id(entity_id);
        let decoded = decode_idp_entity_id(&encoded).unwrap();
        assert_eq!(decoded, entity_id);
    }

    #[test]
    fn test_build_parse_cookie() {
        let idps = &["https://idp1.example.com", "https://idp2.example.com"];
        let cookie = build_cookie_value(idps);
        let parsed = parse_cookie_value(&cookie).unwrap();
        assert_eq!(parsed, idps);
    }

    #[test]
    fn test_parse_empty_cookie() {
        let parsed = parse_cookie_value("").unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_most_recent_idp() {
        let idps = &["https://idp1.example.com", "https://idp2.example.com"];
        let cookie = build_cookie_value(idps);
        let recent = most_recent_idp(&cookie).unwrap();
        assert_eq!(recent, Some("https://idp2.example.com".to_string()));
    }

    #[test]
    fn test_add_idp_new() {
        let cookie = add_idp_to_cookie(None, "https://idp1.example.com").unwrap();
        let idps = parse_cookie_value(&cookie).unwrap();
        assert_eq!(idps, vec!["https://idp1.example.com"]);
    }

    #[test]
    fn test_add_idp_move_to_end() {
        let initial = build_cookie_value(&["https://idp1.example.com", "https://idp2.example.com"]);
        let cookie = add_idp_to_cookie(Some(&initial), "https://idp1.example.com").unwrap();
        let idps = parse_cookie_value(&cookie).unwrap();
        assert_eq!(
            idps,
            vec!["https://idp2.example.com", "https://idp1.example.com",]
        );
    }

    #[test]
    fn test_build_return_url() {
        let url = build_return_url(
            "https://sp.example.com/ds",
            "https://idp.example.com",
            "entityID",
        );
        assert!(url.starts_with("https://sp.example.com/ds?entityID="));
        assert!(url.contains("https%3A%2F%2Fidp.example.com"));
    }

    #[test]
    fn test_build_return_url_existing_query() {
        let url = build_return_url(
            "https://sp.example.com/ds?foo=bar",
            "https://idp.example.com",
            "entityID",
        );
        assert!(url.contains("&entityID="));
    }
}
