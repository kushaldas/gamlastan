// SAML 2.0 Identity Provider Discovery
//
// Two mechanisms are implemented:
// - SAML Profiles Section 4.3 (Common Domain Cookie): a `_saml_idp` cookie
//   in a common domain stores the list of IdPs that authenticated the user.
// - The Identity Provider Discovery Service Protocol and Profile
//   (sstc-saml-idp-discovery): an SP redirects the browser to a discovery
//   service with `entityID`/`return`/`returnIDParam`/`policy`/`isPassive`
//   query parameters; the DS redirects back with the chosen IdP entity ID.
//   The DS MUST validate the `return` URL against the SP's registered
//   `idpdisc:DiscoveryResponse` metadata endpoints (phishing protection).

use crate::bindings::encoding::{parse_query_string_raw, url_decode};
use crate::profiles::error::ProfileError;

/// The standard cookie name for SAML IdP Discovery.
pub const COMMON_DOMAIN_COOKIE_NAME: &str = "_saml_idp";

/// Namespace of the `idpdisc:DiscoveryResponse` metadata extension, also used
/// as the Binding value on DiscoveryResponse endpoints.
pub const IDPDISC_NS: &str = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";

/// The single-IdP discovery protocol policy URI (the default policy).
pub const DISCOVERY_POLICY_SINGLE: &str =
    "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol:single";

/// Default name of the query parameter carrying the chosen IdP entity ID.
pub const DEFAULT_RETURN_ID_PARAM: &str = "entityID";

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

// ── Discovery Service protocol (sstc-saml-idp-discovery) ──────────────────

/// A parsed discovery service request (the SP -> DS redirect).
#[derive(Debug, Clone)]
pub struct DiscoveryServiceRequest {
    /// The requesting SP's entity ID (`entityID`, required).
    pub entity_id: String,
    /// Where to send the response (`return`). When absent, the DS uses the
    /// SP's default DiscoveryResponse endpoint from metadata.
    pub return_url: Option<String>,
    /// Query parameter name for the chosen IdP (`returnIDParam`).
    pub return_id_param: String,
    /// The discovery protocol policy (`policy`). `None` means the default
    /// single-IdP policy.
    pub policy: Option<String>,
    /// Whether the DS must not interact with the user (`isPassive`).
    pub is_passive: bool,
}

impl DiscoveryServiceRequest {
    /// Whether the requested policy is one this implementation supports
    /// (absent or the single-IdP policy).
    pub fn is_supported_policy(&self) -> bool {
        match &self.policy {
            None => true,
            Some(p) => p == DISCOVERY_POLICY_SINGLE,
        }
    }
}

/// Parse a discovery service request from the request's query string.
pub fn parse_discovery_service_request(
    query: &str,
) -> Result<DiscoveryServiceRequest, ProfileError> {
    let mut entity_id = None;
    let mut return_url = None;
    let mut return_id_param = None;
    let mut policy = None;
    let mut is_passive = false;

    for (key, value) in parse_query_string_raw(query) {
        let value = url_decode(value)?;
        match key {
            "entityID" => entity_id = Some(value),
            "return" => return_url = Some(value),
            "returnIDParam" => return_id_param = Some(value),
            "policy" => policy = Some(value),
            "isPassive" => is_passive = value == "true",
            _ => {}
        }
    }

    Ok(DiscoveryServiceRequest {
        entity_id: entity_id.ok_or(ProfileError::DiscoveryMissingEntityId)?,
        return_url,
        return_id_param: return_id_param.unwrap_or_else(|| DEFAULT_RETURN_ID_PARAM.to_string()),
        policy,
        is_passive,
    })
}

/// A DiscoveryResponse endpoint registered in SP metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryResponseEndpoint {
    /// The endpoint location (the allowed return URL base).
    pub location: String,
    /// The endpoint index.
    pub index: u16,
    /// Whether this is the default endpoint.
    pub is_default: bool,
}

/// Extract `idpdisc:DiscoveryResponse` endpoints from the raw XML of an SP
/// role's `<Extensions>` element (see
/// [`Extensions::raw_xml`](crate::metadata::types::extensions::Extensions)).
///
/// The fragment is parsed with common metadata-extension prefixes
/// pre-declared, so extensions that rely on prefixes declared on an ancestor
/// element still parse.
pub fn parse_discovery_response_endpoints(
    extensions_raw_xml: &str,
) -> Result<Vec<DiscoveryResponseEndpoint>, ProfileError> {
    if extensions_raw_xml.trim().is_empty() {
        return Ok(vec![]);
    }

    // Wrap the fragment so it has a single root, pre-declaring prefixes that
    // are conventionally bound in SAML metadata documents.
    let wrapped = format!(
        concat!(
            "<w xmlns:idpdisc=\"{idpdisc}\"",
            " xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"",
            " xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\"",
            " xmlns:mdrpi=\"urn:oasis:names:tc:SAML:metadata:rpi\"",
            " xmlns:mdattr=\"urn:oasis:names:tc:SAML:metadata:attribute\"",
            " xmlns:shibmd=\"urn:mace:shibboleth:metadata:1.0\"",
            " xmlns:alg=\"urn:oasis:names:tc:SAML:metadata:algsupport\"",
            " xmlns:init=\"urn:oasis:names:tc:SAML:profiles:SSO:request-init\"",
            " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
            " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            ">{body}</w>"
        ),
        idpdisc = IDPDISC_NS,
        body = extensions_raw_xml
    );

    let doc = uppsala::parse(&wrapped)
        .map_err(|e| ProfileError::Metadata(format!("cannot parse Extensions XML: {e}")))?;
    let root = doc
        .document_element()
        .ok_or_else(|| ProfileError::Metadata("empty Extensions XML".to_string()))?;

    let mut endpoints = Vec::new();
    collect_discovery_responses(&doc, root, &mut endpoints);
    Ok(endpoints)
}

fn collect_discovery_responses(
    doc: &uppsala::Document<'_>,
    node: uppsala::NodeId,
    out: &mut Vec<DiscoveryResponseEndpoint>,
) {
    for child in doc.children_iter(node) {
        if let Some(elem) = doc.element(child) {
            if elem.matches_name_ns(IDPDISC_NS, "DiscoveryResponse") {
                if let Some(location) = doc.get_attribute(child, "Location") {
                    let index = doc
                        .get_attribute(child, "index")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let is_default = doc
                        .get_attribute(child, "isDefault")
                        .is_some_and(|v| v == "true" || v == "1");
                    out.push(DiscoveryResponseEndpoint {
                        location: location.to_string(),
                        index,
                        is_default,
                    });
                }
            }
            collect_discovery_responses(doc, child, out);
        }
    }
}

/// The default DiscoveryResponse endpoint: isDefault=true, else lowest index.
pub fn default_discovery_response_endpoint(
    endpoints: &[DiscoveryResponseEndpoint],
) -> Option<&DiscoveryResponseEndpoint> {
    endpoints
        .iter()
        .find(|e| e.is_default)
        .or_else(|| endpoints.iter().min_by_key(|e| e.index))
}

/// Verify a `return` URL against the SP's registered DiscoveryResponse
/// endpoints (phishing protection, sstc-saml-idp-discovery section 2.4.1).
///
/// The scheme, host, port and path of the return URL MUST match a registered
/// Location; any registered query string must be preserved, and MAY be
/// extended with additional parameters.
pub fn verify_return_url(return_url: &str, registered: &[DiscoveryResponseEndpoint]) -> bool {
    let (return_base, return_query) = split_url_query(return_url);
    registered.iter().any(|e| {
        let (registered_base, registered_query) = split_url_query(&e.location);
        return_base == registered_base
            && match registered_query {
                None => true,
                Some(expected) => {
                    return_query == Some(expected)
                        || return_query
                            .is_some_and(|actual| actual.starts_with(&format!("{expected}&")))
                }
            }
    })
}

fn split_url_query(url: &str) -> (&str, Option<&str>) {
    match url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (url, None),
    }
}

/// Build the DS -> SP redirect URL answering a discovery request.
///
/// - The return URL is taken from the request, falling back to the SP's
///   default DiscoveryResponse endpoint.
/// - When `registered` is non-empty, the return URL MUST match a registered
///   endpoint or the request is rejected.
/// - `selected_idp = None` (e.g. an isPassive request with no known IdP)
///   redirects back without the returnIDParam, as the profile requires.
pub fn create_discovery_service_response(
    request: &DiscoveryServiceRequest,
    registered: &[DiscoveryResponseEndpoint],
    selected_idp: Option<&str>,
) -> Result<String, ProfileError> {
    let return_url = match &request.return_url {
        Some(url) => {
            if !registered.is_empty() && !verify_return_url(url, registered) {
                return Err(ProfileError::DiscoveryReturnUrlNotRegistered(url.clone()));
            }
            url.clone()
        }
        None => default_discovery_response_endpoint(registered)
            .map(|e| e.location.clone())
            .ok_or(ProfileError::DiscoveryNoReturnUrl)?,
    };

    Ok(match selected_idp {
        Some(idp) => build_return_url(&return_url, idp, &request.return_id_param),
        None => return_url,
    })
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

    // ── Discovery Service protocol tests ────────────────────────────────────

    fn registered_endpoints() -> Vec<DiscoveryResponseEndpoint> {
        vec![
            DiscoveryResponseEndpoint {
                location: "https://sp.example.com/disco".to_string(),
                index: 1,
                is_default: false,
            },
            DiscoveryResponseEndpoint {
                location: "https://sp.example.com/disco-default".to_string(),
                index: 0,
                is_default: true,
            },
        ]
    }

    #[test]
    fn test_parse_discovery_service_request() {
        let query = "entityID=https%3A%2F%2Fsp.example.com&return=https%3A%2F%2Fsp.example.com%2Fdisco%3Fsid%3D42&returnIDParam=idp&isPassive=true";
        let req = parse_discovery_service_request(query).unwrap();
        assert_eq!(req.entity_id, "https://sp.example.com");
        assert_eq!(
            req.return_url.as_deref(),
            Some("https://sp.example.com/disco?sid=42")
        );
        assert_eq!(req.return_id_param, "idp");
        assert!(req.is_passive);
        assert!(req.is_supported_policy());
    }

    #[test]
    fn test_parse_discovery_service_request_defaults() {
        let req = parse_discovery_service_request("entityID=https%3A%2F%2Fsp.example.com").unwrap();
        assert_eq!(req.return_id_param, DEFAULT_RETURN_ID_PARAM);
        assert!(req.return_url.is_none());
        assert!(!req.is_passive);
    }

    #[test]
    fn test_parse_discovery_service_request_missing_entity_id() {
        let result = parse_discovery_service_request("return=https%3A%2F%2Fsp.example.com");
        assert!(matches!(
            result,
            Err(ProfileError::DiscoveryMissingEntityId)
        ));
    }

    #[test]
    fn test_parse_discovery_response_endpoints() {
        let extensions = r#"<idpdisc:DiscoveryResponse xmlns:idpdisc="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Binding="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" index="0" isDefault="true" Location="https://sp.example.com/disco"/>"#;
        let endpoints = parse_discovery_response_endpoints(extensions).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].location, "https://sp.example.com/disco");
        assert!(endpoints[0].is_default);
    }

    #[test]
    fn test_parse_discovery_response_endpoints_undeclared_prefix() {
        // Prefix declared on an ancestor in the original document — the
        // parser pre-declares the conventional idpdisc prefix.
        let extensions = r#"<idpdisc:DiscoveryResponse index="2" Location="https://sp.example.com/d2"/><mdui:UIInfo/>"#;
        let endpoints = parse_discovery_response_endpoints(extensions).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].index, 2);
    }

    #[test]
    fn test_parse_discovery_response_endpoints_empty() {
        assert!(parse_discovery_response_endpoints("").unwrap().is_empty());
    }

    #[test]
    fn test_verify_return_url() {
        let registered = registered_endpoints();
        // Exact match
        assert!(verify_return_url(
            "https://sp.example.com/disco",
            &registered
        ));
        // Query string extension is allowed
        assert!(verify_return_url(
            "https://sp.example.com/disco?sid=42",
            &registered
        ));
        // Different path is rejected
        assert!(!verify_return_url(
            "https://sp.example.com/other",
            &registered
        ));
        // Different host is rejected
        assert!(!verify_return_url(
            "https://evil.example.com/disco",
            &registered
        ));
    }

    #[test]
    fn test_verify_return_url_preserves_registered_query() {
        let registered = vec![DiscoveryResponseEndpoint {
            location: "https://sp.example.com/disco?sid=42".to_string(),
            index: 0,
            is_default: true,
        }];

        assert!(verify_return_url(
            "https://sp.example.com/disco?sid=42&entityID=https%3A%2F%2Fidp.example.com",
            &registered,
        ));
        assert!(!verify_return_url(
            "https://sp.example.com/disco?sid=99&entityID=https%3A%2F%2Fidp.example.com",
            &registered,
        ));
    }

    #[test]
    fn test_create_discovery_service_response_selected() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: Some("https://sp.example.com/disco?sid=42".to_string()),
            return_id_param: "entityID".to_string(),
            policy: None,
            is_passive: false,
        };
        let url = create_discovery_service_response(
            &req,
            &registered_endpoints(),
            Some("https://idp.example.com"),
        )
        .unwrap();
        assert!(url.starts_with("https://sp.example.com/disco?sid=42&entityID="));
        assert!(url.contains("https%3A%2F%2Fidp.example.com"));
    }

    #[test]
    fn test_create_discovery_service_response_passive_none() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: Some("https://sp.example.com/disco".to_string()),
            return_id_param: "entityID".to_string(),
            policy: None,
            is_passive: true,
        };
        let url = create_discovery_service_response(&req, &registered_endpoints(), None).unwrap();
        assert_eq!(url, "https://sp.example.com/disco");
    }

    #[test]
    fn test_create_discovery_service_response_unregistered_return() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: Some("https://evil.example.com/phish".to_string()),
            return_id_param: "entityID".to_string(),
            policy: None,
            is_passive: false,
        };
        let result = create_discovery_service_response(
            &req,
            &registered_endpoints(),
            Some("https://idp.example.com"),
        );
        assert!(matches!(
            result,
            Err(ProfileError::DiscoveryReturnUrlNotRegistered(_))
        ));
    }

    #[test]
    fn test_create_discovery_service_response_default_endpoint() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: None,
            return_id_param: "entityID".to_string(),
            policy: None,
            is_passive: false,
        };
        let url = create_discovery_service_response(
            &req,
            &registered_endpoints(),
            Some("https://idp.example.com"),
        )
        .unwrap();
        assert!(url.starts_with("https://sp.example.com/disco-default?entityID="));
    }

    #[test]
    fn test_create_discovery_service_response_no_return_available() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: None,
            return_id_param: "entityID".to_string(),
            policy: None,
            is_passive: false,
        };
        let result = create_discovery_service_response(&req, &[], Some("https://idp.example.com"));
        assert!(matches!(result, Err(ProfileError::DiscoveryNoReturnUrl)));
    }

    #[test]
    fn test_unsupported_policy_detected() {
        let req = DiscoveryServiceRequest {
            entity_id: "https://sp.example.com".to_string(),
            return_url: None,
            return_id_param: "entityID".to_string(),
            policy: Some("urn:example:custom-policy".to_string()),
            is_passive: false,
        };
        assert!(!req.is_supported_policy());
    }
}
