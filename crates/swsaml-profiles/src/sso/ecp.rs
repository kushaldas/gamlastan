// SAML 2.0 Enhanced Client or Proxy (ECP) Profile
//
// SAML Profiles Section 4.2
//
// ECP uses PAOS binding with SOAP header blocks:
// - SP sends AuthnRequest in SOAP response (phase 1)
// - ECP forwards to IdP via SOAP, receives Response
// - ECP forwards Response to SP via PAOS (phase 2)
// - ECP MUST verify ACS URL matches PAOS responseConsumerURL

use crate::error::ProfileError;

/// ECP request information extracted from the SP's PAOS response.
#[derive(Debug, Clone)]
pub struct EcpRequest {
    /// The AuthnRequest XML from the SOAP body.
    pub authn_request_xml: String,

    /// The ACS URL where the response should be sent (from ECP Request header).
    pub acs_url: String,

    /// The provider name (from ECP Request header).
    pub provider_name: Option<String>,

    /// Whether the SP requires the IdP to authenticate the principal
    /// (IsPassive from ECP Request header).
    pub is_passive: Option<bool>,

    /// The PAOS response consumer URL (must match ACS URL).
    pub paos_response_consumer_url: String,

    /// The PAOS MessageID (for correlation).
    pub paos_message_id: Option<String>,

    /// RelayState (from ECP RelayState header).
    pub relay_state: Option<String>,
}

/// ECP response information to forward from IdP to SP.
#[derive(Debug, Clone)]
pub struct EcpResponse {
    /// The SAML Response XML from the IdP.
    pub response_xml: String,

    /// The ACS URL to send the response to (from ECP Response header).
    pub acs_url: String,

    /// The RelayState to include (from original request).
    pub relay_state: Option<String>,

    /// The PAOS MessageID to reference (refToMessageID).
    pub ref_to_message_id: Option<String>,
}

/// Verify that the ACS URL from the ECP Response header matches the
/// PAOS responseConsumerURL from the original request.
///
/// Per Profiles 4.2.4.4: The ECP MUST verify that the value of the
/// AssertionConsumerServiceURL attribute in the IdP's response matches
/// the responseConsumerURL value from the SP's PAOS response.
pub fn verify_acs_url_match(
    ecp_acs_url: &str,
    paos_response_consumer_url: &str,
) -> Result<(), ProfileError> {
    if ecp_acs_url != paos_response_consumer_url {
        Err(ProfileError::EcpAcsUrlMismatch)
    } else {
        Ok(())
    }
}

/// Check if an HTTP request is a PAOS/ECP request by examining headers.
///
/// ECP clients include:
/// - Accept header with `application/vnd.paos+xml`
/// - PAOS header with `urn:liberty:paos:2003-08` version
pub fn is_ecp_request(accept_header: Option<&str>, paos_header: Option<&str>) -> bool {
    let has_paos_accept = accept_header.is_some_and(|h| h.contains("application/vnd.paos+xml"));
    let has_paos_version = paos_header.is_some_and(|h| h.contains("urn:liberty:paos:2003-08"));
    has_paos_accept && has_paos_version
}

/// Build the ECP IdP list from the AuthnRequest Scoping/IDPList.
///
/// The ECP MAY use this list to select an IdP for authentication.
pub fn extract_idp_list(authn_request_scoping_idp_list: &[String]) -> Vec<String> {
    authn_request_scoping_idp_list.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_acs_url_match_ok() {
        assert!(
            verify_acs_url_match("https://sp.example.com/acs", "https://sp.example.com/acs")
                .is_ok()
        );
    }

    #[test]
    fn test_verify_acs_url_match_mismatch() {
        let result =
            verify_acs_url_match("https://evil.example.com/acs", "https://sp.example.com/acs");
        assert!(matches!(result, Err(ProfileError::EcpAcsUrlMismatch)));
    }

    #[test]
    fn test_is_ecp_request_valid() {
        assert!(is_ecp_request(
            Some("text/html, application/vnd.paos+xml"),
            Some("ver=\"urn:liberty:paos:2003-08\""),
        ));
    }

    #[test]
    fn test_is_ecp_request_missing_accept() {
        assert!(!is_ecp_request(
            Some("text/html"),
            Some("ver=\"urn:liberty:paos:2003-08\""),
        ));
    }

    #[test]
    fn test_is_ecp_request_missing_paos() {
        assert!(!is_ecp_request(Some("application/vnd.paos+xml"), None,));
    }

    #[test]
    fn test_is_ecp_request_no_headers() {
        assert!(!is_ecp_request(None, None));
    }
}
