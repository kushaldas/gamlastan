// SAML 2.0 Enhanced Client or Proxy (ECP) Profile
//
// SAML Profiles Section 4.2
//
// ECP uses the PAOS binding with SOAP header blocks:
// - Phase 1: SP sends AuthnRequest in a PAOS response (paos:Request +
//   ecp:Request headers) to the enhanced client
// - The ECP forwards the AuthnRequest to an IdP via SOAP and receives the
//   Response in an envelope carrying an ecp:Response header
// - Phase 2: the ECP forwards the Response to the SP via PAOS
//   (paos:Response header, optional ecp:RelayState)
// - The ECP MUST verify the IdP's AssertionConsumerServiceURL matches the
//   SP's responseConsumerURL; on mismatch it MUST deliver a SOAP fault
//
// This module provides all three roles:
// - SP side: `create_ecp_authn_request_envelope`, `parse_ecp_response_at_sp`
// - ECP client side: `parse_ecp_authn_request_envelope` + `EcpRequest`
//   (transport-agnostic conversation state machine)
// - IdP side: `parse_idp_ecp_request`, `create_ecp_response_envelope`

use crate::bindings::paos::{
    self, EcpRelayState, PaosRequest, PaosResponse, ECP_NS, PAOS_CONTENT_TYPE, PAOS_NS,
};
use crate::bindings::soap::{soap_envelope_wrap, soap_fault};
use crate::core::namespace::{SAML_ASSERTION_NS, SAML_PROTOCOL_NS, SOAP11_NS};
use crate::profiles::error::ProfileError;

/// HTTP `Accept` header value an ECP client sends to signal PAOS support.
pub const ECP_ACCEPT_HEADER: &str = "text/html; application/vnd.paos+xml";

/// Options for building the SP's phase-1 PAOS envelope (SP -> ECP).
#[derive(Debug, Clone)]
pub struct EcpAuthnRequestOptions<'a> {
    /// The serialized AuthnRequest XML (SOAP body).
    pub authn_request_xml: &'a str,
    /// SP entity ID (saml:Issuer in the ecp:Request header).
    pub sp_entity_id: &'a str,
    /// Where the ECP must deliver the response (paos:Request
    /// responseConsumerURL). MUST equal the AuthnRequest's ACS URL.
    pub response_consumer_url: &'a str,
    /// PAOS messageID for correlation (echoed in phase 2 refToMessageID).
    pub message_id: Option<&'a str>,
    /// Human-readable SP name (ecp:Request ProviderName).
    pub provider_name: Option<&'a str>,
    /// Whether the IdP must not interact with the user.
    pub is_passive: bool,
    /// RelayState the ECP must echo back in phase 2.
    pub relay_state: Option<&'a str>,
    /// IdP entity IDs the ECP may use (ecp:Request samlp:IDPList).
    pub idp_list: &'a [String],
}

/// Build the SP's phase-1 PAOS envelope carrying the AuthnRequest.
///
/// One-call SP-side entry point: serialize an AuthnRequest (see
/// [`crate::profiles::sso::sp::create_authn_request`]), then wrap it here.
/// The response must be served with Content-Type
/// [`PAOS_CONTENT_TYPE`](crate::bindings::paos::PAOS_CONTENT_TYPE).
pub fn create_ecp_authn_request_envelope(
    options: &EcpAuthnRequestOptions<'_>,
) -> Result<String, ProfileError> {
    if options.sp_entity_id.is_empty() {
        return Err(ProfileError::MissingIssuer);
    }
    if options.response_consumer_url.is_empty() {
        return Err(ProfileError::Other(
            "responseConsumerURL must not be empty".to_string(),
        ));
    }

    let paos_request = PaosRequest {
        response_consumer_url: options.response_consumer_url.to_string(),
        service: Some(ECP_NS.to_string()),
        message_id: options.message_id.map(|s| s.to_string()),
    };
    let ecp_request = paos::EcpRequest {
        issuer: Some(options.sp_entity_id.to_string()),
        provider_name: options.provider_name.map(|s| s.to_string()),
        is_passive: options.is_passive,
        idp_list: options.idp_list.to_vec(),
    };
    let relay_state = options.relay_state.map(|rs| EcpRelayState {
        relay_state: rs.to_string(),
    });

    paos::build_ecp_phase1_envelope(
        options.authn_request_xml,
        &ecp_request,
        &paos_request,
        relay_state.as_ref(),
    )
    .map_err(ProfileError::Binding)
}

/// The phase-2 envelope the SP receives from the ECP.
#[derive(Debug, Clone)]
pub struct EcpSpResponse {
    /// The SAML Response XML (process with the normal SP response pipeline,
    /// using the PAOS binding rules for validation).
    pub response_xml: String,
    /// RelayState echoed by the ECP (from the ecp:RelayState header).
    pub relay_state: Option<String>,
}

/// Parse the phase-2 PAOS envelope at the SP (ECP -> SP).
///
/// Extracts the SAML Response from the SOAP body and the optional
/// ecp:RelayState header. SOAP faults are surfaced as errors.
pub fn parse_ecp_response_at_sp(soap_xml: &[u8]) -> Result<EcpSpResponse, ProfileError> {
    let envelope = parse_envelope(soap_xml)?;
    Ok(EcpSpResponse {
        response_xml: envelope.body_xml,
        relay_state: envelope.relay_state,
    })
}

/// Parsed phase-1 envelope: the ECP client's view of the SP's PAOS response,
/// and the state needed to complete the conversation.
#[derive(Debug, Clone)]
pub struct EcpRequest {
    /// The AuthnRequest XML to forward to the IdP.
    pub authn_request_xml: String,
    /// Where the SP requires the response to be delivered
    /// (paos:Request responseConsumerURL).
    pub response_consumer_url: String,
    /// PAOS messageID (echoed back as refToMessageID in phase 2).
    pub message_id: Option<String>,
    /// The SP entity ID (saml:Issuer from the ecp:Request header).
    pub issuer: Option<String>,
    /// The SP's human-readable name (ecp:Request ProviderName).
    pub provider_name: Option<String>,
    /// Whether the SP requires passive authentication.
    pub is_passive: Option<bool>,
    /// RelayState that must be echoed back to the SP.
    pub relay_state: Option<String>,
    /// IdP entity IDs the ECP may choose from (ecp:Request samlp:IDPList).
    pub idp_list: Vec<String>,
}

/// Parse the SP's phase-1 PAOS envelope at the ECP client.
pub fn parse_ecp_authn_request_envelope(soap_xml: &[u8]) -> Result<EcpRequest, ProfileError> {
    let envelope = parse_envelope(soap_xml)?;

    let (response_consumer_url, message_id) = envelope
        .paos_request
        .ok_or(ProfileError::MissingPaosHeader)?;

    let ecp_request = envelope
        .ecp_request
        .ok_or(ProfileError::EcpMissingRequestHeader)?;
    let EcpRequestHeader {
        issuer,
        provider_name,
        is_passive,
        idp_list,
    } = ecp_request;

    Ok(EcpRequest {
        authn_request_xml: envelope.body_xml,
        response_consumer_url,
        message_id,
        issuer,
        provider_name,
        is_passive,
        relay_state: envelope.relay_state,
        idp_list,
    })
}

/// The phase-2 delivery produced by the ECP client.
#[derive(Debug, Clone)]
pub struct EcpRelay {
    /// Where to POST the envelope (the verified ACS URL).
    pub destination_url: String,
    /// The phase-2 PAOS envelope (SAML Response + paos:Response header).
    pub envelope: String,
    /// Content-Type to use for the POST (`application/vnd.paos+xml`).
    pub content_type: &'static str,
}

impl EcpRequest {
    /// Build the plain SOAP envelope to POST to the IdP's SSO SOAP endpoint.
    pub fn idp_soap_envelope(&self) -> String {
        soap_envelope_wrap(&self.authn_request_xml, None)
    }

    /// Process the IdP's SOAP response and produce the phase-2 PAOS envelope
    /// for the SP.
    ///
    /// Per Profiles 4.2.4.4 the ECP MUST verify that the IdP's
    /// AssertionConsumerServiceURL (ecp:Response header) matches the SP's
    /// responseConsumerURL. On mismatch this returns
    /// [`ProfileError::EcpAcsUrlMismatch`]; the caller MUST then deliver a
    /// SOAP fault to the SP instead (see [`ecp_fault_envelope`]).
    pub fn process_idp_response(&self, soap_xml: &[u8]) -> Result<EcpRelay, ProfileError> {
        let envelope = parse_envelope(soap_xml)?;

        let acs_url = envelope
            .ecp_response_acs_url
            .ok_or(ProfileError::EcpMissingResponseHeader)?;
        verify_acs_url_match(&acs_url, &self.response_consumer_url)?;

        let paos_response = PaosResponse {
            ref_to_message_id: self.message_id.clone(),
        };
        let relay_state = self.relay_state.as_ref().map(|rs| EcpRelayState {
            relay_state: rs.clone(),
        });

        let envelope = paos::build_ecp_phase2_envelope(
            &envelope.body_xml,
            &paos_response,
            relay_state.as_ref(),
        )?;

        Ok(EcpRelay {
            destination_url: acs_url,
            envelope,
            content_type: PAOS_CONTENT_TYPE,
        })
    }
}

/// HTTP headers an ECP client sends with its initial request to the SP.
pub fn ecp_client_http_headers() -> [(&'static str, String); 2] {
    [
        ("Accept", ECP_ACCEPT_HEADER.to_string()),
        ("PAOS", format!(r#"ver="{}";"{}""#, PAOS_NS, ECP_NS)),
    ]
}

/// Build the SOAP fault envelope the ECP MUST deliver to the SP's
/// responseConsumerURL when it cannot complete the conversation
/// (e.g., ACS URL mismatch per Profiles 4.2.4.5).
pub fn ecp_fault_envelope(reason: &str) -> String {
    soap_fault("soap:Server", reason, None)
}

/// Extract the AuthnRequest XML from the ECP's SOAP request at the IdP.
///
/// The ECP -> IdP envelope carries the AuthnRequest as the sole body element;
/// header blocks (if any) are not required for processing.
pub fn parse_idp_ecp_request(soap_xml: &[u8]) -> Result<String, ProfileError> {
    let envelope = parse_envelope(soap_xml)?;
    Ok(envelope.body_xml)
}

/// Wrap a SAML Response in the IdP -> ECP SOAP envelope.
///
/// One-call IdP-side entry point: create and sign the Response (see
/// [`crate::profiles::sso::idp::create_response`]), serialize it, then wrap
/// it here. The ecp:Response header carries the ACS URL the ECP must verify
/// against the SP's responseConsumerURL.
pub fn create_ecp_response_envelope(
    response_xml: &str,
    acs_url: &str,
) -> Result<String, ProfileError> {
    if acs_url.is_empty() {
        return Err(ProfileError::Other(
            "AssertionConsumerServiceURL must not be empty".to_string(),
        ));
    }
    let header = paos::ecp_response_header_xml(&paos::EcpResponse {
        assertion_consumer_service_url: acs_url.to_string(),
    });
    Ok(soap_envelope_wrap(response_xml, Some(&header)))
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

// ── Envelope parsing ────────────────────────────────────────────────────────

/// Parsed ecp:Request header contents.
#[derive(Debug, Default)]
struct EcpRequestHeader {
    issuer: Option<String>,
    provider_name: Option<String>,
    is_passive: Option<bool>,
    idp_list: Vec<String>,
}

/// All ECP-relevant parts of a SOAP envelope (headers + body).
#[derive(Debug, Default)]
struct ParsedEcpEnvelope {
    body_xml: String,
    paos_request: Option<(String, Option<String>)>,
    ecp_request: Option<EcpRequestHeader>,
    ecp_response_acs_url: Option<String>,
    relay_state: Option<String>,
}

fn parse_envelope(soap_xml: &[u8]) -> Result<ParsedEcpEnvelope, ProfileError> {
    let xml_str = std::str::from_utf8(soap_xml)
        .map_err(|e| ProfileError::Other(format!("envelope is not valid UTF-8: {e}")))?;
    let doc = crate::xml::parse_secure(xml_str)
        .map_err(|e| ProfileError::Other(format!("envelope XML parse error: {e}")))?;

    let root = doc
        .document_element()
        .ok_or_else(|| ProfileError::Other("envelope has no root element".to_string()))?;
    let root_elem = doc
        .element(root)
        .ok_or_else(|| ProfileError::Other("invalid root element".to_string()))?;
    if !root_elem.matches_name_ns(SOAP11_NS, "Envelope") {
        return Err(ProfileError::Other(format!(
            "expected SOAP 1.1 Envelope, got {{{}}}{}",
            root_elem.name.namespace_uri.as_deref().unwrap_or(""),
            root_elem.name.local_name
        )));
    }

    let mut parsed = ParsedEcpEnvelope::default();
    let mut body_count = 0usize;

    for child in doc.children_iter(root) {
        let Some(elem) = doc.element(child) else {
            continue;
        };
        if elem.matches_name_ns(SOAP11_NS, "Header") {
            parse_header_blocks(&doc, child, &mut parsed)?;
        } else if elem.matches_name_ns(SOAP11_NS, "Body") {
            body_count += 1;
            if body_count > 1 {
                return Err(ProfileError::Other(
                    "SOAP Envelope must contain exactly one Body".to_string(),
                ));
            }

            // The SOAP binding requires exactly one element in the Body;
            // accepting extras would allow element smuggling (a decoy first
            // element with the real SAML message hidden after it).
            let mut body_children = 0usize;
            for bc in doc.children_iter(child) {
                if let Some(bc_elem) = doc.element(bc) {
                    if bc_elem.matches_name_ns(SOAP11_NS, "Fault") {
                        let fault = doc.text_content_deep(bc);
                        return Err(ProfileError::Other(format!(
                            "SOAP fault in ECP envelope: {}",
                            fault.trim()
                        )));
                    }
                    body_children += 1;
                    if body_children > 1 {
                        return Err(ProfileError::Other(
                            "SOAP Body must contain exactly one element".to_string(),
                        ));
                    }
                    parsed.body_xml = doc.node_to_xml(bc);
                }
            }
        }
    }

    if parsed.body_xml.is_empty() {
        return Err(ProfileError::Other(
            "no SAML element in SOAP Body".to_string(),
        ));
    }

    Ok(parsed)
}

fn parse_header_blocks(
    doc: &uppsala::Document<'_>,
    header: uppsala::NodeId,
    parsed: &mut ParsedEcpEnvelope,
) -> Result<(), ProfileError> {
    for block in doc.children_iter(header) {
        let Some(elem) = doc.element(block) else {
            continue;
        };
        if elem.matches_name_ns(PAOS_NS, "Request") {
            let rcu = doc
                .get_attribute(block, "responseConsumerURL")
                .ok_or(ProfileError::MissingPaosHeader)?;
            let message_id = doc.get_attribute(block, "messageID").map(|s| s.to_string());
            parsed.paos_request = Some((rcu.to_string(), message_id));
        } else if elem.matches_name_ns(ECP_NS, "Request") {
            let mut h = EcpRequestHeader {
                provider_name: doc.get_attribute(block, "ProviderName").map(String::from),
                is_passive: doc
                    .get_attribute(block, "IsPassive")
                    .map(|v| v == "true" || v == "1"),
                ..Default::default()
            };
            if let Some(issuer) =
                doc.first_child_element_by_name_ns(block, SAML_ASSERTION_NS, "Issuer")
            {
                h.issuer = doc.element_text(issuer).map(|s| s.trim().to_string());
            }
            if let Some(idp_list) =
                doc.first_child_element_by_name_ns(block, SAML_PROTOCOL_NS, "IDPList")
            {
                for entry in doc.child_elements_by_name_ns(idp_list, SAML_PROTOCOL_NS, "IDPEntry") {
                    if let Some(provider_id) = doc.get_attribute(entry, "ProviderID") {
                        h.idp_list.push(provider_id.to_string());
                    }
                }
            }
            parsed.ecp_request = Some(h);
        } else if elem.matches_name_ns(ECP_NS, "Response") {
            parsed.ecp_response_acs_url = doc
                .get_attribute(block, "AssertionConsumerServiceURL")
                .map(String::from);
        } else if elem.matches_name_ns(ECP_NS, "RelayState") {
            parsed.relay_state = doc.element_text(block).map(|s| s.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHN_REQUEST: &str = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example.com/acs"/>"#;
    const SAML_RESPONSE: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>"#;

    fn sp_options<'a>() -> EcpAuthnRequestOptions<'a> {
        EcpAuthnRequestOptions {
            authn_request_xml: AUTHN_REQUEST,
            sp_entity_id: "https://sp.example.com",
            response_consumer_url: "https://sp.example.com/acs",
            message_id: Some("_paos_msg_1"),
            provider_name: Some("Example SP"),
            is_passive: false,
            relay_state: Some("state-42"),
            idp_list: &[],
        }
    }

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

    #[test]
    fn test_ecp_client_http_headers() {
        let headers = ecp_client_http_headers();
        assert_eq!(headers[0].0, "Accept");
        assert!(headers[0].1.contains("application/vnd.paos+xml"));
        assert_eq!(headers[1].0, "PAOS");
        assert!(headers[1].1.contains("urn:liberty:paos:2003-08"));
        assert!(headers[1].1.contains(ECP_NS));
    }

    #[test]
    fn test_sp_envelope_roundtrip_to_ecp_client() {
        let mut options = sp_options();
        let idps = vec!["https://idp.example.com".to_string()];
        options.idp_list = &idps;
        let envelope = create_ecp_authn_request_envelope(&options).unwrap();

        let parsed = parse_ecp_authn_request_envelope(envelope.as_bytes()).unwrap();
        assert!(parsed.authn_request_xml.contains("AuthnRequest"));
        assert_eq!(parsed.response_consumer_url, "https://sp.example.com/acs");
        assert_eq!(parsed.message_id.as_deref(), Some("_paos_msg_1"));
        assert_eq!(parsed.issuer.as_deref(), Some("https://sp.example.com"));
        assert_eq!(parsed.provider_name.as_deref(), Some("Example SP"));
        assert_eq!(parsed.is_passive, Some(false));
        assert_eq!(parsed.relay_state.as_deref(), Some("state-42"));
        assert_eq!(parsed.idp_list, vec!["https://idp.example.com"]);
    }

    #[test]
    fn test_sp_envelope_requires_issuer() {
        let mut options = sp_options();
        options.sp_entity_id = "";
        assert!(matches!(
            create_ecp_authn_request_envelope(&options),
            Err(ProfileError::MissingIssuer)
        ));
    }

    #[test]
    fn test_parse_phase1_missing_paos_request() {
        let envelope = soap_envelope_wrap(AUTHN_REQUEST, None);
        let result = parse_ecp_authn_request_envelope(envelope.as_bytes());
        assert!(matches!(result, Err(ProfileError::MissingPaosHeader)));
    }

    #[test]
    fn test_parse_phase1_missing_ecp_request() {
        let paos_request = PaosRequest {
            response_consumer_url: "https://sp.example.com/acs".to_string(),
            service: Some(ECP_NS.to_string()),
            message_id: Some("_paos_msg_1".to_string()),
        };
        let headers = paos::paos_request_header_xml(&paos_request);
        let envelope = soap_envelope_wrap(AUTHN_REQUEST, Some(&headers));

        let result = parse_ecp_authn_request_envelope(envelope.as_bytes());
        assert!(matches!(result, Err(ProfileError::EcpMissingRequestHeader)));
    }

    #[test]
    fn test_full_ecp_conversation() {
        // Phase 1: SP -> ECP
        let envelope = create_ecp_authn_request_envelope(&sp_options()).unwrap();
        let ecp = parse_ecp_authn_request_envelope(envelope.as_bytes()).unwrap();

        // ECP -> IdP
        let idp_envelope = ecp.idp_soap_envelope();
        assert!(idp_envelope.contains("soap:Envelope"));
        assert!(idp_envelope.contains("AuthnRequest"));

        // IdP side: unwrap, then answer
        let request_xml = parse_idp_ecp_request(idp_envelope.as_bytes()).unwrap();
        assert!(request_xml.contains("AuthnRequest"));
        let idp_response =
            create_ecp_response_envelope(SAML_RESPONSE, "https://sp.example.com/acs").unwrap();

        // ECP: verify + build phase 2
        let relay = ecp.process_idp_response(idp_response.as_bytes()).unwrap();
        assert_eq!(relay.destination_url, "https://sp.example.com/acs");
        assert_eq!(relay.content_type, PAOS_CONTENT_TYPE);
        assert!(relay.envelope.contains("paos:Response"));
        assert!(relay.envelope.contains("refToMessageID=\"_paos_msg_1\""));
        assert!(relay.envelope.contains("state-42"));

        // Phase 2: SP consumes
        let sp_response = parse_ecp_response_at_sp(relay.envelope.as_bytes()).unwrap();
        assert!(sp_response.response_xml.contains("Response"));
        assert_eq!(sp_response.relay_state.as_deref(), Some("state-42"));
    }

    #[test]
    fn test_ecp_client_rejects_acs_mismatch() {
        let envelope = create_ecp_authn_request_envelope(&sp_options()).unwrap();
        let ecp = parse_ecp_authn_request_envelope(envelope.as_bytes()).unwrap();

        let idp_response =
            create_ecp_response_envelope(SAML_RESPONSE, "https://evil.example.com/acs").unwrap();
        let result = ecp.process_idp_response(idp_response.as_bytes());
        assert!(matches!(result, Err(ProfileError::EcpAcsUrlMismatch)));
    }

    #[test]
    fn test_ecp_client_missing_response_header() {
        let envelope = create_ecp_authn_request_envelope(&sp_options()).unwrap();
        let ecp = parse_ecp_authn_request_envelope(envelope.as_bytes()).unwrap();

        let idp_response = soap_envelope_wrap(SAML_RESPONSE, None);
        let result = ecp.process_idp_response(idp_response.as_bytes());
        assert!(matches!(
            result,
            Err(ProfileError::EcpMissingResponseHeader)
        ));
    }

    #[test]
    fn test_ecp_fault_envelope() {
        let fault = ecp_fault_envelope("ACS URL mismatch");
        assert!(fault.contains("soap:Fault"));
        assert!(fault.contains("ACS URL mismatch"));
    }

    #[test]
    fn test_parse_envelope_rejects_fault() {
        let fault = ecp_fault_envelope("boom");
        let result = parse_ecp_response_at_sp(fault.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_idp_list() {
        let idps = vec!["https://idp.example.com".to_string()];
        assert_eq!(extract_idp_list(&idps), idps);
    }

    #[test]
    fn test_parse_envelope_rejects_non_soap_namespace() {
        let xml = r#"<Envelope xmlns="urn:not-soap"><Body><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/></Body></Envelope>"#;
        let result = parse_ecp_response_at_sp(xml.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_envelope_rejects_multiple_body_children() {
        let xml = concat!(
            r#"<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body>"#,
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_decoy"/>"#,
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_real"/>"#,
            r#"</S:Body></S:Envelope>"#
        );
        let result = parse_ecp_response_at_sp(xml.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_envelope_rejects_multiple_body_elements() {
        let xml = concat!(
            r#"<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">"#,
            r#"<S:Body><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_decoy"/></S:Body>"#,
            r#"<S:Body><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_real"/></S:Body>"#,
            r#"</S:Envelope>"#
        );
        let result = parse_ecp_response_at_sp(xml.as_bytes());
        assert!(result.is_err());
    }
}
