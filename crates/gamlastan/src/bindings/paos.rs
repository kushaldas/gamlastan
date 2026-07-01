// PAOS (Reverse SOAP) Binding for SAML 2.0 (SAML Bindings Section 3.3).
//
// PAOS is used for ECP (Enhanced Client or Proxy) profile.
//
// HTTP headers:
// - Accept: application/vnd.paos+xml
// - PAOS: urn:liberty:paos:2003-08
//
// SOAP headers (all with mustUnderstand="1" and actor=next):
// - PAOS Request/Response
// - ECP Request/Response
// - ECP RelayState
//
// Two-phase exchange:
// - Phase 1: SAML request in SOAP response from IdP
// - Phase 2: SAML response in SOAP request to SP

use crate::bindings::error::BindingError;
use crate::bindings::soap::SOAP11_ACTOR_NEXT;
use crate::xml::XmlWriter;

/// PAOS content type.
pub const PAOS_CONTENT_TYPE: &str = "application/vnd.paos+xml";

/// PAOS header value for HTTP.
pub const PAOS_HEADER_VALUE: &str = "ver=\"urn:liberty:paos:2003-08\"";

/// PAOS namespace.
pub const PAOS_NS: &str = "urn:liberty:paos:2003-08";

/// ECP namespace.
pub const ECP_NS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";

/// PAOS Request SOAP header block.
///
/// Included in the initial HTTP request from the ECP to the SP.
#[derive(Debug, Clone)]
pub struct PaosRequest {
    /// Response consumer URL (where the SP should send the response).
    pub response_consumer_url: String,
    /// Service name (optional display name for the SP).
    pub service: Option<String>,
    /// Message ID for correlation.
    pub message_id: Option<String>,
}

/// PAOS Response SOAP header block.
///
/// Included in the SOAP message from ECP to SP (phase 2).
#[derive(Debug, Clone)]
pub struct PaosResponse {
    /// Reference to the original messageID from the PAOS Request.
    pub ref_to_message_id: Option<String>,
}

/// ECP Request SOAP header block.
///
/// Included in the SOAP response from SP to ECP (phase 1).
#[derive(Debug, Clone)]
pub struct EcpRequest {
    /// The SP entity ID (serialized as a `saml:Issuer` child, required by
    /// Profiles 4.2.4.2).
    pub issuer: Option<String>,
    /// Human-readable SP name.
    pub provider_name: Option<String>,
    /// Whether passive authentication is required.
    pub is_passive: bool,
    /// IdP entity IDs the ECP may use (serialized as `samlp:IDPList`).
    pub idp_list: Vec<String>,
}

/// ECP Response SOAP header block.
///
/// Included in the SOAP response from IdP to ECP.
#[derive(Debug, Clone)]
pub struct EcpResponse {
    /// The ACS URL where the ECP should deliver the SAML response.
    pub assertion_consumer_service_url: String,
}

/// ECP RelayState SOAP header block.
#[derive(Debug, Clone)]
pub struct EcpRelayState {
    /// The RelayState value to be echoed back.
    pub relay_state: String,
}

/// Serialize a PAOS Request header block to XML.
pub fn paos_request_header_xml(req: &PaosRequest) -> String {
    let mut w = XmlWriter::with_capacity(256);
    let mut attrs: Vec<(&str, &str)> = vec![
        ("xmlns:paos", PAOS_NS),
        ("soap:mustUnderstand", "1"),
        ("soap:actor", SOAP11_ACTOR_NEXT),
        ("responseConsumerURL", req.response_consumer_url.as_str()),
    ];
    if let Some(svc) = &req.service {
        attrs.push(("service", svc.as_str()));
    }
    if let Some(mid) = &req.message_id {
        attrs.push(("messageID", mid.as_str()));
    }
    w.empty_element("paos:Request", &attrs);
    w.into_string()
}

/// Serialize a PAOS Response header block to XML.
pub fn paos_response_header_xml(resp: &PaosResponse) -> String {
    let mut w = XmlWriter::with_capacity(128);
    let mut attrs: Vec<(&str, &str)> = vec![
        ("xmlns:paos", PAOS_NS),
        ("soap:mustUnderstand", "1"),
        ("soap:actor", SOAP11_ACTOR_NEXT),
    ];
    if let Some(mid) = &resp.ref_to_message_id {
        attrs.push(("refToMessageID", mid.as_str()));
    }
    w.empty_element("paos:Response", &attrs);
    w.into_string()
}

/// Serialize an ECP Request header block to XML.
pub fn ecp_request_header_xml(req: &EcpRequest) -> String {
    let is_passive = req.is_passive.to_string();
    let mut attrs: Vec<(&str, &str)> = vec![
        ("xmlns:ecp", ECP_NS),
        ("soap:mustUnderstand", "1"),
        ("soap:actor", SOAP11_ACTOR_NEXT),
        ("IsPassive", is_passive.as_str()),
    ];
    if let Some(pn) = &req.provider_name {
        attrs.push(("ProviderName", pn.as_str()));
    }

    let mut w = XmlWriter::with_capacity(256);
    if req.issuer.is_none() && req.idp_list.is_empty() {
        w.empty_element("ecp:Request", &attrs);
        return w.into_string();
    }
    w.start_element("ecp:Request", &attrs);
    if let Some(issuer) = &req.issuer {
        w.start_element(
            "saml:Issuer",
            &[("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")],
        );
        w.text(issuer);
        w.end_element("saml:Issuer");
    }
    if !req.idp_list.is_empty() {
        w.start_element(
            "samlp:IDPList",
            &[("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")],
        );
        for idp in &req.idp_list {
            w.empty_element("samlp:IDPEntry", &[("ProviderID", idp.as_str())]);
        }
        w.end_element("samlp:IDPList");
    }
    w.end_element("ecp:Request");
    w.into_string()
}

/// Serialize an ECP Response header block to XML.
pub fn ecp_response_header_xml(resp: &EcpResponse) -> String {
    let mut w = XmlWriter::new();
    w.empty_element(
        "ecp:Response",
        &[
            ("xmlns:ecp", ECP_NS),
            ("soap:mustUnderstand", "1"),
            ("soap:actor", SOAP11_ACTOR_NEXT),
            (
                "AssertionConsumerServiceURL",
                resp.assertion_consumer_service_url.as_str(),
            ),
        ],
    );
    w.into_string()
}

/// Serialize an ECP RelayState header block to XML.
pub fn ecp_relay_state_header_xml(rs: &EcpRelayState) -> String {
    let mut w = XmlWriter::new();
    w.start_element(
        "ecp:RelayState",
        &[
            ("xmlns:ecp", ECP_NS),
            ("soap:mustUnderstand", "1"),
            ("soap:actor", SOAP11_ACTOR_NEXT),
        ],
    );
    w.text(&rs.relay_state);
    w.end_element("ecp:RelayState");
    w.into_string()
}

/// Check if an HTTP request is a PAOS request (from an ECP).
///
/// Checks for the PAOS Accept header and PAOS version header.
pub fn is_paos_request(request: &impl crate::bindings::traits::HttpRequest) -> bool {
    let accept = request.header("Accept").unwrap_or("");
    let paos = request.header("PAOS").unwrap_or("");
    accept.contains(PAOS_CONTENT_TYPE) && paos.contains("urn:liberty:paos:2003-08")
}

/// Build a complete PAOS/ECP SOAP envelope for phase 1 (SP -> ECP).
///
/// The SP sends this to the ECP containing the AuthnRequest for the IdP.
/// Per Profiles 4.2.4.2 the envelope carries a `paos:Request` header
/// (responseConsumerURL) and an `ecp:Request` header.
pub fn build_ecp_phase1_envelope(
    authn_request_xml: &str,
    ecp_request: &EcpRequest,
    paos_request: &PaosRequest,
    relay_state: Option<&EcpRelayState>,
) -> Result<String, BindingError> {
    let mut headers = String::new();
    headers.push_str(&paos_request_header_xml(paos_request));
    headers.push_str(&ecp_request_header_xml(ecp_request));
    if let Some(rs) = relay_state {
        headers.push_str(&ecp_relay_state_header_xml(rs));
    }

    Ok(crate::bindings::soap::soap_envelope_wrap(
        authn_request_xml,
        Some(&headers),
    ))
}

/// Build a complete PAOS/ECP SOAP envelope for phase 2 (ECP -> SP).
///
/// The ECP sends this to the SP containing the SAML Response from the IdP.
pub fn build_ecp_phase2_envelope(
    saml_response_xml: &str,
    paos_response: &PaosResponse,
    relay_state: Option<&EcpRelayState>,
) -> Result<String, BindingError> {
    let mut headers = String::new();
    headers.push_str(&paos_response_header_xml(paos_response));
    if let Some(rs) = relay_state {
        headers.push_str(&ecp_relay_state_header_xml(rs));
    }

    Ok(crate::bindings::soap::soap_envelope_wrap(
        saml_response_xml,
        Some(&headers),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paos_request_header() {
        let req = PaosRequest {
            response_consumer_url: "https://sp.example.com/acs".to_string(),
            service: Some("My SP".to_string()),
            message_id: Some("_msg001".to_string()),
        };
        let xml = paos_request_header_xml(&req);
        assert!(xml.contains("paos:Request"));
        assert!(xml.contains("mustUnderstand=\"1\""));
        assert!(xml.contains("responseConsumerURL=\"https://sp.example.com/acs\""));
        assert!(xml.contains("service=\"My SP\""));
        assert!(xml.contains("messageID=\"_msg001\""));
    }

    #[test]
    fn test_ecp_response_header() {
        let resp = EcpResponse {
            assertion_consumer_service_url: "https://sp.example.com/acs".to_string(),
        };
        let xml = ecp_response_header_xml(&resp);
        assert!(xml.contains("ecp:Response"));
        assert!(xml.contains("AssertionConsumerServiceURL="));
    }

    #[test]
    fn test_ecp_relay_state_header() {
        let rs = EcpRelayState {
            relay_state: "token123".to_string(),
        };
        let xml = ecp_relay_state_header_xml(&rs);
        assert!(xml.contains("ecp:RelayState"));
        assert!(xml.contains("token123"));
    }

    #[test]
    fn test_ecp_phase1_envelope() {
        let authn_req = "<samlp:AuthnRequest/>";
        let ecp_req = EcpRequest {
            issuer: Some("https://sp.example.com".to_string()),
            provider_name: Some("Test SP".to_string()),
            is_passive: false,
            idp_list: vec!["https://idp.example.com".to_string()],
        };
        let paos_req = PaosRequest {
            response_consumer_url: "https://sp.example.com/acs".to_string(),
            service: Some(ECP_NS.to_string()),
            message_id: Some("_msg001".to_string()),
        };

        let env = build_ecp_phase1_envelope(authn_req, &ecp_req, &paos_req, None).unwrap();
        assert!(env.contains("soap:Envelope"));
        assert!(env.contains("soap:Header"));
        assert!(env.contains("ecp:Request"));
        assert!(env.contains("paos:Request"));
        assert!(env.contains("saml:Issuer"));
        assert!(env.contains("samlp:IDPEntry"));
        assert!(env.contains("responseConsumerURL=\"https://sp.example.com/acs\""));
        assert!(env.contains("AuthnRequest"));
    }

    #[test]
    fn test_ecp_request_header_empty_children_self_closes() {
        let req = EcpRequest {
            issuer: None,
            provider_name: None,
            is_passive: true,
            idp_list: vec![],
        };
        let xml = ecp_request_header_xml(&req);
        assert!(xml.ends_with("/>"));
        assert!(xml.contains("IsPassive=\"true\""));
    }

    #[test]
    fn test_xml_escape_in_headers() {
        let resp = EcpResponse {
            assertion_consumer_service_url: "https://sp.example.com/acs?a=1&b=2".to_string(),
        };
        let xml = ecp_response_header_xml(&resp);
        assert!(xml.contains("a=1&amp;b=2"));
    }

    #[test]
    fn test_ecp_phase2_envelope() {
        let saml_resp = "<samlp:Response/>";
        let paos_resp = PaosResponse {
            ref_to_message_id: Some("_msg001".to_string()),
        };
        let rs = EcpRelayState {
            relay_state: "abc".to_string(),
        };

        let env = build_ecp_phase2_envelope(saml_resp, &paos_resp, Some(&rs)).unwrap();
        assert!(env.contains("soap:Envelope"));
        assert!(env.contains("paos:Response"));
        assert!(env.contains("ecp:RelayState"));
        assert!(env.contains("abc"));
        assert!(env.contains("Response"));
    }
}
