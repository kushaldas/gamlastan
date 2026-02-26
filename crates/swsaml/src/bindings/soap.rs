// SOAP 1.1 Binding for SAML 2.0 (SAML Bindings Section 3.2).
//
// - SOAP 1.1 envelope wrapping/unwrapping
// - Single SAML element per SOAP Body, no additional elements
// - SOAPAction header: http://www.oasis-open.org/committees/security
//   (responder MUST NOT depend on value)
// - Content-Type: text/xml
// - Error handling: HTTP 403 (refuse), HTTP 500 (SOAP fault), HTTP 200 (SAML errors)

use crate::bindings::error::BindingError;
use crate::bindings::traits::HttpRequest;

/// SOAP 1.1 envelope namespace.
pub const SOAP11_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// SOAP 1.1 actor for header blocks.
pub const SOAP11_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";

/// Wrap a SAML message in a SOAP 1.1 envelope.
///
/// Produces a SOAP envelope with the given SAML XML as the sole Body child.
/// Optional SOAP header blocks can be included (e.g., for PAOS).
pub fn soap_envelope_wrap(saml_xml: &str, header_blocks: Option<&str>) -> String {
    let mut env = String::with_capacity(256 + saml_xml.len());
    env.push_str(r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">"#);

    if let Some(headers) = header_blocks {
        env.push_str("<soap:Header>");
        env.push_str(headers);
        env.push_str("</soap:Header>");
    }

    env.push_str("<soap:Body>");
    env.push_str(saml_xml);
    env.push_str("</soap:Body>");
    env.push_str("</soap:Envelope>");
    env
}

/// Extract the SAML element from a SOAP 1.1 envelope body.
///
/// Returns the raw XML content of the `<soap:Body>` element.
/// Uses the uppsala XML parser for reliable extraction.
pub fn soap_envelope_unwrap(soap_xml: &[u8]) -> Result<SoapUnwrapped, BindingError> {
    let xml_str = std::str::from_utf8(soap_xml)
        .map_err(|e| BindingError::InvalidSoapEnvelope(format!("not valid UTF-8: {}", e)))?;

    let doc = uppsala::parse(xml_str)
        .map_err(|e| BindingError::InvalidSoapEnvelope(format!("XML parse error: {}", e)))?;

    let root = doc
        .document_element()
        .ok_or_else(|| BindingError::InvalidSoapEnvelope("no root element".to_string()))?;

    let root_elem = doc
        .element(root)
        .ok_or_else(|| BindingError::InvalidSoapEnvelope("invalid root element".to_string()))?;

    // Verify this is a SOAP Envelope
    if root_elem.name.local_name != "Envelope" {
        return Err(BindingError::InvalidSoapEnvelope(format!(
            "expected Envelope, got {}",
            root_elem.name.local_name
        )));
    }

    // Find Body element
    let mut body_content = None;
    let mut header_content = None;

    for child in doc.children_iter(root) {
        if let Some(elem) = doc.element(child) {
            match elem.name.local_name.as_ref() {
                "Header" => {
                    // Extract header blocks as raw XML
                    let header_children: Vec<_> = doc.children_iter(child).collect();
                    if !header_children.is_empty() {
                        let mut headers = String::new();
                        for hc in &header_children {
                            headers.push_str(&doc.node_to_xml(*hc));
                        }
                        header_content = Some(headers);
                    }
                }
                "Body" => {
                    // Extract the first child element of Body, checking for Fault first
                    for bc in doc.children_iter(child) {
                        if let Some(bc_elem) = doc.element(bc) {
                            // Check for SOAP Fault before treating as body content
                            if bc_elem.name.local_name == "Fault" {
                                return parse_soap_fault(&doc, bc);
                            }
                            if body_content.is_none() {
                                body_content = Some(doc.node_to_xml(bc));
                            }
                        }
                    }
                }
                "Fault" => {
                    // SOAP Fault at top level (shouldn't happen but handle)
                    return parse_soap_fault(&doc, child);
                }
                _ => {}
            }
        }
    }

    let body_xml = body_content.ok_or_else(|| {
        BindingError::InvalidSoapEnvelope("no SAML element in SOAP Body".to_string())
    })?;

    Ok(SoapUnwrapped {
        body_xml,
        header_xml: header_content,
    })
}

/// Result of unwrapping a SOAP envelope.
#[derive(Debug)]
pub struct SoapUnwrapped {
    /// The SAML XML element from the SOAP Body.
    pub body_xml: String,
    /// Optional SOAP header blocks XML.
    pub header_xml: Option<String>,
}

/// Create a SOAP 1.1 Fault envelope.
pub fn soap_fault(faultcode: &str, faultstring: &str, detail: Option<&str>) -> String {
    let mut env = String::with_capacity(256);
    env.push_str(r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">"#);
    env.push_str("<soap:Body>");
    env.push_str("<soap:Fault>");
    env.push_str("<faultcode>");
    env.push_str(faultcode);
    env.push_str("</faultcode>");
    env.push_str("<faultstring>");
    env.push_str(faultstring);
    env.push_str("</faultstring>");
    if let Some(d) = detail {
        env.push_str("<detail>");
        env.push_str(d);
        env.push_str("</detail>");
    }
    env.push_str("</soap:Fault>");
    env.push_str("</soap:Body>");
    env.push_str("</soap:Envelope>");
    env
}

/// Decode a SAML message from a SOAP request.
///
/// Expects Content-Type: text/xml and a SOAP envelope body.
pub fn soap_decode(request: &impl HttpRequest) -> Result<SoapUnwrapped, BindingError> {
    let body = request.body();
    if body.is_empty() {
        return Err(BindingError::InvalidSoapEnvelope(
            "empty request body".to_string(),
        ));
    }
    soap_envelope_unwrap(body)
}

fn parse_soap_fault(
    doc: &uppsala::Document<'_>,
    fault_node: uppsala::NodeId,
) -> Result<SoapUnwrapped, BindingError> {
    let mut faultcode = String::new();
    let mut faultstring = String::new();
    let mut detail = None;

    for child in doc.children_iter(fault_node) {
        if let Some(elem) = doc.element(child) {
            match elem.name.local_name.as_ref() {
                "faultcode" => {
                    faultcode = doc.text_content_deep(child);
                }
                "faultstring" => {
                    faultstring = doc.text_content_deep(child);
                }
                "detail" => {
                    detail = Some(doc.text_content_deep(child));
                }
                _ => {}
            }
        }
    }

    Err(BindingError::SoapFault {
        faultcode,
        faultstring,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soap_wrap_unwrap_roundtrip() {
        let saml_xml = r#"<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_abc" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"><samlp:Artifact>AAQ=</samlp:Artifact></samlp:ArtifactResolve>"#;

        let envelope = soap_envelope_wrap(saml_xml, None);
        assert!(envelope.contains("soap:Envelope"));
        assert!(envelope.contains("soap:Body"));
        assert!(envelope.contains("ArtifactResolve"));

        let unwrapped = soap_envelope_unwrap(envelope.as_bytes()).unwrap();
        // The unwrapped body should contain the SAML element
        assert!(unwrapped.body_xml.contains("ArtifactResolve"));
        assert!(unwrapped.header_xml.is_none());
    }

    #[test]
    fn test_soap_wrap_with_headers() {
        let saml_xml = "<samlp:Response/>";
        let headers = r#"<ecp:Request xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" soap:mustUnderstand="1" soap:actor="http://schemas.xmlsoap.org/soap/actor/next"/>"#;

        let envelope = soap_envelope_wrap(saml_xml, Some(headers));
        assert!(envelope.contains("soap:Header"));
        assert!(envelope.contains("ecp:Request"));
    }

    #[test]
    fn test_soap_fault_generation() {
        let fault = soap_fault(
            "soap:Client",
            "Invalid request",
            Some("Missing ID attribute"),
        );
        assert!(fault.contains("soap:Fault"));
        assert!(fault.contains("soap:Client"));
        assert!(fault.contains("Invalid request"));
        assert!(fault.contains("Missing ID attribute"));
    }

    #[test]
    fn test_soap_fault_no_detail() {
        let fault = soap_fault("soap:Server", "Internal error", None);
        assert!(!fault.contains("<detail>"));
    }

    #[test]
    fn test_soap_unwrap_fault() {
        let fault_envelope = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Client</faultcode><faultstring>Bad request</faultstring></soap:Fault></soap:Body></soap:Envelope>"#;

        let result = soap_envelope_unwrap(fault_envelope.as_bytes());
        assert!(matches!(result, Err(BindingError::SoapFault { .. })));
    }

    #[test]
    fn test_soap_unwrap_invalid_xml() {
        let result = soap_envelope_unwrap(b"not xml at all");
        assert!(matches!(result, Err(BindingError::InvalidSoapEnvelope(_))));
    }

    #[test]
    fn test_soap_unwrap_not_envelope() {
        let result = soap_envelope_unwrap(b"<NotEnvelope/>");
        assert!(matches!(result, Err(BindingError::InvalidSoapEnvelope(_))));
    }
}
