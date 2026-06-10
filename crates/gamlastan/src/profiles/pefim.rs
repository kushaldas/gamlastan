// PEFIM SPCertEnc extension (Privacy-Enhanced Federated Identity Management)
//
// Interoperable with pysaml2's `saml2.extension.pefim` module: the SP places
// a per-request encryption certificate in the AuthnRequest's Extensions
// (`pefim:SPCertEnc` containing `ds:KeyInfo/ds:X509Data/ds:X509Certificate`),
// and the IdP encrypts the assertion toward that certificate instead of the
// metadata encryption key.
//
// SP side: build the extension with [`sp_cert_enc_extensions_xml`] and set it
// as `AuthnRequestOptions::extensions`.
// IdP side: read `ProcessedAuthnRequest::extensions` and extract the
// certificate(s) with [`extract_encryption_certs`] /
// [`first_encryption_cert_der`], then pass the certificate to the encryption
// layer.

use crate::profiles::error::ProfileError;

/// PEFIM assertion namespace (`pefim:SPCertEnc`).
pub const PEFIM_NS: &str = "urn:net:eustix:names:tc:PEFIM:0.0:assertion";

const SAMLP_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Build a namespace self-contained `samlp:Extensions` element carrying one
/// `pefim:SPCertEnc` per certificate.
///
/// `certs_b64` are base64-encoded DER certificates (PEM body without the
/// BEGIN/END lines); whitespace is removed. `verify_depth` maps to the
/// SPCertEnc `VerifyDepth` attribute (chain verification depth hint).
///
/// The returned XML is intended for
/// [`AuthnRequestOptions::extensions`](crate::profiles::sso::web_browser::AuthnRequestOptions).
pub fn sp_cert_enc_extensions_xml(certs_b64: &[&str], verify_depth: Option<u8>) -> String {
    let mut xml = String::with_capacity(256);
    xml.push_str(&format!(r#"<samlp:Extensions xmlns:samlp="{SAMLP_NS}">"#));
    for cert in certs_b64 {
        let normalized: String = cert.chars().filter(|c| !c.is_whitespace()).collect();
        xml.push_str(&format!(r#"<pefim:SPCertEnc xmlns:pefim="{PEFIM_NS}""#));
        if let Some(depth) = verify_depth {
            xml.push_str(&format!(r#" VerifyDepth="{depth}""#));
        }
        xml.push('>');
        xml.push_str(&format!(
            r#"<ds:KeyInfo xmlns:ds="{DSIG_NS}"><ds:X509Data><ds:X509Certificate>{normalized}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#
        ));
        xml.push_str("</pefim:SPCertEnc>");
    }
    xml.push_str("</samlp:Extensions>");
    xml
}

/// Extract base64 DER certificates from `pefim:SPCertEnc` elements in raw
/// `samlp:Extensions` XML (as carried on
/// [`AuthnRequest::extensions`](crate::core::protocol::request::AuthnRequest)).
///
/// The fragment is parsed with the conventional `samlp`/`pefim`/`ds` prefixes
/// pre-declared, so extensions relying on prefixes declared on an ancestor
/// element still parse. Returns an empty list when no SPCertEnc is present.
pub fn extract_encryption_certs(extensions_xml: &str) -> Result<Vec<String>, ProfileError> {
    if extensions_xml.trim().is_empty() {
        return Ok(vec![]);
    }

    let wrapped = format!(
        r#"<w xmlns:samlp="{SAMLP_NS}" xmlns:pefim="{PEFIM_NS}" xmlns:ds="{DSIG_NS}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{extensions_xml}</w>"#
    );
    let doc = uppsala::parse(&wrapped)
        .map_err(|e| ProfileError::Other(format!("cannot parse Extensions XML: {e}")))?;
    let root = doc
        .document_element()
        .ok_or_else(|| ProfileError::Other("empty Extensions XML".to_string()))?;

    let mut certs = Vec::new();
    collect_sp_cert_enc(&doc, root, &mut certs);
    Ok(certs)
}

/// Extract the first SPCertEnc certificate, decoded to DER bytes.
///
/// Convenience for the IdP encryption path. Returns `Ok(None)` when the
/// request carries no SPCertEnc.
pub fn first_encryption_cert_der(extensions_xml: &str) -> Result<Option<Vec<u8>>, ProfileError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    match extract_encryption_certs(extensions_xml)?.into_iter().next() {
        None => Ok(None),
        Some(cert_b64) => STANDARD
            .decode(&cert_b64)
            .map(Some)
            .map_err(|e| ProfileError::Other(format!("invalid SPCertEnc base64: {e}"))),
    }
}

fn collect_sp_cert_enc(doc: &uppsala::Document<'_>, node: uppsala::NodeId, out: &mut Vec<String>) {
    for child in doc.children_iter(node) {
        if let Some(elem) = doc.element(child) {
            if elem.matches_name_ns(PEFIM_NS, "SPCertEnc") {
                collect_certificates(doc, child, out);
            } else {
                collect_sp_cert_enc(doc, child, out);
            }
        }
    }
}

fn collect_certificates(doc: &uppsala::Document<'_>, node: uppsala::NodeId, out: &mut Vec<String>) {
    for child in doc.children_iter(node) {
        if let Some(elem) = doc.element(child) {
            if elem.matches_name_ns(DSIG_NS, "X509Certificate") {
                let text = doc.text_content_deep(child);
                let normalized: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                if !normalized.is_empty() {
                    out.push(normalized);
                }
            } else {
                collect_certificates(doc, child, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::sso::sp::create_authn_request;
    use crate::profiles::sso::web_browser::AuthnRequestOptions;
    use crate::xml::serialize::SamlSerialize;

    const CERT_B64: &str = "MIIBfakecertbase64dataAAAA";

    #[test]
    fn test_build_and_extract_roundtrip() {
        let xml = sp_cert_enc_extensions_xml(&[CERT_B64], Some(1));
        assert!(xml.contains("pefim:SPCertEnc"));
        assert!(xml.contains("VerifyDepth=\"1\""));

        let certs = extract_encryption_certs(&xml).unwrap();
        assert_eq!(certs, vec![CERT_B64.to_string()]);
    }

    #[test]
    fn test_build_strips_whitespace() {
        let pem_body = "MIIBfake\ncertbase64\n dataAAAA";
        let xml = sp_cert_enc_extensions_xml(&[pem_body], None);
        let certs = extract_encryption_certs(&xml).unwrap();
        assert_eq!(certs, vec!["MIIBfakecertbase64dataAAAA".to_string()]);
    }

    #[test]
    fn test_extract_empty() {
        assert!(extract_encryption_certs("").unwrap().is_empty());
        assert!(extract_encryption_certs(
            "<samlp:Extensions xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>"
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn test_extract_undeclared_prefixes() {
        // Prefixes declared on an ancestor in the original document
        let fragment = r#"<samlp:Extensions><pefim:SPCertEnc><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></pefim:SPCertEnc></samlp:Extensions>"#;
        let certs = extract_encryption_certs(fragment).unwrap();
        assert_eq!(certs, vec!["AAAA".to_string()]);
    }

    #[test]
    fn test_first_encryption_cert_der() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let der: &[u8] = b"fake-der-bytes";
        let b64 = STANDARD.encode(der);
        let xml = sp_cert_enc_extensions_xml(&[&b64], None);
        let extracted = first_encryption_cert_der(&xml).unwrap().unwrap();
        assert_eq!(extracted, der);

        assert!(first_encryption_cert_der("").unwrap().is_none());
    }

    #[test]
    fn test_through_authn_request_serialization() {
        // SP: embed SPCertEnc in an AuthnRequest, serialize, re-parse at the
        // IdP, and recover the certificate from ProcessedAuthnRequest.
        let options = AuthnRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: Some("https://sp.example.com/acs".to_string()),
            extensions: Some(sp_cert_enc_extensions_xml(&[CERT_B64], None)),
            ..Default::default()
        };
        let request = create_authn_request(&options).unwrap();
        let xml = request.to_xml_string().unwrap();
        assert!(xml.contains("SPCertEnc"));

        // Re-parse the serialized request
        let doc = uppsala::parse(&xml).unwrap();
        let root = doc.document_element().unwrap();
        use crate::core::protocol::request::AuthnRequestRef;
        use crate::xml::deserialize::SamlDeserialize;
        let parsed = AuthnRequestRef::from_xml(&doc, root).unwrap().to_owned();

        let processed = crate::profiles::sso::idp::process_authn_request(&parsed, None).unwrap();
        let extensions = processed.extensions.expect("extensions present");
        let certs = extract_encryption_certs(&extensions).unwrap();
        assert_eq!(certs, vec![CERT_B64.to_string()]);
    }
}
