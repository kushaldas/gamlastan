// SAML 2.0 Signature validation rules
//
// Per Errata:
// - E91: Reject signatures containing ds:Object elements.
// - E81: Any signature algorithm is supported (not just RSA-SHA1).
//
// This module provides functions to validate signature properties
// before/after cryptographic verification.

/// Check whether XML contains an XMLDSig `Object` element (E91).
///
/// Per E91, SAML signatures MUST NOT contain ds:Object elements. This is a
/// security requirement to prevent signature wrapping attacks.
///
/// The `signature_xml` parameter may be either the raw XML of a
/// `<ds:Signature>` element or a complete signed XML document. The check walks
/// the parsed XML tree and compares expanded names, so it is independent of the
/// XML Signature prefix used by the input.
///
/// Returns `true` if a ds:Object is found (meaning the signature should be rejected).
pub fn contains_ds_object(signature_xml: &str) -> bool {
    const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

    let Ok(doc) = uppsala::parse(signature_xml) else {
        // The caller's XML verifier will report malformed XML later. This
        // helper only answers "is there a real XMLDSig Object element?" and
        // avoids guessing from text when the fragment is not parseable XML.
        return false;
    };

    let Some(root) = doc.document_element() else {
        return false;
    };

    for node in doc.descendants(root) {
        let Some(elem) = doc.element(node) else {
            continue;
        };

        // E91 is namespace based: any element whose expanded name is
        // {XMLDSig}Object is forbidden, independent of prefix choice.
        if elem.name.local_name == "Object"
            && elem.name.namespace_uri.as_deref() == Some(XMLDSIG_NS)
        {
            return true;
        }
    }

    false
}

/// Known signature algorithm URIs.
///
/// Per E81: any algorithm supported by the implementation may be used.
/// This list includes algorithms from XMLDSig, XMLDSig 1.1, and common extensions.
pub const KNOWN_SIGNATURE_ALGORITHMS: &[&str] = &[
    // RSA
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    // RSA-PSS
    "http://www.w3.org/2007/05/xmldsig-more#rsa-pss",
    // ECDSA
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    // DSA
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2009/xmldsig11#dsa-sha256",
    // HMAC
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
];

/// Check if a signature algorithm URI is recognized.
///
/// Per E81, any algorithm the implementation supports may be used.
/// Returns `true` if the algorithm is in the known list.
/// Note: this is informational only - bergshamra handles actual algorithm support.
pub fn is_known_algorithm(algorithm_uri: &str) -> bool {
    KNOWN_SIGNATURE_ALGORITHMS.contains(&algorithm_uri)
}

/// CBC-mode encryption algorithm URIs (E93).
///
/// Per E93: CBC modes require separate integrity protection.
/// Prefer GCM modes which provide built-in integrity.
pub const CBC_ENCRYPTION_ALGORITHMS: &[&str] = &[
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
];

/// GCM-mode encryption algorithm URIs (preferred per E93).
pub const GCM_ENCRYPTION_ALGORITHMS: &[&str] = &[
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#aes192-gcm",
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
];

/// Check if an encryption algorithm uses CBC mode (E93).
///
/// Returns `true` if the algorithm is a CBC-mode algorithm that requires
/// separate integrity protection.
pub fn is_cbc_algorithm(algorithm_uri: &str) -> bool {
    CBC_ENCRYPTION_ALGORITHMS.contains(&algorithm_uri)
}

/// Check if an encryption algorithm uses GCM mode (preferred per E93).
///
/// Returns `true` if the algorithm provides built-in integrity protection.
pub fn is_gcm_algorithm(algorithm_uri: &str) -> bool {
    GCM_ENCRYPTION_ALGORITHMS.contains(&algorithm_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_ds_object_with_prefix() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo/>
            <ds:SignatureValue>abc</ds:SignatureValue>
            <ds:Object>malicious content</ds:Object>
        </ds:Signature>"#;
        assert!(contains_ds_object(xml));
    }

    #[test]
    fn test_contains_ds_object_without_prefix() {
        let xml = r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo/>
            <SignatureValue>abc</SignatureValue>
            <Object>malicious content</Object>
        </Signature>"#;
        assert!(contains_ds_object(xml));
    }

    #[test]
    fn test_no_ds_object() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo/>
            <ds:SignatureValue>abc</ds:SignatureValue>
            <ds:KeyInfo/>
        </ds:Signature>"#;
        assert!(!contains_ds_object(xml));
    }

    #[test]
    fn test_dsig_prefix_object() {
        let xml = r#"<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
            <dsig:Object>content</dsig:Object>
        </dsig:Signature>"#;
        assert!(contains_ds_object(xml));
    }

    #[test]
    fn test_self_closing_object() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:Object />
        </ds:Signature>"#;
        assert!(contains_ds_object(xml));
    }

    #[test]
    fn test_ignores_non_dsig_object() {
        let xml = r#"<Signature xmlns="urn:example:not-dsig">
            <Object>application content</Object>
        </Signature>"#;
        assert!(!contains_ds_object(xml));
    }

    #[test]
    fn test_dsig_object_with_unusual_prefix() {
        let xml = r#"<sig:Signature xmlns:sig="http://www.w3.org/2000/09/xmldsig#">
            <sig:Object>content</sig:Object>
        </sig:Signature>"#;
        assert!(contains_ds_object(xml));
    }

    #[test]
    fn test_known_algorithms() {
        assert!(is_known_algorithm(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        ));
        assert!(is_known_algorithm(
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        ));
        assert!(is_known_algorithm(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        ));
        assert!(!is_known_algorithm("http://example.com/unknown-algorithm"));
    }

    #[test]
    fn test_cbc_algorithms() {
        assert!(is_cbc_algorithm(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        ));
        assert!(is_cbc_algorithm(
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        ));
        assert!(is_cbc_algorithm(
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
        ));
        assert!(!is_cbc_algorithm(
            "http://www.w3.org/2009/xmlenc11#aes128-gcm"
        ));
    }

    #[test]
    fn test_gcm_algorithms() {
        assert!(is_gcm_algorithm(
            "http://www.w3.org/2009/xmlenc11#aes128-gcm"
        ));
        assert!(is_gcm_algorithm(
            "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        ));
        assert!(!is_gcm_algorithm(
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        ));
    }
}
