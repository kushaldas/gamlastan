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
/// Returns `Ok(true)` if a ds:Object is found (meaning the signature should be
/// rejected), `Ok(false)` if the XML parsed cleanly and no ds:Object is present,
/// and `Err(_)` if the input could not be parsed.
///
/// This is a *fail-closed* hardening check: the previous version returned
/// `false` (i.e. "no forbidden Object, proceed") when the XML failed to parse,
/// so a parser differential that prevented this helper from inspecting the
/// document — while the real verifier still accepted it — would bypass E91. The
/// `Err` result forces callers to decide explicitly, and every caller in this
/// crate treats it as a rejection (CWE-693).
pub fn contains_ds_object(signature_xml: &str) -> Result<bool, uppsala::XmlError> {
    const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

    // Use the comment/PI-tolerant metadata parse. This helper runs inside
    // `verify_enveloped`, which also verifies federation metadata (MDQ), and
    // metadata legitimately carries comments. A strict parse here would fail
    // closed on comment-bearing-but-valid metadata. Nothing is weakened: this is
    // a structural scan for a `{XMLDSig}Object` element (comments cannot hide or
    // forge an element), CDATA/DTD are still rejected, and the comment-truncation
    // defense for protocol messages is enforced at the deserialize parse layer.
    let doc = crate::xml::parse_secure_metadata(signature_xml)?;

    let Some(root) = doc.document_element() else {
        return Ok(false);
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
            return Ok(true);
        }
    }

    Ok(false)
}

/// HMAC-family XML-DSig `SignatureMethod` URIs.
///
/// HMAC is a *symmetric* MAC: verifying it requires the same secret used to
/// produce it. In SAML the IdP authenticates with an asymmetric key, so a
/// legitimate response is never HMAC-signed. Accepting HMAC opens a key-
/// confusion class where an attacker who learns (or supplies) the shared secret
/// forges signatures. gamlastan already refuses attacker-supplied inline keys
/// (`trusted_keys_only`), but this list lets the verifier reject the HMAC
/// `SignatureMethod` outright as defence in depth.
pub const HMAC_SIGNATURE_ALGORITHMS: &[&str] = &[
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
    // Legacy MD5 HMAC, listed so it is caught as well.
    "http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
    // RIPEMD-160 HMAC — supported by the underlying DSig backend
    // (`bergshamra_crypto`), so it must be caught here too or it would slip
    // past this pre-filter.
    "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160",
];

/// Check whether a signature algorithm URI is an HMAC (symmetric) method.
///
/// This must stay a superset of the HMAC URIs the DSig backend
/// ([`bergshamra_crypto::sign::is_hmac_algorithm`]) can actually verify; the
/// backstop below catches any HMAC method the static list above has not been
/// updated for, so the two cannot silently drift.
pub fn is_hmac_algorithm(algorithm_uri: &str) -> bool {
    HMAC_SIGNATURE_ALGORITHMS.contains(&algorithm_uri)
        || bergshamra_crypto::sign::is_hmac_algorithm(algorithm_uri)
}

/// Scan signed XML for an HMAC `<ds:SignatureMethod>`.
///
/// Walks the parsed document and inspects every `{XMLDSig}SignatureMethod`
/// element's `Algorithm` attribute, independent of the XML Signature prefix
/// used. Returns `Ok(true)` if any HMAC method is present (meaning the document
/// should be rejected), `Ok(false)` if none is, and `Err(_)` if the input could
/// not be parsed — callers fail closed on `Err`, mirroring
/// [`contains_ds_object`].
pub fn contains_hmac_signature_method(signed_xml: &str) -> Result<bool, uppsala::XmlError> {
    const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

    // Comment/PI-tolerant metadata parse, for the same reason as
    // [`contains_ds_object`]: this runs inside `verify_enveloped`, which also
    // verifies comment-bearing federation metadata (MDQ). A strict parse would
    // fail closed on otherwise-valid metadata. The scan is purely structural
    // (a `{XMLDSig}SignatureMethod` element's `Algorithm` attribute), so
    // tolerating comments loses no security; CDATA/DTD remain rejected.
    let doc = crate::xml::parse_secure_metadata(signed_xml)?;

    let Some(root) = doc.document_element() else {
        return Ok(false);
    };

    for node in doc.descendants(root) {
        let Some(elem) = doc.element(node) else {
            continue;
        };

        // Match {XMLDSig}SignatureMethod by expanded name, then test its
        // Algorithm attribute against the HMAC list.
        if elem.name.local_name == "SignatureMethod"
            && elem.name.namespace_uri.as_deref() == Some(XMLDSIG_NS)
        {
            if let Some(alg) = elem.get_attribute("Algorithm") {
                if is_hmac_algorithm(alg) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
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
        assert_eq!(contains_ds_object(xml), Ok(true));
    }

    #[test]
    fn test_contains_ds_object_without_prefix() {
        let xml = r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo/>
            <SignatureValue>abc</SignatureValue>
            <Object>malicious content</Object>
        </Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(true));
    }

    #[test]
    fn test_no_ds_object() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo/>
            <ds:SignatureValue>abc</ds:SignatureValue>
            <ds:KeyInfo/>
        </ds:Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(false));
    }

    #[test]
    fn test_dsig_prefix_object() {
        let xml = r#"<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
            <dsig:Object>content</dsig:Object>
        </dsig:Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(true));
    }

    #[test]
    fn test_self_closing_object() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:Object />
        </ds:Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(true));
    }

    #[test]
    fn test_ignores_non_dsig_object() {
        let xml = r#"<Signature xmlns="urn:example:not-dsig">
            <Object>application content</Object>
        </Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(false));
    }

    #[test]
    fn test_dsig_object_with_unusual_prefix() {
        let xml = r#"<sig:Signature xmlns:sig="http://www.w3.org/2000/09/xmldsig#">
            <sig:Object>content</sig:Object>
        </sig:Signature>"#;
        assert_eq!(contains_ds_object(xml), Ok(true));
    }

    #[test]
    fn test_unparseable_xml_fails_closed() {
        // Finding #16 regression: malformed XML must return Err (forcing callers
        // to fail closed), not Ok(false) which would silently bypass E91.
        let xml = "<ds:Signature><ds:Object>unterminated";
        assert!(contains_ds_object(xml).is_err());
    }

    #[test]
    fn test_scans_tolerate_comments_in_metadata() {
        // PR #33 review: these helpers run inside `verify_enveloped`, which also
        // verifies federation metadata (MDQ). Metadata legitimately carries XML
        // comments, so a comment-bearing document must not fail closed in the
        // structural pre-scans — while the scans still detect the real content.
        let with_comment = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <!-- published by test federation -->
            <ds:SignedInfo>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            </ds:SignedInfo>
        </ds:Signature>"#;
        // Comment present but no ds:Object and no HMAC method: both scans must
        // parse cleanly and report "not present" rather than erroring.
        assert_eq!(contains_ds_object(with_comment), Ok(false));
        assert_eq!(contains_hmac_signature_method(with_comment), Ok(false));

        // Detection still works with a comment in the document.
        let obj = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <!-- c --><ds:Object>x</ds:Object>
        </ds:Signature>"#;
        assert_eq!(contains_ds_object(obj), Ok(true));

        let hmac = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <!-- c --><ds:SignedInfo>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
            </ds:SignedInfo>
        </ds:Signature>"#;
        assert_eq!(contains_hmac_signature_method(hmac), Ok(true));
    }

    #[test]
    fn test_scans_still_reject_cdata() {
        // Tolerating comments must not reopen the CDATA truncation vector: the
        // metadata parse still rejects CDATA, so these scans fail closed on it.
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><![CDATA[x]]></ds:Signature>"#;
        assert!(contains_ds_object(xml).is_err());
        assert!(contains_hmac_signature_method(xml).is_err());
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

    #[test]
    fn test_hmac_algorithms_cover_every_backend_hmac() {
        // The static list plus the backend backstop must flag every HMAC URI the
        // DSig backend can actually verify — including RIPEMD-160, which the
        // static list historically omitted.
        for uri in [
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
            "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160",
        ] {
            assert!(is_hmac_algorithm(uri), "{uri} must be flagged as HMAC");
            assert!(
                bergshamra_crypto::sign::is_hmac_algorithm(uri),
                "{uri} should also be an HMAC per the backend"
            );
        }
        assert!(!is_hmac_algorithm(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        ));
    }

    #[test]
    fn test_contains_hmac_ripemd160_signature_method() {
        // A document declaring the RIPEMD-160 HMAC method must be caught by the
        // pre-filter (regression for the URI the static list had omitted).
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160"/>
            </ds:SignedInfo>
        </ds:Signature>"#;
        assert_eq!(contains_hmac_signature_method(xml), Ok(true));
    }
}
