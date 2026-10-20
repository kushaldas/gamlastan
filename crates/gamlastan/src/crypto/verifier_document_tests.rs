//! Compare document reuse against the former string-based verification path.

use super::*;
use crate::crypto::{keys::loader, SamlSigner};
use crate::profiles::sso::idp::sign_response_xml;

const CERT: &str = include_str!("../../tests/fixtures/enc-cert.pem");
const KEY: &str = include_str!("../../tests/fixtures/enc-key.pem");
const UNSIGNED: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.test</saml:Issuer><saml:Subject><saml:NameID>test-user</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;

fn signer() -> SamlSigner {
    let mut key = loader::load_pem_auto(KEY.as_bytes(), None).unwrap();
    key.usage = KeyUsage::Sign;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    SamlSigner::new(keys)
}

fn verifier() -> SamlVerifier {
    let mut key = loader::load_pem_auto(CERT.as_bytes(), None).unwrap();
    key.usage = KeyUsage::Verify;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    let mut verifier = SamlVerifier::new(keys);
    verifier.set_skip_time_checks(true);
    verifier
}

fn signed(assertion: bool, response: bool) -> String {
    let cert: String = CERT
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    sign_response_xml(
        UNSIGNED,
        &signer(),
        &cert,
        "_response",
        Some("_assertion"),
        assertion,
        response,
    )
    .unwrap()
}

/// Retain the old parse/guard/backend sequence as a differential oracle. Compare
/// errors as well as validity, reference NodeIds, digest flags and key metadata.
fn legacy(
    verifier: &SamlVerifier,
    xml: &str,
    selection: SignatureSelection,
) -> Result<Vec<VerifyResult>, CryptoError> {
    if verifier.reject_ds_object {
        match crate::security::signature::contains_ds_object(xml) {
            Ok(true) => return Err(CryptoError::SignatureContainsDsObject),
            Ok(false) => {}
            Err(error) => {
                return Err(CryptoError::VerificationFailed(format!(
                    "could not parse XML for E91 ds:Object check: {error}"
                )));
            }
        }
    }
    if !verifier.algorithm_policy.is_permissive() || verifier.reject_hmac_signatures {
        let doc = crate::xml::parse_secure_metadata(xml).map_err(|error| {
            CryptoError::VerificationFailed(format!(
                "could not parse XML for algorithm policy check: {error}"
            ))
        })?;
        validate_enveloped_algorithm_policy(
            &doc,
            &verifier.algorithm_policy,
            verifier.reject_hmac_signatures,
            selection,
        )?;
    }
    let ctx = verifier.dsig_context();
    Ok(match selection {
        SignatureSelection::First => vec![bergshamra_dsig::verify::verify(&ctx, xml)?],
        SignatureSelection::All => bergshamra_dsig::verify::verify_all(&ctx, xml)?,
    })
}

fn assert_equivalent(verifier: &SamlVerifier, xml: &str) {
    for selection in [SignatureSelection::First, SignatureSelection::All] {
        let old = legacy(verifier, xml, selection);
        let new = match selection {
            SignatureSelection::First => verifier.verify_enveloped(xml).map(|result| vec![result]),
            SignatureSelection::All => verifier.verify_all_enveloped(xml),
        };
        assert_eq!(format!("{old:?}"), format!("{new:?}"));
    }
}

#[test]
fn signed_documents_and_guard_configurations_match_legacy() {
    for (assertion, response) in [(true, false), (false, true), (true, true)] {
        let xml = signed(assertion, response);
        let mut verifier = verifier();
        let results = verifier.verify_all_enveloped(&xml).unwrap();
        assert_eq!(
            results.len(),
            usize::from(assertion) + usize::from(response)
        );
        assert!(results
            .iter()
            .all(VerifyResult::all_reference_digests_verified));

        let cases = [
            xml.clone(),
            // Namespace identity, not the spelling of the signature prefix.
            xml.replace("ds:", "sig:").replace("xmlns:ds", "xmlns:sig"),
            xml.replace("test-user", "tampered-user"),
            xml.replace(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            ),
            xml.replace(
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
            ),
            xml.replace(
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2000/09/xmldsig#sha1",
            ),
            xml.replace("ID=\"_assertion\"", "ID=\"_response\""),
            xml.replace(
                "</samlp:Response>",
                "<extra ID=\"_assertion\"/></samlp:Response>",
            ),
            xml.replace("</ds:Signature>", "<ds:Object/></ds:Signature>"),
            xml.replace("test-user", "test<!--split-->-user"),
            xml.replace("test-user", "test<?split value?>-user"),
            xml.replace("test-user", "<![CDATA[test-user]]>"),
            format!("<!DOCTYPE samlp:Response>{xml}"),
            xml[..xml.len() / 2].to_string(),
            UNSIGNED.to_string(),
        ];
        for reject_object in [false, true] {
            for permissive in [false, true] {
                for reject_hmac in [false, true] {
                    verifier.reject_ds_object = reject_object;
                    verifier.algorithm_policy = if permissive {
                        AlgorithmPolicy::permissive()
                    } else {
                        AlgorithmPolicy::default()
                    };
                    verifier.reject_hmac_signatures = reject_hmac;
                    for case in &cases {
                        assert_equivalent(&verifier, case);
                    }
                }
            }
        }
    }
}

#[test]
fn structural_comments_and_pis_remain_accepted_but_protocol_parse_is_strict() {
    let xml = signed(true, false);
    // Outside the signed assertion: comments/PIs must not alter its digest.
    let xml = xml.replace(
        "<saml:Assertion ",
        "<!--metadata--><?note value?><saml:Assertion ",
    );
    let verifier = verifier();
    assert!(verifier.verify_enveloped(&xml).unwrap().is_valid());
    assert!(crate::xml::parse_secure(&xml).is_err());
    assert!(crate::xml::parse_secure_metadata(&xml).is_ok());
    assert_equivalent(&verifier, &xml);
}

#[test]
fn malformed_sibling_does_not_hide_valid_signature() {
    let xml = signed(true, true);
    // Damage only the first SignatureValue. SignedInfo and algorithm policy are
    // still well-formed; the backend must retain a result for each signature.
    let start = xml.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
    let end = start + xml[start..].find("</ds:SignatureValue>").unwrap();
    let xml = format!("{}!{}", &xml[..start], &xml[end..]);
    let verifier = verifier();
    let results = verifier.verify_all_enveloped(&xml).unwrap();
    assert_eq!(results.len(), 2);
    assert!(!results[0].is_valid());
    assert!(results[1].all_reference_digests_verified());
    assert_equivalent(&verifier, &xml);
}

#[test]
fn generic_xpath_transform_keeps_original_source_and_rejects_tampering() {
    let xml = signed(false, true);
    // XPath signature exclusion before C14N forces the generic transform
    // pipeline (the preceding enveloped transform already excludes this sig).
    let mut xml = xml.replace(
        r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    assert!(xml.contains("<ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath>"));
    // The signing API fills empty template values; it does not overwrite an
    // already-populated signature after its SignedInfo has been changed.
    for name in ["DigestValue", "SignatureValue"] {
        let open = format!("<ds:{name}>");
        let close = format!("</ds:{name}>");
        let start = xml.find(&open).unwrap() + open.len();
        let end = start + xml[start..].find(&close).unwrap();
        xml.replace_range(start..end, "");
    }
    let xml = signer().sign_enveloped(&xml).unwrap();
    let verifier = verifier();
    assert!(verifier
        .verify_enveloped(&xml)
        .unwrap()
        .all_reference_digests_verified());
    assert_equivalent(&verifier, &xml);
    let tampered = xml.replace("test-user", "tampered-user");
    assert!(!verifier.verify_enveloped(&tampered).unwrap().is_valid());
    assert_equivalent(&verifier, &tampered);
}
