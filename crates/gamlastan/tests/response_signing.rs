//! End-to-end tests for the IdP response/assertion signing helpers.
//!
//! Proves that `create_signed_response` / `sign_response_xml` splice the
//! `<ds:Signature>` template at the schema-correct position (after the element's
//! `<saml:Issuer>`) and that the resulting enveloped signature validates against
//! the signing certificate - for assertion-only and for assertion+response.

use base64::Engine;
use chrono::Utc;

use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::constants;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use gamlastan::profiles::sso::idp::create_signed_response;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};

const CERT_PEM: &str = include_str!("fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("fixtures/enc-key.pem");

/// base64 body (as it appears inside `<ds:X509Certificate>`) and decoded DER.
fn cert_b64_and_der() -> (String, Vec<u8>) {
    let b64: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("certificate body is valid base64");
    (b64, der)
}

/// A signer backed by the fixture RSA private key.
fn signer() -> SamlSigner {
    let mut key = loader::load_pem_auto(KEY_PEM.as_bytes(), None).expect("load private key");
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    SamlSigner::new(km)
}

/// A verifier that trusts the fixture certificate.
fn verifier(cert_der: Vec<u8>) -> SamlVerifier {
    let mut vkey = loader::load_pem_auto(CERT_PEM.as_bytes(), None).expect("load cert as key");
    vkey.usage = KeyUsage::Verify;
    let mut km = KeysManager::new();
    km.add_key(vkey);
    km.add_trusted_cert(cert_der);
    let mut v = SamlVerifier::new(km);
    // Fixtures are static; the assertion timestamps are "now" but skip anyway so
    // the test is about the signature, not clock skew.
    v.set_skip_time_checks(true);
    v
}

fn sample_options() -> ResponseOptions {
    ResponseOptions {
        idp_entity_id: "https://idp.example.com".to_string(),
        in_response_to: Some("_req123".to_string()),
        sp_entity_id: "https://sp.example.com".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        assertion_lifetime_seconds: 300,
        session_index: Some("_sess1".to_string()),
        session_not_on_or_after: None,
        authn_context_class_ref: Some(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_string(),
        ),
        client_address: None,
        attributes: vec![],
    }
}

fn sample_name_id() -> NameId {
    NameId {
        value: "user@example.com".to_string(),
        format: Some(constants::NAMEID_EMAIL.to_string()),
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    }
}

#[test]
fn signs_assertion_and_verifies() {
    let (cert_b64, cert_der) = cert_b64_and_der();
    let signed = create_signed_response(
        &sample_options(),
        &sample_name_id(),
        ResponseTimes::at(Utc::now()),
        &signer(),
        &cert_b64,
        true,  // sign assertion
        false, // do not sign response
    )
    .expect("create_signed_response");

    // The placeholders were filled in.
    assert!(signed.contains("<ds:SignatureValue>") && !signed.contains("<ds:SignatureValue/>"));
    // Schema-correct placement: the signature sits after the assertion's Issuer.
    let assertion_at = signed.find("<saml:Assertion").expect("assertion present");
    let sig_at = signed[assertion_at..]
        .find("<ds:Signature")
        .map(|p| assertion_at + p)
        .expect("assertion signature present");
    let issuer_end = signed[assertion_at..]
        .find("</saml:Issuer>")
        .map(|p| assertion_at + p)
        .expect("assertion issuer present");
    let subject_at = signed[assertion_at..]
        .find("<saml:Subject")
        .map(|p| assertion_at + p)
        .expect("assertion subject present");
    assert!(issuer_end < sig_at && sig_at < subject_at);

    let result = verifier(cert_der)
        .verify_enveloped(&signed)
        .expect("verify enveloped signature");
    assert!(result.is_valid(), "assertion signature did not validate");
}

#[test]
fn signs_response_and_assertion_and_verifies() {
    let (cert_b64, cert_der) = cert_b64_and_der();
    let signed = create_signed_response(
        &sample_options(),
        &sample_name_id(),
        ResponseTimes::at(Utc::now()),
        &signer(),
        &cert_b64,
        true, // sign assertion
        true, // and sign the response envelope
    )
    .expect("create_signed_response");

    // Two signatures: response (outer) and assertion (inner).
    assert_eq!(
        signed.matches("<ds:Signature ").count() + signed.matches("<ds:Signature>").count(),
        2
    );
    // The outer (response) signature is anchored after the response Issuer, i.e.
    // before the assertion.
    let resp_sig = signed.find("<ds:Signature").expect("a signature");
    let assertion_at = signed.find("<saml:Assertion").expect("assertion present");
    assert!(
        resp_sig < assertion_at,
        "response signature precedes the assertion"
    );

    // Both signatures must validate. `verify_enveloped` only reports the first
    // (the Response) signature, so the Assertion signature would go unchecked;
    // `verify_all_enveloped` returns one result per <ds:Signature>.
    let results = verifier(cert_der)
        .verify_all_enveloped(&signed)
        .expect("verify enveloped signatures");
    assert_eq!(
        results.len(),
        2,
        "expected response and assertion signatures"
    );
    assert!(
        results.iter().all(|r| r.is_valid()),
        "response/assertion signatures did not validate"
    );
}
