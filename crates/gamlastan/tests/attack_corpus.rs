//! Attack-corpus regression tests.
//!
//! These tests replay the malicious SAML payloads from the samlshield contract
//! suite against gamlastan's real parse and signature-verification pipeline to
//! prove each attack is refused. The `.xml` fixtures under
//! `tests/fixtures/attacks/` are copied verbatim from that corpus so the payload
//! bytes match what a hostile IdP/attacker would actually send.
//!
//! Attacks are grouped by the layer that stops them:
//!
//! * **Parse layer** — `parse_secure` fails closed before any field is read
//!   (DTD/XXE/entity-expansion, XML comments, processing instructions). Comment
//!   rejection is what closes the comment-truncation signature-bypass class.
//! * **Structure layer** — `ResponseRef::from_xml` rejects a smuggled
//!   `AuthnRequest`, and a non-`Response` root is rejected by element checking.
//! * **Signature layer** — an untrusted / forged / HMAC signature never yields a
//!   valid verification result.
//!
//! A positive control (`valid_keycloak_response`) proves the new parse-time
//! comment/PI rejection does not over-block a legitimate IdP response.

use std::path::PathBuf;

use gamlastan::core::protocol::response::ResponseRef;
use gamlastan::crypto::{KeysManager, SamlVerifier};
use gamlastan::xml::{parse_saml, parse_secure};

/// Read an attack fixture by file name from `tests/fixtures/attacks/`.
fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/attacks");
    path.push(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// A verifier that trusts no key. This models the real trust posture for an
/// attacker-supplied document: gamlastan uses only pre-configured IdP keys
/// (`trusted_keys_only`), so a certificate the attacker embedded in `<KeyInfo>`
/// can never satisfy verification. Time checks are skipped so the assertions are
/// about signature structure/trust, not clock skew on these static fixtures.
fn untrusted_verifier() -> SamlVerifier {
    let mut v = SamlVerifier::new(KeysManager::new());
    v.set_skip_time_checks(true);
    v
}

/// Assert that no `<ds:Signature>` in `xml` produces a valid verification
/// result: verification either errors outright or returns only invalid results.
/// This is the security invariant for the signature-wrapping fixtures — the
/// attacker's crafted document must never be accepted.
fn assert_no_valid_signature(name: &str) {
    let xml = fixture(name);
    // Parse must itself succeed (these fixtures carry no comment/DTD/PI); the
    // rejection we care about is at the signature layer.
    parse_secure(&xml).unwrap_or_else(|e| panic!("{name}: expected clean parse, got {e}"));

    match untrusted_verifier().verify_all_enveloped(&xml) {
        // Verification refused the document — good.
        Err(_) => {}
        // Verification ran but no signature validated — also good.
        Ok(results) => assert!(
            results.iter().all(|r| !r.is_valid()),
            "{name}: a forged/untrusted signature was accepted as valid"
        ),
    }
}

// ── Parse layer: DTD / XXE / entity-expansion ────────────────────────────────

#[test]
fn doctype_simple_is_rejected() {
    // A bare `<!DOCTYPE saml>` with no entities is still refused: SAML messages
    // never carry a DTD, so the DTD itself is the disqualifier.
    assert!(parse_secure(&fixture("doctype_simple.xml")).is_err());
}

#[test]
fn doctype_entity_is_rejected() {
    assert!(parse_secure(&fixture("doctype_entity.xml")).is_err());
}

#[test]
fn external_entity_expansion_is_rejected() {
    // XXE: the external entity can only be declared inside a DTD, which the
    // parser refuses, removing the entity-injection entry point entirely.
    assert!(parse_secure(&fixture("external_entity_expansion.xml")).is_err());
}

#[test]
fn billion_laughs_is_rejected() {
    // Entity-expansion DoS: refused at the DTD, well before any expansion.
    assert!(parse_secure(&fixture("billion_laughs.xml")).is_err());
}

#[test]
fn quadratic_blowup_is_rejected() {
    assert!(parse_secure(&fixture("quadratic_blowup.xml")).is_err());
}

// ── Parse layer: XML comments (comment-truncation bypass) ─────────────────────

/// Every comment-bearing fixture must be refused with the comment error, before
/// any element text is extracted — this is what closes the comment-truncation
/// authentication bypass (CVE-2017-11427).
fn assert_rejected_for_comment(name: &str) {
    let err = parse_secure(&fixture(name)).expect_err("comment-bearing document must be rejected");
    assert!(
        err.to_string().contains("illegal XML comments"),
        "{name}: expected comment rejection, got: {err}"
    );
}

#[test]
fn comment_in_nameid_is_rejected() {
    assert_rejected_for_comment("comment_in_nameid.xml");
}

#[test]
fn comment_in_attribute_is_rejected() {
    assert_rejected_for_comment("comment_in_attribute.xml");
}

#[test]
fn xml_comment_injection_is_rejected() {
    assert_rejected_for_comment("xml_comment_injection.xml");
}

#[test]
fn digest_value_comment_is_rejected() {
    // XML-signature bypass via a comment inside DigestValue: refused at the
    // parse layer along with every other comment.
    assert_rejected_for_comment("digest_value_comment.xml");
}

// ── Parse layer: processing instructions ─────────────────────────────────────

/// Processing-instruction fixtures must be refused with the PI error.
fn assert_rejected_for_pi(name: &str) {
    let err = parse_secure(&fixture(name)).expect_err("PI-bearing document must be rejected");
    assert!(
        err.to_string().contains("illegal processing instructions"),
        "{name}: expected PI rejection, got: {err}"
    );
}

#[test]
fn processing_instruction_in_nameid_is_rejected() {
    assert_rejected_for_pi("processing_instruction.xml");
}

#[test]
fn processing_instructions_is_rejected() {
    assert_rejected_for_pi("processing_instructions.xml");
}

// ── Structure layer ──────────────────────────────────────────────────────────

#[test]
fn forbidden_authnrequest_is_rejected() {
    // A protocol request smuggled inside a Response is a wrapping vector. The
    // corpus fixture happens to also be namespace-malformed (an undeclared
    // `saml2:` prefix on the nested request's Issuer), so the hardened parser may
    // refuse it before deserialization. Either refusal is acceptable — the
    // invariant is that the payload never yields a usable Response. The clean,
    // well-formed F2 path is isolated in
    // `well_formed_response_with_nested_authnrequest_is_rejected`.
    let xml = fixture("forbidden_authnrequest.xml");
    let rejected = match parse_secure(&xml) {
        Err(_) => true,
        Ok(doc) => parse_saml::<ResponseRef>(&doc).is_err(),
    };
    assert!(
        rejected,
        "Response carrying an AuthnRequest must be rejected"
    );
}

#[test]
fn well_formed_response_with_nested_authnrequest_is_rejected() {
    // Isolates F2: a fully well-formed Response whose only defect is a smuggled
    // <samlp:AuthnRequest> child must be rejected by ResponseRef deserialization.
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_r1" Version="2.0" IssueInstant="2022-11-17T22:15:54Z">
  <saml:Issuer>http://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <samlp:AuthnRequest ID="_a1" Version="2.0" IssueInstant="2022-11-17T22:15:54Z">
    <saml:Issuer>http://attacker.example.com</saml:Issuer>
  </samlp:AuthnRequest>
</samlp:Response>"#;
    let doc = parse_secure(xml).expect("well-formed document parses");
    let err = parse_saml::<ResponseRef>(&doc)
        .expect_err("Response carrying an AuthnRequest must be rejected");
    assert!(
        err.to_string().contains("AuthnRequest"),
        "expected AuthnRequest rejection, got: {err}"
    );
}

#[test]
fn multiple_responses_is_rejected() {
    // The corpus wraps two <Response> elements in a synthetic <root>. gamlastan
    // deserializes from the document element, which is not a samlp:Response, so
    // the document is rejected as not-a-Response.
    let xml = fixture("multiple_responses.xml");
    let doc = parse_secure(&xml).expect("fixture parses");
    assert!(
        parse_saml::<ResponseRef>(&doc).is_err(),
        "a non-Response document root must be rejected"
    );
}

#[test]
fn multiple_assertions_are_parsed_but_not_implicitly_trusted() {
    // Divergence from samlshield (which blocks multiple assertions): gamlastan
    // allows multiple <Assertion> elements per errata E26. Safety does not come
    // from a count check here — it comes from the SP only trusting an assertion
    // whose signature was verified and whose ID is in `verified_signed_ids`
    // (security::validation check 6). So parsing succeeds, but a smuggled,
    // unsigned second assertion is never promoted to a trusted AuthnResult.
    let xml = fixture("multiple_assertions.xml");
    let doc = parse_secure(&xml).expect("fixture parses");
    let response = parse_saml::<ResponseRef>(&doc).expect("multiple assertions are allowed (E26)");
    assert_eq!(
        response.assertions.len(),
        2,
        "both assertions are parsed; trust is decided later by signed-ID binding"
    );
}

// ── Signature layer ──────────────────────────────────────────────────────────

#[test]
fn hmac_signature_method_is_rejected() {
    // HMAC is symmetric; a real SAML IdP signs with an asymmetric key. The
    // verifier rejects the HMAC SignatureMethod before any crypto runs, so this
    // fails regardless of key trust.
    let xml = fixture("hmac_signature_method.xml");
    parse_secure(&xml).expect("fixture parses");
    let err = untrusted_verifier()
        .verify_all_enveloped(&xml)
        .expect_err("HMAC-signed document must be rejected");
    assert!(
        err.to_string().contains("HMAC"),
        "expected HMAC rejection, got: {err}"
    );
}

#[test]
fn multiple_signedinfo_is_not_accepted() {
    // XML-signature bypass via a second <SignedInfo> carrying an "EVIL" digest.
    // bergshamra signs only the first SignedInfo's node-set, so the forged one
    // is inert; combined with untrusted-key rejection, no valid signature is
    // produced for the attacker's document.
    assert_no_valid_signature("multiple_signedinfo.xml");
}

#[test]
fn digestvalue_wrapping_is_not_accepted() {
    assert_no_valid_signature("digestvalue_wrapping.xml");
}

#[test]
fn digestvalue_location_mismatch_is_not_accepted() {
    assert_no_valid_signature("digestvalue_location_mismatch.xml");
}

#[test]
fn invalid_canonicalization_is_not_accepted() {
    assert_no_valid_signature("invalid_canonicalization.xml");
}

#[test]
fn invalid_transform_is_not_accepted() {
    assert_no_valid_signature("invalid_transform.xml");
}

#[test]
fn too_many_transforms_is_not_accepted() {
    assert_no_valid_signature("too_many_transforms.xml");
}

#[test]
fn malformed_uri_is_not_accepted() {
    // Signature Reference URI pointing at an external resource must not resolve
    // to signed content.
    assert_no_valid_signature("malformed_uri.xml");
}

#[test]
fn nonexistent_id_is_not_accepted() {
    // Signature Reference URI pointing at a non-existent ID must not verify.
    assert_no_valid_signature("nonexistent_id.xml");
}

// ── Positive control ─────────────────────────────────────────────────────────

#[test]
fn legitimate_response_still_parses() {
    // A real, comment-free IdP response must sail through the hardened parser and
    // deserialize as a Response — proving the new comment/PI rejection does not
    // over-block legitimate traffic.
    let xml = fixture("valid_keycloak_response.xml");
    let doc = parse_secure(&xml).expect("legitimate response must parse");
    parse_saml::<ResponseRef>(&doc).expect("legitimate response must deserialize");
}
