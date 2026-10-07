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
//!   (DTD/XXE/entity-expansion, XML comments, processing instructions, CDATA
//!   sections). Comment and CDATA rejection is what closes the text-truncation
//!   signature-bypass class (both split element text while canonicalizing to the
//!   same signed bytes).
//! * **Structure layer** — `ResponseRef::from_xml` rejects a smuggled
//!   `AuthnRequest`, and a non-`Response` root is rejected by element checking.
//! * **Signature layer** — an untrusted / forged / HMAC signature never yields a
//!   valid verification result.
//!
//! A positive control (`valid_keycloak_response`) proves the new parse-time
//! comment/PI rejection does not over-block a legitimate IdP response.
//!
//! The `orchestrator_attacks` module extends the corpus with attacker-supplied
//! *request* input driven through `idp::orchestrator`, rather than replayed
//! response fixtures: a hostile `AttributeConsumingServiceIndex`, markup
//! injected into a `NameIDPolicy/@SPNameQualifier`, and confirmation that a
//! denial's `StatusMessage` never echoes SP-supplied text.

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

// ── Parse layer: CDATA sections (comment-truncation's CDATA sibling) ──────────

#[test]
fn cdata_in_nameid_is_rejected() {
    // The CDATA variant of the comment-truncation bypass: `mgerber<![CDATA[
    // @berkeley.edu]]>` splits the NameID so a first-text-node reader sees
    // "mgerber" while Canonical XML — which folds CDATA into the same character
    // data — covers "mgerber@berkeley.edu", leaving the enveloping signature
    // valid. parse_secure must refuse the document before any text extraction,
    // exactly as it does for the comment form.
    let err =
        parse_secure(&fixture("cdata_in_nameid.xml")).expect_err("CDATA document must be rejected");
    assert!(
        err.to_string().contains("illegal CDATA sections"),
        "expected CDATA rejection, got: {err}"
    );
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

// ── Orchestrator: attacker-supplied request input ───────────────────────────

mod orchestrator_attacks {
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::constants;
    use gamlastan::idp::authn_broker::AuthnBroker;
    use gamlastan::idp::ident::IdentDb;
    use gamlastan::idp::orchestrator::{check_request, Disposition, ResponseParams};
    use gamlastan::idp::orchestrator::{
        create_authn_response, AuthenticatedSubject, AuthnMethodRef, ResponseEngine,
        ResponseOutcome,
    };
    use gamlastan::idp::policy::ReleasePolicy;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::metadata::types::sp::{
        AttributeConsumingService, RequestedAttribute, SpSsoDescriptor,
    };
    use gamlastan::profiles::sso::idp::ProcessedAuthnRequest;
    use gamlastan::xml::{parse_saml, parse_secure};

    const IDP: &str = "https://idp.example.org/metadata";
    const SP: &str = "https://sp.example.org/metadata";
    const ACS: &str = "https://sp.example.org/acs";

    fn processed(sp_entity_id: &str) -> ProcessedAuthnRequest {
        ProcessedAuthnRequest {
            request_id: "_req1".to_string(),
            sp_entity_id: sp_entity_id.to_string(),
            acs_url: ACS.to_string(),
            acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
            force_authn: false,
            is_passive: false,
            requested_name_id_format: None,
            requested_sp_name_qualifier: None,
            allow_create: false,
            has_name_id_policy: false,
            requested_authn_context_class_refs: vec![],
            authn_context_comparison: None,
            requested_authn_context_decl_refs: vec![],
            attribute_consuming_service_index: None,
            extensions: None,
        }
    }

    fn sp_sso_with_default_service() -> SpSsoDescriptor {
        SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base: RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ]),
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            authn_requests_signed: None,
            want_assertions_signed: Some(false),
            assertion_consumer_services: vec![],
            attribute_consuming_services: vec![AttributeConsumingService {
                index: 0,
                is_default: Some(true),
                service_names: vec![],
                service_descriptions: vec![],
                requested_attributes: vec![RequestedAttribute {
                    attribute: Attribute {
                        name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
                        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                        friendly_name: Some("mail".to_string()),
                        values: vec![],
                    },
                    is_required: Some(true),
                }],
            }],
        }
    }

    fn engine<'a>(
        idents: &'a IdentDb,
        broker: &'a AuthnBroker,
        decisions: &'a ReleasePolicy,
        signer: &'a gamlastan::crypto::SamlSigner,
    ) -> ResponseEngine<'a> {
        ResponseEngine {
            idp_entity_id: IDP,
            decisions,
            release: decisions,
            idents,
            broker,
            assertions: None,
            signer,
            cert_der_b64: "",
        }
    }

    /// An attacker-controlled `AttributeConsumingServiceIndex` that names no
    /// service configured in the SP's metadata (the SP publishes only index 0)
    /// must resolve to *no* requirements, never fall back to some other
    /// service's requirements.
    #[test]
    fn unknown_attribute_consuming_service_index_is_denied() {
        // An explicit index naming no declared service is a protocol error,
        // not silently "no requirements" - falling through would bypass that
        // service's own attribute scoping and, for an SP with no entity
        // categories configured (as here), release the subject's entire
        // attribute set instead of failing closed. Denials sign
        // unconditionally, so this needs a real fixture key.
        let idents = IdentDb::in_memory(IDP);
        let broker = AuthnBroker::new();
        let decisions = ReleasePolicy::new();
        let (signer, cert) = super::response_signing_fixture_signer();
        let engine = ResponseEngine {
            idp_entity_id: IDP,
            decisions: &decisions,
            release: &decisions,
            idents: &idents,
            broker: &broker,
            assertions: None,
            signer: &signer,
            cert_der_b64: &cert,
        };

        let mut request = processed(SP);
        request.attribute_consuming_service_index = Some(99); // not configured
        let params = ResponseParams {
            processed: request,
            sp_sso: sp_sso_with_default_service(),
            sp_entity: None,
        };
        let subject = AuthenticatedSubject {
            subject_id: "alice".to_string(),
            attributes: vec![Attribute {
                name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("mail".to_string()),
                values: vec![AttributeValue::String("alice@example.org".to_string())],
            }],
            authn_method: AuthnMethodRef::Inline {
                class_ref: constants::AUTHN_CONTEXT_PASSWORD.to_string(),
                authn_authority: None,
            },
            authn_instant: None,
            session_index: Some("_sess1".to_string()),
        };

        let outcome = create_authn_response(&engine, &params, &subject).expect("no config fault");
        assert!(matches!(
            outcome,
            ResponseOutcome::Denied {
                denial: gamlastan::idp::orchestrator::Denial::InvalidAttributeConsumingServiceIndex,
                ..
            }
        ));
    }

    /// An SPNameQualifier carrying XML metacharacters must be escaped in the
    /// signed response, never spliced in as raw markup - covered here for
    /// the one case such a value can still reach the response at all: it
    /// equals the requester's own (verified) entity ID, which is otherwise
    /// a free-form string. A qualifier naming a *different* entity is
    /// rejected outright before response assembly (see
    /// `sp_name_qualifier_for_a_different_entity_is_denied` in
    /// `idp::orchestrator::tests`), so it's not this test's concern.
    #[test]
    fn sp_name_qualifier_injection_is_escaped_not_executed() {
        let idents = IdentDb::in_memory(IDP);
        let broker = AuthnBroker::new();
        let decisions = ReleasePolicy::new();
        // The default policy signs the assertion, so this needs a real key.
        let (signer, cert) = super::response_signing_fixture_signer();
        let engine = ResponseEngine {
            cert_der_b64: &cert,
            ..engine(&idents, &broker, &decisions, &signer)
        };

        const PAYLOAD: &str = "evil\"><saml:Evil xmlns:saml=\"x\"/>";
        let mut request = processed(PAYLOAD);
        request.has_name_id_policy = true;
        request.requested_name_id_format = Some(constants::NAMEID_TRANSIENT.to_string());
        request.requested_sp_name_qualifier = Some(PAYLOAD.to_string());
        let params = ResponseParams {
            processed: request,
            sp_sso: SpSsoDescriptor {
                sso_base: SsoDescriptorBase {
                    base: RoleDescriptorBase::new(vec![
                        "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                    ]),
                    artifact_resolution_services: vec![],
                    single_logout_services: vec![],
                    manage_name_id_services: vec![],
                    name_id_formats: vec![],
                },
                authn_requests_signed: None,
                want_assertions_signed: Some(false),
                assertion_consumer_services: vec![],
                attribute_consuming_services: vec![],
            },
            sp_entity: None,
        };
        let subject = AuthenticatedSubject {
            subject_id: "alice".to_string(),
            attributes: vec![],
            authn_method: AuthnMethodRef::Inline {
                class_ref: constants::AUTHN_CONTEXT_PASSWORD.to_string(),
                authn_authority: None,
            },
            authn_instant: None,
            session_index: Some("_sess1".to_string()),
        };

        let outcome = create_authn_response(&engine, &params, &subject).expect("no config fault");
        let issued = match outcome {
            ResponseOutcome::Issued(issued) => issued,
            other => panic!("expected Issued, got {other:?}"),
        };

        // The raw payload must never appear verbatim (it would only appear
        // unescaped as a literal `"><saml:Evil` if the serializer spliced it
        // into an attribute or element without escaping).
        assert!(
            !issued.xml.contains("\"><saml:Evil"),
            "unescaped SPNameQualifier markup leaked into the signed response"
        );
        assert!(!issued.xml.contains("<saml:Evil"));

        // And the document is still well-formed, hardened XML — proving the
        // payload was neutralized by escaping, not simply dropped.
        let doc = parse_secure(&issued.xml).expect("issued response must still be well-formed");
        let response = parse_saml::<gamlastan::core::protocol::response::ResponseRef>(&doc)
            .expect("issued response must still deserialize")
            .to_owned();
        let assertion = response.assertions.first().expect("one assertion");
        let name_id = match assertion.subject.as_ref().unwrap().name_id.as_ref() {
            Some(gamlastan::core::assertion::name_id::NameIdOrEncryptedId::NameId(nid)) => nid,
            other => panic!("expected a plaintext NameID, got {other:?}"),
        };
        // The qualifier round-trips as inert data, byte-for-byte.
        assert_eq!(name_id.sp_name_qualifier.as_deref(), Some(PAYLOAD));
    }

    /// A denial's `StatusMessage` is always the fixed, IdP-controlled string
    /// from `Denial::status()` — never an echo of the SP-supplied
    /// `RequestedAuthnContext` class ref that triggered it.
    #[test]
    fn denial_status_message_never_echoes_sp_supplied_class_ref() {
        let idents = IdentDb::in_memory(IDP);
        let mut broker = AuthnBroker::new();
        broker.add(
            constants::AUTHN_CONTEXT_PASSWORD,
            "/login/password",
            1,
            None,
        );
        let decisions = ReleasePolicy::new();
        let (signer, cert) = super::response_signing_fixture_signer();
        let engine = ResponseEngine {
            idp_entity_id: IDP,
            decisions: &decisions,
            release: &decisions,
            idents: &idents,
            broker: &broker,
            assertions: None,
            signer: &signer,
            cert_der_b64: &cert,
        };

        const EVIL_CLASS_REF: &str = "urn:evil\"><saml:Injected xmlns:saml=\"x\"/><x Name=\"";
        let mut request = processed(SP);
        request.requested_authn_context_class_refs = vec![EVIL_CLASS_REF.to_string()];
        request.authn_context_comparison =
            Some(gamlastan::core::protocol::request::AuthnContextComparison::Exact);
        let params = ResponseParams {
            processed: request,
            sp_sso: sp_sso_with_default_service(),
            sp_entity: None,
        };

        let disposition = check_request(&engine, &params, None);
        let denial = match disposition {
            Disposition::Deny { denial } => denial,
            other => panic!("expected Deny(NoAuthnContext), got {other:?}"),
        };
        assert_eq!(denial, gamlastan::idp::orchestrator::Denial::NoAuthnContext);

        let issued =
            gamlastan::idp::orchestrator::create_denial_response(&engine, &params, &denial)
                .expect("denials always sign successfully with a real key");

        assert!(!issued.xml.contains("urn:evil"));
        assert!(!issued.xml.contains("Injected"));
        assert!(issued
            .xml
            .contains("The requested authentication context is unavailable"));
    }
}

/// Shared with `orchestrator_attacks`: a signer backed by the repo's fixture
/// RSA key, for the one test that needs denials to actually sign.
fn response_signing_fixture_signer() -> (gamlastan::crypto::SamlSigner, String) {
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};

    const CERT_PEM: &str = include_str!("fixtures/enc-cert.pem");
    const KEY_PEM: &str = include_str!("fixtures/enc-key.pem");

    let mut key = loader::load_pem_auto(KEY_PEM.as_bytes(), None).expect("load private key");
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);
    let cert_b64: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    (signer, cert_b64)
}
