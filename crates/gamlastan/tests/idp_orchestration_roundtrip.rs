//! Orchestrated XML through the SP-side verification path.
//!
//! `idp::orchestrator::create_authn_response` is only correct if the signed
//! XML it produces actually satisfies `profiles::sso::sp`'s own acceptance
//! criteria: `InResponseTo`, audience/recipient, `NotOnOrAfter`, and a
//! signature that verifies. This closes the gap between "the engine says it
//! issued a response" and "an SP would actually accept it" that the
//! orchestrator's own unit tests (which stop at `IssuedResponse`) cannot see.

use chrono::Utc;

use gamlastan::core::protocol::response::ResponseRef;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier, VerifyResult};
use gamlastan::idp::authn_broker::AuthnBroker;
use gamlastan::idp::ident::IdentDb;
use gamlastan::idp::orchestrator::{
    create_authn_response, AuthenticatedSubject, AuthnMethodRef, ResponseEngine, ResponseOutcome,
    ResponseParams,
};
use gamlastan::idp::policy::{PolicyEntry, ReleasePolicy};
use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use gamlastan::metadata::types::sp::SpSsoDescriptor;
use gamlastan::profiles::sso::idp::ProcessedAuthnRequest;
use gamlastan::profiles::sso::sp::process_response_with_verified_signatures;
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::replay::InMemoryReplayCache;
use gamlastan::xml::{parse_saml, parse_secure};

const IDP: &str = "https://idp.example.org/metadata";
const SP: &str = "https://sp.example.org/metadata";
const ACS: &str = "https://sp.example.org/acs";
const REQUEST_ID: &str = "_req_roundtrip_1";

const CERT_PEM: &str = include_str!("fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("fixtures/enc-key.pem");

fn fixture_signer_and_certs() -> (SamlSigner, String, Vec<u8>) {
    use base64::Engine;

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
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&cert_b64)
        .expect("certificate body is valid base64");
    (signer, cert_b64, cert_der)
}

fn sp_sso() -> SpSsoDescriptor {
    SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]),
            artifact_resolution_services: vec![],
            single_logout_services: vec![],
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        },
        authn_requests_signed: None,
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![],
        attribute_consuming_services: vec![],
    }
}

fn processed() -> ProcessedAuthnRequest {
    ProcessedAuthnRequest {
        request_id: REQUEST_ID.to_string(),
        sp_entity_id: SP.to_string(),
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

fn subject() -> AuthenticatedSubject {
    AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                .to_string(),
            authn_authority: Some("https://upstream.example.org/idp".to_string()),
        },
        authn_instant: None,
        session_index: Some("_sess1".to_string()),
    }
}

/// A verifier that trusts the fixture certificate, with time checks skipped
/// (the fixture key/cert have no bearing on the assertion's own timestamps,
/// which the test asserts on directly).
fn trusting_verifier(cert_der: Vec<u8>) -> SamlVerifier {
    let mut vkey = loader::load_pem_auto(CERT_PEM.as_bytes(), None).expect("load cert as key");
    vkey.usage = KeyUsage::Verify;
    let mut km = KeysManager::new();
    km.add_key(vkey);
    km.add_trusted_cert(cert_der);
    let mut v = SamlVerifier::new(km);
    v.set_skip_time_checks(true);
    v
}

#[test]
fn orchestrated_response_is_accepted_by_the_sp_side() {
    let (signer, cert_b64, cert_der) = fixture_signer_and_certs();
    let idents = IdentDb::in_memory(IDP);
    let broker = AuthnBroker::new();
    let decisions = ReleasePolicy::with_default(PolicyEntry::new().with_sign(
        gamlastan::idp::policy::SignTargets {
            response: true,
            assertion: true,
            on_demand: false,
        },
    ));

    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &signer,
        cert_der_b64: &cert_b64,
    };
    let params = ResponseParams {
        processed: processed(),
        sp_sso: sp_sso(),
        sp_entity: None,
    };

    let outcome = create_authn_response(&engine, &params, &subject()).expect("no config fault");
    let issued = match outcome {
        ResponseOutcome::Issued(issued) => issued,
        other => panic!("expected Issued, got {other:?}"),
    };

    // `authenticating_authorities` (the ADR's concrete first fix) reached the
    // wire.
    assert!(issued.xml.contains("<saml:AuthenticatingAuthority>https://upstream.example.org/idp</saml:AuthenticatingAuthority>"));

    // Both signatures verify.
    let results = trusting_verifier(cert_der)
        .verify_all_enveloped(&issued.xml)
        .expect("verify enveloped signatures");
    assert_eq!(results.len(), 2, "expected response + assertion signatures");
    assert!(
        results.iter().all(|r| r.is_valid()),
        "a signature over the orchestrated response failed to verify"
    );
    assert!(results
        .iter()
        .all(|r| matches!(r, VerifyResult::Valid { .. })));

    // Parse the signed XML back into a `Response` the way an SP would, and run
    // it through the SP-side acceptance path unmodified.
    let doc = parse_secure(&issued.xml).expect("orchestrated XML must be well-formed");
    let response = parse_saml::<ResponseRef>(&doc)
        .expect("orchestrated XML must deserialize as a Response")
        .to_owned();

    assert_eq!(response.base.id, issued.response_id);
    assert_eq!(response.base.in_response_to.as_deref(), Some(REQUEST_ID));

    let verified_signed_ids: Vec<&str> = [
        Some(issued.response_id.as_str()),
        issued.assertion_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();

    let config = SecurityConfig {
        require_signed_responses: true,
        ..SecurityConfig::default()
    };
    let replay_cache = InMemoryReplayCache::default();

    let result = process_response_with_verified_signatures(
        &response,
        &config,
        &replay_cache,
        SP,
        ACS,
        Some(REQUEST_ID),
        IDP,
        &verified_signed_ids,
        Utc::now(),
    )
    .expect("the SP-side path must accept a response the engine itself issued");

    assert_eq!(result.name_id, issued.name_id.value);
    assert_eq!(result.session_index.as_deref(), Some("_sess1"));
    assert_eq!(result.idp_entity_id, IDP);
    assert_eq!(result.assertion_id, issued.assertion_id.unwrap());
    assert_eq!(result.response_id, issued.response_id);
    assert_eq!(
        result.authenticating_authorities,
        vec!["https://upstream.example.org/idp".to_string()],
        "authenticating_authorities must survive the round trip"
    );
    // XML serialization truncates to whole seconds; compare at that precision.
    assert_eq!(
        result.session_not_on_or_after.map(|t| t.timestamp()),
        Some(issued.not_on_or_after.timestamp())
    );
}

#[test]
fn session_lifetime_is_independent_of_assertion_lifetime() {
    // With distinct assertion/session lifetimes configured, the SSO session
    // (AuthnStatement/@SessionNotOnOrAfter) must reflect the session
    // lifetime, not the assertion's own (much shorter) validity window.
    let (signer, cert_b64, _cert_der) = fixture_signer_and_certs();
    let idents = IdentDb::in_memory(IDP);
    let broker = AuthnBroker::new();
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new()
            .with_sign(gamlastan::idp::policy::SignTargets {
                response: true,
                assertion: true,
                on_demand: false,
            })
            .with_lifetime(chrono::TimeDelta::minutes(5))
            .with_session_lifetime(chrono::TimeDelta::hours(8)),
    );

    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &signer,
        cert_der_b64: &cert_b64,
    };
    let params = ResponseParams {
        processed: processed(),
        sp_sso: sp_sso(),
        sp_entity: None,
    };

    let outcome = create_authn_response(&engine, &params, &subject()).expect("no config fault");
    let issued = match outcome {
        ResponseOutcome::Issued(issued) => issued,
        other => panic!("expected Issued, got {other:?}"),
    };

    let doc = parse_secure(&issued.xml).expect("orchestrated XML must be well-formed");
    let response = parse_saml::<ResponseRef>(&doc)
        .expect("orchestrated XML must deserialize as a Response")
        .to_owned();
    let verified_signed_ids: Vec<&str> = [
        Some(issued.response_id.as_str()),
        issued.assertion_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let config = SecurityConfig {
        require_signed_responses: true,
        ..SecurityConfig::default()
    };
    let replay_cache = InMemoryReplayCache::default();
    let result = process_response_with_verified_signatures(
        &response,
        &config,
        &replay_cache,
        SP,
        ACS,
        Some(REQUEST_ID),
        IDP,
        &verified_signed_ids,
        Utc::now(),
    )
    .expect("the SP-side path must accept a response the engine itself issued");

    let session_not_on_or_after = result
        .session_not_on_or_after
        .expect("session lifetime must be set");
    // The assertion's own NotOnOrAfter (5 min) must be much shorter than the
    // session's (8h) - specifically, the session must outlive the assertion
    // by roughly the 8h - 5min difference between the two configured
    // lifetimes, not be equal to it.
    let delta = session_not_on_or_after - issued.not_on_or_after;
    assert!(
        delta > chrono::TimeDelta::hours(7),
        "session lifetime did not outlive the assertion lifetime as configured: delta={delta:?}"
    );
}
