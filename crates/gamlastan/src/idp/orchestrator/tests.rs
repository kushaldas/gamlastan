//! Unit tests for the response orchestrator.
//!
//! The highest-value surface is [`check_request`]: it is pure and I/O-free, so
//! the whole ForceAuthn × IsPassive × RequestedAuthnContext matrix can be
//! asserted exhaustively. The remaining tests cover `AuthnMethodRef`
//! resolution (including the ambiguous/unknown broker reference) and the
//! `fail_on_missing_requested` on/off behaviour through
//! [`create_authn_response`].

use chrono::{TimeDelta, Utc};

use crate::core::assertion::attribute::{Attribute, AttributeValue};
use crate::core::assertion::name_id::NameId;
use crate::core::constants;
use crate::core::protocol::request::AuthnContextComparison;
use crate::crypto::keys::loader;
use crate::crypto::{KeyUsage, KeysManager, SamlSigner};
use crate::idp::authn_broker::AuthnBroker;
use crate::idp::ident::{IdentDb, IdentityStore, InsertError, StoreError};
use crate::idp::orchestrator::release::PassThroughRelease;
use crate::idp::orchestrator::{
    check_request, create_authn_response, AuthnMethodRef, Disposition, EstablishedSession,
    ResponseEngine, ResponseOutcome, ResponseParams,
};
use crate::idp::policy::ReleasePolicy;
use crate::metadata::types::sp::{AttributeConsumingService, RequestedAttribute, SpSsoDescriptor};
use crate::profiles::sso::idp::ProcessedAuthnRequest;

const IDP: &str = "https://idp.example.org/metadata";
const SP: &str = "https://sp.example.org/metadata";
const ACS: &str = "https://sp.example.org/acs";

const PASSWORD: &str = constants::AUTHN_CONTEXT_PASSWORD;
const PPT: &str = constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT;
const X509: &str = constants::AUTHN_CONTEXT_X509;

const CERT_PEM: &str = include_str!("../../../tests/fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("../../../tests/fixtures/enc-key.pem");

/// A signer backed by the fixture RSA key, with the cert as base64 DER.
///
/// Denials sign the Response envelope unconditionally, so any test that
/// exercises the denial path needs a real signing key.
fn fixture_signer() -> (SamlSigner, &'static str) {
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
    (signer, Box::leak(cert_b64.into_boxed_str()))
}

/// One signer for tests that do not care about it. Responses are signed unless
/// the policy says otherwise, so an engine needs a real key.
fn shared_signer() -> &'static (SamlSigner, &'static str) {
    static SIGNER: std::sync::OnceLock<(SamlSigner, &'static str)> = std::sync::OnceLock::new();
    SIGNER.get_or_init(fixture_signer)
}

/// A broker with three methods at increasing strength.
fn broker() -> AuthnBroker {
    let mut b = AuthnBroker::new();
    b.add(PASSWORD, "/login/password", 1, None);
    b.add(PPT, "/login/ppt", 2, None);
    b.add(X509, "/login/cert", 3, None);
    b
}

/// A `ProcessedAuthnRequest` with the given constraint flags.
fn processed(
    force_authn: bool,
    is_passive: bool,
    class_refs: Vec<&str>,
    comparison: Option<AuthnContextComparison>,
) -> ProcessedAuthnRequest {
    ProcessedAuthnRequest {
        request_id: "_req1".to_string(),
        sp_entity_id: SP.to_string(),
        acs_url: ACS.to_string(),
        acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
        force_authn,
        is_passive,
        requested_name_id_format: None,
        requested_sp_name_qualifier: None,
        allow_create: false,
        has_name_id_policy: false,
        requested_authn_context_class_refs: class_refs.into_iter().map(String::from).collect(),
        authn_context_comparison: comparison,
        requested_authn_context_decl_refs: vec![],
        attribute_consuming_service_index: None,
        extensions: None,
    }
}

/// An `SpSsoDescriptor` with no attribute requirements.
fn sp_sso() -> SpSsoDescriptor {
    SpSsoDescriptor {
        sso_base: crate::metadata::types::role_descriptor::SsoDescriptorBase {
            base: crate::metadata::types::role_descriptor::RoleDescriptorBase::new(vec![
                "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            ]),
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

fn params(p: ProcessedAuthnRequest) -> ResponseParams {
    ResponseParams {
        processed: p,
        sp_sso: sp_sso(),
        sp_entity: None,
    }
}

/// A `ResponseEngine` wired to the test broker and an in-memory identity DB.
fn engine() -> ResponseEngine<'static> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static DECISIONS: std::sync::OnceLock<ReleasePolicy> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let decisions = DECISIONS.get_or_init(ReleasePolicy::new);
    let (signer, cert) = shared_signer();

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: &PassThroughRelease,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    }
}

/// A session established by the given method reference.
fn session(method: AuthnMethodRef) -> EstablishedSession {
    EstablishedSession {
        subject_id: "alice".to_string(),
        authn_method: method,
        authn_instant: Utc::now(),
        session_index: "_sess_1".to_string(),
    }
}

// ── check_request: the ForceAuthn × IsPassive × ACR matrix ─────────────────

#[test]
fn no_session_no_passive_authenticates() {
    let engine = engine();
    let p = params(processed(false, false, vec![], None));
    let d = check_request(&engine, &p, None);
    // No constraint: every registered method is offered.
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn no_session_passive_denies_no_passive() {
    let engine = engine();
    let p = params(processed(false, true, vec![], None));
    let d = check_request(&engine, &p, None);
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoPassive
        }
    ));
}

#[test]
fn reusable_session_is_reused() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

#[test]
fn session_with_unregistered_inline_class_ref_is_reused_when_nothing_requested() {
    // Regression: class_ref_satisfies's doc says "with no constraint, any
    // class ref is acceptable", but the code only took that path when the
    // broker's own `pick(None)` (an `unspecified`/Minimum probe) happened to
    // come back empty. Once a broker has an `unspecified` baseline
    // registered, pick(None) is non-empty, so the old code fell through to
    // requiring the session's class ref to be one of the *registered*
    // methods - rejecting an otherwise-valid inline session/method that was
    // never registered in the broker, even though the SP asked for nothing.
    let decisions = ReleasePolicy::new();
    let idents = IdentDb::in_memory(IDP);
    let mut broker = AuthnBroker::new();
    broker.add(constants::AUTHN_CONTEXT_UNSPECIFIED, "/login/any", 0, None);
    let (signer, cert) = shared_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &PassThroughRelease,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    };

    let p = params(processed(false, false, vec![], None));
    let s = session(AuthnMethodRef::Inline {
        class_ref: "urn:custom:inline-method-never-registered".to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(
        matches!(d, Disposition::ReuseSession { .. }),
        "no RequestedAuthnContext means any session is acceptable: {d:?}"
    );
}

#[test]
fn exact_request_for_an_unregistered_inline_class_ref_is_satisfied_by_literal_match() {
    // Regression: AuthnMethodRef::Inline is documented as usable without any
    // broker registration, but Exact satisfaction was checked via
    // broker.pick(), and pick_by_class_ref's exact branch only considers
    // methods registered under that exact class ref - an inline method
    // whose class ref was never registered in the broker at all was
    // rejected even when it was a literal, exact match for the request.
    let decisions = ReleasePolicy::new();
    let idents = IdentDb::in_memory(IDP);
    let broker = AuthnBroker::new(); // deliberately empty - no registrations
    let (signer, cert) = shared_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &PassThroughRelease,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    };

    let unregistered = "urn:custom:inline-method-never-registered";
    let p = params(processed(
        false,
        false,
        vec![unregistered],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: unregistered.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(
        matches!(d, Disposition::ReuseSession { .. }),
        "an unregistered inline class ref must satisfy an exact request for \
         that same literal class ref: {d:?}"
    );
}

#[test]
fn expired_session_is_not_reused() {
    // Regression: check_request only checked ForceAuthn and method
    // satisfaction, never whether the session's own absolute expiry
    // (authn_instant + session_lifetime) had already passed - so a session
    // could be reused indefinitely regardless of how long ago it was
    // actually established.
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_session_lifetime(TimeDelta::minutes(30)),
    );
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let mut s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    s.authn_instant = Utc::now() - TimeDelta::hours(1);
    let d = check_request(&engine, &p, Some(&s));
    assert!(
        matches!(d, Disposition::Authenticate { .. }),
        "an expired session must not be reused: {d:?}"
    );
}

#[test]
fn expired_session_plus_passive_denies_no_passive() {
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_session_lifetime(TimeDelta::minutes(30)),
    );
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(
        false,
        true,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let mut s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    s.authn_instant = Utc::now() - TimeDelta::hours(1);
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoPassive
        }
    ));
}

#[test]
fn force_authn_defeats_session_reuse() {
    let engine = engine();
    // ForceAuthn set: the session must not be reused even though it satisfies
    // the request.
    let p = params(processed(
        true,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn force_authn_plus_passive_denies_no_passive() {
    let engine = engine();
    // ForceAuthn defeats reuse, and IsPassive forbids a fresh login: NoPassive.
    let p = params(processed(
        true,
        true,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoPassive
        }
    ));
}

#[test]
fn session_method_below_minimum_is_not_reused() {
    let engine = engine();
    // Requested PPT at minimum; the session was established by Password (level
    // 1 < 2), so it does not satisfy the request and must not be reused.
    let p = params(processed(
        false,
        false,
        vec![PPT],
        Some(AuthnContextComparison::Minimum),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn session_method_at_or_above_minimum_is_reused() {
    let engine = engine();
    // Requested Password at minimum; the session was established by PPT (level
    // 2 >= 1), so it satisfies the request and is reused.
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PPT.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

#[test]
fn exact_unregistered_class_denies_no_authn_context() {
    let engine = engine();
    // An exact request for a class the broker does not register: nothing is
    // picked, so the request is denied.
    let p = params(processed(
        false,
        false,
        vec!["urn:example:unknown"],
        Some(AuthnContextComparison::Exact),
    ));
    let d = check_request(&engine, &p, None);
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoAuthnContext
        }
    ));
}

#[test]
fn minimum_picks_stronger_methods() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let d = check_request(&engine, &p, None);
    if let Disposition::Authenticate { methods } = d {
        let refs: Vec<&str> = methods.iter().map(|m| m.class_ref.as_str()).collect();
        // Password (1), PPT (2), X509 (3) all satisfy minimum-Password.
        assert!(refs.contains(&PASSWORD));
        assert!(refs.contains(&PPT));
        assert!(refs.contains(&X509));
    } else {
        panic!("expected Authenticate, got {d:?}");
    }
}

#[test]
fn authenticate_methods_are_strongest_first() {
    // Regression: Disposition::Authenticate's own doc comment promises
    // "strongest preference first", but AuthnBroker::pick preserves
    // registration order (Password=1, PPT=2, X509=3 — weakest first in the
    // test broker). A caller that just takes methods[0] must get the
    // strongest, not the first-registered.
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let Disposition::Authenticate { methods } = check_request(&engine, &p, None) else {
        panic!("expected Authenticate");
    };
    let levels: Vec<u32> = methods.iter().map(|m| m.level).collect();
    assert_eq!(methods[0].class_ref, X509, "strongest method must be first");
    assert!(
        levels.windows(2).all(|w| w[0] >= w[1]),
        "methods must be sorted strongest-first, got levels {levels:?}"
    );
}

#[test]
fn better_excludes_requested_class() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Better),
    ));
    let d = check_request(&engine, &p, None);
    if let Disposition::Authenticate { methods } = d {
        let refs: Vec<&str> = methods.iter().map(|m| m.class_ref.as_str()).collect();
        // "better" than Password: PPT and X509, but not Password itself.
        assert!(!refs.contains(&PASSWORD));
        assert!(refs.contains(&PPT));
        assert!(refs.contains(&X509));
    } else {
        panic!("expected Authenticate, got {d:?}");
    }
}

#[test]
fn passive_with_satisfying_session_reuses() {
    let engine = engine();
    // IsPassive with a session that satisfies the request: reuse, no denial.
    let p = params(processed(
        false,
        true,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

// ── AuthnMethodRef resolution ───────────────────────────────────────────────

#[test]
fn inline_method_resolves_as_is() {
    let b = broker();
    let m = AuthnMethodRef::Inline {
        class_ref: PPT.to_string(),
        authn_authority: Some("https://upstream.example.org".to_string()),
    };
    let (class_ref, authority) = m.resolve(&b).expect("Inline always resolves");
    assert_eq!(class_ref, PPT);
    assert_eq!(authority.as_deref(), Some("https://upstream.example.org"));
}

#[test]
fn broker_reference_resolves_from_registration() {
    let b = broker();
    // The broker assigns references "1", "2", "3" in registration order.
    let m = AuthnMethodRef::BrokerReference("2".to_string());
    let (class_ref, authority) = m.resolve(&b).expect("registered reference resolves");
    assert_eq!(class_ref, PPT);
    assert_eq!(authority, None);
}

#[test]
fn unknown_broker_reference_does_not_resolve() {
    // Regression: a BrokerReference is an opaque registration ID, not an
    // AuthnContext class ref. An unregistered reference must not silently
    // become the class ref itself (a stale/mistyped reference could then
    // reach a signed assertion as a bogus AuthnContextClassRef) - it must
    // fail to resolve so callers can reject it instead.
    let b = broker();
    let m = AuthnMethodRef::BrokerReference("does-not-exist".to_string());
    assert_eq!(m.resolve(&b), None);
}

// ── fail_on_missing_requested through create_authn_response ─────────────────

fn mail_attribute() -> Attribute {
    Attribute {
        name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
        friendly_name: Some("mail".to_string()),
        values: vec![AttributeValue::String("alice@example.org".to_string())],
    }
}

/// An `SpSsoDescriptor` whose default AttributeConsumingService requires `mail`.
fn sp_sso_requiring_mail() -> SpSsoDescriptor {
    let mut sp = sp_sso();
    sp.attribute_consuming_services = vec![AttributeConsumingService {
        index: 0,
        is_default: Some(true),
        service_names: vec![],
        service_descriptions: vec![],
        requested_attributes: vec![RequestedAttribute {
            attribute: mail_attribute(),
            is_required: Some(true),
        }],
    }];
    sp
}

fn subject_with_mail() -> crate::idp::orchestrator::AuthenticatedSubject {
    crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    }
}

fn subject_without_mail() -> crate::idp::orchestrator::AuthenticatedSubject {
    crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    }
}

/// An engine whose release seam is a pass-through (so the held attributes are
/// what the subject supplied) and whose decisions control
/// `fail_on_missing_requested`. Uses a fixture-backed signer so the denial
/// path (which signs unconditionally) can run.
fn engine_with_decisions(decisions: &ReleasePolicy) -> ResponseEngine<'_> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static SIGNER: std::sync::OnceLock<SamlSigner> = std::sync::OnceLock::new();
    static CERT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let (signer, cert) = fixture_signer();
    let signer = SIGNER.get_or_init(|| signer);
    let cert = CERT.get_or_init(|| cert);

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: &PassThroughRelease,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    }
}

#[test]
fn fail_on_missing_requested_denies_when_required_attribute_absent() {
    let decisions = ReleasePolicy::new(); // fail_on_missing_requested defaults to true
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // The subject holds no `mail`, so the required attribute is missing.
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn fail_on_missing_requested_issued_when_attribute_present() {
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // The subject holds `mail`, so the required attribute is satisfied.
    let outcome = create_authn_response(&engine, &p, &subject_with_mail()).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

/// An engine whose release seam is the real `ReleasePolicy` (not
/// `PassThroughRelease`) — the documented default for an originating IdP.
fn engine_with_release_policy(decisions: &ReleasePolicy) -> ResponseEngine<'_> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static SIGNER: std::sync::OnceLock<SamlSigner> = std::sync::OnceLock::new();
    static CERT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let (signer, cert) = fixture_signer();
    let signer = SIGNER.get_or_init(|| signer);
    let cert = CERT.get_or_init(|| cert);

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: decisions,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    }
}

#[test]
fn release_policy_missing_required_attribute_denies_not_errors() {
    // With the real ReleasePolicy as the release seam (an originating IdP,
    // the documented common case), `ReleasePolicy::release` itself refuses a
    // missing required attribute with `PolicyError::MissingRequiredAttribute`.
    // That must surface as a signed `Denial::MissingRequiredAttributes`, not
    // an `Err` (which the Actix/example-idp callers would otherwise turn into
    // an HTTP 500 for what is actually a normal, expected SP-side condition).
    let decisions = ReleasePolicy::new(); // fail_on_missing_requested defaults to true
    let engine = engine_with_release_policy(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    let outcome = create_authn_response(&engine, &p, &subject_without_mail())
        .expect("a missing required attribute is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn release_policy_missing_required_value_denies_not_errors() {
    // Same as above, but the attribute name is present while the specific
    // required *value* is not - PolicyError::MissingRequiredValue, which must
    // map to the same signed denial.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_release_policy(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    let mut sp = sp_sso_requiring_mail();
    sp.attribute_consuming_services[0].requested_attributes[0]
        .attribute
        .values = vec![AttributeValue::String("required@example.org".to_string())];
    p.sp_sso = sp;

    // The subject holds `mail`, but with a different value than required.
    let outcome = create_authn_response(&engine, &p, &subject_with_mail())
        .expect("a missing required value is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn pass_through_release_missing_required_value_is_still_denied() {
    // The value check (step 3) must not depend on which AttributeRelease
    // implementation ran: PassThroughRelease never validates values itself,
    // so this is the only safety net for a proxy shape.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions); // release: &PassThroughRelease
    let mut p = params(processed(false, false, vec![], None));
    let mut sp = sp_sso_requiring_mail();
    sp.attribute_consuming_services[0].requested_attributes[0]
        .attribute
        .values = vec![AttributeValue::String("required@example.org".to_string())];
    p.sp_sso = sp;

    let outcome = create_authn_response(&engine, &p, &subject_with_mail())
        .expect("a missing required value is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn fail_on_missing_requested_disabled_omits_silently() {
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_fail_on_missing_requested(false),
    );
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // With the flag off, a missing required attribute is a silent omission,
    // not a denial.
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            assert!(issued.released_attribute_names.is_empty());
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

// ── Authn context revalidation through create_authn_response ───────────────

#[test]
fn create_authn_response_denies_a_method_that_does_not_satisfy_the_request() {
    // check_request only offers methods that would satisfy the request; it
    // cannot guarantee which method the application's callback ultimately
    // used to authenticate the subject it hands to create_authn_response
    // directly. A Password subject for an exact X509 request must not
    // produce a successful assertion claiming a context that was never
    // actually satisfied. Uses a fixture-backed signer since the denial path
    // signs unconditionally.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(
        false,
        false,
        vec![X509],
        Some(AuthnContextComparison::Exact),
    ));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::NoAuthnContext,
            ..
        }
    ));
}

#[test]
fn create_authn_response_issues_when_method_satisfies_the_request() {
    // Positive control: a method that does satisfy the exact request must
    // still succeed - the revalidation must not be overly strict.
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![X509],
        Some(AuthnContextComparison::Exact),
    ));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: X509.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

#[test]
fn create_authn_response_issues_for_an_unregistered_inline_exact_class_ref() {
    // Regression: the revalidation step (class_ref_satisfies) must accept
    // an Inline method whose class ref is a literal exact match, even
    // though it was never registered with the broker - see
    // exact_request_for_an_unregistered_inline_class_ref_is_satisfied_by_literal_match
    // for the same fix exercised through check_request instead.
    let engine = engine(); // broker only has PASSWORD/PPT/X509 registered
    let unregistered = "urn:custom:inline-method-never-registered";
    let p = params(processed(
        false,
        false,
        vec![unregistered],
        Some(AuthnContextComparison::Exact),
    ));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: unregistered.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

#[test]
fn create_authn_response_errors_on_a_stale_broker_reference() {
    // Regression: a BrokerReference the AuthnBroker no longer has registered
    // (renamed, removed, or simply mistyped by the application) must not
    // silently become the literal AuthnContextClassRef in a signed
    // assertion - it's a configuration fault (ProfileError), not something
    // that can be issued or denied as a protocol outcome.
    let engine = engine();
    let p = params(processed(false, false, vec![], None));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::BrokerReference("does-not-exist".to_string()),
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let result = create_authn_response(&engine, &p, &subject);
    assert!(result.is_err(), "expected a ProfileError, got {result:?}");
}

#[test]
fn a_bad_authn_method_is_refused_before_a_durable_nameid_is_stored() {
    use crate::idp::orchestrator::AuthenticatedSubject;
    let decisions = ReleasePolicy::new();
    with_engine(&decisions, |engine, idents| {
        // A durable (persistent) NameID is requested, but the method is stale.
        let p = params(processed_with_name_id_policy(
            Some(constants::NAMEID_PERSISTENT),
            None,
            true,
        ));
        let subject = AuthenticatedSubject {
            authn_method: AuthnMethodRef::BrokerReference("does-not-exist".to_string()),
            ..subject_without_mail()
        };
        assert!(create_authn_response(engine, &p, &subject).is_err());
        assert!(
            idents.name_ids_for(&subject.subject_id).unwrap().is_empty(),
            "nothing may be stored for a response that is not issued"
        );
    });
}

#[test]
fn a_session_that_expired_before_issuance_is_refused_and_nothing_is_stored() {
    use crate::idp::orchestrator::{AuthenticatedSubject, Denial};
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_session_lifetime(TimeDelta::hours(8)),
    );
    with_engine(&decisions, |engine, idents| {
        // Approved by `check_request` earlier, but past its absolute expiry now.
        let p = params(processed_with_name_id_policy(
            Some(constants::NAMEID_PERSISTENT),
            None,
            true,
        ));
        let subject = AuthenticatedSubject {
            authn_instant: Some(Utc::now() - TimeDelta::hours(9)),
            ..subject_without_mail()
        };
        match create_authn_response(engine, &p, &subject).unwrap() {
            ResponseOutcome::Denied { denial, .. } => assert_eq!(denial, Denial::AuthnFailed),
            other => panic!("an expired session must not be issued: {other:?}"),
        }
        assert!(idents.name_ids_for(&subject.subject_id).unwrap().is_empty());
    });
}

#[test]
fn reused_session_asserts_its_original_absolute_expiry_not_a_sliding_one() {
    // Regression: SessionNotOnOrAfter was computed as `now + session_lifetime`
    // unconditionally, so reusing an old session pushed its asserted expiry
    // further out on every single-sign-on hop - an absolute cap on paper,
    // but an indefinitely-renewable sliding window in practice. It must be
    // derived from the subject's actual authn_instant (the original
    // authentication time on reuse; "now" for a fresh login) instead.
    use crate::xml::{parse_saml, parse_secure};

    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_session_lifetime(TimeDelta::hours(8)),
    );
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));

    let original_authn_instant = Utc::now() - TimeDelta::hours(7);
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: Some(original_authn_instant),
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    let issued = match outcome {
        ResponseOutcome::Issued(issued) => issued,
        other => panic!("expected Issued, got {other:?}"),
    };

    let doc = parse_secure(&issued.xml).unwrap();
    let response = parse_saml::<crate::core::protocol::response::ResponseRef>(&doc)
        .unwrap()
        .to_owned();
    let statement = &response.assertions[0].authn_statements[0];
    let session_not_on_or_after = statement.session_not_on_or_after.expect("set");

    // Expected: original_authn_instant + 8h, NOT now + 8h.
    let expected = original_authn_instant + TimeDelta::hours(8);
    let delta = (session_not_on_or_after - expected)
        .num_milliseconds()
        .abs();
    assert!(
        delta < 1000,
        "session_not_on_or_after {session_not_on_or_after} should be ~{expected} \
         (original authn_instant + session_lifetime), not derived from now"
    );
}

#[test]
fn issued_not_on_or_after_matches_the_wire_assertion_lifetime() {
    // Regression: the assertion's wire NotOnOrAfter is built from a
    // normalized (whole-second, non-negative) lifetime
    // (`lifetime.num_seconds().max(0)`), but IssuedResponse.not_on_or_after
    // must be derived from that same normalized value, not the raw
    // sub-second TimeDelta, or the two can disagree.
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_lifetime(TimeDelta::milliseconds(2_500)),
    );
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));
    let subject = subject_with_mail();

    let before = chrono::Utc::now();
    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            // The normalized lifetime is 2 whole seconds, not 2.5.
            let expected = before + TimeDelta::seconds(2);
            let delta = (issued.not_on_or_after - expected).num_milliseconds().abs();
            assert!(
                delta < 500,
                "not_on_or_after {} should be ~2s (normalized) after issuance, not 2.5s",
                issued.not_on_or_after
            );
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

// ── ResponseParams metadata signals ──────────────────────────────────────────

#[test]
fn subject_id_req_reads_the_full_metadata_attribute_name() {
    // Regression: the SP metadata attribute Name is the full URI
    // (SUBJECT_ID_REQ_ATTR), not the short label "subject-id:req". Looking
    // up the short label can never match, so this signal would always read
    // as SubjectIdReq::None regardless of what the SP actually published.
    use crate::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use crate::metadata::types::extensions::Extensions;

    let entity = EntityDescriptor {
        entity_id: SP.to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: Some(Extensions::new(format!(
            r#"<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute Name="{}">
                <saml:AttributeValue>any</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>"#,
            crate::idp::entity_category::SUBJECT_ID_REQ_ATTR
        ))),
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };

    let mut p = params(processed(false, false, vec![], None));
    p.sp_entity = Some(entity);
    assert_eq!(
        p.subject_id_req(),
        crate::idp::entity_category::SubjectIdReq::Any
    );
}

// ── ResponseEngine over a non-default IdentityStore ─────────────────────────

/// A distinct `IdentityStore` impl (not `InMemoryIdentityStore`) — stands in
/// for a Redis/SQL-backed store. Proves `ResponseEngine::idents` (`dyn
/// NameIdConstructor`) actually accepts an `IdentDb` over any store, not
/// just the default.
#[derive(Default)]
struct CustomStore(crate::idp::ident::InMemoryIdentityStore);

impl IdentityStore for CustomStore {
    fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
        self.0.for_user(user_id)
    }
    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
        self.0.user_for(value)
    }
    fn get_or_insert_durable(
        &self,
        user_id: &str,
        candidate: NameId,
    ) -> Result<NameId, InsertError> {
        self.0.get_or_insert_durable(user_id, candidate)
    }
    fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
        self.0.insert(user_id, name_id)
    }
    fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
        self.0.replace(user_id, name_id)
    }
    fn remove(&self, value: &str) -> Result<(), StoreError> {
        self.0.remove(value)
    }
    fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
        self.0.remove_all(user_id)
    }
}

#[test]
fn response_engine_accepts_a_non_default_identity_store() {
    let idents = IdentDb::new(CustomStore::default(), IDP);
    let broker = broker();
    let decisions = ReleasePolicy::new();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents, // &IdentDb<CustomStore> coerces to &dyn NameIdConstructor
        broker: &broker,
        assertions: None,
        signer: &shared_signer().0,
        cert_der_b64: shared_signer().1,
    };

    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

// ── Review findings: authn context, compatibility mode, advertised roles ─────

#[test]
fn a_declaration_only_authn_context_request_is_denied_not_ignored() {
    use crate::idp::orchestrator::Denial;
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.processed.requested_authn_context_decl_refs = vec!["urn:example:decl".to_string()];

    // No session: a declaration cannot be met, so this is not "unconstrained".
    assert!(matches!(
        check_request(&engine, &p, None),
        Disposition::Deny {
            denial: Denial::NoAuthnContext
        }
    ));
    // A perfectly good session must not be reused to answer a constraint it
    // cannot be shown to meet.
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    assert!(matches!(
        check_request(&engine, &p, Some(&s)),
        Disposition::Deny {
            denial: Denial::NoAuthnContext
        }
    ));
    // Same with IsPassive.
    p.processed.is_passive = true;
    assert!(matches!(
        check_request(&engine, &p, Some(&s)),
        Disposition::Deny {
            denial: Denial::NoAuthnContext
        }
    ));
    // And the response path refuses to issue for a caller that skipped
    // check_request.
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: Denial::NoAuthnContext,
            ..
        }
    ));
}

#[test]
fn an_empty_requested_authn_context_is_denied_not_treated_as_unconstrained() {
    use crate::idp::orchestrator::Denial;
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    // The element is present (a comparison is set) but names nothing. The
    // schema requires at least one ref, so this is malformed; the engine must
    // not read it as "no constraint" and reuse any session.
    let p = params(processed(
        false,
        false,
        vec![],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    assert!(matches!(
        check_request(&engine, &p, Some(&s)),
        Disposition::Deny {
            denial: Denial::NoAuthnContext
        }
    ));
    assert!(matches!(
        check_request(&engine, &p, None),
        Disposition::Deny {
            denial: Denial::NoAuthnContext
        }
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: Denial::NoAuthnContext,
            ..
        }
    ));

    // An absent element (no comparison, no refs) is still unconstrained.
    let p = params(processed(false, false, vec![], None));
    assert!(matches!(
        check_request(&engine, &p, Some(&s)),
        Disposition::ReuseSession { .. }
    ));
}

#[test]
fn exact_level_matching_opt_in_is_consistent_between_check_and_response() {
    // With `allow_exact_level_matching(true)`, check_request offers a method
    // registered at the same level as the requested class. The response must
    // accept that method, not deny it after the user has authenticated, and an
    // existing session established by it must be reusable.
    let mut b = AuthnBroker::new();
    b.add(PASSWORD, "/login/password", 1, None);
    b.add(PPT, "/login/ppt", 1, None);
    let broker = b.allow_exact_level_matching(true);
    let idents = IdentDb::in_memory(IDP);
    let decisions = ReleasePolicy::new();
    let (signer, cert) = fixture_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &signer,
        cert_der_b64: cert,
    };
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));

    match check_request(&engine, &p, None) {
        Disposition::Authenticate { methods } => assert!(
            methods.iter().any(|m| m.class_ref == PPT),
            "the same-level method is offered in compatibility mode"
        ),
        other => panic!("expected Authenticate, got {other:?}"),
    }

    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PPT.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: None,
    };
    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(
        matches!(outcome, ResponseOutcome::Issued(_)),
        "the offered method must be accepted: {outcome:?}"
    );

    let s = session(AuthnMethodRef::Inline {
        class_ref: PPT.to_string(),
        authn_authority: None,
    });
    assert!(matches!(
        check_request(&engine, &p, Some(&s)),
        Disposition::ReuseSession { .. }
    ));
}

#[test]
fn signing_algorithms_come_from_the_entity_and_the_requested_role_only() {
    use crate::crypto::{DigestMethod, SignatureMethod, SigningPreference};
    use crate::idp::policy::PolicyEntry;
    use crate::metadata::types::entity_descriptor::EntityDescriptor;
    use crate::metadata::types::extensions::Extensions;

    fn alg(kind: &str, uri: &str) -> String {
        format!(
            r#"<alg:{kind} xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" Algorithm="{uri}"/>"#
        )
    }

    // The role the request was bound to advertises RSA-SHA384; the entity
    // advertises a SHA-384 digest; a *different* SP role of the same entity
    // advertises RSA-SHA512 and must not count.
    let mut role = sp_sso();
    role.sso_base.base.extensions = Some(Extensions::new(alg(
        "SigningMethod",
        SignatureMethod::RsaSha384.uri(),
    )));
    let mut other_role = sp_sso();
    other_role.sso_base.base.extensions = Some(Extensions::new(alg(
        "SigningMethod",
        SignatureMethod::RsaSha512.uri(),
    )));
    let mut entity = EntityDescriptor::for_sp(SP, other_role);
    entity.extensions = Some(Extensions::new(alg(
        "DigestMethod",
        DigestMethod::Sha384.uri(),
    )));

    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = role;
    p.sp_entity = Some(entity);

    let (signature, digest) = crate::idp::orchestrator::respond::sp_advertised_algorithms(&p);
    assert_eq!(
        signature,
        vec![SignatureMethod::RsaSha384.uri().to_string()]
    );
    assert_eq!(digest, vec![DigestMethod::Sha384.uri().to_string()]);
    assert!(
        !signature.contains(&SignatureMethod::RsaSha512.uri().to_string()),
        "an algorithm advertised only by another role must not be selected: {signature:?}"
    );

    // And the IdP's own preference resolves against that, not the aggregate.
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new().with_signing_preference(
            SigningPreference::new()
                .with_signature_methods(vec![
                    SignatureMethod::RsaSha512,
                    SignatureMethod::RsaSha384,
                ])
                .with_digest_methods(vec![DigestMethod::Sha512, DigestMethod::Sha384]),
        ),
    );
    let engine = engine_with_decisions(&decisions);
    let resolved = crate::idp::orchestrator::respond::signing_algorithms(&engine, &p);
    assert_eq!(resolved.signature, Some(SignatureMethod::RsaSha384));
    assert_eq!(resolved.digest, Some(DigestMethod::Sha384));
}

#[test]
fn the_requested_authn_context_helper_keeps_declaration_refs() {
    let mut p = params(processed(false, false, vec![], None));
    assert!(
        p.requested_authn_context().is_none(),
        "no constraint at all"
    );

    // A declaration-only request is still a constraint: the public helper must
    // not report it as "none", or a caller using it would lose the constraint.
    p.processed.requested_authn_context_decl_refs = vec!["urn:example:decl".to_string()];
    let requested = p.requested_authn_context().expect("a constraint");
    assert!(requested.authn_context_class_refs.is_empty());
    assert_eq!(
        requested.authn_context_decl_refs,
        vec!["urn:example:decl".to_string()]
    );

    // A present but empty element (the comparison records it) is a constraint
    // too, not "none".
    let mut p = params(processed(
        false,
        false,
        vec![],
        Some(AuthnContextComparison::Exact),
    ));
    p.processed.requested_authn_context_decl_refs = vec![];
    let requested = p.requested_authn_context().expect("a constraint");
    assert!(requested.authn_context_class_refs.is_empty());
    assert!(requested.authn_context_decl_refs.is_empty());
}

#[test]
fn a_descriptor_for_a_different_sp_is_refused() {
    use crate::idp::orchestrator::{create_denial_response, Denial};
    use crate::metadata::types::entity_descriptor::EntityDescriptor;
    use crate::profiles::error::ProfileError;

    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let request = || processed(false, false, vec![], None);
    let other = EntityDescriptor::for_sp("https://other-sp.example.org/metadata", sp_sso());

    // The constructor reports the mismatch where the parameters are built.
    assert!(matches!(
        ResponseParams::new(request(), sp_sso(), Some(other.clone())),
        Err(ProfileError::SpEntityMismatch { .. })
    ));
    assert!(matches!(
        ResponseParams::from_entity(request(), other.clone()),
        Err(ProfileError::SpEntityMismatch { .. })
    ));

    // The fields are public, so the engine does not rely on the constructor:
    // SP B's entity categories must not decide what SP A's request releases.
    let mut p = params(request());
    p.sp_entity = Some(other);
    assert!(matches!(
        create_authn_response(&engine, &p, &subject_without_mail()),
        Err(ProfileError::SpEntityMismatch { .. })
    ));
    assert!(matches!(
        create_denial_response(&engine, &p, &Denial::Cancelled),
        Err(ProfileError::SpEntityMismatch { .. })
    ));

    // The SP's own descriptor is accepted, and from_entity takes the SAML 2.0
    // role from that same descriptor.
    let own = EntityDescriptor::for_sp(SP, sp_sso());
    assert!(ResponseParams::new(request(), sp_sso(), Some(own.clone())).is_ok());
    assert!(ResponseParams::from_entity(request(), own).is_ok());
}

// ── Requested NameID formats ────────────────────────────────────────────────

/// Run `f` against an engine over a fresh in-memory `IdentDb`, so a test can
/// look at what the engine did or did not record.
fn with_engine<R>(decisions: &ReleasePolicy, f: impl FnOnce(&ResponseEngine, &IdentDb) -> R) -> R {
    let idents = IdentDb::in_memory(IDP);
    let broker = broker();
    let (signer, cert) = fixture_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &signer,
        cert_der_b64: cert,
    };
    f(&engine, &idents)
}

fn issued_name_id(
    engine: &ResponseEngine,
    format: &str,
) -> Result<NameId, crate::idp::orchestrator::Denial> {
    let p = params(processed_with_name_id_policy(Some(format), None, true));
    match create_authn_response(engine, &p, &subject_without_mail()).unwrap() {
        ResponseOutcome::Issued(issued) => Ok(issued.name_id),
        ResponseOutcome::Denied { denial, .. } => Err(denial),
    }
}

#[test]
fn an_unsupported_requested_nameid_format_is_denied_and_nothing_is_minted() {
    use crate::idp::orchestrator::Denial;
    use crate::idp::policy::{PolicyEntry, ISSUABLE_NAMEID_FORMATS};
    // Opt-in: with a supported set configured, a format outside it is
    // InvalidNameIDPolicy (SAML Core 3.4.1.1). Without one, any string is
    // honoured (see the next test).
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new().with_supported_nameid_formats(
            ISSUABLE_NAMEID_FORMATS
                .iter()
                .map(|f| f.to_string())
                .collect(),
        ),
    );
    for format in [
        "urn:evil:made-up",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    ] {
        with_engine(&decisions, |engine, idents| {
            assert_eq!(
                issued_name_id(engine, format),
                Err(Denial::InvalidNameIdPolicy),
                "{format}"
            );
            assert!(
                idents
                    .name_ids_for(&subject_without_mail().subject_id)
                    .unwrap()
                    .is_empty(),
                "{format}: a refused request must not record anything"
            );
        });
    }
}

#[test]
fn an_overlong_requested_nameid_format_is_denied_and_nothing_is_stored() {
    use crate::idp::orchestrator::Denial;
    use crate::idp::policy::MAX_NAMEID_FORMAT_LEN;
    let long = format!("urn:example:{}", "a".repeat(MAX_NAMEID_FORMAT_LEN));
    with_engine(&ReleasePolicy::new(), |engine, idents| {
        assert_eq!(
            issued_name_id(engine, &long),
            Err(Denial::InvalidNameIdPolicy)
        );
        assert!(idents
            .name_ids_for(&subject_without_mail().subject_id)
            .unwrap()
            .is_empty());
    });
}

#[test]
fn the_encrypted_nameid_format_is_denied_even_with_no_supported_set() {
    use crate::idp::orchestrator::Denial;
    with_engine(&ReleasePolicy::new(), |engine, idents| {
        assert_eq!(
            issued_name_id(engine, crate::core::constants::NAMEID_ENCRYPTED),
            Err(Denial::InvalidNameIdPolicy)
        );
        assert!(idents
            .name_ids_for(&subject_without_mail().subject_id)
            .unwrap()
            .is_empty());
    });
}

#[test]
fn an_sp_no_rule_covers_gets_every_attribute_unless_deny_unconfigured_is_set() {
    use crate::idp::orchestrator::AuthenticatedSubject;
    use crate::idp::policy::PolicyEntry;
    let subject = AuthenticatedSubject {
        attributes: vec![mail_attribute()],
        ..subject_without_mail()
    };
    // `with_engine` uses the policy itself as the release seam.
    let released_by = |decisions: &ReleasePolicy| {
        with_engine(decisions, |engine, _| {
            let p = params(processed(false, false, vec![], None));
            match create_authn_response(engine, &p, &subject).unwrap() {
                ResponseOutcome::Issued(issued) => issued.released_attribute_names,
                other => panic!("expected Issued, got {other:?}"),
            }
        })
    };

    // pysaml2's default, pinned: nothing configured releases what was supplied.
    assert_eq!(released_by(&ReleasePolicy::new()).len(), 1);
    // Opted into fail-closed: the same SP gets no attributes.
    let strict =
        ReleasePolicy::with_default(PolicyEntry::new().with_deny_unconfigured_release(true));
    assert!(released_by(&strict).is_empty());
}

#[test]
fn the_default_policy_signs_the_assertion() {
    // Nothing configured: the response is not signed, so the assertion must be.
    let decisions = ReleasePolicy::new();
    with_engine(&decisions, |engine, _| {
        let p = params(processed(false, false, vec![], None));
        match create_authn_response(engine, &p, &subject_without_mail()).unwrap() {
            ResponseOutcome::Issued(issued) => {
                assert!(issued.xml.contains("<ds:SignatureValue>"), "{}", issued.xml)
            }
            other => panic!("expected Issued, got {other:?}"),
        }
    });
}

#[test]
fn an_empty_broker_defers_an_exact_request_to_the_callback() {
    let broker = AuthnBroker::new();
    let decisions = ReleasePolicy::new();
    let idents = IdentDb::in_memory(IDP);
    let (signer, cert) = shared_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &PassThroughRelease,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    };
    let p = params(processed(
        false,
        false,
        vec!["urn:custom:inline-method"],
        Some(AuthnContextComparison::Exact),
    ));
    // No session and nothing registered: authenticate (the callback decides and
    // the response-time check enforces), rather than a pre-login denial.
    assert!(matches!(
        check_request(&engine, &p, None),
        Disposition::Authenticate { methods } if methods.is_empty()
    ));
    // The other comparisons need the broker's strength ordering: with nothing
    // registered they can never be met, so deny before login.
    for comparison in [
        AuthnContextComparison::Minimum,
        AuthnContextComparison::Maximum,
        AuthnContextComparison::Better,
    ] {
        let p = params(processed(
            false,
            false,
            vec!["urn:custom:inline-method"],
            Some(comparison),
        ));
        assert!(
            matches!(
                check_request(&engine, &p, None),
                Disposition::Deny {
                    denial: crate::idp::orchestrator::Denial::NoAuthnContext
                }
            ),
            "{comparison:?}"
        );
    }
    // With a registered method that does not match, it is still a denial.
    let populated = self::broker();
    let engine = ResponseEngine {
        broker: &populated,
        ..engine
    };
    assert!(matches!(
        check_request(&engine, &p, None),
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoAuthnContext
        }
    ));
}

#[test]
fn an_encrypted_default_format_is_a_config_error_never_a_plaintext_nameid() {
    use crate::idp::policy::PolicyEntry;
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new().with_nameid_format(constants::NAMEID_ENCRYPTED),
    );
    with_engine(&decisions, |engine, idents| {
        // The request names no format, so the default applies.
        let p = params(processed_with_name_id_policy(None, None, true));
        assert!(create_authn_response(engine, &p, &subject_without_mail()).is_err());
        let p = params(processed(false, false, vec![], None)); // no NameIDPolicy at all
        assert!(create_authn_response(engine, &p, &subject_without_mail()).is_err());
        assert!(idents
            .name_ids_for(&subject_without_mail().subject_id)
            .unwrap()
            .is_empty());
    });
}

#[test]
fn the_sp_role_must_belong_to_the_supplied_entity() {
    use crate::metadata::types::entity_descriptor::EntityDescriptor;
    let mut foreign = sp_sso();
    foreign.want_assertions_signed = Some(false);
    let entity = EntityDescriptor::for_sp(SP, sp_sso());
    let proc = processed(false, false, vec![], None);

    // Its own role is accepted; another SP's role is not.
    assert!(ResponseParams::new(proc.clone(), sp_sso(), Some(entity.clone())).is_ok());
    assert!(matches!(
        ResponseParams::new(proc, foreign, Some(entity)),
        Err(crate::profiles::error::ProfileError::SpRoleMismatch { .. })
    ));
}

#[test]
fn by_default_any_requested_nameid_format_is_accepted_as_in_pysaml2() {
    // pysaml2 never validates the requested format, so by default neither does
    // this engine: restricting formats is opt-in.
    with_engine(&ReleasePolicy::new(), |engine, _| {
        let nid = issued_name_id(engine, "urn:example:custom-format")
            .expect("no supported set configured: every format is accepted");
        assert_eq!(nid.format.as_deref(), Some("urn:example:custom-format"));
    });
}

#[test]
fn every_issuable_nameid_format_is_issued_when_opted_in() {
    use crate::idp::policy::{PolicyEntry, ISSUABLE_NAMEID_FORMATS};
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new().with_supported_nameid_formats(
            ISSUABLE_NAMEID_FORMATS
                .iter()
                .map(|f| f.to_string())
                .collect(),
        ),
    );
    with_engine(&decisions, |engine, _| {
        for format in ISSUABLE_NAMEID_FORMATS {
            let nid = issued_name_id(engine, format)
                .unwrap_or_else(|d| panic!("{format} must be issued, got {d:?}"));
            assert_eq!(nid.format.as_deref(), Some(*format));
        }
    });
}

#[test]
fn a_configured_supported_set_is_honoured_and_the_sp_default_is_always_allowed() {
    use crate::idp::orchestrator::Denial;
    use crate::idp::policy::PolicyEntry;

    // Only persistent is listed, and the SP's own default is email.
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new()
            .with_supported_nameid_formats(vec![constants::NAMEID_PERSISTENT.to_string()])
            .with_nameid_format(constants::NAMEID_EMAIL),
    );
    with_engine(&decisions, |engine, _| {
        assert!(issued_name_id(engine, constants::NAMEID_PERSISTENT).is_ok());
        assert_eq!(
            issued_name_id(engine, constants::NAMEID_TRANSIENT),
            Err(Denial::InvalidNameIdPolicy),
            "transient is not in the configured set"
        );
        assert!(
            issued_name_id(engine, constants::NAMEID_EMAIL).is_ok(),
            "the SP's own default format needs no listing"
        );
    });
}

#[test]
fn a_durable_nameid_is_the_same_on_every_login() {
    with_engine(&ReleasePolicy::new(), |engine, idents| {
        let first = issued_name_id(engine, constants::NAMEID_EMAIL).unwrap();
        let second = issued_name_id(engine, constants::NAMEID_EMAIL).unwrap();
        assert_eq!(
            first.value, second.value,
            "an email-format NameID that changes at each login cannot identify anyone"
        );
        assert_eq!(
            idents
                .name_ids_for(&subject_without_mail().subject_id)
                .unwrap()
                .len(),
            1,
            "and the store does not grow with each response"
        );
    });
}

// ── Per-SP signing algorithms ───────────────────────────────────────────────

fn sha512_policy() -> ReleasePolicy {
    use crate::crypto::{DigestMethod, SignatureMethod, SigningPreference};
    use crate::idp::policy::{PolicyEntry, SignTargets};
    ReleasePolicy::with_default(
        PolicyEntry::new()
            .with_sign(SignTargets {
                response: true,
                ..Default::default()
            })
            .with_signing_preference(
                SigningPreference::new()
                    .with_signature_methods(vec![SignatureMethod::RsaSha512])
                    .with_digest_methods(vec![DigestMethod::Sha512]),
            ),
    )
}

#[test]
fn a_configured_signing_preference_is_used_for_an_issued_response() {
    use crate::crypto::{DigestMethod, SignatureMethod};
    let decisions = sha512_policy();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));
    let ResponseOutcome::Issued(issued) =
        create_authn_response(&engine, &p, &subject_without_mail()).unwrap()
    else {
        panic!("expected an issued response");
    };
    assert!(issued.xml.contains(SignatureMethod::RsaSha512.uri()));
    assert!(issued.xml.contains(DigestMethod::Sha512.uri()));
    assert!(!issued.xml.contains("xmlenc#sha256"));
}

#[test]
fn a_configured_signing_preference_is_used_for_a_denial_too() {
    use crate::crypto::{DigestMethod, SignatureMethod};
    let decisions = sha512_policy();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));
    let denial = crate::idp::orchestrator::create_denial_response(
        &engine,
        &p,
        &crate::idp::orchestrator::Denial::Cancelled,
    )
    .unwrap();
    assert!(denial.xml.contains(SignatureMethod::RsaSha512.uri()));
    assert!(denial.xml.contains(DigestMethod::Sha512.uri()));
}

#[test]
fn without_a_signing_preference_the_signer_default_applies() {
    use crate::crypto::DigestMethod;
    use crate::idp::policy::{PolicyEntry, SignTargets};
    let decisions = ReleasePolicy::with_default(PolicyEntry::new().with_sign(SignTargets {
        response: true,
        ..Default::default()
    }));
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));
    let ResponseOutcome::Issued(issued) =
        create_authn_response(&engine, &p, &subject_without_mail()).unwrap()
    else {
        panic!("expected an issued response");
    };
    assert!(issued.xml.contains(DigestMethod::Sha256.uri()));
    assert!(issued.xml.contains("xmldsig-more#rsa-sha256"));
}

// ── Store outages ───────────────────────────────────────────────────────────

fn outage() -> StoreError {
    StoreError::new("backend unreachable")
}

/// An identity store that is down: every operation fails.
struct DownIdentityStore;

impl IdentityStore for DownIdentityStore {
    fn for_user(&self, _: &str) -> Result<Vec<NameId>, StoreError> {
        Err(outage())
    }
    fn user_for(&self, _: &str) -> Result<Option<String>, StoreError> {
        Err(outage())
    }
    fn get_or_insert_durable(&self, _: &str, _: NameId) -> Result<NameId, InsertError> {
        Err(outage().into())
    }
    fn insert(&self, _: &str, _: NameId) -> Result<(), InsertError> {
        Err(outage().into())
    }
    fn replace(&self, _: &str, _: NameId) -> Result<(), InsertError> {
        Err(outage().into())
    }
    fn remove(&self, _: &str) -> Result<(), StoreError> {
        Err(outage())
    }
    fn remove_all(&self, _: &str) -> Result<(), StoreError> {
        Err(outage())
    }
}

/// An assertion store that is down: every operation fails.
struct DownAssertionStore;

impl crate::idp::assertion_store::AssertionStore for DownAssertionStore {
    fn store_assertion(
        &self,
        _: crate::core::assertion::types::Assertion,
    ) -> Result<(), StoreError> {
        Err(outage())
    }
    fn get_assertion(
        &self,
        _: &str,
    ) -> Result<Option<crate::core::assertion::types::Assertion>, StoreError> {
        Err(outage())
    }
    fn assertions_for_subject(
        &self,
        _: &str,
    ) -> Result<Vec<crate::core::assertion::types::Assertion>, StoreError> {
        Err(outage())
    }
    fn remove_assertion(&self, _: &str) -> Result<(), StoreError> {
        Err(outage())
    }
}

#[test]
fn identity_store_outage_is_an_error_not_a_denial() {
    let idents = IdentDb::new(DownIdentityStore, IDP);
    let broker = broker();
    let decisions = ReleasePolicy::new();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &shared_signer().0,
        cert_der_b64: shared_signer().1,
    };

    // A persistent NameID needs a store lookup. The outage must not look like
    // "no existing identifier" (which would mint a second one) and must not be
    // blamed on the SP with a signed denial: it is an operational fault.
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_PERSISTENT),
        None,
        true,
    ));
    let result = create_authn_response(&engine, &p, &subject_without_mail());
    assert!(
        matches!(result, Err(crate::profiles::error::ProfileError::Store(_))),
        "expected a store error, got {result:?}"
    );
}

#[test]
fn transient_issuance_survives_an_identity_store_outage() {
    // Transient identifiers are never stored, so they do not depend on the
    // store being reachable.
    let idents = IdentDb::new(DownIdentityStore, IDP);
    let broker = broker();
    let decisions = ReleasePolicy::new(); // default format: transient
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &shared_signer().0,
        cert_der_b64: shared_signer().1,
    };
    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

#[test]
fn assertion_store_outage_is_an_error_not_a_silent_skip() {
    let idents = IdentDb::in_memory(IDP);
    let broker = broker();
    let decisions = ReleasePolicy::new();
    let assertions = DownAssertionStore;
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: Some(&assertions),
        signer: &shared_signer().0,
        cert_der_b64: shared_signer().1,
    };
    let p = params(processed(false, false, vec![], None));
    let result = create_authn_response(&engine, &p, &subject_without_mail());
    assert!(
        matches!(result, Err(crate::profiles::error::ProfileError::Store(_))),
        "an assertion that could not be recorded must not be reported as issued: {result:?}"
    );
}

#[test]
fn persist_transient_lets_the_issued_nameid_resolve_to_its_user() {
    // The back-channel logout case: the SP later presents the transient NameID
    // it was given, and the IdP has to find the user from it.
    let idents = IdentDb::in_memory(IDP).with_persist_transient(true);
    let broker = broker();
    let decisions = ReleasePolicy::new(); // default format: transient
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &shared_signer().0,
        cert_der_b64: shared_signer().1,
    };
    let subject = subject_without_mail();
    let p = params(processed(false, false, vec![], None));
    let ResponseOutcome::Issued(issued) = create_authn_response(&engine, &p, &subject).unwrap()
    else {
        panic!("expected an issued response");
    };
    assert_eq!(
        issued.name_id.format.as_deref(),
        Some(constants::NAMEID_TRANSIENT)
    );
    assert_eq!(
        idents.find_local_id(&issued.name_id).unwrap().as_deref(),
        Some(subject.subject_id.as_str())
    );
}

// ── NameID construction through create_authn_response ──────────────────────

#[test]
fn no_name_id_policy_uses_decisions_default_format() {
    // `decisions.nameid_format(sp)` defaults to transient; a request with no
    // NameIDPolicy at all must fall back to it rather than erroring.
    let engine = engine();
    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            assert_eq!(
                issued.name_id.format.as_deref(),
                Some(constants::NAMEID_TRANSIENT)
            );
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

/// A `ProcessedAuthnRequest` carrying a `NameIDPolicy`.
fn processed_with_name_id_policy(
    format: Option<&str>,
    sp_name_qualifier: Option<&str>,
    allow_create: bool,
) -> ProcessedAuthnRequest {
    let mut p = processed(false, false, vec![], None);
    p.has_name_id_policy = true;
    p.requested_name_id_format = format.map(String::from);
    p.requested_sp_name_qualifier = sp_name_qualifier.map(String::from);
    p.allow_create = allow_create;
    p
}

#[test]
fn sp_name_qualifier_for_a_different_entity_is_denied() {
    // Regression: SPNameQualifier legitimately names an affiliation the
    // requester belongs to (saml-core-2.0-os 8.3.7), but only when the IdP
    // can verify that membership (AffiliationDescriptor), which this crate
    // does not implement. Honouring an arbitrary SPNameQualifier would let
    // SP A request SP B's persistent identifier for the same subject just
    // by setting NameIDPolicy/@SPNameQualifier to SP B's entity ID.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_TRANSIENT),
        Some("https://requester.example.org"),
        true,
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::InvalidNameIdPolicy,
            ..
        }
    ));
}

#[test]
fn sp_name_qualifier_matching_the_requester_is_honoured() {
    // The spec-legal, harmless case: SPNameQualifier explicitly set to the
    // requester's own entity ID (redundant, but not a cross-SP claim).
    let engine = engine();
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_TRANSIENT),
        Some(SP),
        true,
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            assert_eq!(issued.name_id.sp_name_qualifier.as_deref(), Some(SP));
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

#[test]
fn persistent_format_disallowed_create_denies_creation() {
    // Persistent format, AllowCreate=false, and no identifier already exists
    // for this (user, SP) pair: the IdP must refuse to fabricate one.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_PERSISTENT),
        None,
        false,
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::NameIdCreationNotAllowed,
            ..
        }
    ));
}

#[test]
fn persistent_default_without_name_id_policy_mints_the_default() {
    // Regression for the review finding "Missing NameIDPolicy incorrectly
    // disables persistent NameID creation": when the IdP's configured default
    // NameID format is persistent and the request carries no NameIDPolicy at
    // all, a first-time subject must be minted the default persistent
    // identifier - not denied with NameIdCreationNotAllowed. Only an explicit
    // NameIDPolicy with AllowCreate=false imposes that constraint (see the
    // sibling test above). A fresh IdentDb is used so the subject is genuinely
    // first-time for this (user, SP) pair.
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_nameid_format(constants::NAMEID_PERSISTENT),
    );
    let idents = IdentDb::in_memory(IDP);
    let (signer, cert) = fixture_signer();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &PassThroughRelease,
        idents: &idents,
        broker: &broker(),
        assertions: None,
        signer: &signer,
        cert_der_b64: cert,
    };
    // No NameIDPolicy: has_name_id_policy stays false, format is None.
    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => assert_eq!(
            issued.name_id.format.as_deref(),
            Some(constants::NAMEID_PERSISTENT),
            "the IdP's configured persistent default must be minted, not denied"
        ),
        other => panic!("expected Issued with the persistent default, got {other:?}"),
    }
}

// ── Two-consumer falsification test (ADR's own condition) ──────────────────

#[test]
fn proxy_shape_produces_compliant_response_without_release_policy_filter() {
    // A fixture IdP configured the way a proxy (e.g. tunnelbana) would use the
    // engine: `PassThroughRelease` (attributes already filtered upstream) and
    // an inline authn method carrying a non-empty `authenticating_authorities`
    // chain. If the engine can only produce a compliant response by routing
    // through `ReleasePolicy::filter`, the release seam is the wrong
    // abstraction — this is the ADR's own falsification condition, not a
    // nice-to-have.
    let engine = engine(); // release: &PassThroughRelease, see engine()
    let p = params(processed(false, false, vec![], None));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: Some("https://upstream.example.org/idp".to_string()),
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            // The pass-through attribute survived untouched (no
            // ReleasePolicy::filter ran on it).
            assert_eq!(issued.released_attribute_names.len(), 1);
            assert!(issued
                .xml
                .contains("<saml:AuthenticatingAuthority>https://upstream.example.org/idp</saml:AuthenticatingAuthority>"));
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

#[test]
fn cancelled_denial_response_is_signed_and_reports_authn_failed() {
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));

    let issued = crate::idp::orchestrator::create_denial_response(
        &engine,
        &p,
        &crate::idp::orchestrator::Denial::Cancelled,
    )
    .unwrap();

    // The Response envelope is signed (a populated SignatureValue, not the empty
    // template placeholder) and answers the request with AuthnFailed.
    assert!(issued.xml.contains("<ds:SignatureValue>"));
    assert!(!issued.xml.contains("<ds:SignatureValue/>"));
    assert!(issued.xml.contains(constants::STATUS_RESPONDER));
    assert!(issued.xml.contains(constants::STATUS_AUTHN_FAILED));
    assert!(issued.xml.contains("Authentication was cancelled"));
    assert!(issued.xml.contains("InResponseTo=\"_req1\""));
    // A denial has no assertion: the type carries none, and the XML has none.
    assert!(!issued.xml.contains("<saml:Assertion"));
}

#[test]
fn authn_failed_denial_response_differs_from_cancelled_only_in_message() {
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));

    let failed = crate::idp::orchestrator::create_denial_response(
        &engine,
        &p,
        &crate::idp::orchestrator::Denial::AuthnFailed,
    )
    .unwrap();

    assert!(failed.xml.contains(constants::STATUS_AUTHN_FAILED));
    assert!(failed.xml.contains("Authentication failed"));
    assert!(!failed.xml.contains("Authentication was cancelled"));
}
