//! Integration tests for the MDQ client.
//!
//! All HTTP is mocked via [`MockFetcher`] and time is driven by a controllable
//! clock, so the suite is fully deterministic and never touches the network.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};

use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
use gamlastan::metadata::MetadataError;
use gamlastan_mdq::{MdqClient, MdqError, MdqTransform, MetadataFetcher, RequiredRole};

// ── Mock transport ──────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct MockFetcher {
    exact: Arc<Mutex<HashMap<String, String>>>,
    default_body: Arc<Mutex<Option<String>>>,
    calls: Arc<AtomicUsize>,
    fail_first: Arc<AtomicUsize>,
    last_url: Arc<Mutex<Option<String>>>,
}

impl MockFetcher {
    /// Serve `body` for every request.
    fn serving(body: &str) -> Self {
        let m = MockFetcher::default();
        *m.default_body.lock().unwrap() = Some(body.to_string());
        m
    }

    fn set_default_body(&self, body: &str) {
        *self.default_body.lock().unwrap() = Some(body.to_string());
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_url(&self) -> Option<String> {
        self.last_url.lock().unwrap().clone()
    }

    /// Make the next `n` calls fail with a transport error.
    fn fail_next(&self, n: usize) {
        self.fail_first.store(n, Ordering::SeqCst);
    }
}

impl MetadataFetcher for MockFetcher {
    async fn fetch(&self, url: &str) -> Result<Bytes, MdqError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_url.lock().unwrap() = Some(url.to_string());

        if self.fail_first.load(Ordering::SeqCst) > 0 {
            self.fail_first.fetch_sub(1, Ordering::SeqCst);
            return Err(MdqError::Transport("mock failure".into()));
        }
        if let Some(body) = self.exact.lock().unwrap().get(url) {
            return Ok(Bytes::from(body.clone()));
        }
        if let Some(body) = self.default_body.lock().unwrap().clone() {
            return Ok(Bytes::from(body));
        }
        Err(MdqError::Http {
            status: 404,
            body: "not found".into(),
        })
    }
}

// ── Controllable clock ────────────────────────────────────────────────────────

#[derive(Clone)]
struct TestClock(Arc<Mutex<DateTime<Utc>>>);

impl TestClock {
    fn new() -> Self {
        TestClock(Arc::new(Mutex::new(
            Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        )))
    }
    fn advance(&self, secs: i64) {
        let mut t = self.0.lock().unwrap();
        *t += chrono::Duration::seconds(secs);
    }
    fn as_fn(&self) -> impl Fn() -> DateTime<Utc> + Send + Sync + 'static {
        let inner = self.0.clone();
        move || *inner.lock().unwrap()
    }
}

// ── Metadata fixtures ─────────────────────────────────────────────────────────

const MD_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

fn idp_metadata(
    entity_id: &str,
    cache_duration: Option<&str>,
    valid_until: Option<&str>,
) -> String {
    let cd = cache_duration
        .map(|c| format!(r#" cacheDuration="{c}""#))
        .unwrap_or_default();
    let vu = valid_until
        .map(|v| format!(r#" validUntil="{v}""#))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="{MD_NS}" entityID="{entity_id}"{cd}{vu}>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
    )
}

fn sp_entity(entity_id: &str) -> String {
    sp_entity_with_hints(entity_id, None, None)
}

fn sp_entity_with_hints(
    entity_id: &str,
    cache_duration: Option<&str>,
    valid_until: Option<&str>,
) -> String {
    let cd = cache_duration
        .map(|c| format!(r#" cacheDuration="{c}""#))
        .unwrap_or_default();
    let vu = valid_until
        .map(|v| format!(r#" validUntil="{v}""#))
        .unwrap_or_default();
    format!(
        r#"<md:EntityDescriptor xmlns:md="{MD_NS}" entityID="{entity_id}"{cd}{vu}>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{entity_id}/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
    )
}

fn aggregate(entity_ids: &[&str]) -> String {
    let children: String = entity_ids.iter().map(|id| sp_entity(id)).collect();
    aggregate_with_children(&children, None, None)
}

fn aggregate_with_children(
    children: &str,
    cache_duration: Option<&str>,
    valid_until: Option<&str>,
) -> String {
    let cd = cache_duration
        .map(|c| format!(r#" cacheDuration="{c}""#))
        .unwrap_or_default();
    let vu = valid_until
        .map(|v| format!(r#" validUntil="{v}""#))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0"?><md:EntitiesDescriptor xmlns:md="{MD_NS}" Name="urn:test"{cd}{vu}>{children}</md:EntitiesDescriptor>"#
    )
}

fn first_entity_id_in_document(xml: &str) -> Option<&str> {
    let entity_start = xml.find("<md:EntityDescriptor")?;
    let entity = &xml[entity_start..];
    let attr_start = entity.find("entityID=\"")? + "entityID=\"".len();
    let value = &entity[attr_start..];
    let attr_end = value.find('"')?;
    Some(&value[..attr_end])
}

// ── Signing helpers (positive signature path) ─────────────────────────────────

const SIGN_CERT_PEM: &str = include_str!("fixtures/sign-cert.pem");
const SIGN_KEY_PEM: &[u8] = include_bytes!("fixtures/sign-key.pem");

fn cert_b64() -> String {
    SIGN_CERT_PEM
        .lines()
        .filter(|l| !l.contains("CERTIFICATE"))
        .collect::<String>()
}

fn signer() -> SamlSigner {
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64())
        .unwrap();
    let mut key = loader::load_pem_auto(SIGN_KEY_PEM, None).unwrap();
    key.usage = KeyUsage::Sign;
    key.x509_chain = vec![cert_der];
    let mut km = KeysManager::new();
    km.add_key(key);
    SamlSigner::new(km)
}

fn signature_template(reference_id: &str, cert: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    )
}

/// Build a signed IdP EntityDescriptor with the given ID/entityID.
fn signed_idp(entity_id: &str, id: &str) -> String {
    let template = signature_template(id, &cert_b64());
    let xml = format!(
        r#"<md:EntityDescriptor xmlns:md="{MD_NS}" ID="{id}" entityID="{entity_id}">{template}<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    );
    signer().sign_enveloped(&xml).unwrap()
}

/// Build an XML Signature Wrapping (XSW) attack document.
///
/// The parsed root is an `EntitiesDescriptor` (`agg_id`) whose direct-child
/// signature cryptographically covers a **sibling** bystander `EntityDescriptor`
/// (`signed_id`, for an unrelated entity) — a relocation bergshamra's own strict
/// check *permits* (siblings of the Signature are allowed), so it lands squarely
/// on gamlastan's verified-reference binding. Alongside the genuinely-signed
/// bystander, the attacker injects a second, **unsigned** `EntityDescriptor`
/// advertising the requested `entity_id` and an attacker `SingleSignOnService`;
/// that is the entity `select_entity` would return.
///
/// The aggregate root itself is **not** signed (the reference targets the
/// sibling, not `agg_id`), so binding the signature to the parsed/returned
/// element must reject it. A decoy `#agg_id` string satisfies the legacy
/// substring signing-profile check so only the cryptographic binding can catch
/// the wrap.
fn wrapping_attack_idp(entity_id: &str, agg_id: &str, signed_id: &str) -> String {
    let template = signature_template(signed_id, &cert_b64());
    // Decoy "#agg_id" so the legacy substring profile check passes; only the
    // cryptographic reference binding can then catch the wrap.
    let decoy = format!("#{agg_id}");
    let xml = format!(
        r#"<md:EntitiesDescriptor xmlns:md="{MD_NS}" ID="{agg_id}">{template}<md:Extensions><md:PublisherInfo xmlns:mdrpi="urn:decoy" publisher="{decoy}"/></md:Extensions><md:EntityDescriptor ID="{signed_id}" entityID="https://bystander.example.com"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://bystander.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor><md:EntityDescriptor ID="_evil" entityID="{entity_id}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://attacker.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"#
    );
    signer().sign_enveloped(&xml).unwrap()
}

// ── Dynamic-mode tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn dynamic_get_success() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher).allow_unverified();
    let ed = client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
    assert!(ed.is_idp());
    assert_eq!(
        ed.idp_sso_descriptors()[0].single_sign_on_services[0].location,
        "https://idp.example.com/sso"
    );
}

#[tokio::test]
async fn dynamic_caching_hits_server_once() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client =
        MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone()).allow_unverified();
    for _ in 0..3 {
        client.get("https://idp.example.com/idp").await.unwrap();
    }
    assert_eq!(fetcher.calls(), 1, "cached after first fetch");
    assert_eq!(client.cache_len(), 1);
}

#[tokio::test]
async fn dynamic_cache_duration_expiry_refetches() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata(
        "https://idp.example.com/idp",
        Some("PT60S"),
        None,
    ));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn());

    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 1);
    // Still within cacheDuration.
    clock.advance(30);
    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 1);
    // Past cacheDuration -> refetch.
    clock.advance(40);
    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 2);
}

#[tokio::test]
async fn dynamic_valid_until_past_refetches() {
    let clock = TestClock::new();
    // validUntil in 2025-01-01T00:05:00Z; clock starts at 2025-01-01T00:00:00Z.
    let fetcher = MockFetcher::serving(&idp_metadata(
        "https://idp.example.com/idp",
        None,
        Some("2025-01-01T00:05:00Z"),
    ));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn());

    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 1);
    // Advance past validUntil -> invalid -> refetch, then reject the expired document.
    clock.advance(10 * 60);
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(matches!(err, MdqError::Metadata(MetadataError::Expired(_))));
    assert_eq!(fetcher.calls(), 2);
}

#[tokio::test]
async fn dynamic_expired_metadata_rejected_immediately() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata(
        "https://idp.example.com/idp",
        None,
        Some("2024-12-31T23:59:59Z"),
    ));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .allow_unverified()
        .with_clock(clock.as_fn());

    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(
        matches!(err, MdqError::Metadata(MetadataError::Expired(_))),
        "got {err:?}"
    );
}

#[tokio::test]
async fn dynamic_fallback_ttl_applies_without_cache_duration() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_fallback_ttl(Duration::from_secs(100))
        .with_clock(clock.as_fn());

    client.get("https://idp.example.com/idp").await.unwrap();
    clock.advance(50);
    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 1, "within fallback ttl");
    clock.advance(60);
    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(fetcher.calls(), 2, "past fallback ttl");
}

#[tokio::test]
async fn dynamic_http_error_propagates() {
    let fetcher = MockFetcher::default(); // no body configured -> 404
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher);
    let err = client.get("https://nope.example.com").await.unwrap_err();
    assert!(matches!(err, MdqError::Http { status: 404, .. }));
    assert!(err.to_string().contains("404"));
}

#[tokio::test]
async fn dynamic_invalid_xml_is_parse_error() {
    let fetcher = MockFetcher::serving("this is not xml");
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher);
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(matches!(err, MdqError::Parse(_)), "got {err:?}");
}

#[tokio::test]
async fn dynamic_role_gate_rejects_wrong_role() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .allow_unverified()
        .require_role(RequiredRole::Sp);
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(
        matches!(err, MdqError::RoleMissing(RequiredRole::Sp)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn dynamic_role_gate_accepts_matching_role() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .allow_unverified()
        .require_role(RequiredRole::Idp);
    assert!(client.get("https://idp.example.com/idp").await.is_ok());
}

#[tokio::test]
async fn transform_url_encoded_path() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client =
        MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone()).allow_unverified();
    client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(
        fetcher.last_url().unwrap(),
        "https://mdq.example.org/https%3A%2F%2Fidp.example.com%2Fidp"
    );
}

#[tokio::test]
async fn transform_sha1_path() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_transform(MdqTransform::Sha1);
    client.get("https://idp.example.com/idp").await.unwrap();
    let url = fetcher.last_url().unwrap();
    assert!(
        url.starts_with("https://mdq.example.org/%7Bsha1%7D"),
        "got {url}"
    );
    assert_eq!(url.rsplit("%7D").next().unwrap().len(), 40);
}

// ── Aggregate tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn aggregate_selects_matching_child() {
    let body = aggregate(&["https://sp-a.example.com", "https://sp-b.example.com"]);
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher).allow_unverified();
    let ed = client.get("https://sp-b.example.com").await.unwrap();
    assert_eq!(ed.entity_id, "https://sp-b.example.com");
    assert!(ed.is_sp());
}

#[tokio::test]
async fn aggregate_missing_child_errors() {
    let body = aggregate(&["https://sp-a.example.com"]);
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher).allow_unverified();
    let err = client.get("https://sp-z.example.com").await.unwrap_err();
    assert!(matches!(err, MdqError::EntityNotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn aggregate_parent_cache_duration_takes_precedence() {
    let clock = TestClock::new();
    let child = sp_entity_with_hints("https://sp.example.com", Some("PT1H"), None);
    let body = aggregate_with_children(&child, Some("PT60S"), None);
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn());

    client.get("https://sp.example.com").await.unwrap();
    assert_eq!(fetcher.calls(), 1);

    clock.advance(70);
    client.get("https://sp.example.com").await.unwrap();
    assert_eq!(fetcher.calls(), 2, "parent cacheDuration should win");
}

#[tokio::test]
async fn aggregate_parent_valid_until_takes_precedence() {
    let clock = TestClock::new();
    let child = sp_entity_with_hints("https://sp.example.com", None, Some("2025-01-01T02:00:00Z"));
    let body = aggregate_with_children(&child, None, Some("2025-01-01T00:05:00Z"));
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn());

    client.get("https://sp.example.com").await.unwrap();
    clock.advance(10 * 60);

    let err = client.get("https://sp.example.com").await.unwrap_err();
    assert!(
        matches!(err, MdqError::Metadata(MetadataError::Expired(_))),
        "got {err:?}"
    );
    assert_eq!(
        fetcher.calls(),
        2,
        "expired aggregate should refetch then fail"
    );
}

// ── Signature tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn signed_metadata_verifies_with_cert() {
    let body = signed_idp("https://idp.example.com/idp", "_entity_signed_1");
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .add_signing_cert_pem(SIGN_CERT_PEM.as_bytes())
        .unwrap();
    let ed = client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
}

#[tokio::test]
async fn signature_wrapping_over_sibling_element_is_rejected() {
    // End-to-end XML Signature Wrapping fixture (Finding #1): the EntityDescriptor
    // MDQ parses and would return (`_outer`) carries a real, valid signature, but
    // that signature cryptographically covers a *sibling* bystander element
    // (`_signed`) rather than `_outer`. A decoy "#_outer" string satisfies the
    // legacy substring profile check, so the verified-reference binding is the
    // only control that can catch the wrap. This locks in the binding control
    // end-to-end, not just at the `reference_uri_covers` unit level.
    let body = wrapping_attack_idp("https://idp.example.com/idp", "_outer", "_signed");
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .add_signing_cert_pem(SIGN_CERT_PEM.as_bytes())
        .unwrap();
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(
        matches!(err, MdqError::SignatureNotBound(_)),
        "wrapped sibling signature must be rejected as unbound; got {err:?}"
    );
}

#[tokio::test]
async fn tampered_signed_metadata_is_rejected() {
    let body = signed_idp("https://idp.example.com/idp", "_entity_signed_2").replace(
        "https://idp.example.com/sso",
        "https://attacker.example.com/sso",
    );
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .add_signing_cert_pem(SIGN_CERT_PEM.as_bytes())
        .unwrap();
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(matches!(err, MdqError::SignatureInvalid(_)), "got {err:?}");
}

#[tokio::test]
async fn unsigned_metadata_rejected_when_cert_configured() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .add_signing_cert_pem(SIGN_CERT_PEM.as_bytes())
        .unwrap();
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(matches!(err, MdqError::Unsigned), "got {err:?}");
}

#[tokio::test]
async fn unsigned_metadata_accepted_with_allow_unverified() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher).allow_unverified();
    assert!(client.get("https://idp.example.com/idp").await.is_ok());
}

#[tokio::test]
async fn unverified_metadata_rejected_without_opt_in() {
    // A no-cert client must refuse metadata unless `allow_unverified()` is set;
    // the MDQ server is untrusted, so unverified metadata has no authenticity.
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher);
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(
        matches!(err, MdqError::VerificationNotConfigured),
        "got {err:?}"
    );
}

#[tokio::test]
async fn entity_id_mismatch_rejected_unsigned() {
    // Server answers a query for entity A with metadata for entity B.
    let fetcher = MockFetcher::serving(&idp_metadata("https://evil.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher).allow_unverified();
    let err = client
        .get("https://good.example.com/idp")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            MdqError::EntityIdMismatch { ref returned, ref requested }
                if returned == "https://evil.example.com/idp"
                    && requested == "https://good.example.com/idp"
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn signed_but_substituted_entity_rejected() {
    // The substituted document carries a VALID federation signature (for evil),
    // yet must be rejected because its entityID is not the one requested. This is
    // the core MDQ binding: a valid signature attests provenance, not the query.
    let body = signed_idp("https://evil.example.com/idp", "_entity_signed_sub");
    let fetcher = MockFetcher::serving(&body);
    let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
        .add_signing_cert_pem(SIGN_CERT_PEM.as_bytes())
        .unwrap();
    let err = client
        .get("https://good.example.com/idp")
        .await
        .unwrap_err();
    assert!(
        matches!(err, MdqError::EntityIdMismatch { .. }),
        "got {err:?}"
    );
}

// ── Static-mode tests ──────────────────────────────────────────────────────────

fn temp_metadata_file(contents: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("mdq-test-{unique}.xml"));
    std::fs::write(&path, contents).unwrap();
    path
}

#[tokio::test]
async fn static_from_file_ignores_requested_entity_id() {
    let path = temp_metadata_file(&idp_metadata("https://idp.example.com/idp", None, None));
    // The configured entityID must match the loaded metadata (binding enforced).
    let client = MdqClient::new("https://unused/")
        .allow_unverified()
        .into_static_file(&path, "https://idp.example.com/idp")
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(client.is_static());
    assert_eq!(
        client.static_entity_id().as_deref(),
        Some("https://idp.example.com/idp")
    );
    // The per-call requested entityID is ignored in static mode: any value
    // returns the single configured entity.
    let ed = client
        .get("https://something-else.example.com")
        .await
        .unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
    let ed = client.get("").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
}

#[tokio::test]
async fn static_from_file_missing_is_error() {
    // Note: `Result<MdqClient, _>::unwrap_err` would require MdqClient: Debug,
    // so match on the result directly.
    let result = MdqClient::new("https://unused/")
        .into_static_file("/nonexistent/path/metadata.xml", "https://idp.example.com");
    assert!(matches!(result, Err(MdqError::Io(_))));
}

#[tokio::test]
async fn static_from_file_rejects_entity_id_mismatch() {
    // A file whose entityID differs from the configured one must be rejected.
    let path = temp_metadata_file(&idp_metadata("https://idp.example.com/idp", None, None));
    let result = MdqClient::new("https://unused/")
        .allow_unverified()
        .into_static_file(&path, "https://configured.example.com/idp");
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(result, Err(MdqError::EntityIdMismatch { .. })));
}

#[tokio::test]
async fn static_from_file_stops_serving_expired_metadata() {
    let clock = TestClock::new();
    let path = temp_metadata_file(&idp_metadata(
        "https://idp.example.com/idp",
        None,
        Some("2025-01-01T00:05:00Z"),
    ));
    let client = MdqClient::new("https://unused/")
        .allow_unverified()
        .with_clock(clock.as_fn())
        .into_static_file(&path, "https://idp.example.com/idp")
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    client.get("").await.unwrap();
    clock.advance(10 * 60);

    let err = client.get("").await.unwrap_err();
    assert!(
        matches!(err, MdqError::Metadata(MetadataError::Expired(_))),
        "got {err:?}"
    );
}

#[tokio::test]
async fn static_from_url_success() {
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    let client = MdqClient::with_fetcher("https://unused/", fetcher)
        .allow_unverified()
        .into_static_url(
            "https://idp.example.com/metadata",
            "https://idp.example.com/idp",
        )
        .await;
    assert!(client.is_static());
    let ed = client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
}

#[tokio::test]
async fn static_from_url_refetches_after_expiry() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata(
        "https://idp.example.com/idp",
        None,
        Some("2025-01-01T00:00:05Z"),
    ));
    let client = MdqClient::with_fetcher("https://unused/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn())
        .into_static_url(
            "https://idp.example.com/metadata",
            "https://idp.example.com/idp",
        )
        .await;

    assert_eq!(fetcher.calls(), 1);

    fetcher.set_default_body(&idp_metadata(
        "https://idp.example.com/idp",
        None,
        Some("2025-01-01T01:00:00Z"),
    ));
    clock.advance(10);

    let ed = client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
    assert_eq!(
        fetcher.calls(),
        2,
        "expired static URL metadata must be reloaded"
    );
}

#[tokio::test]
async fn static_from_url_lazy_retry() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    fetcher.fail_next(1); // initial construction fetch fails

    let client = MdqClient::with_fetcher("https://unused/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn())
        .into_static_url(
            "https://idp.example.com/metadata",
            "https://idp.example.com/idp",
        )
        .await;

    // Still static mode, but not yet loaded.
    assert!(client.is_static());

    // Before retry_after: deferred without contacting the server.
    let calls_before = fetcher.calls();
    let err = client.get("https://idp.example.com/idp").await.unwrap_err();
    assert!(matches!(err, MdqError::StaticUnavailable(_)), "got {err:?}");
    assert_eq!(fetcher.calls(), calls_before, "no fetch before retry_after");

    // After advancing past the backoff, the retry succeeds.
    clock.advance(6);
    let ed = client.get("https://idp.example.com/idp").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
}

#[tokio::test]
async fn static_from_url_backoff_doubles_on_repeated_failure() {
    let clock = TestClock::new();
    let fetcher = MockFetcher::serving(&idp_metadata("https://idp.example.com/idp", None, None));
    fetcher.fail_next(2); // construction + one retry fail

    // t0. Construction fetch fails -> retry_after = t0+5s, backoff = 5s.
    let client = MdqClient::with_fetcher("https://unused/", fetcher.clone())
        .allow_unverified()
        .with_clock(clock.as_fn())
        .into_static_url(
            "https://idp.example.com/metadata",
            "https://idp.example.com/idp",
        )
        .await;

    // t0+6s: past the 5s window -> retry runs and fails -> backoff doubles to 10s,
    // retry_after = t0+16s.
    clock.advance(6);
    assert!(client.get("x").await.is_err());

    // t0+12s: if the backoff had stayed at 5s (retry_after t0+11s) this would
    // fetch; it is deferred instead, proving the backoff doubled to 10s.
    clock.advance(6);
    let calls = fetcher.calls();
    let err = client.get("x").await.unwrap_err();
    assert!(matches!(err, MdqError::StaticUnavailable(_)));
    assert_eq!(fetcher.calls(), calls, "deferred within doubled backoff");

    // t0+18s: past the 10s window, the retry runs and (failures exhausted) succeeds.
    clock.advance(6);
    let ed = client.get("x").await.unwrap();
    assert_eq!(ed.entity_id, "https://idp.example.com/idp");
}

#[tokio::test]
#[ignore = "large local fixture"]
async fn static_from_real_edugain_file_loads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../edugain-v2.xml");
    let xml = std::fs::read_to_string(&path).unwrap();
    let entity_id = first_entity_id_in_document(&xml)
        .expect("aggregate should contain at least one EntityDescriptor")
        .to_string();

    let client = MdqClient::new("https://unused/")
        .allow_unverified()
        .into_static_file(&path, &entity_id)
        .unwrap();
    let entity = client.get("").await.unwrap();
    assert_eq!(entity.entity_id, entity_id);
}
