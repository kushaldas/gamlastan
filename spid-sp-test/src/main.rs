// SPID SAML Conformance Test SP
//
// This binary implements a SPID-compliant Service Provider (SP) for testing
// against the italia/spid-saml-check Docker container.
//
// Usage:
//   1. Start spid-saml-check Docker container (port 8443)
//   2. Run this binary (listens on https://localhost:8443 for SP, default 8080)
//   3. Navigate to https://localhost:8443 to access the validator
//   4. Configure the validator with the SP metadata URL
//   5. Run the conformance tests
//
// Optional HSM-backed SP signing key:
//   GAMLASTAN_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//   GAMLASTAN_PKCS11_PIN=1234 \
//   GAMLASTAN_PKCS11_LABEL=saml-signing-key \
//   GAMLASTAN_PKCS11_CERT=/path/to/sp-cert.pem \
//   cargo run -p spid-sp-test

use std::fs;
use std::io;
use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer};
use log::info;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};

use gamlastan::bindings::redirect::{redirect_encode, RedirectEncodeParams};
use gamlastan::core::assertion::issuer::Issuer;
use gamlastan::core::constants;
use gamlastan::core::identifiers::{SamlId, SamlVersion};
use gamlastan::core::protocol::request::{
    AuthnContextComparison, AuthnRequest, RequestBase, RequestedAuthnContext,
};
use gamlastan::core::protocol::response::Response;
use gamlastan::crypto::{SamlSigner, SamlVerifier};
use gamlastan::metadata::types::contact::{ContactPerson, ContactType};
use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
use gamlastan::metadata::types::key_descriptor::{KeyDescriptor, KeyUse};
use gamlastan::metadata::types::localized::{LocalizedName, LocalizedUri};
use gamlastan::metadata::types::organization::Organization;
use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use gamlastan::metadata::types::sp::{
    AttributeConsumingService, RequestedAttribute, SpSsoDescriptor,
};
use gamlastan::metadata::types::spid::{SpidContactExtensions, SpidSpType};
use gamlastan::security::{InMemoryReplayCache, ReplayCache, SecurityConfig};
use gamlastan::xml::serialize::SamlSerialize;

use chrono::Utc;

// ── Constants ──────────────────────────────────────────────────────────────

/// SPID AuthnContext class references
const SPID_L1: &str = "https://www.spid.gov.it/SpidL1";
const SPID_L2: &str = "https://www.spid.gov.it/SpidL2";
#[allow(dead_code)]
const SPID_L3: &str = "https://www.spid.gov.it/SpidL3";

// ── App State ──────────────────────────────────────────────────────────────

struct AppState {
    /// Our SP entity ID
    entity_id: String,
    /// Our ACS URL
    acs_url: String,
    /// Our SLO URL
    slo_url: String,
    /// Our metadata URL
    #[allow(dead_code)]
    metadata_url: String,
    /// The IdP SSO endpoint (spid-saml-check validator)
    idp_sso_url: String,
    /// The IdP SLO endpoint
    #[allow(dead_code)]
    idp_slo_url: String,
    /// The IdP entity ID
    idp_entity_id: String,
    /// X.509 cert for KeyInfo (base64 DER)
    cert_b64: String,
    /// SAML signer
    signer: Arc<SamlSigner>,
    /// SAML verifier (for IdP responses) - configured with IdP's certificate
    idp_verifier: Arc<SamlVerifier>,
    /// Pending request IDs (maps request_id -> authn_context_class_ref)
    pending_requests: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// Replay cache for assertion ID deduplication
    #[allow(dead_code)]
    replay_cache: Arc<InMemoryReplayCache>,
    /// Security configuration for response validation
    security_config: SecurityConfig,
}

struct Pkcs11SigningConfig {
    module: String,
    pin: String,
    label: String,
    cert_path: String,
}

fn register_replay_ids(
    replay_cache: &dyn ReplayCache,
    security_config: &SecurityConfig,
    response: &Response,
) -> bool {
    let fallback_expiry = Utc::now()
        + chrono::TimeDelta::seconds(
            (security_config.max_assertion_age_seconds + security_config.clock_skew_seconds) as i64,
        );

    if !replay_cache.check_and_insert(&response.base.id, fallback_expiry) {
        return false;
    }

    for assertion in &response.assertions {
        let expiry = assertion
            .conditions
            .as_ref()
            .and_then(|conditions| conditions.not_on_or_after)
            .unwrap_or(fallback_expiry);
        if !replay_cache.check_and_insert(&assertion.id, expiry) {
            return false;
        }
    }

    replay_cache.cleanup();
    true
}

// ── Metadata Handler ───────────────────────────────────────────────────────

/// Generate SPID-compliant SP metadata (signed).
async fn sp_metadata(state: web::Data<AppState>) -> HttpResponse {
    let metadata_id = format!("_{}", uuid_v4());

    let metadata_xml = build_sp_metadata(&state, &metadata_id);

    // Insert signature template right after the opening <md:EntityDescriptor ...> tag
    let signed_xml = sign_metadata(&state, &metadata_xml, &metadata_id);

    match signed_xml {
        Ok(xml) => HttpResponse::Ok()
            .content_type("application/samlmetadata+xml")
            .body(xml),
        Err(e) => {
            log::error!("Failed to sign metadata: {e}");
            HttpResponse::InternalServerError()
                .content_type("text/plain; charset=utf-8")
                .body("Failed to sign SP metadata")
        }
    }
}

/// Build the SP metadata XML (unsigned).
fn build_sp_metadata(state: &AppState, metadata_id: &str) -> String {
    let key_info_xml = gamlastan::crypto::build_x509_key_info(&[&state.cert_b64]);

    let key_descriptor = KeyDescriptor {
        use_: Some(KeyUse::Signing),
        key_info_xml: key_info_xml.clone(),
        encryption_methods: vec![],
    };

    // Build SLO endpoints
    let slo_services = vec![
        Endpoint::new(constants::BINDING_HTTP_POST, &state.slo_url),
        Endpoint::new(constants::BINDING_HTTP_REDIRECT, &state.slo_url),
    ];

    // Build ACS endpoint (HTTP-POST only, as required by SPID)
    let acs = IndexedEndpoint::new_default(
        Endpoint::new(constants::BINDING_HTTP_POST, &state.acs_url),
        0,
    );

    // Build AttributeConsumingService (SPID-required)
    let attr_consuming = AttributeConsumingService {
        index: 0,
        is_default: Some(true),
        service_names: vec![LocalizedName {
            lang: "it".to_string(),
            value: "Test SPID SP".to_string(),
        }],
        service_descriptions: vec![LocalizedName {
            lang: "it".to_string(),
            value: "Servizio di test per validazione SPID".to_string(),
        }],
        requested_attributes: vec![
            spid_requested_attr("name"),
            spid_requested_attr("familyName"),
            spid_requested_attr("fiscalNumber"),
            spid_requested_attr("email"),
        ],
    };

    let sp_sso = SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase {
                id: None,
                valid_until: None,
                cache_duration: None,
                protocol_support_enumeration: vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ],
                error_url: None,
                extensions: None,
                key_descriptors: vec![key_descriptor],
                organization: None,
                contact_persons: vec![],
            },
            artifact_resolution_services: vec![],
            single_logout_services: slo_services,
            manage_name_id_services: vec![],
            name_id_formats: vec![constants::NAMEID_TRANSIENT.to_string()],
        },
        authn_requests_signed: Some(true), // SPID mandatory
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![acs],
        attribute_consuming_services: vec![attr_consuming],
    };

    // Build Organization (SPID-mandatory)
    let organization = Organization {
        extensions: None,
        organization_names: vec![LocalizedName {
            lang: "it".to_string(),
            value: "Test SPID Service Provider".to_string(),
        }],
        organization_display_names: vec![LocalizedName {
            lang: "it".to_string(),
            value: "Test SPID SP".to_string(),
        }],
        organization_urls: vec![LocalizedUri {
            lang: "it".to_string(),
            value: "https://sp.example.com".to_string(),
        }],
    };

    // Build SPID-specific ContactPerson with typed extensions
    let spid_extensions = SpidContactExtensions {
        sp_type: SpidSpType::Public,
        vat_number: Some("VATIT-12345678901".into()),
        fiscal_code: Some("XYZABC80A01H501T".into()),
        ipa_code: None,
        municipality: None,
        province: None,
        country: None,
    };

    let spid_contact = ContactPerson {
        contact_type: ContactType::Other,
        extensions: Some(spid_extensions.to_extensions()),
        company: Some("Test SPID Service Provider".to_string()),
        given_name: None,
        sur_name: None,
        email_addresses: vec!["tech@sp.example.com".to_string()],
        telephone_numbers: vec!["+390123456789".to_string()],
    };

    let entity = EntityDescriptor {
        entity_id: state.entity_id.clone(),
        id: Some(metadata_id.to_string()),
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![sp_sso],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: Some(organization),
        contact_persons: vec![spid_contact],
        additional_metadata_locations: vec![],
    };

    entity
        .to_xml_string()
        .expect("Failed to serialize metadata")
}

/// Helper: create a SPID RequestedAttribute with basic name format.
fn spid_requested_attr(name: &str) -> RequestedAttribute {
    use gamlastan::core::assertion::attribute::Attribute;
    RequestedAttribute {
        attribute: Attribute {
            name: name.to_string(),
            name_format: Some(constants::ATTRNAME_FORMAT_BASIC.to_string()),
            friendly_name: None,
            values: vec![],
        },
        is_required: Some(true),
    }
}

/// Sign metadata XML by inserting a signature template and using the SAML signer.
fn sign_metadata(
    state: &AppState,
    metadata_xml: &str,
    metadata_id: &str,
) -> Result<String, String> {
    let signature_method_uri = state
        .signer
        .signature_method_uri()
        .map_err(|e| format!("Unsupported signing algorithm: {e}"))?;
    let sig_template = gamlastan_actix::idp::signature_template(
        metadata_id,
        &state.cert_b64,
        signature_method_uri,
    );
    let xml_with_sig = gamlastan_actix::idp::insert_signature_after_element(
        metadata_xml,
        "md:EntityDescriptor",
        &sig_template,
    )
    .map_err(|e| format!("Failed to insert signature template: {e}"))?;

    // Sign using bergshamra
    state
        .signer
        .sign_enveloped(&xml_with_sig)
        .map_err(|e| format!("Signing failed: {e}"))
}

// ── Login Handler ──────────────────────────────────────────────────────────

/// Initiate SPID login - create AuthnRequest and redirect to IdP.
async fn sp_login(state: web::Data<AppState>, query: web::Query<LoginParams>) -> HttpResponse {
    let spid_level = query.level.as_deref().unwrap_or("SpidL1");
    let authn_context = match spid_level {
        "SpidL2" => SPID_L2,
        "SpidL3" => SPID_L3,
        _ => SPID_L1,
    };

    let request_id = SamlId::generate().as_str().to_string();

    // Build SPID-compliant AuthnRequest
    let authn_request = AuthnRequest {
        base: RequestBase {
            id: request_id.clone(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: Some(state.idp_sso_url.clone()),
            consent: None,
            issuer: Some(Issuer {
                value: state.entity_id.clone(),
                format: Some(constants::NAMEID_ENTITY.to_string()),
                name_qualifier: Some(state.entity_id.clone()),
                sp_name_qualifier: None,
            }),
            has_signature: false,
        },
        subject: None,
        name_id_policy: Some(gamlastan::core::assertion::name_id::NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        }),
        conditions: None,
        requested_authn_context: Some(RequestedAuthnContext {
            authn_context_class_refs: vec![authn_context.to_string()],
            authn_context_decl_refs: vec![],
            comparison: AuthnContextComparison::Exact,
        }),
        scoping: None,
        force_authn: if authn_context != SPID_L1 {
            Some(true)
        } else {
            None
        },
        is_passive: None, // Must NOT be present for SPID
        assertion_consumer_service_index: Some(0),
        assertion_consumer_service_url: None,
        protocol_binding: None,
        attribute_consuming_service_index: Some(0),
        provider_name: None,
        extensions: None,
    };

    // Serialize to XML
    let xml = authn_request
        .to_xml_string()
        .expect("Failed to serialize AuthnRequest");

    info!("AuthnRequest XML:\n{xml}");

    // Store pending request ID with the requested authn context
    state
        .pending_requests
        .lock()
        .unwrap()
        .insert(request_id.clone(), authn_context.to_string());

    // Encode using HTTP-Redirect binding with signature
    let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    // RelayState must not be immediately intelligible (SPID requirement)
    // Use an opaque random token instead of a readable URL
    let relay_token = format!("rs_{}", uuid_v4().replace('-', ""));
    let relay = gamlastan::bindings::relay_state::RelayState::new(&relay_token)
        .expect("RelayState validation failed");
    let redirect_url = redirect_encode(&RedirectEncodeParams {
        saml_xml: xml.as_bytes(),
        is_request: true,
        destination: &state.idp_sso_url,
        relay_state: Some(&relay),
        signer: Some((&*state.signer, sig_alg)),
    })
    .expect("Failed to encode redirect");

    info!("Redirecting to: {redirect_url}");

    HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .append_header(("Cache-Control", "no-cache, no-store"))
        .append_header(("Pragma", "no-cache"))
        .finish()
}

#[derive(serde::Deserialize)]
struct LoginParams {
    level: Option<String>,
}

// ── ACS Handler (Assertion Consumer Service) ───────────────────────────────

/// SPID AuthnContext class refs that are considered valid.
const SPID_VALID_ACRS: &[&str] = &[
    "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
];

/// Handle SAML Response from IdP (HTTP-POST binding).
///
/// This handler performs full SPID-compliant validation:
/// 1. Base64 decode the SAMLResponse
/// 2. Verify XML signatures (Response and/or Assertion level)
/// 3. Parse the SAML Response
/// 4. Run SPID-specific structural checks
/// 5. Run the 32-check assertion validation
/// 6. Return HTTP 200 for valid responses, HTTP 400/403/500 for invalid
async fn sp_acs(state: web::Data<AppState>, form: web::Form<AcsForm>) -> HttpResponse {
    info!("ACS: received SAML Response");

    // ── Step 1: Decode base64 ──────────────────────────────────────────
    let saml_response_b64 = &form.SAMLResponse;
    let _relay_state = form.RelayState.as_deref();

    use base64::Engine;
    let xml_bytes = match base64::engine::general_purpose::STANDARD.decode(saml_response_b64) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Failed to decode SAML Response: {e}");
            return HttpResponse::BadRequest().body(format!("Invalid base64: {e}"));
        }
    };

    let xml_str = match String::from_utf8(xml_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Invalid UTF-8 in SAML Response: {e}");
            return HttpResponse::BadRequest().body("Invalid UTF-8");
        }
    };

    info!(
        "SAML Response XML (first 500 chars):\n{}",
        &xml_str[..xml_str.len().min(500)]
    );

    // ── Step 2: Quick structural XML checks before full parse ──────────
    // These catch malformed XML that the parser might reject or that indicate attacks.

    // Check for XSLT injection attacks (test: xslt)
    if xml_str.contains("xsl:stylesheet") || xml_str.contains("xsl:transform") {
        log::warn!("ACS: XSLT injection detected");
        return HttpResponse::BadRequest().body("XSLT injection detected");
    }

    // ── Step 3: Verify signatures ──────────────────────────────────────
    // We verify signatures on the raw XML before parsing into typed structs.
    // This catches wrong certs, missing signatures, XSW attacks, etc.
    let sig_verified = match state.idp_verifier.verify_enveloped(&xml_str) {
        Ok(result) => {
            if result.is_valid() {
                info!("ACS: Signature verification succeeded");
                true
            } else {
                log::warn!("ACS: Signature verification failed: invalid signature");
                false
            }
        }
        Err(e) => {
            // ds:Object rejection (E91) or other crypto errors
            log::warn!("ACS: Signature verification error: {e}");
            false
        }
    };

    // ── Step 4: Parse the SAML Response ────────────────────────────────
    let doc = match gamlastan::xml::uppsala::parse(&xml_str) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to parse SAML Response XML: {e}");
            return HttpResponse::BadRequest().body(format!("XML parse error: {e}"));
        }
    };

    use gamlastan::xml::deserialize::SamlDeserialize;
    let doc_elem = match doc.document_element() {
        Some(e) => e,
        None => {
            return HttpResponse::BadRequest().body("Empty XML document");
        }
    };

    let response_ref =
        match gamlastan::core::protocol::response::ResponseRef::from_xml(&doc, doc_elem) {
            Ok(r) => r,
            Err(e) => {
                // Many SPID tests send malformed XML that fails at parse time.
                // This is expected - return 400 for parse errors.
                log::warn!("Failed to parse SAML Response: {e}");
                return HttpResponse::BadRequest().body(format!("SAML parse error: {e}"));
            }
        };

    let response: Response = response_ref.to_owned();

    // ── Step 5: Check status code ──────────────────────────────────────
    // Error status codes (tests 104-108, 111) should be handled gracefully.
    if !response.base.status.is_success() {
        let status_code = &response.base.status.status_code.value;
        let sub_status = response.base.status.status_code.sub_status.as_deref();
        let status_msg = response
            .base
            .status
            .status_message
            .as_deref()
            .unwrap_or(status_code);
        log::warn!(
            "SAML Response status: {status_code} sub={sub:?} msg={msg}",
            sub = sub_status,
            msg = status_msg,
        );
        // SPID requires error responses to be rejected with an error HTTP code.
        return HttpResponse::Forbidden()
            .content_type("text/html")
            .body(format!(
                "<html><body><h1>Authentication Failed</h1><p>Status: {}</p></body></html>",
                html_escape(status_msg)
            ));
    }

    // ── Step 6: SPID structural checks ─────────────────────────────────
    // These are SPID-specific requirements beyond what the generic validator checks.

    // 6a. Response MUST have an ID
    if response.base.id.is_empty() {
        log::warn!("ACS: Response ID is empty");
        return HttpResponse::BadRequest().body("Response ID is empty");
    }

    // 6b. Response MUST have Version 2.0
    if !response.base.version.is_v2_0() {
        log::warn!("ACS: Response Version is not 2.0");
        return HttpResponse::BadRequest().body("Invalid Response Version");
    }

    // 6c. Response MUST have IssueInstant (already required by parser, but check age)
    {
        let now = Utc::now();
        let diff = (now - response.base.issue_instant)
            .num_seconds()
            .unsigned_abs();
        // Response IssueInstant must be recent (within 5 minutes + skew)
        let max_age = state.security_config.max_assertion_age_seconds
            + state.security_config.clock_skew_seconds;
        if diff > max_age {
            log::warn!(
                "ACS: Response IssueInstant too far from now: {}s (max {}s)",
                diff,
                max_age
            );
            return HttpResponse::BadRequest().body("Response IssueInstant out of range");
        }
    }

    // 6d. Response MUST have Destination matching our ACS URL
    match response.base.destination.as_deref() {
        Some(dest) if dest == state.acs_url => {}
        Some("") => {
            log::warn!("ACS: Destination is empty");
            return HttpResponse::BadRequest().body("Destination is empty");
        }
        Some(dest) => {
            log::warn!(
                "ACS: Destination mismatch: expected={}, got={}",
                state.acs_url,
                dest
            );
            return HttpResponse::BadRequest().body("Destination mismatch");
        }
        None => {
            log::warn!("ACS: Destination missing");
            return HttpResponse::BadRequest().body("Destination missing");
        }
    }

    // 6e. Response MUST have InResponseTo matching a pending request
    let (expected_request_id, requested_acr) = match response.base.in_response_to.as_deref() {
        Some(irt) if !irt.is_empty() => {
            let pending = state.pending_requests.lock().unwrap();
            match pending.get(irt) {
                Some(acr) => (Some(irt.to_string()), Some(acr.clone())),
                None => {
                    log::warn!(
                        "ACS: InResponseTo '{}' does not match any pending request",
                        irt
                    );
                    return HttpResponse::BadRequest().body("InResponseTo does not match");
                }
            }
        }
        Some("") => {
            log::warn!("ACS: InResponseTo is empty");
            return HttpResponse::BadRequest().body("InResponseTo is empty");
        }
        _ => {
            log::warn!("ACS: InResponseTo missing");
            return HttpResponse::BadRequest().body("InResponseTo missing");
        }
    };

    // 6f. Response MUST have an Issuer
    match response.base.issuer.as_ref() {
        Some(issuer) => {
            if issuer.value.is_empty() {
                log::warn!("ACS: Response Issuer is empty");
                return HttpResponse::BadRequest().body("Response Issuer is empty");
            }
            // Issuer format must be entity or omitted
            if let Some(ref format) = issuer.format {
                if format != constants::NAMEID_ENTITY {
                    log::warn!("ACS: Response Issuer format invalid: {format}");
                    return HttpResponse::BadRequest().body("Response Issuer format invalid");
                }
            }
            // Issuer value must match expected IdP
            if issuer.value != state.idp_entity_id {
                log::warn!(
                    "ACS: Response Issuer mismatch: expected={}, got={}",
                    state.idp_entity_id,
                    issuer.value
                );
                return HttpResponse::BadRequest().body("Response Issuer mismatch");
            }
        }
        None => {
            log::warn!("ACS: Response Issuer missing");
            return HttpResponse::BadRequest().body("Response Issuer missing");
        }
    }

    // ── Step 7: Signature requirement check ────────────────────────────
    // SPID requires at least the Assertion to be signed. Both Response+Assertion
    // signed is also valid.
    if !sig_verified {
        log::warn!("ACS: No valid signature found");
        return HttpResponse::Forbidden().body("Signature verification failed");
    }

    // Check that the assertion has a signature (SPID requirement for POST binding)
    if response.assertions.is_empty() {
        log::warn!("ACS: No assertions in response");
        return HttpResponse::BadRequest().body("No assertions in response");
    }
    // SPID mandates that the Assertion itself MUST always be signed.
    // A signed Response alone is NOT sufficient (test [3]).
    for (idx, assertion) in response.assertions.iter().enumerate() {
        if !assertion.has_signature {
            log::warn!("ACS: Assertion[{idx}] is not signed (SPID requires signed assertions)");
            return HttpResponse::Forbidden().body("Assertion must be signed");
        }
    }

    // ── Step 8: SPID Assertion-level structural checks ─────────────────
    for (idx, assertion) in response.assertions.iter().enumerate() {
        // 8a. Assertion ID must be present and non-empty
        if assertion.id.is_empty() {
            log::warn!("ACS: Assertion[{idx}] ID is empty");
            return HttpResponse::BadRequest().body("Assertion ID is empty");
        }

        // 8b. Assertion Version must be 2.0
        if !assertion.version.is_v2_0() {
            log::warn!("ACS: Assertion[{idx}] Version is not 2.0");
            return HttpResponse::BadRequest().body("Invalid Assertion Version");
        }

        // 8c. Assertion IssueInstant age check
        {
            let now = Utc::now();
            let diff = (now - assertion.issue_instant).num_seconds().unsigned_abs();
            let max_age = state.security_config.max_assertion_age_seconds
                + state.security_config.clock_skew_seconds;
            if diff > max_age {
                log::warn!(
                    "ACS: Assertion[{idx}] IssueInstant too far from now: {}s",
                    diff
                );
                return HttpResponse::BadRequest().body("Assertion IssueInstant out of range");
            }
        }

        // 8d. Assertion Issuer must match IdP entity ID
        if assertion.issuer.value.is_empty() {
            log::warn!("ACS: Assertion[{idx}] Issuer is empty");
            return HttpResponse::BadRequest().body("Assertion Issuer is empty");
        }
        if assertion.issuer.value != state.idp_entity_id {
            log::warn!("ACS: Assertion[{idx}] Issuer mismatch");
            return HttpResponse::BadRequest().body("Assertion Issuer mismatch");
        }
        // Assertion Issuer format check (SPID requires Format = entity)
        // Tests [70]/[71]: missing or empty Format must be rejected
        match &assertion.issuer.format {
            None => {
                log::warn!("ACS: Assertion[{idx}] Issuer Format attribute missing");
                return HttpResponse::BadRequest().body("Assertion Issuer Format missing");
            }
            Some(format) if format.is_empty() => {
                log::warn!("ACS: Assertion[{idx}] Issuer Format attribute empty");
                return HttpResponse::BadRequest().body("Assertion Issuer Format empty");
            }
            Some(format) if format != constants::NAMEID_ENTITY => {
                log::warn!("ACS: Assertion[{idx}] Issuer format invalid: {format}");
                return HttpResponse::BadRequest().body("Assertion Issuer format invalid");
            }
            _ => {} // Format is present and correct
        }

        // 8e. Subject checks
        match &assertion.subject {
            None => {
                log::warn!("ACS: Assertion[{idx}] Subject missing");
                return HttpResponse::BadRequest().body("Subject missing");
            }
            Some(subject) => {
                // NameID checks
                match &subject.name_id {
                    None => {
                        log::warn!("ACS: Assertion[{idx}] NameID missing");
                        return HttpResponse::BadRequest().body("NameID missing");
                    }
                    Some(gamlastan::core::assertion::name_id::NameIdOrEncryptedId::NameId(nid)) => {
                        if nid.value.is_empty() {
                            log::warn!("ACS: Assertion[{idx}] NameID value is empty");
                            return HttpResponse::BadRequest().body("NameID value is empty");
                        }
                        // SPID requires transient format
                        match nid.format.as_deref() {
                            Some(f) if f == constants::NAMEID_TRANSIENT => {}
                            Some("") => {
                                log::warn!("ACS: Assertion[{idx}] NameID Format is empty");
                                return HttpResponse::BadRequest().body("NameID Format is empty");
                            }
                            Some(f) => {
                                log::warn!("ACS: Assertion[{idx}] NameID Format invalid: {f}");
                                return HttpResponse::BadRequest()
                                    .body("NameID Format must be transient");
                            }
                            None => {
                                log::warn!("ACS: Assertion[{idx}] NameID Format missing");
                                return HttpResponse::BadRequest().body("NameID Format missing");
                            }
                        }
                        // SPID requires NameQualifier
                        match nid.name_qualifier.as_deref() {
                            Some("") => {
                                log::warn!("ACS: Assertion[{idx}] NameID NameQualifier is empty");
                                return HttpResponse::BadRequest()
                                    .body("NameID NameQualifier is empty");
                            }
                            None => {
                                log::warn!("ACS: Assertion[{idx}] NameID NameQualifier missing");
                                return HttpResponse::BadRequest()
                                    .body("NameID NameQualifier missing");
                            }
                            _ => {}
                        }
                    }
                    _ => {} // EncryptedID - skip for now
                }

                // SubjectConfirmation checks
                if subject.subject_confirmations.is_empty() {
                    log::warn!("ACS: Assertion[{idx}] SubjectConfirmation missing");
                    return HttpResponse::BadRequest().body("SubjectConfirmation missing");
                }
                for sc in &subject.subject_confirmations {
                    // Method must be bearer
                    if sc.method.is_empty() {
                        log::warn!("ACS: SubjectConfirmation Method is empty");
                        return HttpResponse::BadRequest()
                            .body("SubjectConfirmation Method is empty");
                    }
                    if sc.method != constants::CM_BEARER {
                        log::warn!("ACS: SubjectConfirmation Method invalid: {}", sc.method);
                        return HttpResponse::BadRequest()
                            .body("SubjectConfirmation Method must be bearer");
                    }
                    match &sc.subject_confirmation_data {
                        None => {
                            log::warn!("ACS: SubjectConfirmationData missing");
                            return HttpResponse::BadRequest()
                                .body("SubjectConfirmationData missing");
                        }
                        Some(scd) => {
                            // Recipient must match ACS URL
                            match scd.recipient.as_deref() {
                                Some(r) if r == state.acs_url => {}
                                Some("") => {
                                    log::warn!("ACS: Recipient is empty");
                                    return HttpResponse::BadRequest().body("Recipient is empty");
                                }
                                Some(r) => {
                                    log::warn!(
                                        "ACS: Recipient mismatch: expected={}, got={}",
                                        state.acs_url,
                                        r
                                    );
                                    return HttpResponse::BadRequest().body("Recipient mismatch");
                                }
                                None => {
                                    log::warn!("ACS: Recipient missing");
                                    return HttpResponse::BadRequest().body("Recipient missing");
                                }
                            }
                            // NotOnOrAfter must be present and not expired
                            match scd.not_on_or_after {
                                Some(nooa) => {
                                    let now = Utc::now();
                                    let skew = chrono::TimeDelta::seconds(
                                        state.security_config.clock_skew_seconds as i64,
                                    );
                                    if now > nooa + skew {
                                        log::warn!("ACS: SubjectConfirmationData NotOnOrAfter expired: {nooa}");
                                        return HttpResponse::BadRequest()
                                            .body("SubjectConfirmation expired");
                                    }
                                }
                                None => {
                                    log::warn!("ACS: SubjectConfirmationData NotOnOrAfter missing");
                                    return HttpResponse::BadRequest()
                                        .body("SubjectConfirmationData NotOnOrAfter missing");
                                }
                            }
                            // InResponseTo must match
                            match scd.in_response_to.as_deref() {
                                Some(irt) if expected_request_id.as_deref() == Some(irt) => {}
                                Some("") => {
                                    log::warn!(
                                        "ACS: SubjectConfirmationData InResponseTo is empty"
                                    );
                                    return HttpResponse::BadRequest()
                                        .body("SubjectConfirmationData InResponseTo is empty");
                                }
                                Some(irt) => {
                                    log::warn!(
                                        "ACS: SubjectConfirmationData InResponseTo mismatch: expected={:?}, got={}",
                                        expected_request_id, irt
                                    );
                                    return HttpResponse::BadRequest()
                                        .body("SubjectConfirmationData InResponseTo mismatch");
                                }
                                None => {
                                    log::warn!("ACS: SubjectConfirmationData InResponseTo missing");
                                    return HttpResponse::BadRequest()
                                        .body("SubjectConfirmationData InResponseTo missing");
                                }
                            }
                        }
                    }
                }
            }
        }

        // 8f. Conditions checks
        match &assertion.conditions {
            None => {
                log::warn!("ACS: Assertion[{idx}] Conditions missing");
                return HttpResponse::BadRequest().body("Conditions missing");
            }
            Some(conditions) => {
                let now = Utc::now();
                let skew =
                    chrono::TimeDelta::seconds(state.security_config.clock_skew_seconds as i64);

                // NotBefore must be present
                match conditions.not_before {
                    Some(nb) => {
                        if now + skew < nb {
                            log::warn!("ACS: Conditions NotBefore not yet valid: {nb}");
                            return HttpResponse::BadRequest()
                                .body("Conditions NotBefore not yet valid");
                        }
                    }
                    None => {
                        log::warn!("ACS: Conditions NotBefore missing");
                        return HttpResponse::BadRequest().body("Conditions NotBefore missing");
                    }
                }

                // NotOnOrAfter must be present
                match conditions.not_on_or_after {
                    Some(nooa) => {
                        if now > nooa + skew {
                            log::warn!("ACS: Conditions NotOnOrAfter expired: {nooa}");
                            return HttpResponse::BadRequest()
                                .body("Conditions NotOnOrAfter expired");
                        }
                    }
                    None => {
                        log::warn!("ACS: Conditions NotOnOrAfter missing");
                        return HttpResponse::BadRequest().body("Conditions NotOnOrAfter missing");
                    }
                }

                // AudienceRestriction must be present with our entity ID
                if conditions.audience_restrictions.is_empty() {
                    log::warn!("ACS: AudienceRestriction missing");
                    return HttpResponse::BadRequest().body("AudienceRestriction missing");
                }
                let audience_ok = conditions
                    .audience_restrictions
                    .iter()
                    .all(|ar| ar.audiences.iter().any(|a| a == &state.entity_id));
                if !audience_ok {
                    // Check if any audience restriction has empty audiences
                    let has_empty = conditions.audience_restrictions.iter().any(|ar| {
                        ar.audiences.is_empty() || ar.audiences.iter().any(|a| a.is_empty())
                    });
                    if has_empty {
                        log::warn!("ACS: Audience is empty");
                        return HttpResponse::BadRequest().body("Audience is empty");
                    }
                    log::warn!("ACS: Audience mismatch");
                    return HttpResponse::BadRequest().body("Audience restriction not satisfied");
                }
            }
        }

        // 8g. AuthnStatement checks
        if assertion.authn_statements.is_empty() {
            log::warn!("ACS: Assertion[{idx}] AuthnStatement missing");
            return HttpResponse::BadRequest().body("AuthnStatement missing");
        }
        for stmt in &assertion.authn_statements {
            // AuthnContext must be present
            let acr = stmt.authn_context.authn_context_class_ref.as_deref();
            match acr {
                Some("") => {
                    log::warn!("ACS: AuthnContextClassRef is empty");
                    return HttpResponse::BadRequest().body("AuthnContextClassRef is empty");
                }
                Some(acr_val) => {
                    // Must be a valid SPID level
                    if !SPID_VALID_ACRS.contains(&acr_val) {
                        log::warn!("ACS: AuthnContextClassRef invalid: {acr_val}");
                        return HttpResponse::BadRequest().body("AuthnContextClassRef invalid");
                    }
                    // Check ACR level against requested level
                    if let Some(ref req_acr) = requested_acr {
                        let requested_level = spid_acr_level(req_acr);
                        let received_level = spid_acr_level(acr_val);
                        // The IdP must return a level >= the requested level
                        // (or equal if comparison was "exact")
                        if received_level < requested_level {
                            log::warn!(
                                "ACS: ACR level too low: requested={} (L{}), got={} (L{})",
                                req_acr,
                                requested_level,
                                acr_val,
                                received_level
                            );
                            return HttpResponse::Forbidden()
                                .body("AuthnContextClassRef level insufficient");
                        }
                    }
                }
                None => {
                    log::warn!("ACS: AuthnContextClassRef missing");
                    return HttpResponse::BadRequest().body("AuthnContextClassRef missing");
                }
            }
        }

        // 8h. AttributeStatement checks (SPID requires attributes)
        // Tests 98, 99: empty AttributeStatement or empty Attribute elements should be rejected
        for attr_stmt in &assertion.attribute_statements {
            if attr_stmt.attributes.is_empty() {
                log::warn!("ACS: AttributeStatement has no Attribute elements");
                return HttpResponse::BadRequest().body("AttributeStatement has no attributes");
            }
            for attr in &attr_stmt.attributes {
                if attr.name.is_empty() {
                    log::warn!("ACS: Attribute has empty name");
                    return HttpResponse::BadRequest().body("Attribute has empty name");
                }
                // Test [99]: Attribute element present but no AttributeValue children
                if attr.values.is_empty() {
                    log::warn!(
                        "ACS: Attribute '{}' has no AttributeValue elements",
                        attr.name
                    );
                    return HttpResponse::BadRequest().body("Attribute has no values");
                }
            }
        }
    }

    // ── Step 9: Replay protection ─────────────────────────────────────
    if !register_replay_ids(
        state.replay_cache.as_ref(),
        &state.security_config,
        &response,
    ) {
        log::warn!("ACS: Replay detected for Response or Assertion ID");
        return HttpResponse::Forbidden().body("Replay detected");
    }

    // ── Step 9: Remove processed request ID ────────────────────────────
    if let Some(ref req_id) = expected_request_id {
        state
            .pending_requests
            .lock()
            .unwrap()
            .remove(req_id.as_str());
    }

    // ── Step 10: Success response ──────────────────────────────────────
    // Extract name ID from first assertion
    let name_id = response
        .assertions
        .first()
        .and_then(|a| a.subject.as_ref())
        .and_then(|s| match &s.name_id {
            Some(gamlastan::core::assertion::name_id::NameIdOrEncryptedId::NameId(nid)) => {
                Some(nid.value.as_str())
            }
            _ => None,
        })
        .unwrap_or("unknown");

    // Extract attributes
    let attrs: Vec<(String, String)> = response
        .assertions
        .iter()
        .flat_map(|a| &a.attribute_statements)
        .flat_map(|stmt| &stmt.attributes)
        .flat_map(|attr| {
            attr.values.iter().map(move |v| {
                let val = match v {
                    gamlastan::core::assertion::attribute::AttributeValue::String(s) => s.clone(),
                    gamlastan::core::assertion::attribute::AttributeValue::Integer(i) => {
                        i.to_string()
                    }
                    gamlastan::core::assertion::attribute::AttributeValue::Boolean(b) => {
                        b.to_string()
                    }
                    gamlastan::core::assertion::attribute::AttributeValue::DateTime(s) => s.clone(),
                    gamlastan::core::assertion::attribute::AttributeValue::Base64(b) => {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.encode(b)
                    }
                    gamlastan::core::assertion::attribute::AttributeValue::NameId(n) => {
                        n.value.clone()
                    }
                    gamlastan::core::assertion::attribute::AttributeValue::Xml(b) => {
                        String::from_utf8_lossy(b).to_string()
                    }
                    gamlastan::core::assertion::attribute::AttributeValue::Null => {
                        "null".to_string()
                    }
                };
                (attr.name.clone(), val)
            })
        })
        .collect();

    let attrs_html: String = attrs
        .iter()
        .map(|(k, v)| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(k),
                html_escape(v)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    info!("Authentication successful: NameID={name_id}");

    HttpResponse::Ok().content_type("text/html").body(format!(
        r#"<html><body>
<h1>Authentication Successful</h1>
<p><b>NameID:</b> {nameid}</p>
<table border="1"><tr><th>Attribute</th><th>Value</th></tr>
{attrs}
</table>
<p><a href="/login">Login Again</a></p>
</body></html>"#,
        nameid = html_escape(name_id),
        attrs = attrs_html,
    ))
}

/// Extract the SPID level number (1, 2, 3) from an AuthnContextClassRef.
fn spid_acr_level(acr: &str) -> u8 {
    if acr.ends_with("SpidL3") || acr.ends_with('3') {
        3
    } else if acr.ends_with("SpidL2") || acr.ends_with('2') {
        2
    } else {
        1
    }
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct AcsForm {
    SAMLResponse: String,
    RelayState: Option<String>,
}

// ── SLO Handler ────────────────────────────────────────────────────────────

/// Handle Single Logout (incoming or outgoing).
async fn sp_slo(_state: web::Data<AppState>, form: Option<web::Form<SloForm>>) -> HttpResponse {
    if let Some(form) = form {
        info!("SLO: received SAML message");
        if form.SAMLRequest.is_some() {
            // IdP-initiated logout - respond with success
            return HttpResponse::Ok()
                .content_type("text/html")
                .body("<html><body><h1>Logout Successful</h1><p><a href=\"/login\">Login Again</a></p></body></html>");
        }
        if form.SAMLResponse.is_some() {
            // Response to our logout request
            return HttpResponse::Ok()
                .content_type("text/html")
                .body("<html><body><h1>Logout Completed</h1><p><a href=\"/login\">Login Again</a></p></body></html>");
        }
    }
    HttpResponse::Ok()
        .content_type("text/html")
        .body("<html><body><h1>Logout</h1><p>No SAML message received.</p></body></html>")
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct SloForm {
    SAMLRequest: Option<String>,
    SAMLResponse: Option<String>,
    #[allow(dead_code)]
    RelayState: Option<String>,
}

// ── Index Page ─────────────────────────────────────────────────────────────

async fn index(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().content_type("text/html").body(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>SPID SP Test</title></head>
<body>
<h1>SPID SP Test Application</h1>
<p>Entity ID: <code>{entity_id}</code></p>
<p>IdP: <code>{idp_entity_id}</code></p>
<hr>
<h2>Login</h2>
<ul>
  <li><a href="/login?level=SpidL1">Login with SpidL1</a></li>
  <li><a href="/login?level=SpidL2">Login with SpidL2</a></li>
  <li><a href="/login?level=SpidL3">Login with SpidL3</a></li>
</ul>
<h2>Metadata</h2>
<ul>
  <li><a href="/metadata">SP Metadata</a></li>
</ul>
<h2>SPID Validator</h2>
<ul>
  <li><a href="https://localhost:8443" target="_blank">Open SPID SAML Check Validator</a></li>
</ul>
</body>
</html>"#,
        entity_id = html_escape(&state.entity_id),
        idp_entity_id = html_escape(&state.idp_entity_id),
    ))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn uuid_v4() -> String {
    // Simple UUID v4 generation without external crate
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ts >> 96) as u32,
        (ts >> 80) as u16,
        (ts >> 68) as u16 & 0x0fff,
        ((ts >> 52) as u16 & 0x3fff) | 0x8000,
        ts as u64 & 0xffffffffffff
    )
}

fn pkcs11_signing_config() -> Option<Pkcs11SigningConfig> {
    Some(Pkcs11SigningConfig {
        module: std::env::var("GAMLASTAN_PKCS11_MODULE").ok()?,
        pin: std::env::var("GAMLASTAN_PKCS11_PIN").ok()?,
        label: std::env::var("GAMLASTAN_PKCS11_LABEL").ok()?,
        cert_path: std::env::var("GAMLASTAN_PKCS11_CERT").ok()?,
    })
}

fn load_sp_signer(cert_dir: &str) -> io::Result<(Arc<SamlSigner>, String)> {
    if let Some(pkcs11) = pkcs11_signing_config() {
        info!(
            "Using HSM-backed SP signing key with label {} via {}",
            pkcs11.label, pkcs11.module
        );

        let cert_pem = fs::read(&pkcs11.cert_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to read HSM signing cert from {}: {e}",
                    pkcs11.cert_path
                ),
            )
        })?;
        let cert_b64 = extract_cert_b64(&cert_pem);

        let provider = gamlastan::crypto::kryptering::pkcs11::Pkcs11Provider::new(
            std::path::Path::new(&pkcs11.module),
        )
        .map_err(|e| io::Error::other(format!("Failed to load PKCS#11 module: {e}")))?;
        let session = provider
            .open_session(&pkcs11.pin)
            .map_err(|e| io::Error::other(format!("Failed to open PKCS#11 session: {e}")))?;
        let signer = gamlastan::crypto::kryptering::pkcs11::Pkcs11Signer::new(
            &session,
            &pkcs11.label,
            gamlastan::crypto::kryptering::SignatureAlgorithm::RsaPkcs1v15(
                gamlastan::crypto::kryptering::HashAlgorithm::Sha256,
            ),
        )
        .map_err(|e| io::Error::other(format!("Failed to bind PKCS#11 signer: {e}")))?;

        return Ok((
            Arc::new(SamlSigner::with_hsm_signer(
                gamlastan::crypto::KeysManager::new(),
                Arc::new(signer),
            )),
            cert_b64,
        ));
    }

    info!("Using file-based SP signing key from {cert_dir}/sp-key.pem");
    let sp_key_pem =
        fs::read(format!("{cert_dir}/sp-key.pem")).expect("Failed to read SP private key");
    let sp_cert_pem =
        fs::read(format!("{cert_dir}/sp-cert.pem")).expect("Failed to read SP certificate");

    let cert_b64 = extract_cert_b64(&sp_cert_pem);

    let mut signing_key = gamlastan::crypto::keys::loader::load_pem_auto(&sp_key_pem, None)
        .expect("Failed to load SP private key");
    signing_key.usage = gamlastan::crypto::KeyUsage::Sign;

    let cert_der = pem_to_der(&sp_cert_pem);
    signing_key.x509_chain = vec![cert_der];

    let mut keys_manager = gamlastan::crypto::KeysManager::new();
    keys_manager.add_key(signing_key);

    Ok((Arc::new(SamlSigner::new(keys_manager)), cert_b64))
}

// ── Main ───────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let sp_port: u16 = std::env::var("SP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let sp_host = std::env::var("SP_HOST").unwrap_or_else(|_| "localhost".to_string());

    let base_url = format!("https://{sp_host}:{sp_port}");

    // IdP (spid-saml-check validator) configuration
    let idp_base =
        std::env::var("IDP_BASE_URL").unwrap_or_else(|_| "https://localhost:8443".to_string());
    // The IdP entity ID may differ from the base URL (e.g., spid_sp_test tool
    // always uses https://localhost:8443 as entity ID regardless of where we run)
    let idp_entity_id =
        std::env::var("IDP_ENTITY_ID").unwrap_or_else(|_| "https://localhost:8443".to_string());

    info!("SP base URL: {base_url}");
    info!("IdP base URL: {idp_base}");
    info!("IdP entity ID: {idp_entity_id}");

    // Load SP signing key and certificate
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "spid-sp-test/certs".to_string());
    let (signer, cert_b64) = load_sp_signer(&cert_dir)?;

    // Load the IdP certificate for signature verification
    let idp_cert_pem = fs::read(format!("{cert_dir}/idp-cert.pem"))
        .expect("Failed to read IdP certificate (idp-cert.pem)");
    let idp_cert_der = pem_to_der(&idp_cert_pem);

    // Load the IdP cert as an actual verification key (extract public key from X.509)
    let idp_key = gamlastan::crypto::keys::loader::load_x509_cert_der(&idp_cert_der)
        .expect("Failed to parse IdP certificate");
    let mut idp_keys_manager = gamlastan::crypto::KeysManager::new();
    idp_keys_manager.add_key(idp_key);
    // Also add as trusted cert for chain validation
    idp_keys_manager.add_trusted_cert(idp_cert_der);
    let idp_verifier = Arc::new(SamlVerifier::new(idp_keys_manager));

    // Create replay cache and security config
    let replay_cache = Arc::new(InMemoryReplayCache::new());
    let security_config = SecurityConfig {
        clock_skew_seconds: 180,                // 3 minutes
        max_assertion_age_seconds: 300,         // 5 minutes
        require_signed_assertions: true,        // SPID requirement
        reject_signatures_with_ds_object: true, // E91
        ..SecurityConfig::default()
    };

    let state = AppState {
        entity_id: base_url.clone(),
        acs_url: format!("{base_url}/acs"),
        slo_url: format!("{base_url}/slo"),
        metadata_url: format!("{base_url}/metadata"),
        idp_sso_url: format!("{idp_base}/samlsso"),
        idp_slo_url: format!("{idp_base}/samlsso"),
        idp_entity_id,
        cert_b64,
        signer,
        idp_verifier,
        pending_requests: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        replay_cache,
        security_config,
    };

    let state_data = web::Data::new(state);

    // Load TLS certificates
    let tls_cert_path = format!("{cert_dir}/tls-cert.pem");
    let tls_key_path = format!("{cert_dir}/tls-key.pem");

    let cert_file = &mut io::BufReader::new(fs::File::open(&tls_cert_path)?);
    let key_file = &mut io::BufReader::new(fs::File::open(&tls_key_path)?);

    let cert_chain: Vec<_> = certs(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cert error: {e}")))?;

    let mut keys = pkcs8_private_keys(key_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key error: {e}")))?;

    if keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No private key found",
        ));
    }

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            cert_chain,
            rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS error: {e}")))?;

    info!("Starting SPID SP Test on https://{sp_host}:{sp_port}");

    HttpServer::new(move || {
        App::new()
            .app_data(state_data.clone())
            .route("/", web::get().to(index))
            .route("/metadata", web::get().to(sp_metadata))
            .route("/login", web::get().to(sp_login))
            .route("/acs", web::post().to(sp_acs))
            .route("/slo", web::get().to(sp_slo))
            .route("/slo", web::post().to(sp_slo))
    })
    .workers(2)
    .bind_rustls_0_23(("0.0.0.0", sp_port), tls_config)?
    .run()
    .await
}

/// Extract base64-encoded certificate from PEM file.
fn extract_cert_b64(pem_data: &[u8]) -> String {
    let pem_str = std::str::from_utf8(pem_data).expect("PEM is not valid UTF-8");
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    b64
}

/// Convert PEM certificate to DER bytes.
fn pem_to_der(pem_data: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = extract_cert_b64(pem_data);
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("Failed to decode certificate base64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use gamlastan::core::assertion::conditions::{AudienceRestriction, Conditions};
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::assertion::types::Assertion;
    use gamlastan::core::protocol::response::ResponseBase;
    use gamlastan::core::protocol::status::Status;
    use gamlastan::crypto::KeysManager;

    fn test_app_state() -> AppState {
        AppState {
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            slo_url: "https://sp.example.com/slo".to_string(),
            metadata_url: "https://sp.example.com/metadata".to_string(),
            idp_sso_url: "https://idp.example.com/sso".to_string(),
            idp_slo_url: "https://idp.example.com/slo".to_string(),
            idp_entity_id: "https://idp.example.com/metadata".to_string(),
            cert_b64: "MIIB".to_string(),
            signer: Arc::new(SamlSigner::new(KeysManager::new())),
            idp_verifier: Arc::new(SamlVerifier::new(KeysManager::new())),
            pending_requests: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            replay_cache: Arc::new(InMemoryReplayCache::new()),
            security_config: SecurityConfig {
                clock_skew_seconds: 180,
                max_assertion_age_seconds: 300,
                require_signed_assertions: true,
                ..SecurityConfig::default()
            },
        }
    }

    fn replay_test_response() -> Response {
        let now = Utc::now();
        Response {
            base: ResponseBase {
                id: "_resp1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: now,
                destination: Some("https://sp.example.com/acs".to_string()),
                consent: None,
                issuer: Some(Issuer::entity("https://idp.example.com/metadata")),
                has_signature: true,
                in_response_to: Some("_req1".to_string()),
                status: Status::success(),
            },
            assertions: vec![Assertion {
                id: "_assertion1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: now,
                issuer: Issuer::entity("https://idp.example.com/metadata"),
                has_signature: true,
                subject: None,
                conditions: Some(Conditions {
                    not_before: Some(now - TimeDelta::seconds(5)),
                    not_on_or_after: Some(now + TimeDelta::minutes(5)),
                    audience_restrictions: vec![AudienceRestriction {
                        audiences: vec!["https://sp.example.com/metadata".to_string()],
                    }],
                    one_time_use: false,
                    proxy_restriction: None,
                }),
                advice: None,
                authn_statements: vec![],
                authz_decision_statements: vec![],
                attribute_statements: vec![],
            }],
            encrypted_assertions: vec![],
        }
    }

    #[actix_web::test]
    async fn test_sp_metadata_fails_closed_when_signing_fails() {
        let response = sp_metadata(web::Data::new(test_app_state())).await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_register_replay_ids_rejects_second_use() {
        let state = test_app_state();
        let response = replay_test_response();

        assert!(register_replay_ids(
            state.replay_cache.as_ref(),
            &state.security_config,
            &response,
        ));
        assert!(!register_replay_ids(
            state.replay_cache.as_ref(),
            &state.security_config,
            &response,
        ));
    }
}
