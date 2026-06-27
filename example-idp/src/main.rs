// Example SAML Identity Provider
//
// A minimal IdP for testing against the dsamlsp Django SP (django-allauth + python3-saml).
//
// Endpoints:
//   GET  /           - Landing page with links
//   GET  /metadata   - Signed IdP metadata XML
//   GET  /sso        - SSO (receives AuthnRequest via HTTP-Redirect, shows login form)
//   POST /sso        - SSO (receives AuthnRequest via HTTP-POST, or login form submission)
//   GET  /slo        - Single Logout endpoint (stub)
//   POST /slo        - Single Logout endpoint (stub)
//
// Test users: alice/hunter2, bob/hunter2
//
// SP_METADATA_PATH may point at a single SP metadata file or a directory of
// *.xml files; in the directory case every file is loaded as a trusted SP, so
// the IdP can serve more than one Service Provider at a time.
//
// Usage:
//   cargo run -p example-idp
//   # or with env vars (single SP):
//   IDP_PORT=9443 CERT_DIR=example-idp/certs SP_METADATA_PATH=/path/to/sp-metadata.xml cargo run -p example-idp
//   # multiple SPs (directory of *.xml metadata files):
//   SP_METADATA_PATH=./sp_metadata cargo run -p example-idp
//   # optional HSM-backed SAML signing key:
//   GAMLASTAN_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//   GAMLASTAN_PKCS11_PIN=1234 \
//   GAMLASTAN_PKCS11_LABEL=saml-signing-key \
//   GAMLASTAN_PKCS11_CERT=/path/to/idp-cert.pem \
//   SP_METADATA_PATH=./sp_metadata cargo run -p example-idp
//   # insecure local interop override:
//   ALLOW_UNSIGNED_AUTHN_REQUESTS=true cargo run -p example-idp

use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::{Arc, Mutex};

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use chrono::Utc;
use log::info;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

use gamlastan::bindings::redirect::{redirect_decode, redirect_verify_signature, RedirectDecoded};
use gamlastan::bindings::relay_state::RelayState;
use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::constants;
use gamlastan::core::identifiers::SamlId;
use gamlastan::crypto::{KeysManager, SamlSigner, SamlVerifier, VerifyResult};
use gamlastan::metadata::types::entity_descriptor::EntityDescriptorRef;
use gamlastan::profiles::sso::idp as idp_profile;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use gamlastan::xml::deserialize::parse_saml;
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan_actix::{ActixHttpRequest, IdpConfig, IdpSigningContext};

// ── OID attribute names for dsamlsp compatibility ─────────────────────────
const OID_UID: &str = "urn:oid:0.9.2342.19200300.100.1.1";
const OID_EMAIL: &str = "urn:oid:0.9.2342.19200300.100.1.3";
const OID_GIVEN_NAME: &str = "urn:oid:2.5.4.42";
const OID_SURNAME: &str = "urn:oid:2.5.4.4";

// ── Test user ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct User {
    username: String,
    password: String,
    email: String,
    first_name: String,
    last_name: String,
}

impl User {
    fn attributes(&self) -> Vec<Attribute> {
        vec![
            Attribute {
                name: OID_UID.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("uid".to_string()),
                values: vec![AttributeValue::String(self.username.clone())],
            },
            Attribute {
                name: OID_EMAIL.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("email".to_string()),
                values: vec![AttributeValue::String(self.email.clone())],
            },
            Attribute {
                name: OID_GIVEN_NAME.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("givenName".to_string()),
                values: vec![AttributeValue::String(self.first_name.clone())],
            },
            Attribute {
                name: OID_SURNAME.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("sn".to_string()),
                values: vec![AttributeValue::String(self.last_name.clone())],
            },
        ]
    }

    fn name_id(&self) -> NameId {
        NameId {
            value: self.email.clone(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }
}

fn test_users() -> HashMap<String, User> {
    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        User {
            username: "alice".to_string(),
            password: "hunter2".to_string(),
            email: "alice@example.com".to_string(),
            first_name: "Alice".to_string(),
            last_name: "Smith".to_string(),
        },
    );
    users.insert(
        "bob".to_string(),
        User {
            username: "bob".to_string(),
            password: "hunter2".to_string(),
            email: "bob@example.com".to_string(),
            first_name: "Bob".to_string(),
            last_name: "Jones".to_string(),
        },
    );
    users
}

// ── Pending AuthnRequest (waiting for user login) ─────────────────────────

#[derive(Debug, Clone)]
struct PendingAuthnRequest {
    processed: idp_profile::ProcessedAuthnRequest,
    relay_state: Option<String>,
}

// ── Session (authenticated user) ──────────────────────────────────────────

#[derive(Debug, Clone)]
struct Session {
    username: String,
    #[allow(dead_code)]
    session_index: String,
}

struct TrustedSp {
    entity_id: String,
    sp_sso: gamlastan::metadata::types::sp::SpSsoDescriptor,
    request_verifier: SamlVerifier,
    require_signed_authn_requests: bool,
}

// ── Application state ─────────────────────────────────────────────────────

struct AppState {
    config: IdpConfig,
    /// Map of SP entity ID -> trusted Service Provider.
    trusted_sps: HashMap<String, TrustedSp>,
    /// IdP-level hint advertised in metadata (`WantAuthnRequestsSigned`).
    /// Per-SP enforcement still honours each SP's own `AuthnRequestsSigned`.
    want_authn_requests_signed: bool,
    signing_ctx: Arc<IdpSigningContext>,
    users: HashMap<String, User>,
    /// Map of pending_id -> PendingAuthnRequest (waiting for login)
    pending_requests: Arc<Mutex<HashMap<String, PendingAuthnRequest>>>,
    /// Map of session_cookie_value -> Session
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Pkcs11SigningConfig {
    module: String,
    pin: String,
    label: String,
    cert_path: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// GET / - Landing page
async fn index(state: web::Data<AppState>) -> HttpResponse {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Example SAML IdP</title></head>
<body>
<h1>Example SAML Identity Provider</h1>
<p>Entity ID: <code>{entity_id}</code></p>
<ul>
  <li><a href="/metadata">IdP Metadata (XML)</a></li>
  <li><a href="/sso">SSO Endpoint</a></li>
</ul>
<h2>Test Users</h2>
<table border="1" cellpadding="4">
<tr><th>Username</th><th>Password</th><th>Email</th></tr>
<tr><td>alice</td><td>hunter2</td><td>alice@example.com</td></tr>
<tr><td>bob</td><td>hunter2</td><td>bob@example.com</td></tr>
</table>
</body>
</html>"#,
        entity_id = state.config.entity_id,
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// GET /metadata - Signed IdP metadata
async fn idp_metadata(state: web::Data<AppState>) -> HttpResponse {
    use gamlastan::metadata::types::endpoint::Endpoint;
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use gamlastan::metadata::types::idp::IdpSsoDescriptor;
    use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    let cert_b64 = &state.signing_ctx.cert_b64;

    let key_info_xml = gamlastan::crypto::build_x509_key_info(&[cert_b64.as_str()]);

    let mut base =
        RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
    base.key_descriptors = vec![KeyDescriptor::signing(key_info_xml)];

    let idp_sso_desc = IdpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base,
            artifact_resolution_services: vec![],
            single_logout_services: if state.config.slo_url.is_empty() {
                vec![]
            } else {
                vec![
                    Endpoint::new(constants::BINDING_HTTP_REDIRECT, &state.config.slo_url),
                    Endpoint::new(constants::BINDING_HTTP_POST, &state.config.slo_url),
                ]
            },
            manage_name_id_services: vec![],
            name_id_formats: vec![
                constants::NAMEID_TRANSIENT.to_string(),
                constants::NAMEID_EMAIL.to_string(),
            ],
        },
        want_authn_requests_signed: Some(state.want_authn_requests_signed),
        single_sign_on_services: vec![
            Endpoint::new(constants::BINDING_HTTP_REDIRECT, &state.config.sso_url),
            Endpoint::new(constants::BINDING_HTTP_POST, &state.config.sso_url),
        ],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
    };

    let metadata_id = SamlId::generate().to_string();
    let entity = EntityDescriptor {
        entity_id: state.config.entity_id.clone(),
        id: Some(metadata_id.clone()),
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![idp_sso_desc],
            sp_sso: vec![],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };

    let xml = match entity.to_xml_string() {
        Ok(xml) => xml,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to serialize metadata: {e}"))
        }
    };

    let signature_method_uri = match state.signing_ctx.signer.signature_method_uri() {
        Ok(uri) => uri,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Unsupported signing algorithm: {e}"))
        }
    };

    // Sign the metadata
    let sig =
        gamlastan_actix::idp::signature_template(&metadata_id, cert_b64, signature_method_uri);
    let xml_with_sig = match gamlastan_actix::idp::insert_signature_after_element(
        &xml,
        "md:EntityDescriptor",
        &sig,
    ) {
        Ok(x) => x,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to insert signature: {e}"))
        }
    };

    let signed_xml = match state.signing_ctx.signer.sign_enveloped(&xml_with_sig) {
        Ok(x) => x,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to sign metadata: {e}"))
        }
    };

    HttpResponse::Ok()
        .content_type("application/samlmetadata+xml; charset=utf-8")
        .body(signed_xml)
}

/// GET+POST /sso - SSO endpoint
///
/// This handles three scenarios:
/// 1. Incoming AuthnRequest (GET = HTTP-Redirect, POST with SAMLRequest = HTTP-POST)
///    -> If user has session cookie, respond immediately
///    -> If no session, store pending request, show login form
/// 2. Login form submission (POST with username+password)
///    -> Authenticate, create session, respond to pending AuthnRequest
/// 3. Direct access without AuthnRequest (show info page)
async fn sso_handler(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    // Check if this is a login form submission
    if req.method() == actix_web::http::Method::POST {
        // Parse form body
        let body_str = String::from_utf8_lossy(&body);
        let form_params: HashMap<String, String> = body_str
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next().unwrap_or("");
                Some((urldecode(key), urldecode(value)))
            })
            .collect();

        // Is this a login form submission (has username field)?
        if form_params.contains_key("username") {
            return handle_login(req, state, form_params).await;
        }

        // Otherwise check for SAMLRequest in POST body
        if form_params.contains_key("SAMLRequest") {
            let saml_request = form_params.get("SAMLRequest").unwrap().clone();
            let relay_state = form_params.get("RelayState").cloned();
            return handle_authn_request_post(req, state, &saml_request, relay_state).await;
        }
    }

    // Check for SAMLRequest in query string (HTTP-Redirect binding)
    if query.contains_key("SAMLRequest") {
        return handle_authn_request_redirect(req, state).await;
    }

    // No AuthnRequest — show info page
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            r#"<!DOCTYPE html>
<html><head><title>SSO Endpoint</title></head>
<body>
<h1>SSO Endpoint</h1>
<p>This endpoint receives SAML AuthnRequests from Service Providers.</p>
<p>To test, initiate login from your SP (e.g., <code>https://localhost:8443/accounts/saml/sunet/login/</code>).</p>
</body></html>"#,
        )
}

/// Handle an AuthnRequest received via HTTP-Redirect binding
async fn handle_authn_request_redirect(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let adapter = ActixHttpRequest::new(&req, &[]);
    let decoded = match redirect_decode(&adapter) {
        Ok(d) if d.is_request => d,
        Ok(_) => {
            return HttpResponse::BadRequest().body("Expected SAMLRequest in redirect binding")
        }
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("Failed to decode AuthnRequest: {e}"))
        }
    };

    let xml_str = match std::str::from_utf8(&decoded.saml_xml) {
        Ok(s) => s.to_string(),
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("SAMLRequest is not valid UTF-8: {e}"))
        }
    };

    handle_authn_request(
        req,
        state,
        &xml_str,
        decoded.relay_state.clone(),
        Some(&decoded),
    )
    .await
}

/// Handle an AuthnRequest received via HTTP-POST binding
async fn handle_authn_request_post(
    req: HttpRequest,
    state: web::Data<AppState>,
    saml_request_b64: &str,
    relay_state: Option<String>,
) -> HttpResponse {
    // Decode: base64 -> raw XML (POST binding does NOT use deflate)
    use base64::Engine;
    let xml_bytes = match base64::engine::general_purpose::STANDARD.decode(saml_request_b64) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest()
                .body(format!("Failed to decode base64 SAMLRequest: {e}"))
        }
    };

    let xml_str = match String::from_utf8(xml_bytes) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("SAMLRequest is not valid UTF-8: {e}"))
        }
    };

    handle_authn_request(req, state, &xml_str, relay_state, None).await
}

/// Common AuthnRequest processing logic
async fn handle_authn_request(
    req: HttpRequest,
    state: web::Data<AppState>,
    xml_str: &str,
    relay_state: Option<String>,
    redirect_binding: Option<&RedirectDecoded>,
) -> HttpResponse {
    // Parse the AuthnRequest
    let doc = match gamlastan::xml::uppsala::parse(xml_str) {
        Ok(d) => d,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid XML: {e}")),
    };

    let request_ref = match gamlastan::xml::deserialize::parse_saml::<
        gamlastan::core::protocol::request::AuthnRequestRef<'_>,
    >(&doc)
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("Failed to parse AuthnRequest: {e}"))
        }
    };
    let authn_request = request_ref.to_owned();

    // Process against the configured SP metadata and signature policy.
    let processed = match validate_authn_request(&state, &authn_request, xml_str, redirect_binding)
    {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::BadRequest().body(format!("AuthnRequest validation failed: {e}"))
        }
    };

    info!(
        "Received AuthnRequest from SP={}, RequestID={}, ACS={}",
        processed.sp_entity_id, processed.request_id, processed.acs_url
    );

    // Check if user already has a session
    if let Some(session) = get_session_from_cookie(&req, &state) {
        info!(
            "User {} already has session, responding directly",
            session.username
        );
        if let Some(user) = state.users.get(&session.username) {
            return build_saml_response(&state, &processed, user, relay_state);
        }
    }

    // No session — store pending request and show login form
    let pending_id = SamlId::generate().to_string();
    {
        let mut pending = state.pending_requests.lock().unwrap();
        pending.insert(
            pending_id.clone(),
            PendingAuthnRequest {
                processed,
                relay_state,
            },
        );
    }

    show_login_form(&pending_id, None)
}

/// Handle login form submission
async fn handle_login(
    _req: HttpRequest,
    state: web::Data<AppState>,
    form: HashMap<String, String>,
) -> HttpResponse {
    let username = form.get("username").map(|s| s.as_str()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let pending_id = form.get("pending_id").map(|s| s.as_str()).unwrap_or("");

    // Look up pending request
    let pending = {
        let pending_map = state.pending_requests.lock().unwrap();
        pending_map.get(pending_id).cloned()
    };

    let pending = match pending {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().body("No pending authentication request found. Please start the login flow from your SP.");
        }
    };

    // Authenticate
    let user = match state.users.get(username) {
        Some(u) if constant_time_eq(u.password.as_bytes(), password.as_bytes()) => u,
        _ => {
            return show_login_form(pending_id, Some("Invalid username or password"));
        }
    };

    info!("User {} authenticated successfully", username);

    // Remove pending request
    {
        let mut pending_map = state.pending_requests.lock().unwrap();
        pending_map.remove(pending_id);
    }

    // Create session
    let session_id = SamlId::generate().to_string();
    let session_index = SamlId::generate().to_string();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(
            session_id.clone(),
            Session {
                username: username.to_string(),
                session_index: session_index.clone(),
            },
        );
    }

    // Build SAML Response
    let mut response = build_saml_response(&state, &pending.processed, user, pending.relay_state);

    // Set session cookie
    response.headers_mut().insert(
        actix_web::http::header::SET_COOKIE,
        actix_web::http::header::HeaderValue::from_str(&format!(
            "idp_session={session_id}; Path=/; Secure; HttpOnly; SameSite=None"
        ))
        .unwrap(),
    );

    response
}

/// Build a signed SAML Response for the given user and send via POST binding
fn build_saml_response(
    state: &AppState,
    processed: &idp_profile::ProcessedAuthnRequest,
    user: &User,
    relay_state: Option<String>,
) -> HttpResponse {
    let now = Utc::now();
    let session_not_on_or_after = now
        + chrono::TimeDelta::try_seconds(state.config.session_lifetime_seconds as i64)
            .unwrap_or(chrono::TimeDelta::try_hours(8).unwrap());

    let session_index = SamlId::generate().to_string();

    let response_options = ResponseOptions {
        idp_entity_id: state.config.entity_id.clone(),
        in_response_to: Some(processed.request_id.clone()),
        sp_entity_id: processed.sp_entity_id.clone(),
        acs_url: processed.acs_url.clone(),
        assertion_lifetime_seconds: state.config.assertion_lifetime_seconds,
        session_index: Some(session_index),
        session_not_on_or_after: Some(session_not_on_or_after),
        authn_context_class_ref: Some(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_string(),
        ),
        client_address: None,
        attributes: user.attributes(),
    };

    // This example always authenticates the user fresh per request, so the
    // authentication instant equals the response issue instant.
    let response =
        idp_profile::create_response(&response_options, &user.name_id(), ResponseTimes::at(now));

    let response_xml = match response.to_xml_string() {
        Ok(xml) => xml,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to serialize Response: {e}"));
        }
    };

    // Sign the Response and Assertion
    let assertion_id = response.assertions.first().map(|a| a.id.as_str());
    let signed_xml = match gamlastan_actix::idp::sign_response_xml(
        &response_xml,
        &state.signing_ctx,
        &response.base.id,
        assertion_id,
        state.config.sign_assertions,
        state.config.sign_responses,
    ) {
        Ok(xml) => xml,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to sign Response: {e}"));
        }
    };

    // Build RelayState
    let relay = relay_state.as_deref().map(RelayState::echo);

    // POST-encode and send
    let html = gamlastan::bindings::post::post_encode(
        signed_xml.as_bytes(),
        false, // is_response (not request)
        &processed.acs_url,
        relay.as_ref(),
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Cache-Control", "no-cache, no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(html)
}

/// GET+POST /slo - Single Logout endpoint (stub)
async fn slo_handler() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            r#"<!DOCTYPE html>
<html><head><title>Single Logout</title></head>
<body>
<h1>Single Logout</h1>
<p>Logout successful.</p>
<p><a href="/">Return to IdP</a></p>
</body></html>"#,
        )
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Show the login form HTML
fn show_login_form(pending_id: &str, error: Option<&str>) -> HttpResponse {
    let error_html = if let Some(msg) = error {
        format!(r#"<p style="color: red; font-weight: bold;">{msg}</p>"#)
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<title>Login - Example IdP</title>
<style>
body {{ font-family: sans-serif; max-width: 400px; margin: 80px auto; }}
h1 {{ color: #333; }}
form {{ margin-top: 20px; }}
label {{ display: block; margin-top: 10px; font-weight: bold; }}
input[type=text], input[type=password] {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
button {{ margin-top: 16px; padding: 10px 24px; background: #0066cc; color: white; border: none; cursor: pointer; font-size: 16px; }}
button:hover {{ background: #0052a3; }}
.hint {{ color: #666; font-size: 13px; margin-top: 20px; }}
</style>
</head>
<body>
<h1>Sign In</h1>
{error_html}
<form method="POST" action="/sso">
  <input type="hidden" name="pending_id" value="{pending_id}" />
  <label for="username">Username</label>
  <input type="text" id="username" name="username" required autofocus />
  <label for="password">Password</label>
  <input type="password" id="password" name="password" required />
  <button type="submit">Sign In</button>
</form>
<p class="hint">Test users: alice/hunter2, bob/hunter2</p>
</body>
</html>"#,
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// Get session from cookie
fn get_session_from_cookie(req: &HttpRequest, state: &web::Data<AppState>) -> Option<Session> {
    let cookie_header = req.headers().get("cookie")?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("idp_session=") {
            let sessions = state.sessions.lock().unwrap();
            return sessions.get(value).cloned();
        }
    }
    None
}

fn validate_authn_request(
    state: &AppState,
    authn_request: &gamlastan::core::protocol::request::AuthnRequest,
    xml_str: &str,
    redirect_binding: Option<&RedirectDecoded>,
) -> Result<idp_profile::ProcessedAuthnRequest, String> {
    let issuer = authn_request
        .base
        .issuer
        .as_ref()
        .ok_or_else(|| "AuthnRequest is missing Issuer".to_string())?;
    let sp = state
        .trusted_sps
        .get(&issuer.value)
        .ok_or_else(|| format!("untrusted Service Provider {:?}", issuer.value))?;

    let mut signed = false;

    if let Some(decoded) = redirect_binding {
        let has_redirect_signature = decoded.signature.is_some()
            || decoded.sig_alg.is_some()
            || decoded.signature_input.is_some();
        if has_redirect_signature {
            let valid = redirect_verify_signature(decoded, &sp.request_verifier)
                .map_err(|e| format!("redirect signature verification failed: {e}"))?;
            if !valid {
                return Err("redirect signature verification failed".to_string());
            }
            signed = true;
        }
    }

    if authn_request.base.has_signature {
        match sp.request_verifier.verify_enveloped(xml_str) {
            Ok(VerifyResult::Valid { .. }) => signed = true,
            Ok(VerifyResult::Invalid { reason }) => {
                return Err(format!("XML signature verification failed: {reason}"));
            }
            Err(e) => return Err(format!("XML signature verification failed: {e}")),
        }
    }

    if sp.require_signed_authn_requests && !signed {
        return Err("unsigned AuthnRequest rejected by IdP policy".to_string());
    }

    idp_profile::process_authn_request(authn_request, Some(&sp.sp_sso)).map_err(|e| e.to_string())
}

/// Load every trusted SP, keyed by entity ID.
///
/// `path` may be a single metadata file or a directory; when it is a directory,
/// every `*.xml` file inside it is loaded as one SP. This lets the IdP trust
/// more than one Service Provider at a time.
fn load_trusted_sps(
    path: &str,
    allow_unsigned_authn_requests: bool,
) -> io::Result<HashMap<String, TrustedSp>> {
    let meta = fs::metadata(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to stat SP metadata path {path}: {e}"),
        )
    })?;

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let is_xml = entry_path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("xml"));
            if entry_path.is_file() && is_xml {
                files.push(entry_path);
            }
        }
        files.sort();
        if files.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no SP metadata (*.xml) files found in directory {path}"),
            ));
        }
    } else {
        files.push(std::path::PathBuf::from(path));
    }

    let mut trusted_sps = HashMap::new();
    for file in files {
        let file_str = file.to_string_lossy();
        let sp = load_trusted_sp(&file_str, allow_unsigned_authn_requests)?;
        if let Some(existing) = trusted_sps.insert(sp.entity_id.clone(), sp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "duplicate SP entity ID {:?} across metadata files",
                    existing.entity_id
                ),
            ));
        }
    }

    Ok(trusted_sps)
}

fn load_trusted_sp(
    metadata_path: &str,
    allow_unsigned_authn_requests: bool,
) -> io::Result<TrustedSp> {
    let metadata_xml = fs::read_to_string(metadata_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read SP metadata from {metadata_path}: {e}"),
        )
    })?;

    let metadata_doc = gamlastan::xml::uppsala::parse(&metadata_xml).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid SP metadata XML: {e}"),
        )
    })?;
    let entity_ref = parse_saml::<EntityDescriptorRef<'_>>(&metadata_doc).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse SP metadata: {e}"),
        )
    })?;
    let entity = entity_ref.to_owned();
    let sp_sso = entity
        .sp_sso_descriptors()
        .first()
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SP metadata contains no SPSSODescriptor",
            )
        })?;

    let mut verifier_keys = KeysManager::new();
    let mut cert_count = 0usize;
    for key_descriptor in &sp_sso.sso_base.base.key_descriptors {
        if !key_descriptor.can_sign() {
            continue;
        }
        for cert_der in extract_x509_certificates(&key_descriptor.key_info_xml)? {
            let key =
                gamlastan::crypto::keys::loader::load_x509_cert_der(&cert_der).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to parse SP signing certificate from metadata: {e}"),
                    )
                })?;
            verifier_keys.add_key(key);
            verifier_keys.add_trusted_cert(cert_der);
            cert_count += 1;
        }
    }
    if cert_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SP metadata does not contain any signing certificates",
        ));
    }

    let metadata_requires_signed = sp_sso.authn_requests_signed.unwrap_or(false);
    let require_signed_authn_requests = metadata_requires_signed || !allow_unsigned_authn_requests;

    Ok(TrustedSp {
        entity_id: entity.entity_id,
        sp_sso,
        request_verifier: SamlVerifier::new(verifier_keys),
        require_signed_authn_requests,
    })
}

fn extract_x509_certificates(key_info_xml: &str) -> io::Result<Vec<Vec<u8>>> {
    if key_info_xml.trim().is_empty() {
        return Ok(Vec::new());
    }

    let doc = gamlastan::xml::uppsala::parse(key_info_xml).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ds:KeyInfo XML in metadata: {e}"),
        )
    })?;
    let root = doc.document_element().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ds:KeyInfo XML is missing a document element",
        )
    })?;

    let mut certificates = Vec::new();
    collect_x509_certificates(&doc, root, &mut certificates)?;
    Ok(certificates)
}

fn collect_x509_certificates<'a>(
    doc: &'a gamlastan::xml::uppsala::Document<'a>,
    node: gamlastan::xml::uppsala::NodeId,
    out: &mut Vec<Vec<u8>>,
) -> io::Result<()> {
    if let Some(elem) = doc.element(node) {
        if elem.name.namespace_uri.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#")
            && elem.name.local_name.as_ref() == "X509Certificate"
        {
            let text = doc
                .text_content(node)
                .map(|t| t.to_string())
                .unwrap_or_else(|| doc.text_content_deep(node));
            let cert_b64 = text.trim();
            if !cert_b64.is_empty() {
                use base64::Engine;
                let cert_der = base64::engine::general_purpose::STANDARD
                    .decode(cert_b64)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid base64 in X509Certificate: {e}"),
                        )
                    })?;
                out.push(cert_der);
            }
        }
    }

    for child in doc.children_iter(node) {
        if doc.element(child).is_some() {
            collect_x509_certificates(doc, child, out)?;
        }
    }

    Ok(())
}

/// Simple URL decoding (percent-decoding)
fn urldecode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Constant-time comparison (not cryptographically hardened, but prevents
/// trivial timing attacks in this test-only context)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract base64-encoded certificate from PEM data
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

fn pkcs11_signing_config() -> Option<Pkcs11SigningConfig> {
    Some(Pkcs11SigningConfig {
        module: std::env::var("GAMLASTAN_PKCS11_MODULE").ok()?,
        pin: std::env::var("GAMLASTAN_PKCS11_PIN").ok()?,
        label: std::env::var("GAMLASTAN_PKCS11_LABEL").ok()?,
        cert_path: std::env::var("GAMLASTAN_PKCS11_CERT").ok()?,
    })
}

fn load_signing_context(cert_dir: &str) -> io::Result<Arc<IdpSigningContext>> {
    if let Some(pkcs11) = pkcs11_signing_config() {
        info!(
            "Using HSM-backed SAML signing key with label {} via {}",
            pkcs11.label, pkcs11.module
        );

        let signing_cert_pem = fs::read(&pkcs11.cert_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to read HSM signing cert from {}: {e}",
                    pkcs11.cert_path
                ),
            )
        })?;
        let cert_b64 = extract_cert_b64(&signing_cert_pem);

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

        return Ok(Arc::new(IdpSigningContext::from_hsm(
            Arc::new(signer),
            cert_b64,
        )));
    }

    info!("Using file-based SAML signing key from {cert_dir}/idp-key.pem");
    let signing_key_pem = fs::read(format!("{cert_dir}/idp-key.pem"))
        .expect("Failed to read IdP signing key (idp-key.pem)");
    let signing_cert_pem = fs::read(format!("{cert_dir}/idp-cert.pem"))
        .expect("Failed to read IdP signing cert (idp-cert.pem)");

    let cert_b64 = extract_cert_b64(&signing_cert_pem);

    let mut signing_key = gamlastan::crypto::keys::loader::load_pem_auto(&signing_key_pem, None)
        .expect("Failed to load IdP signing key");
    signing_key.usage = gamlastan::crypto::KeyUsage::Sign;

    // Add X.509 certificate chain
    let cert_der = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&cert_b64)
            .expect("Failed to decode signing cert base64")
    };
    signing_key.x509_chain = vec![cert_der];

    let mut keys_manager = gamlastan::crypto::KeysManager::new();
    keys_manager.add_key(signing_key);

    Ok(Arc::new(IdpSigningContext::new(
        SamlSigner::new(keys_manager),
        cert_b64,
    )))
}

// ── Main ──────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> io::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let port: u16 = std::env::var("IDP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9443);
    let host = std::env::var("IDP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let base_url = format!("https://{host}:{port}");
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "example-idp/certs".to_string());
    let sp_metadata_path = std::env::var("SP_METADATA_PATH").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SP_METADATA_PATH is required so the IdP can validate incoming AuthnRequests \
             (a single metadata file or a directory of *.xml files for multiple SPs)",
        )
    })?;
    let allow_unsigned_authn_requests = std::env::var("ALLOW_UNSIGNED_AUTHN_REQUESTS")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false);

    info!("Loading certificates from {cert_dir}");
    info!("Loading trusted SP metadata from {sp_metadata_path}");

    let signing_ctx = load_signing_context(&cert_dir)?;
    let cert_b64 = signing_ctx.cert_b64.clone();

    let trusted_sps = load_trusted_sps(&sp_metadata_path, allow_unsigned_authn_requests)?;
    // The IdP advertises that it wants signed AuthnRequests unless the local
    // override is in effect; per-SP enforcement still honours each SP metadata.
    let want_authn_requests_signed = !allow_unsigned_authn_requests;
    if allow_unsigned_authn_requests {
        info!("Unsigned AuthnRequests are allowed by local override");
    }

    // Build IdP config
    let config = IdpConfig::new(format!("{base_url}/metadata"), format!("{base_url}/sso"))
        .with_slo_url(format!("{base_url}/slo"))
        .with_metadata_url(format!("{base_url}/metadata"))
        .with_signing_cert(cert_b64);

    let state = web::Data::new(AppState {
        config,
        trusted_sps,
        want_authn_requests_signed,
        signing_ctx,
        users: test_users(),
        pending_requests: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    });

    // Load TLS certificates
    let tls_cert_path = format!("{cert_dir}/tls-cert.pem");
    let tls_key_path = format!("{cert_dir}/tls-key.pem");

    let cert_file = &mut io::BufReader::new(fs::File::open(&tls_cert_path)?);
    let key_file = &mut io::BufReader::new(fs::File::open(&tls_key_path)?);

    let cert_chain: Vec<_> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cert error: {e}")))?;

    let mut keys: Vec<PrivatePkcs8KeyDer<'_>> = PrivatePkcs8KeyDer::pem_reader_iter(key_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key error: {e}")))?;

    if keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No TLS private key found",
        ));
    }

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            cert_chain,
            rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0)),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS error: {e}")))?;

    info!("Starting Example IdP at {base_url}");
    info!("  Entity ID: {base_url}/metadata");
    info!("  SSO URL:   {base_url}/sso");
    info!("  Metadata:  {base_url}/metadata");
    info!("  Trusted SPs ({}):", state.trusted_sps.len());
    let mut sp_entity_ids: Vec<&String> = state.trusted_sps.keys().collect();
    sp_entity_ids.sort();
    for entity_id in sp_entity_ids {
        let sp = &state.trusted_sps[entity_id];
        info!(
            "    - {} (require signed AuthnRequests: {})",
            entity_id, sp.require_signed_authn_requests
        );
    }

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/", web::get().to(index))
            .route("/metadata", web::get().to(idp_metadata))
            .route("/sso", web::get().to(sso_handler))
            .route("/sso", web::post().to(sso_handler))
            .route("/slo", web::get().to(slo_handler))
            .route("/slo", web::post().to(slo_handler))
    })
    .workers(2)
    .bind_rustls_0_23(("0.0.0.0", port), tls_config)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::identifiers::SamlVersion;
    use gamlastan::core::protocol::request::{AuthnRequest, RequestBase};
    use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::metadata::types::sp::SpSsoDescriptor;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_metadata(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("example-idp-test-{unique}.xml"));
        fs::write(&path, contents).unwrap();
        path
    }

    fn test_metadata(authn_requests_signed: Option<bool>) -> String {
        let cert_b64 = extract_cert_b64(include_bytes!("../certs/idp-cert.pem"));
        let key_info_xml = gamlastan::crypto::build_x509_key_info(&[cert_b64.as_str()]);
        let authn_requests_signed_attr = match authn_requests_signed {
            Some(true) => " AuthnRequestsSigned=\"true\"",
            Some(false) => " AuthnRequestsSigned=\"false\"",
            None => "",
        };

        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.se/metadata">
                 <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"{authn_requests_signed_attr}>
                   <md:KeyDescriptor use="signing">{key_info_xml}</md:KeyDescriptor>
                   <md:AssertionConsumerService Binding="{binding}" Location="https://sp.example.se/acs" index="0" isDefault="true"/>
                 </md:SPSSODescriptor>
               </md:EntityDescriptor>"#,
            binding = constants::BINDING_HTTP_POST,
        )
    }

    fn dummy_sp_sso(authn_requests_signed: Option<bool>) -> SpSsoDescriptor {
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
            authn_requests_signed,
            want_assertions_signed: None,
            assertion_consumer_services: vec![IndexedEndpoint::new_default(
                Endpoint::new(constants::BINDING_HTTP_POST, "https://sp.example.se/acs"),
                0,
            )],
            attribute_consuming_services: vec![],
        }
    }

    fn test_state(require_signed_authn_requests: bool, trusted_sp_entity_ids: &[&str]) -> AppState {
        let mut trusted_sps = HashMap::new();
        for entity_id in trusted_sp_entity_ids {
            trusted_sps.insert(
                entity_id.to_string(),
                TrustedSp {
                    entity_id: entity_id.to_string(),
                    sp_sso: dummy_sp_sso(Some(require_signed_authn_requests)),
                    request_verifier: SamlVerifier::new(KeysManager::new()),
                    require_signed_authn_requests,
                },
            );
        }
        AppState {
            config: IdpConfig::new(
                "https://idp.example.se/metadata".to_string(),
                "https://idp.example.se/sso".to_string(),
            ),
            trusted_sps,
            want_authn_requests_signed: require_signed_authn_requests,
            signing_ctx: Arc::new(IdpSigningContext::new(
                SamlSigner::new(KeysManager::new()),
                String::new(),
            )),
            users: test_users(),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn unsigned_request(issuer: &str) -> AuthnRequest {
        AuthnRequest {
            base: RequestBase {
                id: "_req1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.se/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity(issuer)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.se/acs".to_string()),
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        }
    }

    #[test]
    fn test_load_trusted_sp_requires_signed_requests_by_default() {
        let path = write_temp_metadata(&test_metadata(Some(false)));
        let trusted_sp = load_trusted_sp(path.to_str().unwrap(), false).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(trusted_sp.entity_id, "https://sp.example.se/metadata");
        assert!(trusted_sp.require_signed_authn_requests);
    }

    #[test]
    fn test_load_trusted_sp_allows_unsigned_override() {
        let path = write_temp_metadata(&test_metadata(Some(false)));
        let trusted_sp = load_trusted_sp(path.to_str().unwrap(), true).unwrap();
        std::fs::remove_file(path).unwrap();

        assert!(!trusted_sp.require_signed_authn_requests);
    }

    #[test]
    fn test_validate_authn_request_rejects_untrusted_sp() {
        let state = test_state(true, &["https://sp.example.se/metadata"]);
        let request = unsigned_request("https://evil.example.se/metadata");
        let err = validate_authn_request(&state, &request, "<AuthnRequest/>", None).unwrap_err();
        assert!(err.contains("untrusted Service Provider"));
    }

    #[test]
    fn test_validate_authn_request_rejects_unsigned_when_required() {
        let state = test_state(true, &["https://sp.example.se/metadata"]);
        let request = unsigned_request("https://sp.example.se/metadata");
        let err = validate_authn_request(&state, &request, "<AuthnRequest/>", None).unwrap_err();
        assert!(err.contains("unsigned AuthnRequest rejected"));
    }

    #[test]
    fn test_validate_authn_request_accepts_any_trusted_sp() {
        // The IdP trusts more than one SP; a request from either is matched to
        // its own metadata entry by issuer entity ID.
        let state = test_state(
            false,
            &[
                "https://sp-one.example.se/metadata",
                "https://sp-two.example.se/metadata",
            ],
        );

        let processed_one = validate_authn_request(
            &state,
            &unsigned_request("https://sp-one.example.se/metadata"),
            "",
            None,
        )
        .expect("first SP should be trusted");
        assert_eq!(
            processed_one.sp_entity_id,
            "https://sp-one.example.se/metadata"
        );

        let processed_two = validate_authn_request(
            &state,
            &unsigned_request("https://sp-two.example.se/metadata"),
            "",
            None,
        )
        .expect("second SP should be trusted");
        assert_eq!(
            processed_two.sp_entity_id,
            "https://sp-two.example.se/metadata"
        );

        let err = validate_authn_request(
            &state,
            &unsigned_request("https://sp-three.example.se/metadata"),
            "",
            None,
        )
        .unwrap_err();
        assert!(err.contains("untrusted Service Provider"));
    }

    #[test]
    fn test_load_trusted_sps_from_directory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("example-idp-sps-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        // Two SP metadata files with distinct entity IDs.
        fs::write(
            dir.join("sp-a.xml"),
            test_metadata(Some(false)).replace(
                "https://sp.example.se/metadata",
                "https://sp-a.example.se/metadata",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("sp-b.xml"),
            test_metadata(Some(false)).replace(
                "https://sp.example.se/metadata",
                "https://sp-b.example.se/metadata",
            ),
        )
        .unwrap();
        // A non-XML file in the directory must be ignored.
        fs::write(dir.join("README.txt"), "not metadata").unwrap();

        let trusted = load_trusted_sps(dir.to_str().unwrap(), false).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(trusted.len(), 2);
        assert!(trusted.contains_key("https://sp-a.example.se/metadata"));
        assert!(trusted.contains_key("https://sp-b.example.se/metadata"));
    }
}
