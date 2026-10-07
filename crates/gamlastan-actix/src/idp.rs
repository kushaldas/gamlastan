// Ready-to-use Identity Provider (IdP) handlers for actix-web.
//
// Provides handlers for the standard SAML IdP endpoints:
// - SSO endpoint (receive AuthnRequest and authenticate user)
// - Single Logout Service (receive and process LogoutRequest/Response)
// - Artifact Resolution Service (resolve artifacts over SOAP back-channel)
// - Metadata generation
//
// Register all routes at once with `configure_idp()`.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};

use gamlastan::bindings::relay_state::RelayState;
use gamlastan::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use gamlastan::core::protocol::logout::LogoutRequest;
use gamlastan::crypto::signer::SamlSigner;
use gamlastan::profiles::artifact_resolution;
use gamlastan::profiles::logout;
use gamlastan::profiles::sso::idp as idp_profile;
// The canonical enveloped-signature template now lives in core gamlastan;
// re-export it so existing call sites (and the doc links) keep resolving.
use gamlastan::idp::assertion_store::AssertionStore;
use gamlastan::idp::authn_broker::AuthnBroker;
use gamlastan::idp::ident::NameIdConstructor;
use gamlastan::idp::orchestrator::{
    check_request, create_authn_response, create_denial_response, AttributeRelease,
    AuthenticatedSubject, Denial, Disposition, EstablishedSession, ResponseEngine, ResponseOutcome,
    ResponseParams,
};
use gamlastan::idp::policy::ReleasePolicy;
pub use gamlastan::profiles::sso::idp::signature_template;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan::xml::uppsala;

use crate::config::IdpConfig;
use crate::error::SamlActixError;
use crate::extractors::{RedirectSignatureData, SamlMessage};
use crate::responders::MetadataXml;

/// IdP signing context for signing responses, assertions, and metadata.
///
/// Separate from `IdpConfig` so it can be shared via `Arc` and contains
/// the actual signer (which holds the private key).
pub struct IdpSigningContext {
    /// The SAML signer (wraps bergshamra).
    pub signer: SamlSigner,
    /// Base64-encoded DER certificate for KeyInfo elements.
    pub cert_b64: String,
}

impl IdpSigningContext {
    /// Build a signing context from an already-constructed [`SamlSigner`].
    ///
    /// `cert_b64` is the base64 DER of the signing certificate — the same value
    /// that populates `<ds:X509Certificate>` in signed messages and metadata.
    pub fn new(signer: SamlSigner, cert_b64: impl Into<String>) -> Self {
        Self {
            signer,
            cert_b64: cert_b64.into(),
        }
    }

    /// Build an HSM / PKCS#11-backed signing context.
    ///
    /// `signer` is any [`gamlastan::crypto::kryptering::Signer`] — typically a
    /// `kryptering::pkcs11::Pkcs11Signer` bound to a private key on a token. The
    /// private key never leaves the token; signing happens on the HSM.
    ///
    /// The XML `SignatureMethod` placed into response/assertion/metadata
    /// templates is derived from the signer's configured algorithm.
    ///
    /// The IdP handlers already embed `cert_b64` into the `<ds:KeyInfo>` of the
    /// signature template (see [`signature_template`]), which is exactly what
    /// the HSM signing path needs — bergshamra-dsig does not auto-populate
    /// `<ds:KeyInfo>` when an HSM signer is in use. No `KeysManager` plumbing is
    /// required: an empty one is created internally.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use std::path::Path;
    /// use gamlastan_actix::IdpSigningContext;
    /// use gamlastan::crypto::kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
    /// use gamlastan::crypto::kryptering::{HashAlgorithm, SignatureAlgorithm};
    ///
    /// # let cert_b64 = String::new(); // base64 DER of the signing certificate
    /// let provider = Pkcs11Provider::new(Path::new("/usr/lib/softhsm/libsofthsm2.so"))?;
    /// let session = provider.open_session("1234")?;
    /// let pkcs11_signer = Pkcs11Signer::new(
    ///     &session,
    ///     "saml-signing-key",
    ///     SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
    /// )?;
    ///
    /// let signing_ctx = IdpSigningContext::from_hsm(Arc::new(pkcs11_signer), cert_b64);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_hsm(
        signer: Arc<dyn gamlastan::crypto::kryptering::Signer>,
        cert_b64: impl Into<String>,
    ) -> Self {
        let keys_manager = gamlastan::crypto::KeysManager::new();
        Self {
            signer: SamlSigner::with_hsm_signer(keys_manager, signer),
            cert_b64: cert_b64.into(),
        }
    }
}

/// Callback type for IdP authentication.
///
/// When the IdP receives an AuthnRequest, the application must authenticate the user.
/// This callback receives the processed request and returns the authenticated
/// user's NameId and attributes (or an error to reject the request).
///
/// # Limits
///
/// The processed request leaves out `Scoping` (`ProxyCount` / `IDPList`, which
/// a proxying IdP must honour) and the requested `Subject`, and this callback
/// is not given the original `AuthnRequest`. It also decides everything itself
/// (NameID, attributes, authn context), with none of the engine's checks. An
/// application that needs either should use [`AuthnSubjectCallback`], which
/// receives the parsed `AuthnRequest`.
pub type AuthnCallback = Box<
    dyn Fn(
            &idp_profile::ProcessedAuthnRequest,
            &HttpRequest,
        ) -> Result<AuthnCallbackResult, SamlActixError>
        + Send
        + Sync
        + 'static,
>;

/// Result from the authentication callback.
#[derive(Debug, Clone)]
pub struct AuthnCallbackResult {
    /// The authenticated user's NameId.
    pub name_id: NameId,
    /// User attributes to include in the assertion.
    pub attributes: Vec<gamlastan::core::assertion::attribute::Attribute>,
    /// Authentication context class reference (e.g., Password, PasswordProtectedTransport).
    pub authn_context_class_ref: Option<String>,
    /// Session index (generated by IdP, used for SLO).
    pub session_index: Option<String>,
    /// When the principal actually authenticated to the IdP.
    ///
    /// Set this to the SSO session's authentication time when reusing an
    /// existing session, so `AuthnStatement/@AuthnInstant` reflects the real
    /// authentication moment rather than response-generation time. `None`
    /// means "authenticated now" (a fresh login). See ADR 0025.
    pub authn_instant: Option<DateTime<Utc>>,
}

/// The higher-level authentication contract for the IdP SSO handler.
///
/// Unlike [`AuthnCallback`] — which returns a fully-decided
/// [`AuthnCallbackResult`] (NameID already constructed, attributes already
/// filtered, authn context already matched) — this callback reports only the
/// *identity facts* the application knows, and lets the
/// [`ResponseEngine`] derive the
/// NameID, released attributes, and authn context, then assemble and sign the
/// response. This is the crate's policy-driven path; [`AuthnCallback`] remains
/// the lower-level escape hatch for integrators who want to bypass crate policy.
///
/// The handler calls [`check_request`]
/// (via the registered [`EstablishedSessionCallback`], if any) *before*
/// invoking this callback, and passes the resulting [`Disposition`]: a `Deny`
/// is handled directly (a signed protocol error — this callback is never
/// invoked for it), so the callback only ever sees `ReuseSession` or
/// `Authenticate`. This means the callback no longer has to (mis)judge
/// ForceAuthn/IsPassive/RequestedAuthnContext itself — it only supplies real
/// attributes and performs the actual login when one is needed.
///
/// The parsed `AuthnRequest` is passed too (a POST body is already consumed by
/// the time the callback runs), because `ProcessedAuthnRequest` leaves out what
/// the engine does not enforce: `Scoping` (`ProxyCount` / `IDPList`, which a
/// proxying IdP must honour) and the requested `Subject` (compare it with the
/// authenticated user via `AuthnRequest::requested_subject` for a re-login or
/// step-up). Return [`AuthnSubjectResult::Deny`] to refuse.
///
/// When the disposition is `ReuseSession`, the subject returned must be the
/// session's own (`subject_id`); the handler takes the method, authn instant and
/// session index from the session, and answers a different subject with a
/// `Configuration` error instead of signing one user's NameID over another's
/// attributes.
///
/// Register both this callback and a [`ResponseEngineParts`] as application
/// data to use it; the SSO handler prefers it over [`AuthnCallback`] when
/// both are present.
pub type AuthnSubjectCallback = Box<
    dyn Fn(
            &idp_profile::ProcessedAuthnRequest,
            &gamlastan::core::protocol::request::AuthnRequest,
            &Disposition,
            &HttpRequest,
        ) -> Result<AuthnSubjectResult, SamlActixError>
        + Send
        + Sync
        + 'static,
>;

/// Reports whether the current request already carries an established IdP
/// session (e.g. by reading a session cookie the application recognizes),
/// for [`check_request`] to
/// weigh against `ForceAuthn`/`IsPassive`/`RequestedAuthnContext`.
///
/// Distinct from [`SessionStore`](gamlastan::profiles::session::SessionStore):
/// that tracks SP-participant state for Single Logout fan-out, not local
/// login state, which only the application can read (its own cookie/session
/// mechanism). Returns cheap identity facts only — no attributes, which the
/// [`AuthnSubjectCallback`] still supplies when it handles the resulting
/// `Disposition`.
pub type EstablishedSessionCallback =
    Box<dyn Fn(&HttpRequest) -> Option<EstablishedSession> + Send + Sync + 'static>;

/// The outcome of the [`AuthnSubjectCallback`].
///
/// - [`Authenticated`](AuthnSubjectResult::Authenticated) — the principal
///   authenticated; the engine assembles and signs the response from the
///   supplied [`AuthenticatedSubject`].
/// - [`Redirect`](AuthnSubjectResult::Redirect) — the application takes over
///   delivery (e.g. a login form, a step-up redirect, or an IdP-initiated
///   response) and returns its own `HttpResponse`.
/// - [`Deny`](AuthnSubjectResult::Deny) — the request is refused with a signed
///   SAML protocol error carrying the given [`Denial`].
pub enum AuthnSubjectResult {
    /// The principal authenticated; assemble a response from these facts.
    Authenticated(AuthenticatedSubject),
    /// The application returns its own response (no SAML assembly here).
    Redirect(HttpResponse),
    /// Refuse the request with a signed protocol error.
    Deny(Denial),
}

/// Owned dependencies for [`ResponseEngine`], registered once as
/// `web::Data<Arc<ResponseEngineParts>>` and used to build a short-lived
/// borrowed `ResponseEngine` for the duration of one request.
///
/// `idp::orchestrator::ResponseEngine` borrows everything by design (a
/// zero-cost fit for a single synchronous call within one scope); requiring
/// callers to register `web::Data<Arc<ResponseEngine<'static>>>` directly
/// would force every dependency — policy, store, broker, signer — to
/// independently satisfy `'static`, which for ordinary application-owned
/// state (not already a global) means leaking it. `ResponseEngineParts`
/// owns everything instead, so an application registers normal `Arc`s built
/// at startup and the ready handler borrows from them per request via
/// [`ResponseEngineParts::engine`].
pub struct ResponseEngineParts {
    /// This IdP's entity ID (used as the response/assertion `Issuer`).
    pub idp_entity_id: String,
    /// The per-SP decisions: lifetime, NameID format, signing targets, and
    /// `fail_on_missing_requested`.
    pub decisions: Arc<ReleasePolicy>,
    /// The attribute-release seam. Defaults to `decisions` itself (an
    /// originating IdP); override with
    /// [`with_release`](Self::with_release) for a proxy shape.
    pub release: Arc<dyn AttributeRelease>,
    /// The identity database (NameID construction), type-erased over its
    /// `IdentityStore` backend.
    pub idents: Arc<dyn NameIdConstructor>,
    /// The authn broker (RequestedAuthnContext matching).
    pub broker: Arc<AuthnBroker>,
    /// The assertion store, if back-channel queries must be answerable.
    pub assertions: Option<Arc<dyn AssertionStore>>,
    /// The signer for the response/assertion.
    pub signer: Arc<SamlSigner>,
    /// The base64 DER signing certificate for `<ds:KeyInfo>`.
    pub cert_der_b64: String,
}

impl ResponseEngineParts {
    /// Build for an originating IdP, whose own `decisions` also serves as
    /// the release seam (the common case; see [`AttributeRelease`]).
    pub fn new(
        idp_entity_id: impl Into<String>,
        decisions: Arc<ReleasePolicy>,
        idents: Arc<dyn NameIdConstructor>,
        broker: Arc<AuthnBroker>,
        signer: Arc<SamlSigner>,
        cert_der_b64: impl Into<String>,
    ) -> Self {
        let release: Arc<dyn AttributeRelease> = decisions.clone();
        Self {
            idp_entity_id: idp_entity_id.into(),
            decisions,
            release,
            idents,
            broker,
            assertions: None,
            signer,
            cert_der_b64: cert_der_b64.into(),
        }
    }

    /// Override the release seam — e.g. a `PassThroughRelease` or
    /// `ChainedRelease` for a proxy whose attributes are already filtered
    /// upstream.
    pub fn with_release(mut self, release: Arc<dyn AttributeRelease>) -> Self {
        self.release = release;
        self
    }

    /// Register an assertion store for back-channel queries.
    pub fn with_assertions(mut self, assertions: Arc<dyn AssertionStore>) -> Self {
        self.assertions = Some(assertions);
        self
    }

    /// Build a borrowed `ResponseEngine` for the duration of one request.
    pub fn engine(&self) -> ResponseEngine<'_> {
        ResponseEngine {
            idp_entity_id: &self.idp_entity_id,
            decisions: &self.decisions,
            release: self.release.as_ref(),
            idents: self.idents.as_ref(),
            broker: &self.broker,
            assertions: self.assertions.as_deref(),
            signer: &self.signer,
            cert_der_b64: &self.cert_der_b64,
        }
    }
}

/// Register all IdP routes on the given service configuration.
///
/// Routes:
/// - `GET|POST /saml/sso`               - SSO endpoint (receive AuthnRequest)
/// - `GET|POST /saml/slo`               - Single Logout Service
/// - `POST     /saml/artifact-resolve`   - Artifact Resolution Service (SOAP)
/// - `GET      /saml/metadata`           - IdP Metadata
pub fn configure_idp(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/saml/sso")
            .route(web::get().to(idp_sso))
            .route(web::post().to(idp_sso)),
    )
    .service(
        web::resource("/saml/slo")
            .route(web::get().to(idp_slo))
            .route(web::post().to(idp_slo)),
    )
    .service(web::resource("/saml/artifact-resolve").route(web::post().to(idp_artifact_resolve)))
    .service(web::resource("/saml/metadata").route(web::get().to(idp_metadata)));
}

/// Resolve the certificate metadata should advertise, from whichever
/// signing source is actually registered - `ResponseEngineParts` first,
/// since when it's present it's the source of truth for what the
/// policy-driven SSO path actually signs responses with; independently
/// registering `IdpSigningContext`/`IdpConfig` with a *different*
/// certificate would otherwise let metadata advertise a key that never
/// signs anything. Falls back to `IdpSigningContext`, then
/// `IdpConfig::signing_cert_b64`, for deployments using only the low-level
/// `AuthnCallback` path.
fn metadata_signing_cert_b64<'a>(
    config: &'a IdpConfig,
    signing_ctx: Option<&'a IdpSigningContext>,
    response_engine: Option<&'a ResponseEngineParts>,
) -> Option<&'a str> {
    response_engine
        .map(|parts| parts.cert_der_b64.as_str())
        .or_else(|| signing_ctx.map(|ctx| ctx.cert_b64.as_str()))
        .or(config.signing_cert_b64.as_deref())
}

/// The `ResponseEngineParts` that actually sign responses, if any.
///
/// `idp_sso` takes the policy-driven path only when both `ResponseEngineParts`
/// and an `AuthnSubjectCallback` are registered. Parts registered alone do not
/// sign anything, so they must not decide which certificate metadata advertises.
fn policy_driven_parts(
    parts: Option<&ResponseEngineParts>,
    authn_subject_callback_registered: bool,
) -> Option<&ResponseEngineParts> {
    parts.filter(|_| authn_subject_callback_registered)
}

/// Insert a signature template as the FIRST child of a given element (right after
/// its opening tag's `>`).
///
/// This is the correct placement for **metadata** (`md:EntityDescriptor` has
/// `ds:Signature` as its first child and no `saml:Issuer`). It is NOT correct for
/// a SAML `Response`/`Assertion`, where `ds:Signature` must follow `saml:Issuer`:
/// for those use [`sign_response_xml`] / `idp_profile::create_signed_response`,
/// which anchor the signature after the Issuer per the schema.
pub fn insert_signature_after_element(
    xml: &str,
    element_name: &str,
    sig_template: &str,
) -> Result<String, SamlActixError> {
    // Find the opening tag for the element
    let search_with_space = format!("<{element_name} ");
    let search_with_close = format!("<{element_name}>");

    let tag_start = xml
        .find(&search_with_space)
        .or_else(|| xml.find(&search_with_close))
        .ok_or_else(|| SamlActixError::Internal(format!("cannot find <{element_name}> in XML")))?;

    // Find the closing '>' of this opening tag
    let insert_pos = xml[tag_start..]
        .find('>')
        .ok_or_else(|| SamlActixError::Internal(format!("malformed <{element_name}> tag")))?;

    let absolute_pos = tag_start + insert_pos;
    Ok(format!(
        "{}{}{}",
        &xml[..=absolute_pos],
        sig_template,
        &xml[absolute_pos + 1..]
    ))
}

/// Sign a SAML Response XML, optionally signing both the Assertion and Response.
///
/// Signing order: Assertion first (inner), then Response (outer). Delegates to
/// core gamlastan's [`idp_profile::sign_response_xml`], which anchors each
/// signature after the element's `<saml:Issuer>` (schema-correct placement) -
/// replacing this crate's earlier first-child splice. See gamlastan ADR 0033.
pub fn sign_response_xml(
    response_xml: &str,
    signing_ctx: &IdpSigningContext,
    response_id: &str,
    assertion_id: Option<&str>,
    sign_assertions: bool,
    sign_responses: bool,
) -> Result<String, SamlActixError> {
    idp_profile::sign_response_xml(
        response_xml,
        &signing_ctx.signer,
        &signing_ctx.cert_b64,
        response_id,
        assertion_id,
        sign_assertions,
        sign_responses,
    )
    .map_err(|e| SamlActixError::Internal(format!("response/assertion signing failed: {e}")))
}

/// IdP SSO handler: process an incoming AuthnRequest.
///
/// This handler:
/// 1. Decodes and parses the AuthnRequest
/// 2. Validates it against SP metadata (if available)
/// 3. Calls the AuthnCallback to authenticate the user
/// 4. Creates a SAML Response with assertion
/// 5. Signs the Assertion and Response (if signing context is available)
/// 6. Sends the Response back to the SP's ACS URL via POST binding
/// 7. Forwards RelayState from the original request
#[allow(clippy::too_many_arguments)]
async fn idp_sso(
    msg: SamlMessage,
    config: web::Data<IdpConfig>,
    signing_ctx: Option<web::Data<Arc<IdpSigningContext>>>,
    authn_callback: Option<web::Data<AuthnCallback>>,
    authn_subject_callback: Option<web::Data<AuthnSubjectCallback>>,
    established_session_callback: Option<web::Data<EstablishedSessionCallback>>,
    response_engine: Option<web::Data<Arc<ResponseEngineParts>>>,
    req: HttpRequest,
) -> Result<HttpResponse, SamlActixError> {
    // Save relay state before msg is consumed
    let relay_state_str = msg.relay_state.clone();

    // Parse the AuthnRequest
    let xml_str = msg.saml_xml_str()?;
    let doc = gamlastan::xml::parse_secure(xml_str).map_err(|e: uppsala::XmlError| {
        SamlActixError::Xml(gamlastan::xml::error::XmlError::ParseError(e))
    })?;
    let request_ref = gamlastan::xml::deserialize::parse_saml::<
        gamlastan::core::protocol::request::AuthnRequestRef<'_>,
    >(&doc)?;
    let authn_request = request_ref.to_owned();

    // Bind the request to trusted SP metadata before issuing anything. Passing
    // `None` here (the old behaviour) made the core profile trust the
    // request-supplied AssertionConsumerServiceURL, so any requester could have
    // a signed assertion delivered to an ACS URL they control (CWE-346). Require
    // the AuthnRequest issuer to resolve to trusted SP metadata — statically
    // registered or fetched via the (MDQ-backed) resolver — and validate the ACS
    // URL against it; fail closed when no metadata is available.
    let issuer = authn_request.base.issuer.as_ref().map(|i| i.value.as_str());
    let sp_entity = match issuer {
        Some(id) => resolve_trusted_sp_entity(&config, id).await,
        None => None,
    };
    let sp_entity = sp_entity.ok_or_else(|| {
        // Untrusted/unknown requester is an authorization failure on
        // attacker-controllable request input, not a server misconfiguration:
        // surface it as 403 rather than 500 so hostile traffic does not read as
        // internal errors or leak configuration detail.
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            format!(
                "AuthnRequest issuer {:?} is not a trusted SP; refusing to issue \
                 (register it with IdpConfig::with_trusted_sp or configure an MDQ \
                 resolver via IdpConfig::with_sp_resolver)",
                issuer.unwrap_or("<missing>")
            ),
        ))
    })?;
    let sp_sso = sp_entity
        .saml2_sp_sso_descriptor()
        .cloned()
        .ok_or_else(|| {
            SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
                format!(
                    "trusted entity {:?} has no SAML 2.0 SPSSODescriptor",
                    sp_entity.entity_id
                ),
            ))
        })?;

    // Process the AuthnRequest (validates and extracts parameters). With trusted
    // SP metadata, a request-supplied ACS URL not present in metadata is rejected.
    // These are validation failures on attacker-controllable request input, so
    // preserve the ProfileError mapping (HTTP 403) rather than turning a normal
    // rejection into an Internal 500 (which is misleading and noisy under
    // hostile traffic).
    let request_signature_verified = verify_sp_request_signatures(
        msg.redirect_signature.as_ref(),
        &config,
        &sp_sso,
        xml_str,
        &authn_request.base.id,
        authn_request.base.has_signature,
        "AuthnRequest",
    )?;

    let processed =
        idp_profile::process_authn_request(&authn_request, &sp_sso, request_signature_verified)
            .map_err(SamlActixError::Profile)?;
    require_post_acs(&processed)?;

    // The higher-level, policy-driven path: when both an AuthnSubjectCallback
    // and ResponseEngineParts are registered, the engine derives the NameID,
    // released attributes, and authn context, then assembles and signs the
    // response. This is preferred over the lower-level AuthnCallback.
    if let (Some(callback), Some(parts)) = (&authn_subject_callback, &response_engine) {
        // Metadata and request validation name the IdP `config.entity_id`; the
        // engine signs with `parts.idp_entity_id` as Issuer. If they differ
        // every SP rejects the Issuer, so fail loudly instead.
        if parts.idp_entity_id != config.entity_id {
            return Err(SamlActixError::Configuration(format!(
                "ResponseEngineParts::idp_entity_id {:?} differs from IdpConfig::entity_id {:?}",
                parts.idp_entity_id, config.entity_id
            )));
        }
        let params =
            ResponseParams::new(processed.clone(), sp_sso.clone(), Some(sp_entity.clone()))
                .map_err(SamlActixError::Profile)?;
        let engine = parts.engine();
        let engine = &engine;

        // check_request decides ForceAuthn/IsPassive/RequestedAuthnContext
        // *before* the callback runs. A Deny is handled directly here — the
        // callback is never invoked for it, so it cannot redirect to a login
        // form for IsPassive or reuse a session ForceAuthn defeated.
        let established = established_session_callback.as_ref().and_then(|f| f(&req));
        let disposition = check_request(engine, &params, established.as_ref());
        if let Disposition::Deny { denial } = &disposition {
            let issued =
                create_denial_response(engine, &params, denial).map_err(SamlActixError::Profile)?;
            return post_signed_response(
                &issued.xml,
                &processed.acs_url,
                relay_state_str.as_deref(),
            );
        }

        let result = callback(&processed, &authn_request, &disposition, &req)?;
        return match result {
            AuthnSubjectResult::Authenticated(mut subject) => {
                pin_to_reused_session(&mut subject, &disposition)?;
                let outcome = create_authn_response(engine, &params, &subject)
                    .map_err(SamlActixError::Profile)?;
                let xml = match outcome {
                    ResponseOutcome::Issued(issued) => issued.xml,
                    ResponseOutcome::Denied { response, .. } => response.xml,
                };
                post_signed_response(&xml, &processed.acs_url, relay_state_str.as_deref())
            }
            AuthnSubjectResult::Redirect(response) => Ok(response),
            AuthnSubjectResult::Deny(denial) => {
                let issued = create_denial_response(engine, &params, &denial)
                    .map_err(SamlActixError::Profile)?;
                post_signed_response(&issued.xml, &processed.acs_url, relay_state_str.as_deref())
            }
        };
    }

    // Call the authentication callback
    let callback = authn_callback.ok_or_else(|| {
        SamlActixError::Configuration("no AuthnCallback registered for IdP SSO".into())
    })?;

    let authn_result = callback(&processed, &req)?;

    let now = Utc::now();
    let session_not_on_or_after = now
        + chrono::TimeDelta::try_seconds(config.session_lifetime_seconds as i64)
            .unwrap_or(chrono::TimeDelta::try_hours(8).unwrap());

    // Create the SAML Response
    let response_options = ResponseOptions {
        idp_entity_id: config.entity_id.clone(),
        in_response_to: Some(processed.request_id.clone()),
        sp_entity_id: processed.sp_entity_id.clone(),
        acs_url: processed.acs_url.clone(),
        assertion_lifetime_seconds: config.assertion_lifetime_seconds,
        session_index: authn_result.session_index.clone(),
        session_not_on_or_after: Some(session_not_on_or_after),
        authn_context_class_ref: authn_result.authn_context_class_ref.clone(),
        client_address: req
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string()),
        attributes: authn_result.attributes.clone(),
        authenticating_authorities: vec![],
    };

    let times = ResponseTimes {
        issue_instant: now,
        authn_instant: authn_result.authn_instant.unwrap_or(now),
    };
    let response = idp_profile::create_response(&response_options, &authn_result.name_id, times);

    let response_xml = response
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize Response: {e}")))?;

    // Sign the Response and Assertion if signing context is available
    let final_xml = if let Some(ctx) = &signing_ctx {
        // Extract assertion ID from the response for signing
        let assertion_id = response.assertions.first().map(|a| a.id.as_str());
        sign_response_xml(
            &response_xml,
            ctx,
            &response.base.id,
            assertion_id,
            config.sign_assertions,
            config.sign_responses,
        )?
    } else if config.sign_assertions || config.sign_responses {
        return Err(SamlActixError::Configuration(
            "IdP response/assertion signing is enabled but no IdpSigningContext is registered"
                .into(),
        ));
    } else {
        response_xml
    };

    // Build RelayState for forwarding
    let relay_state = relay_state_str.as_deref().map(RelayState::echo);

    // Send via POST binding to the SP's ACS URL
    let html = gamlastan::bindings::post::post_encode(
        final_xml.as_bytes(),
        false, // is_response, not request
        &processed.acs_url,
        relay_state.as_ref(),
    );

    Ok(crate::response_adapter::post_binding_response(&html))
}

/// On `ReuseSession` the session owns the subject, the method that ran, when
/// it ran and the session index; `check_request` validated exactly those. The
/// callback keeps only the attributes. Without this, a callback returning
/// `authn_instant: None` would restart the absolute session expiry from now,
/// or attach a different session index to the reused session.
///
/// The callback must name the same subject as the session. Overwriting a
/// different one would sign the session user's NameID over the other user's
/// attributes, so a mismatch is a configuration error: the established-session
/// callback and the authn-subject callback disagree about who is at the browser.
fn pin_to_reused_session(
    subject: &mut AuthenticatedSubject,
    disposition: &Disposition,
) -> Result<(), SamlActixError> {
    if let Disposition::ReuseSession { session } = disposition {
        if subject.subject_id != session.subject_id {
            return Err(SamlActixError::Configuration(
                "AuthnSubjectCallback returned a different subject than the established \
                 session it was told to reuse"
                    .into(),
            ));
        }
        subject.authn_method = session.authn_method.clone();
        subject.authn_instant = Some(session.authn_instant);
        subject.session_index = Some(session.session_index.clone());
    }
    Ok(())
}

/// The ready handlers deliver a full Response through an auto-submitting HTTP-POST
/// form, whatever the ACS binding the request resolved to. A request that resolves
/// to an endpoint registered for another binding (HTTP-Artifact, HTTP-Redirect)
/// would be answered with the wrong binding, so it is refused here instead.
/// An application that has to serve such an SP uses the profile functions
/// directly: `ProcessedAuthnRequest::acs_binding` says how to deliver.
fn require_post_acs(
    processed: &gamlastan::profiles::sso::idp::ProcessedAuthnRequest,
) -> Result<(), SamlActixError> {
    if processed.acs_binding == gamlastan::core::constants::BINDING_HTTP_POST {
        return Ok(());
    }
    Err(SamlActixError::UnsupportedBinding(format!(
        "the ACS {} resolved from the request is registered for {}, but this handler \
         delivers by HTTP-POST only",
        processed.acs_url, processed.acs_binding
    )))
}

/// POST-encode a signed, assembled response to the SP's ACS and wrap it as the
/// HTTP-POST binding response.
fn post_signed_response(
    xml: &str,
    acs_url: &str,
    relay_state: Option<&str>,
) -> Result<HttpResponse, SamlActixError> {
    let relay = relay_state.map(RelayState::echo);
    let html = gamlastan::bindings::post::post_encode(
        xml.as_bytes(),
        false, // is_response, not request
        acs_url,
        relay.as_ref(),
    );
    Ok(crate::response_adapter::post_binding_response(&html))
}

/// IdP SLO handler: process incoming LogoutRequest or LogoutResponse.
async fn idp_slo(
    msg: SamlMessage,
    config: web::Data<IdpConfig>,
) -> Result<HttpResponse, SamlActixError> {
    let xml_str = msg.saml_xml_str()?;
    let doc = gamlastan::xml::parse_secure(xml_str).map_err(|e: uppsala::XmlError| {
        SamlActixError::Xml(gamlastan::xml::error::XmlError::ParseError(e))
    })?;

    let root = doc
        .document_element()
        .ok_or_else(|| SamlActixError::Internal("empty XML document".into()))?;
    let root_elem = doc
        .element(root)
        .ok_or_else(|| SamlActixError::Internal("invalid root element".into()))?;

    match root_elem.name.local_name.as_ref() {
        "LogoutRequest" => {
            let req_ref = gamlastan::xml::deserialize::parse_saml::<
                gamlastan::core::protocol::logout::LogoutRequestRef<'_>,
            >(&doc)?;
            let logout_req = req_ref.to_owned();

            // Authorize the logout before mutating any session. SLO destroys
            // sessions keyed by the request-supplied NameID, so an unauthenticated
            // request lets anyone who guesses a NameID force-logout a victim
            // (CWE-306/CWE-862). Require the LogoutRequest to be signed by a
            // trusted SP, carry a trusted issuer, and (if present) target this
            // IdP's SLO endpoint. Resolve the issuer's metadata (static registry
            // or MDQ resolver) before the synchronous check.
            let slo_issuer = logout_req.issuer.as_ref().map(|i| i.value.as_str());
            let slo_sp = match slo_issuer {
                Some(id) => resolve_trusted_sp(&config, id).await,
                None => None,
            };
            let slo_authorized = authorize_slo_request(
                &config,
                &logout_req,
                xml_str,
                msg.redirect_signature.as_ref(),
                slo_sp.as_ref(),
            )?;
            // The ready handler has no decryption context. Reject an encrypted
            // identifier after authenticating the requester but before
            // reserving replay state, regardless of whether session storage is
            // configured.
            let request_name_id = ready_idp_logout_name_id(&logout_req)?;
            let now = Utc::now();
            // `expected_issuer` is the request's own issuer: on the IdP side the
            // real issuer trust decision is the metadata resolution and signature
            // check that produced `slo_authorized`, so the equality check inside
            // `validate_logout_request` is already established. The remaining
            // value of the call is the NameID and NotOnOrAfter validation.
            logout::validate_logout_request_with_replay(
                &logout_req,
                slo_issuer.unwrap_or_default(),
                slo_authorized.message_authenticated(),
                now,
                config.security.clock_skew_seconds,
                config.max_logout_request_age_seconds,
                config.logout_replay_cache.as_ref(),
            )
            .map_err(SamlActixError::Profile)?;

            // Atomically recheck and remove the exact participant-bound
            // sessions before using the removed live records for propagation.
            // A split lookup followed by index-only deletion would allow a
            // concurrent replacement to be destroyed without authorization.
            if let Some(ref session_store) = config.session_store {
                let requester_entity_id = slo_issuer.unwrap_or_default();
                let sessions = session_store
                    .take_sessions_for_participant(
                        requester_entity_id,
                        request_name_id,
                        &logout_req.session_indexes,
                    )
                    .map_err(|error| {
                        SamlActixError::Internal(format!(
                            "atomic participant-bound session removal failed: {error}"
                        ))
                    })?;

                for session in &sessions {
                    // Build LogoutRequest for each participant (except the requester)
                    for participant in &session.participants {
                        if participant.entity_id == requester_entity_id {
                            continue; // Don't send back to the requester
                        }
                        let propagation_req =
                            logout::create_idp_propagation_request(&config.entity_id, participant);
                        let _propagation_xml = propagation_req.to_xml_string().ok();
                        // Note: actual HTTP delivery requires an async HTTP client.
                        // The application should implement a SoapTransport or
                        // use the propagation request XML directly. The SessionStore
                        // tracks who needs logout; the application handles delivery.
                    }
                }
            }

            let in_response_to = &logout_req.id;
            let response =
                logout::create_logout_response_success(&config.entity_id, in_response_to, None);

            let response_xml = response.to_xml_string().map_err(|e| {
                SamlActixError::Internal(format!("failed to serialize LogoutResponse: {e}"))
            })?;

            Ok(HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(format!(
                    "<html><body><p>Logout completed</p><!-- {} --></body></html>",
                    response_xml.len()
                )))
        }
        "LogoutResponse" => {
            // Process the SP's response to our propagation LogoutRequest
            Ok(HttpResponse::Ok().body("Logout propagation acknowledged"))
        }
        other => Err(SamlActixError::UnsupportedBinding(format!(
            "unexpected SAML element in SLO: {other}"
        ))),
    }
}

fn ready_idp_logout_name_id(request: &LogoutRequest) -> Result<&NameId, SamlActixError> {
    match &request.name_id {
        NameIdOrEncryptedId::NameId(name_id) => Ok(name_id),
        NameIdOrEncryptedId::EncryptedId(_) => Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(
                "ready IdP SLO cannot correlate an encrypted NameID; decrypt it in a custom handler"
                    .into(),
            ),
        )),
    }
}

/// IdP Artifact Resolution handler: resolve artifacts over SOAP back-channel.
///
/// Expects a SOAP-wrapped ArtifactResolve request.
async fn idp_artifact_resolve(
    msg: SamlMessage,
    config: web::Data<IdpConfig>,
) -> Result<HttpResponse, SamlActixError> {
    let xml_str = msg.saml_xml_str()?;
    let doc = gamlastan::xml::parse_secure(xml_str).map_err(|e: uppsala::XmlError| {
        SamlActixError::Xml(gamlastan::xml::error::XmlError::ParseError(e))
    })?;

    let resolve_ref = gamlastan::xml::deserialize::parse_saml::<
        gamlastan::core::protocol::artifact::ArtifactResolveRef<'_>,
    >(&doc)?;
    let resolve = resolve_ref.to_owned();

    // Authenticate the requester before consuming the one-time artifact. The
    // ArtifactResolve/ArtifactResponse exchange is a mutually authenticated SOAP
    // back-channel; without authentication anyone who obtains a live artifact can
    // drain it (receiving the stored SAML message) or burn it to deny the
    // legitimate resolver (CWE-306). Require a signature from a trusted SP whose
    // issuer matches. Resolve the issuer's metadata (static registry or MDQ
    // resolver) before the synchronous check.
    let ar_issuer = resolve.issuer.as_ref().map(|i| i.value.as_str());
    let ar_sp = match ar_issuer {
        Some(id) => resolve_trusted_sp(&config, id).await,
        None => None,
    };
    authorize_artifact_resolve(&config, &resolve, xml_str, ar_sp.as_ref())?;
    let requester_entity_id = ar_issuer.ok_or_else(|| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            "ArtifactResolve missing Issuer required for artifact ownership".into(),
        ))
    })?;

    // Look up the artifact in the artifact store
    let response_xml = if let Some(ref artifact_store) = config.artifact_store {
        match artifact_store
            .resolve_and_consume_for_requester(&resolve.artifact, requester_entity_id)
        {
            Ok(Some(message_xml)) => {
                // Build a successful ArtifactResponse wrapping the resolved SAML message
                let art_response = artifact_resolution::create_artifact_response(
                    &config.entity_id,
                    &resolve.id,
                    Some(message_xml),
                );
                art_response.to_xml_string().map_err(|e| {
                    SamlActixError::Internal(format!("failed to serialize ArtifactResponse: {e}"))
                })?
            }
            Ok(None) => {
                // Artifact not found (or already consumed)
                let error_response = artifact_resolution::create_artifact_response_error(
                    &config.entity_id,
                    &resolve.id,
                    "artifact not found or already consumed",
                );
                error_response.to_xml_string().map_err(|e| {
                    SamlActixError::Internal(format!("failed to serialize ArtifactResponse: {e}"))
                })?
            }
            Err(e) => {
                let error_response = artifact_resolution::create_artifact_response_error(
                    &config.entity_id,
                    &resolve.id,
                    &format!("artifact store error: {e}"),
                );
                error_response.to_xml_string().map_err(|e| {
                    SamlActixError::Internal(format!("failed to serialize ArtifactResponse: {e}"))
                })?
            }
        }
    } else {
        // No artifact store configured
        let error_response = artifact_resolution::create_artifact_response_error(
            &config.entity_id,
            &resolve.id,
            "artifact resolution not configured",
        );
        error_response.to_xml_string().map_err(|e| {
            SamlActixError::Internal(format!("failed to serialize ArtifactResponse: {e}"))
        })?
    };

    // Wrap in SOAP envelope
    let soap_body = gamlastan::bindings::soap::soap_envelope_wrap(&response_xml, None);
    Ok(HttpResponse::Ok()
        .content_type("text/xml; charset=utf-8")
        .body(soap_body))
}

/// Verify that an enveloped XML-DSig signature over `xml_str` was produced by a
/// trusted Service Provider and is cryptographically bound to the message we
/// parsed.
///
/// This is the shared signature gate for the IdP's back-channel/front-channel
/// handlers (artifact resolution and Single Logout). It enforces three things:
///
/// 1. **Authentication** — the signature must verify against a key built from
///    the *resolved* SP's signing certificates ([`IdpConfig::verifier_for`]).
/// 2. **Integrity** — every XML signature present must be `Valid`, not merely
///    the first one in document order.
/// 3. **Binding** — every verified XML-DSig signature must reference
///    `expected_id` (the parsed message's `ID`) or the document root, so a valid
///    signature over a *sibling* object cannot authorize this message (XML
///    Signature Wrapping).
///
/// `sp` is the metadata resolved for the message's issuer (statically or via the
/// MDQ-backed resolver). `what` is a short human label (e.g. `"LogoutRequest"`)
/// used in error messages. Returns `Ok(())` when the message is authorized, or a
/// 403-mapped [`SamlActixError::Profile`] describing why it was rejected — every
/// rejection here is an unauthenticated/invalid request condition, so none of
/// them is reported as a 500.
///
/// # Examples
///
/// ```ignore
/// // Inside an IdP handler, after parsing the message and resolving its issuer:
/// verify_sp_message_signature(&config, &sp, xml_str, &logout_req.id, "LogoutRequest")?;
/// // ... only now is it safe to act on the request.
/// ```
fn verify_sp_message_signature(
    config: &IdpConfig,
    sp: &gamlastan::metadata::types::sp::SpSsoDescriptor,
    xml_str: &str,
    expected_id: &str,
    what: &str,
) -> Result<(), SamlActixError> {
    // Missing signing material for an inbound request is an authentication
    // failure on attacker-controllable traffic, not a server fault: map it to
    // 403 (via ProfileError) rather than 500.
    let verifier = config.verifier_for(sp).ok_or_else(|| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            format!(
                "{what} issuer has no usable signing certificate in its metadata; \
                 refusing unauthenticated request"
            ),
        ))
    })?;

    let results = verifier.verify_all_enveloped(xml_str).map_err(|e| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            format!("{what} signature verification failed: {e}"),
        ))
    })?;
    if results.is_empty() {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "{what} contains no XML signature"
            )),
        ));
    }

    for result in results {
        match result {
            gamlastan::crypto::VerifyResult::Valid { references, .. } => {
                // Bind every signature to the parsed message. This also keeps
                // a second unbound-but-valid signature from hiding behind a
                // valid first signature.
                if !references.iter().any(|reference| {
                    reference.uri.is_empty() || reference.uri.strip_prefix('#') == Some(expected_id)
                }) {
                    return Err(SamlActixError::Profile(
                        gamlastan::profiles::ProfileError::AssertionValidation(format!(
                            "{what} signature did not reference the message (XML Signature Wrapping)"
                        )),
                    ));
                }
            }
            gamlastan::crypto::VerifyResult::Invalid { reason } => {
                return Err(SamlActixError::Profile(
                    gamlastan::profiles::ProfileError::AssertionValidation(format!(
                        "{what} signature invalid: {reason}"
                    )),
                ));
            }
        }
    }

    Ok(())
}

/// Verify every signature representation present on an SP request and return
/// whether the request was authenticated.
///
/// Returns `true` when at least one signature representation is present and
/// every representation present verifies against the SP metadata keys.
///
/// # Errors
///
/// Returns an error when signing keys are unavailable, a Redirect or XML
/// signature is invalid, or signature verification cannot be completed.
fn verify_sp_request_signatures(
    redirect_signature: Option<&RedirectSignatureData>,
    config: &IdpConfig,
    sp: &gamlastan::metadata::types::sp::SpSsoDescriptor,
    xml: &str,
    request_id: &str,
    has_xml_signature: bool,
    what: &str,
) -> Result<bool, SamlActixError> {
    let mut verified = false;

    if let Some(signature) = redirect_signature {
        let verifier = config.verifier_for(sp).ok_or_else(|| {
            SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
                format!("{what} issuer has no usable signing certificate in metadata"),
            ))
        })?;
        let valid = verifier
            .verify_redirect_query(
                signature.signature_input.as_bytes(),
                &signature.signature,
                &signature.sig_alg,
            )
            .map_err(|e| {
                SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
                    format!("{what} redirect signature verification failed: {e}"),
                ))
            })?;
        if !valid {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(format!(
                    "{what} redirect signature is invalid"
                )),
            ));
        }
        verified = true;
    }

    if has_xml_signature {
        verify_sp_message_signature(config, sp, xml, request_id, what)?;
        verified = true;
    }

    Ok(verified)
}

/// Resolve trusted SP metadata for `entity_id`: the static
/// [`IdpConfig::trusted_sps`] registry first, then the optional
/// [`TrustedSpResolver`](crate::TrustedSpResolver) (e.g. an MDQ client).
///
/// Returns owned [`SpSsoDescriptor`] metadata so the caller can both validate a
/// request-supplied ACS URL against it and build a verifier from its signing
/// keys. `None` means the entityID is not trusted; the handler then fails closed.
///
/// This is the seam that lets a federation IdP with an MDQ setup — and no SPs
/// registered statically — still operate: the resolver fetches and
/// signature-verifies the SP's metadata on demand.
///
/// # Examples
///
/// ```ignore
/// // In an IdP handler:
/// let sp = match issuer {
///     Some(id) => resolve_trusted_sp(&config, id).await,
///     None => None,
/// };
/// ```
async fn resolve_trusted_sp(
    config: &IdpConfig,
    entity_id: &str,
) -> Option<gamlastan::metadata::types::sp::SpSsoDescriptor> {
    resolve_trusted_sp_entity(config, entity_id)
        .await
        .and_then(|entity| entity.saml2_sp_sso_descriptor().cloned())
}

/// Resolve the trusted SP's full entity descriptor by `entityID` — the static
/// registry first, then the dynamic [`TrustedSpResolver`] if configured.
///
/// Unlike [`resolve_trusted_sp`], this carries entity-level extensions
/// (entity categories, `subject-id:req`, etc.) needed for
/// `idp::orchestrator`'s attribute-release policy.
async fn resolve_trusted_sp_entity(
    config: &IdpConfig,
    entity_id: &str,
) -> Option<gamlastan::metadata::types::entity_descriptor::EntityDescriptor> {
    if let Some(entity) = config.trusted_sp_entity(entity_id) {
        return Some(entity.clone());
    }
    if let Some(resolver) = &config.sp_resolver {
        let entity = resolver.resolve_sp(entity_id).await?;
        // A resolver that returns a descriptor for a different entity than
        // requested must not be trusted for this lookup: accepting it would
        // bind the requested issuer's authorization to a different entity's
        // ACS endpoints and release policy.
        if entity.entity_id != entity_id {
            return None;
        }
        return Some(entity);
    }
    None
}

/// Authorize an incoming `LogoutRequest` before it is allowed to destroy any
/// session (Single Logout).
///
/// SLO tears down sessions keyed by the request-supplied `NameID`, so an
/// unauthenticated or unauthorized request would let anyone who can guess or
/// observe a victim's `NameID` force-log-them-out (CWE-306 Missing
/// Authentication, CWE-862 Missing Authorization). This function therefore
/// gates the destructive path on three checks, performed *before* the session
/// store is touched:
///
/// 1. the `Issuer` must resolve to trusted SP metadata (`sp`, resolved by the
///    handler from the static registry or the MDQ resolver);
/// 2. the `Destination`, when present, must address this IdP's SLO endpoint
///    (`IdpConfig::slo_url`); and
/// 3. the message must carry a valid HTTP-Redirect or enveloped XML signature
///    from that SP, bound to the request. Every representation present must
///    verify.
///
/// `sp` is the metadata resolved for `logout_req`'s issuer, or `None` if the
/// issuer is unknown/untrusted. Returns an [`SloAuthorization`] proof when the
/// logout is authorized, otherwise a 403-mapped [`SamlActixError::Profile`]
/// explaining the rejection (these are request authorization failures, not
/// server faults).
///
/// # Examples
///
/// ```ignore
/// // In the SLO handler, after structural validation and issuer resolution:
/// let slo_authorized = authorize_slo_request(
///     &config,
///     &logout_req,
///     xml_str,
///     msg.redirect_signature.as_ref(),
///     slo_sp.as_ref(),
/// )?;
/// // Safe to look up and destroy the principal's sessions now; thread
/// // `slo_authorized.message_authenticated()` into `validate_logout_request`.
/// ```
fn authorize_slo_request(
    config: &IdpConfig,
    logout_req: &gamlastan::core::protocol::logout::LogoutRequest,
    xml_str: &str,
    redirect_signature: Option<&RedirectSignatureData>,
    sp: Option<&gamlastan::metadata::types::sp::SpSsoDescriptor>,
) -> Result<SloAuthorization, SamlActixError> {
    // The issuer must resolve to trusted SP metadata.
    let issuer = logout_req.issuer.as_ref().map(|i| i.value.as_str());
    // Untrusted/missing issuer and Destination mismatch are authorization
    // failures on request input → 403 (via ProfileError), not 500.
    let sp = match (issuer, sp) {
        (Some(_), Some(sp)) => sp,
        (Some(id), None) => {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(format!(
                    "LogoutRequest issuer {id:?} is not a trusted SP; refusing to destroy sessions"
                )),
            ))
        }
        (None, _) => {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(
                    "LogoutRequest has no Issuer; refusing to destroy sessions".into(),
                ),
            ))
        }
    };

    // The Destination, when present, must address this IdP's SLO endpoint.
    if let Some(dest) = logout_req.destination.as_deref() {
        if !config.slo_url.is_empty() && dest != config.slo_url {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(format!(
                    "LogoutRequest Destination {dest:?} does not match this IdP's SLO endpoint"
                )),
            ));
        }
    }

    let authenticated = verify_sp_request_signatures(
        redirect_signature,
        config,
        sp,
        xml_str,
        &logout_req.id,
        logout_req.has_signature,
        "LogoutRequest",
    )?;
    if !authenticated {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(
                "LogoutRequest must be signed by its trusted SP".into(),
            ),
        ));
    }
    Ok(SloAuthorization)
}

/// Proof that [`authorize_slo_request`] authenticated a logout message.
///
/// The token is produced only by that function, so the authentication flag
/// threaded into `logout::validate_logout_request` reflects work that actually
/// ran — a refactor that removes or reorders the authorization step loses the
/// token and fails to compile instead of silently passing a stale `true`.
#[derive(Clone, Copy, Debug)]
#[must_use = "thread this proof into logout validation"]
struct SloAuthorization;

impl SloAuthorization {
    /// The message-authentication flag for `logout::validate_logout_request`.
    ///
    /// This token exists only after a bound message signature verified against
    /// trusted SP metadata.
    fn message_authenticated(self) -> bool {
        true
    }
}

/// Authorize an incoming `ArtifactResolve` before the referenced artifact is
/// looked up and consumed.
///
/// The SAML Artifact Resolution profile is a *mutually authenticated* SOAP
/// back-channel: artifacts are one-time references to stored SAML messages, so
/// an unauthenticated resolve endpoint lets anyone who obtains an artifact
/// either drain it (receiving the stored message) or burn it to deny the
/// legitimate resolver (CWE-306 Missing Authentication). Because the underlying
/// store operation is destructive (resolve-and-consume), this function must run
/// to completion *before* the store is queried.
///
/// It requires the `ArtifactResolve` `Issuer` to resolve to trusted SP metadata
/// (`sp`, resolved by the handler from the static registry or the MDQ resolver)
/// and the message to carry a valid, bound signature from that SP (delegated to
/// [`verify_sp_message_signature`]). A generic transport-authenticated bypass
/// cannot securely bind the claimed SAML Issuer to the transport principal, so
/// the ready handler deliberately does not provide one.
///
/// `sp` is the metadata resolved for `resolve`'s issuer, or `None` if the issuer
/// is unknown/untrusted. Returns `Ok(())` when the requester is authorized,
/// otherwise a 403-mapped [`SamlActixError::Profile`] describing the rejection
/// (a requester-authentication failure, not a server fault).
///
/// # Examples
///
/// ```ignore
/// // In the artifact-resolution handler, after parsing and issuer resolution:
/// authorize_artifact_resolve(&config, &resolve, xml_str, ar_sp.as_ref())?;
/// // Only now consume the one-time artifact from the store.
/// ```
fn authorize_artifact_resolve(
    config: &IdpConfig,
    resolve: &gamlastan::core::protocol::artifact::ArtifactResolve,
    xml_str: &str,
    sp: Option<&gamlastan::metadata::types::sp::SpSsoDescriptor>,
) -> Result<(), SamlActixError> {
    let issuer = resolve.issuer.as_ref().map(|i| i.value.as_str());
    // Untrusted/missing requester is an authentication failure on
    // attacker-controllable input → 403 (via ProfileError), not 500.
    let sp = match (issuer, sp) {
        (Some(_), Some(sp)) => sp,
        (Some(id), None) => {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(format!(
                    "ArtifactResolve issuer {id:?} is not a trusted SP; refusing resolution"
                )),
            ))
        }
        (None, _) => {
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(
                    "ArtifactResolve has no Issuer; refusing resolution".into(),
                ),
            ))
        }
    };

    verify_sp_message_signature(config, sp, xml_str, &resolve.id, "ArtifactResolve")
}

/// IdP metadata handler: generate and return the IdP's SAML metadata.
///
/// If a signing context is available, the metadata will include a KeyDescriptor
/// and will be signed with an enveloped signature.
async fn idp_metadata(
    config: web::Data<IdpConfig>,
    signing_ctx: Option<web::Data<Arc<IdpSigningContext>>>,
    response_engine: Option<web::Data<Arc<ResponseEngineParts>>>,
    authn_subject_callback: Option<web::Data<AuthnSubjectCallback>>,
) -> Result<MetadataXml, SamlActixError> {
    use gamlastan::core::identifiers::SamlId;
    use gamlastan::metadata::types::endpoint::Endpoint;
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use gamlastan::metadata::types::idp::IdpSsoDescriptor;
    use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    // Prefer the active signing source's certificate so metadata stays in sync
    // with the key that actually signs responses and metadata - see
    // metadata_signing_cert_b64's doc for the precedence and why it matters.
    //
    // `idp_sso` signs with `ResponseEngineParts` only when an
    // `AuthnSubjectCallback` is registered too (see its `if let (Some(callback),
    // Some(parts))`); with parts and only the low-level `AuthnCallback`, it signs
    // with `IdpSigningContext` or not at all. The engine's certificate is
    // therefore only advertised when it is the one actually signing.
    let metadata_cert_b64 = metadata_signing_cert_b64(
        config.get_ref(),
        signing_ctx.as_ref().map(|ctx| ctx.get_ref().as_ref()),
        policy_driven_parts(
            response_engine
                .as_ref()
                .map(|parts| parts.get_ref().as_ref()),
            authn_subject_callback.is_some(),
        ),
    );

    let key_descriptors = if let Some(cert_b64) = metadata_cert_b64 {
        let key_info_xml = gamlastan::crypto::build_x509_key_info(&[cert_b64]);
        vec![KeyDescriptor::signing(key_info_xml)]
    } else {
        vec![]
    };

    let mut base =
        RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
    base.key_descriptors = key_descriptors;

    let idp_sso_desc = IdpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base,
            artifact_resolution_services: vec![],
            single_logout_services: if config.slo_url.is_empty() {
                vec![]
            } else {
                vec![
                    Endpoint::new(
                        gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                        &config.slo_url,
                    ),
                    Endpoint::new(
                        gamlastan::profiles::sso::web_browser::bindings::HTTP_POST,
                        &config.slo_url,
                    ),
                ]
            },
            manage_name_id_services: vec![],
            name_id_formats: vec![
                gamlastan::core::constants::NAMEID_TRANSIENT.to_string(),
                gamlastan::core::constants::NAMEID_EMAIL.to_string(),
            ],
        },
        want_authn_requests_signed: Some(false),
        single_sign_on_services: vec![
            Endpoint::new(
                gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                &config.sso_url,
            ),
            Endpoint::new(
                gamlastan::profiles::sso::web_browser::bindings::HTTP_POST,
                &config.sso_url,
            ),
        ],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
    };

    let metadata_id = SamlId::generate().to_string();
    let entity = EntityDescriptor {
        entity_id: config.entity_id.clone(),
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

    let xml = entity
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize metadata: {e}")))?;

    // Sign metadata if signing context is available
    let final_xml = if let Some(ctx) = &signing_ctx {
        let signature_method_uri = ctx
            .signer
            .signature_method_uri()
            .map_err(|e| SamlActixError::Internal(format!("unsupported signing algorithm: {e}")))?;
        let sig = signature_template(&metadata_id, &ctx.cert_b64, signature_method_uri);
        let xml_with_sig = insert_signature_after_element(&xml, "md:EntityDescriptor", &sig)?;
        ctx.signer
            .sign_enveloped(&xml_with_sig)
            .map_err(|e| SamlActixError::Internal(format!("metadata signing failed: {e}")))?
    } else {
        xml
    };

    Ok(MetadataXml(final_xml))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::TrustedSpResolver;
    use base64::Engine;
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::assertion::name_id::{EncryptedId, NameId as CoreNameId};
    use gamlastan::core::identifiers::SamlVersion;
    use gamlastan::core::protocol::artifact::ArtifactResolve;
    use gamlastan::core::protocol::logout::LogoutRequest;
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager};
    use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::metadata::types::sp::SpSsoDescriptor;

    const SIGN_CERT_PEM: &str = include_str!("../../gamlastan-mdq/tests/fixtures/sign-cert.pem");
    const SIGN_KEY_PEM: &[u8] = include_bytes!("../../gamlastan-mdq/tests/fixtures/sign-key.pem");

    fn cert_b64(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.contains("CERTIFICATE"))
            .collect::<String>()
    }

    fn empty_sp_sso() -> SpSsoDescriptor {
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
            want_assertions_signed: Some(true),
            assertion_consumer_services: vec![],
            attribute_consuming_services: vec![],
        }
    }

    fn signing_sp_sso() -> SpSsoDescriptor {
        let mut sp = empty_sp_sso();
        let key_info = format!(
            r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#,
            cert_b64(SIGN_CERT_PEM)
        );
        sp.sso_base
            .base
            .key_descriptors
            .push(KeyDescriptor::signing(key_info));
        sp
    }

    fn test_signer() -> SamlSigner {
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64(SIGN_CERT_PEM))
            .unwrap();
        let mut key = loader::load_pem_auto(SIGN_KEY_PEM, None).unwrap();
        key.usage = KeyUsage::Sign;
        key.x509_chain = vec![cert_der];

        let mut keys = KeysManager::new();
        keys.add_key(key);
        SamlSigner::new(keys)
    }

    fn valid_redirect_signature() -> RedirectSignatureData {
        let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        let signature_input = format!("SAMLRequest=encoded&SigAlg={sig_alg}");
        let signature = test_signer()
            .sign_redirect_query(signature_input.as_bytes(), sig_alg)
            .unwrap();
        RedirectSignatureData {
            sig_alg: sig_alg.to_string(),
            signature,
            signature_input,
        }
    }

    fn insert_test_signature_after_issuer(xml: &str, signature: &str) -> String {
        let marker = "</saml:Issuer>";
        let position = xml.find(marker).expect("LogoutRequest issuer marker") + marker.len();
        format!("{}{}{}", &xml[..position], signature, &xml[position..])
    }

    fn logout_request(issuer: Option<&str>) -> LogoutRequest {
        LogoutRequest {
            id: "_lr_1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: issuer.map(Issuer::entity),
            has_signature: false,
            not_on_or_after: None,
            reason: None,
            name_id: NameIdOrEncryptedId::NameId(CoreNameId {
                value: "victim@example.com".to_string(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            }),
            session_indexes: vec![],
        }
    }

    #[test]
    fn encrypted_logout_name_id_is_rejected_without_session_store() {
        let mut request = logout_request(Some("https://sp.example.com"));
        assert!(ready_idp_logout_name_id(&request).is_ok());

        request.name_id = NameIdOrEncryptedId::EncryptedId(EncryptedId {
            raw: b"<saml:EncryptedID/>".to_vec(),
        });
        assert!(matches!(
            ready_idp_logout_name_id(&request),
            Err(SamlActixError::Profile(_))
        ));
    }

    #[test]
    fn slo_accepts_valid_redirect_only_signature() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let request = logout_request(Some("https://sp.example.com"));
        let sp = signing_sp_sso();
        let signature = valid_redirect_signature();

        let authorization = authorize_slo_request(
            &config,
            &request,
            "<LogoutRequest/>",
            Some(&signature),
            Some(&sp),
        )
        .expect("a valid Redirect signature should authenticate the LogoutRequest");
        assert!(authorization.message_authenticated());
    }

    #[test]
    fn slo_rejects_unsigned_or_invalid_redirect_signature() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let request = logout_request(Some("https://sp.example.com"));
        let sp = signing_sp_sso();

        let unsigned =
            authorize_slo_request(&config, &request, "<LogoutRequest/>", None, Some(&sp))
                .unwrap_err();
        assert!(unsigned.to_string().contains("must be signed"));

        let mut invalid = valid_redirect_signature();
        invalid.signature[0] ^= 1;
        let error = authorize_slo_request(
            &config,
            &request,
            "<LogoutRequest/>",
            Some(&invalid),
            Some(&sp),
        )
        .unwrap_err();
        assert!(error.to_string().contains("redirect signature"));
    }

    #[test]
    fn slo_valid_redirect_cannot_mask_invalid_xml_signature() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let mut request = logout_request(Some("https://sp.example.com"));
        request.has_signature = true;
        let sp = signing_sp_sso();
        let signature = valid_redirect_signature();
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_lr_1" Version="2.0" IssueInstant="2026-09-03T00:00:00Z"><ds:Signature/></samlp:LogoutRequest>"#;

        let error =
            authorize_slo_request(&config, &request, xml, Some(&signature), Some(&sp)).unwrap_err();
        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn slo_valid_first_xml_signature_cannot_mask_invalid_second_signature() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let mut request = logout_request(Some("https://sp.example.com"));
        request.has_signature = true;
        let sp = signing_sp_sso();
        let redirect_signature = valid_redirect_signature();
        let signature_template = signature_template(
            &request.id,
            &cert_b64(SIGN_CERT_PEM),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        );
        let xml = request.to_xml_string().unwrap();
        // Insert the invalid template first, then insert the signature that
        // will be signed at the same position so it appears first. The valid
        // first signature covers the still-invalid second signature.
        let with_invalid_second = insert_test_signature_after_issuer(&xml, &signature_template);
        let with_two_templates =
            insert_test_signature_after_issuer(&with_invalid_second, &signature_template);
        let signed_first = test_signer().sign_enveloped(&with_two_templates).unwrap();
        assert!(matches!(
            config
                .verifier_for(&sp)
                .unwrap()
                .verify_enveloped(&signed_first)
                .unwrap(),
            gamlastan::crypto::VerifyResult::Valid { .. }
        ));

        let error = authorize_slo_request(
            &config,
            &request,
            &signed_first,
            Some(&redirect_signature),
            Some(&sp),
        )
        .unwrap_err();
        assert!(error.to_string().contains("signature invalid"));
    }

    #[test]
    fn test_slo_rejected_when_no_trusted_sps() {
        // Finding #13 regression: the ready SLO handler must fail closed when no
        // trusted SP is configured — an unsigned/issuerless LogoutRequest cannot
        // be allowed to destroy sessions. (The handler resolves no SP, so `None`.)
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let req = logout_request(Some("https://sp.example.com"));
        assert!(authorize_slo_request(&config, &req, "<LogoutRequest/>", None, None).is_err());

        let req_no_issuer = logout_request(None);
        assert!(
            authorize_slo_request(&config, &req_no_issuer, "<LogoutRequest/>", None, None).is_err()
        );
    }

    #[test]
    fn test_slo_rejected_for_untrusted_issuer() {
        // Finding #13 regression: an issuer that is not a configured trusted SP
        // resolves to no metadata (`None`) and is rejected.
        let sp = gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
            "https://good-sp.example.com",
            empty_sp_sso(),
        );
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_trusted_sp(sp);
        let req = logout_request(Some("https://evil-sp.example.com"));
        // `resolve_trusted_sp` would return None for the untrusted issuer.
        assert!(authorize_slo_request(&config, &req, "<LogoutRequest/>", None, None).is_err());
    }

    #[test]
    fn test_authz_failures_map_to_forbidden_not_internal_error() {
        // PR #20 review: untrusted/missing issuer and other request-input
        // authorization failures must surface as 403, not 500 — a 500 makes the
        // endpoint look broken under attack and risks leaking detail in noisy
        // error logs. They go through ProfileError, which maps to FORBIDDEN.
        use actix_web::http::StatusCode;
        use actix_web::ResponseError;

        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");

        let slo_err = authorize_slo_request(
            &config,
            &logout_request(Some("https://sp.example.com")),
            "<LogoutRequest/>",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(slo_err.status_code(), StatusCode::FORBIDDEN);

        let slo_no_issuer_err = authorize_slo_request(
            &config,
            &logout_request(None),
            "<LogoutRequest/>",
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(slo_no_issuer_err.status_code(), StatusCode::FORBIDDEN);

        let resolve = ArtifactResolve {
            id: "_ar_1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: Some(Issuer::entity("https://sp.example.com")),
            has_signature: false,
            artifact: "AAQAAD...".to_string(),
        };
        let ar_err =
            authorize_artifact_resolve(&config, &resolve, "<ArtifactResolve/>", None).unwrap_err();
        assert_eq!(ar_err.status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_artifact_resolve_rejected_when_no_trusted_sps() {
        // Finding #5 regression: artifact resolution must fail closed without a
        // way to authenticate the requester.
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let resolve = ArtifactResolve {
            id: "_ar_1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: Some(Issuer::entity("https://sp.example.com")),
            has_signature: false,
            artifact: "AAQAAD...".to_string(),
        };
        assert!(authorize_artifact_resolve(&config, &resolve, "<ArtifactResolve/>", None).is_err());
    }

    #[actix_web::test]
    async fn test_resolve_trusted_sp_uses_static_then_resolver() {
        // Federation/MDQ support: an SP not in the static registry is resolved
        // via the dynamic resolver, so the handlers do not fail closed when an
        // MDQ-backed resolver is configured.
        struct StubResolver;
        impl TrustedSpResolver for StubResolver {
            fn resolve_sp<'a>(&'a self, entity_id: &'a str) -> crate::config::ResolveSpFuture<'a> {
                Box::pin(async move {
                    (entity_id == "https://mdq-sp.example.com").then(|| {
                        gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
                            entity_id,
                            empty_sp_sso(),
                        )
                    })
                })
            }
        }

        // No static SPs, no resolver -> unknown issuer is unresolved.
        let bare = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        assert!(resolve_trusted_sp(&bare, "https://mdq-sp.example.com")
            .await
            .is_none());

        // With an MDQ-style resolver, the SP is resolved dynamically.
        let federated = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_sp_resolver(std::sync::Arc::new(StubResolver));
        assert!(resolve_trusted_sp(&federated, "https://mdq-sp.example.com")
            .await
            .is_some());
        assert!(
            resolve_trusted_sp(&federated, "https://unknown.example.com")
                .await
                .is_none()
        );
    }

    #[actix_web::test]
    async fn test_resolve_trusted_sp_entity_rejects_resolver_mismatch() {
        // Regression: a resolver returning a descriptor for a different
        // entity than requested must not be trusted for that lookup - doing
        // so would bind the requested issuer's authorization to a different
        // entity's ACS endpoints and release policy.
        struct MismatchedResolver;
        impl TrustedSpResolver for MismatchedResolver {
            fn resolve_sp<'a>(&'a self, _entity_id: &'a str) -> crate::config::ResolveSpFuture<'a> {
                Box::pin(async move {
                    Some(
                        gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
                            "https://other-entity.example.com",
                            empty_sp_sso(),
                        ),
                    )
                })
            }
        }

        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_sp_resolver(std::sync::Arc::new(MismatchedResolver));
        assert!(
            resolve_trusted_sp_entity(&config, "https://requested-entity.example.com")
                .await
                .is_none(),
            "a resolver returning a mismatched entity_id must not be trusted"
        );
    }

    #[test]
    fn test_trusted_sp_lookup() {
        // Finding #4 support: the SSO handler binds the request issuer to trusted
        // SP metadata; lookups must only succeed for registered entityIDs.
        let sp = gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
            "https://sp.example.com",
            empty_sp_sso(),
        );
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_trusted_sp(sp);
        assert!(config.trusted_sp("https://sp.example.com").is_some());
        assert!(config.trusted_sp("https://other.example.com").is_none());
    }

    #[test]
    fn test_authn_callback_result_debug() {
        let result = AuthnCallbackResult {
            name_id: NameId {
                value: "user@example.com".to_string(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            },
            attributes: vec![],
            authn_context_class_ref: None,
            session_index: Some("_sess_123".to_string()),
            authn_instant: None,
        };
        assert!(format!("{result:?}").contains("user@example.com"));
    }

    #[test]
    fn test_signature_template() {
        let sig = signature_template(
            "_abc123",
            "MIID...",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        );
        assert!(sig.contains("URI=\"#_abc123\""));
        assert!(sig.contains("<ds:X509Certificate>MIID...</ds:X509Certificate>"));
        assert!(sig.contains("rsa-sha256"));
        assert!(sig.contains("exc-c14n"));
    }

    #[test]
    fn test_insert_signature_after_element() {
        // First-child placement, as required for metadata (EntityDescriptor has
        // no Issuer). Response/Assertion signing goes through the core helper,
        // which anchors after the Issuer instead.
        let xml = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><md:IDPSSODescriptor/></md:EntityDescriptor>"#;
        let sig = "<SIGNATURE/>";
        let result = insert_signature_after_element(xml, "md:EntityDescriptor", sig).unwrap();
        assert!(result
            .contains(r#"entityID="https://idp.example.com"><SIGNATURE/><md:IDPSSODescriptor"#));
    }

    #[test]
    fn test_metadata_signing_cert_prefers_signing_context() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_signing_cert("CONFIG_CERT");
        let signing_ctx = IdpSigningContext::new(
            SamlSigner::new(gamlastan::crypto::KeysManager::new()),
            "CTX_CERT",
        );

        assert_eq!(
            metadata_signing_cert_b64(&config, Some(&signing_ctx), None),
            Some("CTX_CERT")
        );
    }

    #[test]
    fn test_metadata_signing_cert_falls_back_to_config() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_signing_cert("CONFIG_CERT");

        assert_eq!(
            metadata_signing_cert_b64(&config, None, None),
            Some("CONFIG_CERT")
        );
    }

    #[test]
    fn test_metadata_signing_cert_prefers_response_engine_parts() {
        // Regression: the policy-driven SSO path signs with whatever signer
        // ResponseEngineParts carries, but the metadata handler never
        // consulted it at all - reading only IdpSigningContext/IdpConfig
        // instead. Registering only AuthnSubjectCallback + ResponseEngineParts
        // (the documented policy-driven setup) produced signed responses
        // while metadata advertised no key, or the wrong one if
        // IdpSigningContext also happened to be registered with a different
        // certificate. ResponseEngineParts must win when present, since it's
        // the actual source of truth for what signs responses on that path.
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_signing_cert("CONFIG_CERT");
        let signing_ctx = IdpSigningContext::new(
            SamlSigner::new(gamlastan::crypto::KeysManager::new()),
            "CTX_CERT",
        );
        let parts = response_engine_parts();

        assert_eq!(
            metadata_signing_cert_b64(&config, Some(&signing_ctx), Some(&parts)),
            Some(parts.cert_der_b64.as_str())
        );
    }

    #[test]
    fn test_metadata_signing_cert_uses_response_engine_parts_alone() {
        // The exact scenario from the finding: only ResponseEngineParts is
        // registered (no IdpSigningContext, no config cert) - metadata must
        // still advertise a key, not silently publish none while responses
        // are in fact signed.
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let parts = response_engine_parts();

        assert_eq!(
            metadata_signing_cert_b64(&config, None, Some(&parts)),
            Some(parts.cert_der_b64.as_str())
        );
    }

    #[actix_web::test]
    async fn idp_metadata_advertises_the_certificate_of_the_path_that_signs() {
        // The finding: `idp_sso` uses ResponseEngineParts only when an
        // AuthnSubjectCallback is registered too. With parts plus only the
        // low-level AuthnCallback, responses are signed by IdpSigningContext, so
        // metadata must advertise that certificate, not the engine's.
        const PARTS_CERT: &str = "PARTS_CERT_MARKER";
        let ctx_cert = cert_b64(SIGN_CERT_PEM);
        let config = || {
            web::Data::new(IdpConfig::new(
                "https://idp.example.com",
                "https://idp.example.com/sso",
            ))
        };
        let signing_ctx = || {
            Some(web::Data::new(Arc::new(IdpSigningContext::new(
                test_signer(),
                ctx_cert.clone(),
            ))))
        };
        let parts = || {
            Some(web::Data::new(Arc::new(ResponseEngineParts::new(
                "https://idp.example.com",
                Arc::new(ReleasePolicy::new()),
                Arc::new(gamlastan::idp::ident::IdentDb::in_memory(
                    "https://idp.example.com",
                )),
                Arc::new(AuthnBroker::new()),
                Arc::new(test_signer()),
                PARTS_CERT.to_string(),
            ))))
        };
        let callback = || {
            let callback: AuthnSubjectCallback =
                Box::new(|_processed, _request, _disposition, _req| {
                    Ok(AuthnSubjectResult::Deny(Denial::NoPassive))
                });
            Some(web::Data::new(callback))
        };

        // Metadata is signed with the context's key when one is registered, so
        // the context certificate also appears in the metadata signature's
        // KeyInfo. What this test is about is the advertised KeyDescriptor.
        fn key_descriptor(xml: &str) -> &str {
            let open = xml
                .find("KeyDescriptor")
                .and_then(|i| xml[..i].rfind('<'))
                .expect("metadata has a KeyDescriptor");
            let name_end = xml[open + 1..].find([' ', '>']).expect("tag end") + open + 1;
            let name = &xml[open + 1..name_end];
            let close = xml[open..]
                .find(&format!("</{name}>"))
                .expect("closing tag")
                + open;
            &xml[open..close]
        }

        // Parts + context, no subject callback: the context signs.
        let xml = idp_metadata(config(), signing_ctx(), parts(), None)
            .await
            .unwrap()
            .0;
        let kd = key_descriptor(&xml);
        assert!(kd.contains(&ctx_cert), "context certificate advertised");
        assert!(
            !kd.contains(PARTS_CERT),
            "engine certificate not advertised"
        );

        // Parts + context + subject callback: the policy-driven path signs.
        let xml = idp_metadata(config(), signing_ctx(), parts(), callback())
            .await
            .unwrap()
            .0;
        let kd = key_descriptor(&xml);
        assert!(kd.contains(PARTS_CERT), "engine certificate advertised");
        assert!(
            !kd.contains(&ctx_cert),
            "context certificate not advertised"
        );

        // Parts alone, no callback: nothing signs on this path, so no key.
        let xml = idp_metadata(config(), None, parts(), None).await.unwrap().0;
        assert!(!xml.contains(PARTS_CERT), "parts alone sign nothing");
    }

    #[test]
    fn test_authn_subject_result_variants() {
        // The three outcomes are constructible and distinguishable.
        let subject = gamlastan::idp::orchestrator::AuthenticatedSubject {
            subject_id: "alice".to_string(),
            attributes: vec![],
            authn_method: gamlastan::idp::orchestrator::AuthnMethodRef::Inline {
                class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
                authn_authority: None,
            },
            authn_instant: None,
            session_index: Some("_sess_1".to_string()),
        };
        assert!(matches!(
            AuthnSubjectResult::Authenticated(subject),
            AuthnSubjectResult::Authenticated(_)
        ));
        assert!(matches!(
            AuthnSubjectResult::Redirect(HttpResponse::Ok().body("login form")),
            AuthnSubjectResult::Redirect(_)
        ));
        assert!(matches!(
            AuthnSubjectResult::Deny(Denial::NoPassive),
            AuthnSubjectResult::Deny(_)
        ));
    }

    /// An `SpSsoDescriptor` with one default (index 0) ACS endpoint.
    fn sp_sso_with_acs(acs_url: &str) -> SpSsoDescriptor {
        let mut sp = empty_sp_sso();
        sp.assertion_consumer_services = vec![
            gamlastan::metadata::types::endpoint::IndexedEndpoint::new_default(
                gamlastan::metadata::types::endpoint::Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    acs_url,
                ),
                0,
            ),
        ];
        sp
    }

    /// An unsigned, `IsPassive` `AuthnRequest` from `sp_entity_id`.
    fn passive_authn_request(
        sp_entity_id: &str,
    ) -> gamlastan::core::protocol::request::AuthnRequest {
        gamlastan::core::protocol::request::AuthnRequest {
            base: gamlastan::core::protocol::request::RequestBase {
                id: "_req_1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: None,
                consent: None,
                issuer: Some(Issuer::entity(sp_entity_id)),
                has_signature: false,
            },
            subject: None,
            name_id_policy: None,
            conditions: None,
            requested_authn_context: None,
            scoping: None,
            force_authn: None,
            is_passive: Some(true),
            assertion_consumer_service_index: Some(0),
            assertion_consumer_service_url: None,
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
            extensions: None,
        }
    }

    /// A `ResponseEngine<'static>` with no registered authn methods, so
    /// `check_request` always denies with `NoPassive`/`NoAuthnContext` for a
    /// passive request with no session - enough to prove the handler
    /// actually consults `check_request` rather than trusting the callback.
    /// No `Box::leak` needed: `ResponseEngineParts` owns everything via
    /// ordinary `Arc`s, exactly as an application would build it at startup.
    fn response_engine_parts() -> ResponseEngineParts {
        ResponseEngineParts::new(
            "https://idp.example.com",
            Arc::new(ReleasePolicy::new()),
            Arc::new(gamlastan::idp::ident::IdentDb::in_memory(
                "https://idp.example.com",
            )),
            Arc::new(AuthnBroker::new()),
            Arc::new(test_signer()),
            cert_b64(SIGN_CERT_PEM),
        )
    }

    /// A distinct `IdentityStore` impl (not `InMemoryIdentityStore`) - stands
    /// in for a Redis/SQL-backed store an application registers.
    #[derive(Default)]
    struct CustomStore(gamlastan::idp::ident::InMemoryIdentityStore);

    impl gamlastan::idp::ident::IdentityStore for CustomStore {
        fn for_user(
            &self,
            user_id: &str,
        ) -> Result<
            Vec<gamlastan::core::assertion::name_id::NameId>,
            gamlastan::idp::ident::StoreError,
        > {
            self.0.for_user(user_id)
        }
        fn user_for(
            &self,
            value: &str,
        ) -> Result<Option<String>, gamlastan::idp::ident::StoreError> {
            self.0.user_for(value)
        }
        fn get_or_insert_durable(
            &self,
            user_id: &str,
            candidate: gamlastan::core::assertion::name_id::NameId,
        ) -> Result<gamlastan::core::assertion::name_id::NameId, gamlastan::idp::ident::InsertError>
        {
            self.0.get_or_insert_durable(user_id, candidate)
        }
        fn insert(
            &self,
            user_id: &str,
            name_id: gamlastan::core::assertion::name_id::NameId,
        ) -> Result<(), gamlastan::idp::ident::InsertError> {
            self.0.insert(user_id, name_id)
        }
        fn replace(
            &self,
            user_id: &str,
            name_id: gamlastan::core::assertion::name_id::NameId,
        ) -> Result<(), gamlastan::idp::ident::InsertError> {
            self.0.replace(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), gamlastan::idp::ident::StoreError> {
            self.0.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), gamlastan::idp::ident::StoreError> {
            self.0.remove_all(user_id)
        }
    }

    #[actix_web::test]
    async fn idp_sso_accepts_response_engine_over_a_non_default_identity_store() {
        // Regression: ResponseEngine::idents is type-erased (dyn
        // NameIdConstructor) precisely so a ready-made Actix route handler -
        // whose signature is fixed, unlike a generic function an application
        // could monomorphize itself - is not stuck with the default
        // InMemoryIdentityStore. A Redis/SQL-backed store must work here too.
        // No Box::leak needed: ResponseEngineParts owns everything via Arc.
        const SP: &str = "https://sp.example.com";
        const ACS: &str = "https://sp.example.com/acs";

        let decisions = Arc::new(ReleasePolicy::new());
        let parts = ResponseEngineParts::new(
            "https://idp.example.com",
            decisions,
            Arc::new(gamlastan::idp::ident::IdentDb::new(
                CustomStore::default(),
                "https://idp.example.com",
            )),
            Arc::new(AuthnBroker::new()),
            Arc::new(test_signer()),
            cert_b64(SIGN_CERT_PEM),
        );

        let sp_sso = sp_sso_with_acs(ACS);
        let entity =
            gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(SP, sp_sso);
        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));
        let authn_subject_callback: AuthnSubjectCallback =
            Box::new(move |_processed, _request, _disposition, _req| {
                Ok(AuthnSubjectResult::Authenticated(AuthenticatedSubject {
                    subject_id: "alice".to_string(),
                    attributes: vec![],
                    authn_method: gamlastan::idp::orchestrator::AuthnMethodRef::Inline {
                        class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
                        authn_authority: None,
                    },
                    authn_instant: None,
                    session_index: Some("_sess1".to_string()),
                }))
            });

        let mut request = passive_authn_request(SP);
        request.is_passive = None;
        let xml = request.to_xml_string().unwrap();
        let msg = SamlMessage {
            saml_xml: xml.into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        let response = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(authn_subject_callback)),
            None,
            Some(web::Data::new(Arc::new(parts))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await
        .expect("handler must not error");

        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn idp_sso_denies_passive_request_without_calling_the_callback() {
        // Regression: the policy-driven Actix path must consult check_request
        // (via the ForceAuthn/IsPassive/RequestedAuthnContext matrix) before
        // invoking the AuthnSubjectCallback. A callback that (incorrectly)
        // authenticates unconditionally must never be given the chance to
        // for an IsPassive request with no established session - the
        // handler must deny with a signed NoPassive first.
        const SP: &str = "https://sp.example.com";
        const ACS: &str = "https://sp.example.com/acs";

        let sp_sso = sp_sso_with_acs(ACS);
        let entity =
            gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(SP, sp_sso);
        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));

        let callback_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_invoked_clone = callback_invoked.clone();
        let authn_subject_callback: AuthnSubjectCallback =
            Box::new(move |_processed, _request, _disposition, _req| {
                callback_invoked_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(AuthnSubjectResult::Authenticated(AuthenticatedSubject {
                    subject_id: "alice".to_string(),
                    attributes: vec![],
                    authn_method: gamlastan::idp::orchestrator::AuthnMethodRef::Inline {
                        class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
                        authn_authority: None,
                    },
                    authn_instant: None,
                    session_index: Some("_sess1".to_string()),
                }))
            });

        let request = passive_authn_request(SP);
        let xml = request.to_xml_string().unwrap();
        let msg = SamlMessage {
            saml_xml: xml.into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        let response = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(authn_subject_callback)),
            None, // no EstablishedSessionCallback registered -> no session
            Some(web::Data::new(Arc::new(response_engine_parts()))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await
        .expect("handler must not error");

        assert!(
            !callback_invoked.load(std::sync::atomic::Ordering::SeqCst),
            "AuthnSubjectCallback must not be invoked when check_request denies the request"
        );
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        // A signed protocol-error Response was POST-encoded, not the
        // Authenticated subject the (never-invoked) callback would have
        // produced.
        assert!(body.contains("SAMLResponse"));
    }

    #[actix_web::test]
    async fn idp_sso_invokes_callback_when_authentication_is_needed() {
        // Positive control: a non-passive request with no session reaches
        // Disposition::Authenticate, so the callback *is* invoked and its
        // result is used - the check_request gate must not be overly strict.
        const SP: &str = "https://sp.example.com";
        const ACS: &str = "https://sp.example.com/acs";

        let sp_sso = sp_sso_with_acs(ACS);
        let entity =
            gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(SP, sp_sso);
        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));

        let callback_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_invoked_clone = callback_invoked.clone();
        let authn_subject_callback: AuthnSubjectCallback =
            Box::new(move |_processed, _request, _disposition, _req| {
                callback_invoked_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(AuthnSubjectResult::Authenticated(AuthenticatedSubject {
                    subject_id: "alice".to_string(),
                    attributes: vec![],
                    authn_method: gamlastan::idp::orchestrator::AuthnMethodRef::Inline {
                        class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
                        authn_authority: None,
                    },
                    authn_instant: None,
                    session_index: Some("_sess1".to_string()),
                }))
            });

        let mut request = passive_authn_request(SP);
        request.is_passive = None; // not passive: authentication is allowed
        let xml = request.to_xml_string().unwrap();
        let msg = SamlMessage {
            saml_xml: xml.into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        let response = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(authn_subject_callback)),
            None,
            Some(web::Data::new(Arc::new(response_engine_parts()))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await
        .expect("handler must not error");

        assert!(
            callback_invoked.load(std::sync::atomic::Ordering::SeqCst),
            "AuthnSubjectCallback must be invoked when authentication is needed"
        );
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn idp_sso_refuses_an_acs_registered_for_a_binding_it_cannot_deliver() {
        // The ready handler delivers by HTTP-POST only. A request that resolves
        // to an Artifact endpoint must be refused, not answered with a POSTed
        // Response the SP's artifact endpoint cannot use, and the callback must
        // not run (no login for a response that cannot be delivered).
        const SP: &str = "https://sp.example.com";
        const ACS: &str = "https://sp.example.com/acs";

        let mut sp_sso = sp_sso_with_acs(ACS);
        sp_sso.assertion_consumer_services.push(
            gamlastan::metadata::types::endpoint::IndexedEndpoint::new(
                gamlastan::metadata::types::endpoint::Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                    "https://sp.example.com/artifact",
                ),
                5,
            ),
        );
        let entity =
            gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(SP, sp_sso);
        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));
        let callback_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = callback_invoked.clone();
        let authn_subject_callback: AuthnSubjectCallback =
            Box::new(move |_processed, _request, _disposition, _req| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(AuthnSubjectResult::Deny(Denial::NoPassive))
            });

        let mut request = passive_authn_request(SP);
        request.is_passive = None;
        request.assertion_consumer_service_index = Some(5); // the Artifact endpoint
        let msg = SamlMessage {
            saml_xml: request.to_xml_string().unwrap().into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        let result = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(authn_subject_callback)),
            None,
            Some(web::Data::new(Arc::new(response_engine_parts()))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await;

        assert!(
            matches!(result, Err(SamlActixError::UnsupportedBinding(_))),
            "a non-POST ACS must be refused"
        );
        assert!(
            !callback_invoked.load(std::sync::atomic::Ordering::SeqCst),
            "the callback must not run for a request that cannot be answered"
        );
    }

    #[actix_web::test]
    async fn the_subject_callback_sees_the_scoping_the_processed_request_drops() {
        const SP: &str = "https://sp.example.com";
        let entity = gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
            SP,
            sp_sso_with_acs("https://sp.example.com/acs"),
        );
        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_in_callback = seen.clone();
        let callback: AuthnSubjectCallback = Box::new(move |_processed, request, _d, _req| {
            *seen_in_callback.lock().unwrap() =
                Some(request.scoping.as_ref().and_then(|s| s.proxy_count));
            Ok(AuthnSubjectResult::Deny(Denial::AuthnFailed))
        });

        let mut request = passive_authn_request(SP);
        request.is_passive = None;
        request.scoping = Some(gamlastan::core::protocol::request::Scoping {
            proxy_count: Some(0),
            idp_list: vec![],
            requester_ids: vec![],
        });
        let msg = SamlMessage {
            saml_xml: request.to_xml_string().unwrap().into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };
        idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(callback)),
            None,
            Some(web::Data::new(Arc::new(response_engine_parts()))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await
        .unwrap();
        assert_eq!(*seen.lock().unwrap(), Some(Some(0)));
    }

    #[actix_web::test]
    async fn idp_sso_refuses_an_engine_whose_issuer_differs_from_the_config() {
        const SP: &str = "https://sp.example.com";
        let entity = gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(
            SP,
            sp_sso_with_acs("https://sp.example.com/acs"),
        );
        let config = web::Data::new(
            IdpConfig::new(
                "https://other-idp.example.com",
                "https://other-idp.example.com/sso",
            )
            .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));
        let callback: AuthnSubjectCallback =
            Box::new(|_, _, _, _| Ok(AuthnSubjectResult::Deny(Denial::NoPassive)));
        let msg = SamlMessage {
            saml_xml: passive_authn_request(SP)
                .to_xml_string()
                .unwrap()
                .into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        // `response_engine_parts()` is built for https://idp.example.com.
        let result = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(callback)),
            None,
            Some(web::Data::new(Arc::new(response_engine_parts()))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await;
        assert!(matches!(result, Err(SamlActixError::Configuration(_))));
    }

    #[actix_web::test]
    async fn idp_sso_applies_entity_category_release_from_trusted_metadata() {
        // Regression: sp_entity must not be hardcoded to None on the
        // policy-driven path, or ReleasePolicy's entity-category release
        // (the feature this whole engine exists to provide) never engages.
        const SP: &str = "https://sp.example.com";
        const ACS: &str = "https://sp.example.com/acs";
        const MAIL_OID: &str = "urn:oid:0.9.2342.19200300.100.1.3";

        let sp_sso = sp_sso_with_acs(ACS);
        let mut entity =
            gamlastan::metadata::types::entity_descriptor::EntityDescriptor::for_sp(SP, sp_sso);
        entity.extensions = Some(gamlastan::metadata::types::extensions::Extensions::new(
            r#"<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                  Name="http://macedir.org/entity-category">
                <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>"#
                .to_string(),
        ));

        let decisions = Arc::new(ReleasePolicy::with_default(
            gamlastan::idp::policy::PolicyEntry::new()
                .with_entity_categories(vec![&gamlastan::idp::entity_category::REFEDS]),
        ));
        let parts = ResponseEngineParts::new(
            "https://idp.example.com",
            decisions,
            Arc::new(gamlastan::idp::ident::IdentDb::in_memory(
                "https://idp.example.com",
            )),
            Arc::new(AuthnBroker::new()),
            Arc::new(test_signer()),
            cert_b64(SIGN_CERT_PEM),
        );

        let config = web::Data::new(
            IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
                .with_trusted_sp(entity),
        );
        let signing_ctx = web::Data::new(Arc::new(IdpSigningContext::new(
            test_signer(),
            cert_b64(SIGN_CERT_PEM),
        )));
        let authn_subject_callback: AuthnSubjectCallback =
            Box::new(move |_processed, _request, _disposition, _req| {
                Ok(AuthnSubjectResult::Authenticated(AuthenticatedSubject {
                    subject_id: "alice".to_string(),
                    attributes: vec![
                        gamlastan::core::assertion::attribute::Attribute {
                            name: MAIL_OID.to_string(),
                            name_format: Some(
                                gamlastan::core::constants::ATTRNAME_FORMAT_URI.to_string(),
                            ),
                            friendly_name: Some("mail".to_string()),
                            values: vec![
                                gamlastan::core::assertion::attribute::AttributeValue::String(
                                    "alice@example.org".to_string(),
                                ),
                            ],
                        },
                        gamlastan::core::assertion::attribute::Attribute {
                            name: "urn:oid:2.5.4.3".to_string(),
                            name_format: Some(
                                gamlastan::core::constants::ATTRNAME_FORMAT_URI.to_string(),
                            ),
                            friendly_name: Some("cn".to_string()),
                            values: vec![
                                gamlastan::core::assertion::attribute::AttributeValue::String(
                                    "Alice Example".to_string(),
                                ),
                            ],
                        },
                    ],
                    authn_method: gamlastan::idp::orchestrator::AuthnMethodRef::Inline {
                        class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
                        authn_authority: None,
                    },
                    authn_instant: None,
                    session_index: Some("_sess1".to_string()),
                }))
            });

        let mut request = passive_authn_request(SP);
        request.is_passive = None;
        let xml = request.to_xml_string().unwrap();
        let msg = SamlMessage {
            saml_xml: xml.into_bytes(),
            relay_state: None,
            is_request: true,
            binding: crate::extractors::SamlBinding::HttpPost,
            redirect_signature: None,
        };

        let response = idp_sso(
            msg,
            config,
            Some(signing_ctx),
            None,
            Some(web::Data::new(authn_subject_callback)),
            None,
            Some(web::Data::new(Arc::new(parts))),
            actix_web::test::TestRequest::default().to_http_request(),
        )
        .await
        .expect("handler must not error");

        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        let marker = "name=\"SAMLResponse\" value=\"";
        let start = body.find(marker).expect("SAMLResponse field") + marker.len();
        let end = body[start..].find('"').expect("closing quote") + start;
        let xml = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(&body[start..end])
                .expect("valid base64"),
        )
        .expect("valid UTF-8 XML");

        // `mail` is in REFEDS R&S; `cn` is not, so it must not survive entity
        // category release - proving sp_entity actually reached the engine.
        assert!(xml.contains("alice@example.org"));
        assert!(!xml.contains("Alice Example"));
    }

    #[actix_web::test]
    async fn test_post_signed_response_wraps_post_binding() {
        let xml = "<samlp:Response/>";
        let response =
            post_signed_response(xml, "https://sp.example.com/acs", Some("relay")).unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        // The signed XML is POST-encoded to the ACS and the RelayState is echoed.
        assert!(body.contains("SAMLResponse"));
        assert!(body.contains("https://sp.example.com/acs"));
        assert!(body.contains("RelayState"));
    }

    #[test]
    fn a_reused_session_owns_the_instant_and_index_and_the_subject_must_match() {
        use gamlastan::idp::orchestrator::AuthnMethodRef;
        let method = |c: &str| AuthnMethodRef::Inline {
            class_ref: c.to_string(),
            authn_authority: None,
        };
        let instant = Utc::now() - chrono::TimeDelta::try_hours(3).unwrap();
        let session = EstablishedSession {
            subject_id: "alice".into(),
            authn_method: method("urn:session"),
            authn_instant: instant,
            session_index: "s-1".into(),
        };
        let subject_for = |id: &str| AuthenticatedSubject {
            subject_id: id.into(),
            attributes: vec![],
            authn_method: method("urn:other"),
            authn_instant: None,
            session_index: Some("s-2".into()),
        };
        let reuse = Disposition::ReuseSession { session };

        // A fresh login is the callback's own, whoever it names.
        let mut fresh_login = subject_for("mallory");
        pin_to_reused_session(
            &mut fresh_login,
            &Disposition::Authenticate { methods: vec![] },
        )
        .unwrap();
        assert_eq!(fresh_login.subject_id, "mallory");
        assert_eq!(fresh_login.authn_instant, None);

        // Reuse keeps the callback's attributes, and takes the rest from the session.
        let mut same = subject_for("alice");
        pin_to_reused_session(&mut same, &reuse).unwrap();
        assert_eq!(same.authn_instant, Some(instant));
        assert_eq!(same.session_index.as_deref(), Some("s-1"));
        assert!(matches!(
            same.authn_method,
            AuthnMethodRef::Inline { ref class_ref, .. } if class_ref == "urn:session"
        ));

        // A different subject is refused rather than relabelled: it would sign
        // alice's NameID over mallory's attributes.
        let mut other = subject_for("mallory");
        assert!(matches!(
            pin_to_reused_session(&mut other, &reuse),
            Err(SamlActixError::Configuration(_))
        ));
        assert_eq!(
            other.subject_id, "mallory",
            "nothing is rewritten on refusal"
        );
    }
}
