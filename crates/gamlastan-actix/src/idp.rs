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
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::crypto::signer::SamlSigner;
use gamlastan::profiles::artifact_resolution;
use gamlastan::profiles::logout;
use gamlastan::profiles::sso::idp as idp_profile;
// The canonical enveloped-signature template now lives in core gamlastan;
// re-export it so existing call sites (and the doc links) keep resolving.
pub use gamlastan::profiles::sso::idp::signature_template;
use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan::xml::uppsala;

use crate::config::IdpConfig;
use crate::error::SamlActixError;
use crate::extractors::SamlMessage;
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
    /// `signer` is any [`kryptering::Signer`] — typically a
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

fn metadata_signing_cert_b64<'a>(
    config: &'a IdpConfig,
    signing_ctx: Option<&'a IdpSigningContext>,
) -> Option<&'a str> {
    signing_ctx
        .map(|ctx| ctx.cert_b64.as_str())
        .or(config.signing_cert_b64.as_deref())
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
    .map_err(|e| SamlActixError::Internal(format!("response signing failed: {e}")))
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
async fn idp_sso(
    msg: SamlMessage,
    config: web::Data<IdpConfig>,
    signing_ctx: Option<web::Data<Arc<IdpSigningContext>>>,
    authn_callback: Option<web::Data<AuthnCallback>>,
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
    let sp_sso = match issuer {
        Some(id) => resolve_trusted_sp(&config, id).await,
        None => None,
    };
    let sp_sso = sp_sso.ok_or_else(|| {
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

    // Process the AuthnRequest (validates and extracts parameters). With trusted
    // SP metadata, a request-supplied ACS URL not present in metadata is rejected.
    // These are validation failures on attacker-controllable request input, so
    // preserve the ProfileError mapping (HTTP 403) rather than turning a normal
    // rejection into an Internal 500 (which is misleading and noisy under
    // hostile traffic).
    let processed = idp_profile::process_authn_request(&authn_request, Some(&sp_sso))
        .map_err(SamlActixError::Profile)?;

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

            let now = Utc::now();
            logout::validate_logout_request(&logout_req, now, config.security.clock_skew_seconds)
                .map_err(|e| SamlActixError::Internal(format!("invalid LogoutRequest: {e}")))?;

            // Authorize the logout before mutating any session. SLO destroys
            // sessions keyed by the request-supplied NameID, so an unauthenticated
            // request lets anyone who guesses a NameID force-logout a victim
            // (CWE-306/CWE-862). Require the LogoutRequest to be signed by a
            // trusted SP, carry a trusted issuer, and (if present) target this
            // IdP's SLO endpoint — unless the deployment authenticates the
            // transport and explicitly opted in. Resolve the issuer's metadata
            // (static registry or MDQ resolver) before the synchronous check.
            let slo_issuer = logout_req.issuer.as_ref().map(|i| i.value.as_str());
            let slo_sp = match slo_issuer {
                Some(id) => resolve_trusted_sp(&config, id).await,
                None => None,
            };
            authorize_slo_request(&config, &logout_req, xml_str, slo_sp.as_ref())?;

            // Propagate logout to session participants via the SessionStore
            if let Some(ref session_store) = config.session_store {
                use gamlastan::core::assertion::name_id::NameIdOrEncryptedId;
                let name_id_value = match &logout_req.name_id {
                    NameIdOrEncryptedId::NameId(nid) => nid.value.as_str(),
                    NameIdOrEncryptedId::EncryptedId(_) => "",
                };

                if !name_id_value.is_empty() {
                    let sessions = session_store.get_sessions_by_name_id(name_id_value);

                    for session in &sessions {
                        // Build LogoutRequest for each participant (except the requester)
                        let requester_entity_id = logout_req
                            .issuer
                            .as_ref()
                            .map(|i| i.value.as_str())
                            .unwrap_or("");

                        for participant in &session.participants {
                            if participant.entity_id == requester_entity_id {
                                continue; // Don't send back to the requester
                            }
                            let propagation_req = logout::create_idp_propagation_request(
                                &config.entity_id,
                                participant,
                            );
                            let _propagation_xml = propagation_req.to_xml_string().ok();
                            // Note: actual HTTP delivery requires an async HTTP client.
                            // The application should implement a SoapTransport or
                            // use the propagation request XML directly. The SessionStore
                            // tracks who needs logout; the application handles delivery.
                        }

                        // Clean up session
                        session_store.destroy_session(&session.session_index);
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
    // issuer matches, unless the deployment authenticates the transport (mTLS)
    // and explicitly opted in. Resolve the issuer's metadata (static registry or
    // MDQ resolver) before the synchronous check.
    let ar_issuer = resolve.issuer.as_ref().map(|i| i.value.as_str());
    let ar_sp = match ar_issuer {
        Some(id) => resolve_trusted_sp(&config, id).await,
        None => None,
    };
    authorize_artifact_resolve(&config, &resolve, xml_str, ar_sp.as_ref())?;

    // Look up the artifact in the artifact store
    let response_xml = if let Some(ref artifact_store) = config.artifact_store {
        match artifact_store.resolve_and_consume(&resolve.artifact) {
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
/// 2. **Integrity** — the signature must be `Valid`, not merely present.
/// 3. **Binding** — a verified XML-DSig reference must target `expected_id`
///    (the parsed message's `ID`) or the document root, so a valid signature
///    over a *sibling* object cannot authorize this message (XML Signature
///    Wrapping).
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

    match verifier.verify_enveloped(xml_str) {
        Ok(gamlastan::crypto::VerifyResult::Valid { references, .. }) => {
            // Bind the signature to the parsed message: a verified reference must
            // target the message root (empty URI) or its ID. This prevents a
            // signature over a sibling object from authorizing this message.
            let bound = references
                .iter()
                .any(|r| r.uri.is_empty() || r.uri.strip_prefix('#') == Some(expected_id));
            if bound {
                Ok(())
            } else {
                // Unbound-but-valid signature (XSW) is a request authentication
                // failure → 403, not 500.
                Err(SamlActixError::Profile(
                    gamlastan::profiles::ProfileError::AssertionValidation(format!(
                        "{what} signature did not reference the message (XML Signature Wrapping)"
                    )),
                ))
            }
        }
        Ok(gamlastan::crypto::VerifyResult::Invalid { reason }) => Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "{what} signature invalid: {reason}"
            )),
        )),
        Err(e) => Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "{what} signature verification failed: {e}"
            )),
        )),
    }
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
    if let Some(sp) = config.trusted_sp(entity_id) {
        return Some(sp.clone());
    }
    if let Some(resolver) = &config.sp_resolver {
        return resolver.resolve_sp(entity_id).await;
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
/// 3. the message must carry a valid signature from that SP, bound to the
///    request (delegated to [`verify_sp_message_signature`]).
///
/// As an escape hatch, a deployment that authenticates the front channel at the
/// transport layer may set [`IdpConfig::allow_unauthenticated_backchannel`], in
/// which case the request is accepted without a message signature.
///
/// `sp` is the metadata resolved for `logout_req`'s issuer, or `None` if the
/// issuer is unknown/untrusted. Returns `Ok(())` when the logout is authorized,
/// otherwise a 403-mapped [`SamlActixError::Profile`] explaining the rejection
/// (these are request authorization failures, not server faults).
///
/// # Examples
///
/// ```ignore
/// // In the SLO handler, after structural validation and issuer resolution:
/// authorize_slo_request(&config, &logout_req, xml_str, slo_sp.as_ref())?;
/// // Safe to look up and destroy the principal's sessions now.
/// ```
fn authorize_slo_request(
    config: &IdpConfig,
    logout_req: &gamlastan::core::protocol::logout::LogoutRequest,
    xml_str: &str,
    sp: Option<&gamlastan::metadata::types::sp::SpSsoDescriptor>,
) -> Result<(), SamlActixError> {
    // Transport-authenticated deployments opt out of message-signature checks.
    if config.allow_unauthenticated_backchannel {
        return Ok(());
    }

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

    verify_sp_message_signature(config, sp, xml_str, &logout_req.id, "LogoutRequest")
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
/// [`verify_sp_message_signature`]). Deployments that authenticate the SOAP
/// transport (e.g. mutual TLS) may instead set
/// [`IdpConfig::allow_unauthenticated_backchannel`].
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
    // Transport-authenticated deployments opt out of message-signature checks.
    if config.allow_unauthenticated_backchannel {
        return Ok(());
    }

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
) -> Result<MetadataXml, SamlActixError> {
    use gamlastan::core::identifiers::SamlId;
    use gamlastan::metadata::types::endpoint::Endpoint;
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use gamlastan::metadata::types::idp::IdpSsoDescriptor;
    use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    // Prefer the active signing context's certificate so metadata stays in sync
    // with the key that actually signs responses and metadata.
    let metadata_cert_b64 = metadata_signing_cert_b64(
        config.get_ref(),
        signing_ctx.as_ref().map(|ctx| ctx.get_ref().as_ref()),
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
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::assertion::name_id::{NameId as CoreNameId, NameIdOrEncryptedId};
    use gamlastan::core::identifiers::SamlVersion;
    use gamlastan::core::protocol::artifact::ArtifactResolve;
    use gamlastan::core::protocol::logout::LogoutRequest;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::metadata::types::sp::SpSsoDescriptor;

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
    fn test_slo_rejected_when_no_trusted_sps() {
        // Finding #13 regression: the ready SLO handler must fail closed when no
        // trusted SP is configured — an unsigned/issuerless LogoutRequest cannot
        // be allowed to destroy sessions. (The handler resolves no SP, so `None`.)
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        let req = logout_request(Some("https://sp.example.com"));
        assert!(authorize_slo_request(&config, &req, "<LogoutRequest/>", None).is_err());

        let req_no_issuer = logout_request(None);
        assert!(authorize_slo_request(&config, &req_no_issuer, "<LogoutRequest/>", None).is_err());
    }

    #[test]
    fn test_slo_rejected_for_untrusted_issuer() {
        // Finding #13 regression: an issuer that is not a configured trusted SP
        // resolves to no metadata (`None`) and is rejected.
        let sp = empty_sp_sso();
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_trusted_sp("https://good-sp.example.com", sp);
        let req = logout_request(Some("https://evil-sp.example.com"));
        // `resolve_trusted_sp` would return None for the untrusted issuer.
        assert!(authorize_slo_request(&config, &req, "<LogoutRequest/>", None).is_err());
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
        )
        .unwrap_err();
        assert_eq!(slo_err.status_code(), StatusCode::FORBIDDEN);

        let slo_no_issuer_err =
            authorize_slo_request(&config, &logout_request(None), "<LogoutRequest/>", None)
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

    #[test]
    fn test_backchannel_opt_in_allows_unauthenticated() {
        // The explicit transport-auth opt-in (mTLS deployments) bypasses the
        // message-signature requirement.
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .allow_unauthenticated_backchannel(true);
        let req = logout_request(Some("https://sp.example.com"));
        assert!(authorize_slo_request(&config, &req, "<LogoutRequest/>", None).is_ok());
    }

    #[actix_web::test]
    async fn test_resolve_trusted_sp_uses_static_then_resolver() {
        // Federation/MDQ support: an SP not in the static registry is resolved
        // via the dynamic resolver, so the handlers do not fail closed when an
        // MDQ-backed resolver is configured.
        struct StubResolver;
        impl TrustedSpResolver for StubResolver {
            fn resolve_sp<'a>(&'a self, entity_id: &'a str) -> crate::config::ResolveSpFuture<'a> {
                Box::pin(
                    async move { (entity_id == "https://mdq-sp.example.com").then(empty_sp_sso) },
                )
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

    #[test]
    fn test_trusted_sp_lookup() {
        // Finding #4 support: the SSO handler binds the request issuer to trusted
        // SP metadata; lookups must only succeed for registered entityIDs.
        let sp = empty_sp_sso();
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_trusted_sp("https://sp.example.com", sp);
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
            metadata_signing_cert_b64(&config, Some(&signing_ctx)),
            Some("CTX_CERT")
        );
    }

    #[test]
    fn test_metadata_signing_cert_falls_back_to_config() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_signing_cert("CONFIG_CERT");

        assert_eq!(
            metadata_signing_cert_b64(&config, None),
            Some("CONFIG_CERT")
        );
    }
}
