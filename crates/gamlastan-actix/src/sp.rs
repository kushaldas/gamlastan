// Ready-to-use Service Provider (SP) handlers for actix-web.
//
// Provides handlers for the standard SAML SP endpoints:
// - Login initiation (create AuthnRequest and redirect/POST to IdP)
// - Assertion Consumer Service (receive and validate Response from IdP)
// - Logout initiation (create LogoutRequest)
// - Single Logout Service (receive and process LogoutRequest/Response)
// - Metadata generation
//
// Register all routes at once with `configure_sp()`.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;

use gamlastan::bindings::redirect::RedirectEncodeParams;
use gamlastan::bindings::relay_state::RelayState;
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::protocol::logout::{LogoutRequest, LogoutResponse};
use gamlastan::core::protocol::response::Response as SamlResponse;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::signer::SamlSigner;
use gamlastan::crypto::{KeysManager, SamlVerifier, VerifyResult};
use gamlastan::profiles::logout;
use gamlastan::profiles::sso::sp as sp_profile;
use gamlastan::profiles::sso::web_browser::{AuthnRequestOptions, AuthnResult};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan::xml::uppsala;

use crate::config::SpConfig;
use crate::error::SamlActixError;
use crate::extractors::SamlMessage;
use crate::responders::MetadataXml;

/// SP signing context for signing AuthnRequests in HTTP-Redirect binding.
///
/// Register as `web::Data<Arc<SpSigningContext>>`. If present, the SP login
/// handler will sign the redirect query string.
pub struct SpSigningContext {
    /// The SAML signer (wraps bergshamra).
    pub signer: SamlSigner,
    /// The signature algorithm URI (e.g., `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`).
    pub sig_algorithm: String,
}

/// The result returned by the ACS handler after validating a SAML Response.
///
/// Applications should use a custom ACS handler callback to convert this
/// into a session or JWT.
#[derive(Debug, Clone)]
pub struct SpAuthnResult {
    /// The validated authentication result with user attributes.
    pub authn: AuthnResult,
    /// The RelayState, if present (e.g., the URL the user was trying to access).
    pub relay_state: Option<String>,
}

/// Callback type for SP applications to handle a successful authentication.
///
/// The callback receives the authentication result and returns an actix-web response
/// (e.g., set session cookies and redirect).
pub type AcsCallback =
    Box<dyn Fn(SpAuthnResult, &HttpRequest) -> HttpResponse + Send + Sync + 'static>;

/// Register all SP routes on the given service configuration.
///
/// Routes:
/// - `GET  /saml/login`    - Initiate SSO (redirect to IdP)
/// - `POST /saml/acs`      - Assertion Consumer Service
/// - `GET  /saml/logout`   - Initiate Single Logout
/// - `POST /saml/slo`      - Single Logout Service (receive from IdP)
/// - `GET  /saml/metadata` - SP Metadata
pub fn configure_sp(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/saml/login").route(web::get().to(sp_login)))
        .service(web::resource("/saml/acs").route(web::post().to(sp_acs)))
        .service(
            web::resource("/saml/logout")
                .route(web::get().to(sp_logout))
                .route(web::post().to(sp_logout)),
        )
        .service(
            web::resource("/saml/slo")
                .route(web::get().to(sp_slo))
                .route(web::post().to(sp_slo)),
        )
        .service(web::resource("/saml/metadata").route(web::get().to(sp_metadata)));
}

/// SP login handler: create an AuthnRequest and send the user to the IdP.
///
/// Query parameters:
/// - `RelayState` (optional): URL to redirect to after authentication
/// - `binding` (optional): "redirect" or "post" (default: redirect)
async fn sp_login(
    req: HttpRequest,
    config: web::Data<SpConfig>,
    signing_ctx: Option<web::Data<Arc<SpSigningContext>>>,
) -> Result<HttpResponse, SamlActixError> {
    let query_string = req.query_string();
    let relay_state_value = extract_query_param(query_string, "RelayState");
    let binding_pref =
        extract_query_param(query_string, "binding").unwrap_or_else(|| "redirect".to_string());

    // Find IdP SSO endpoint
    let idp_descriptors = config.idp_metadata.idp_sso_descriptors();
    let idp_desc = idp_descriptors
        .first()
        .ok_or_else(|| SamlActixError::Configuration("no IdP SSO descriptor in metadata".into()))?;

    let binding_uri = if binding_pref == "post" {
        gamlastan::profiles::sso::web_browser::bindings::HTTP_POST
    } else {
        gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT
    };

    let sso_endpoint = sp_profile::find_sso_endpoint(idp_desc, binding_uri).ok_or_else(|| {
        SamlActixError::Configuration(format!(
            "no SSO endpoint for binding {binding_uri} in IdP metadata"
        ))
    })?;

    // Create AuthnRequest
    let options = AuthnRequestOptions {
        sp_entity_id: config.entity_id.clone(),
        acs_url: Some(config.acs_url.clone()),
        protocol_binding: config.protocol_binding.clone(),
        force_authn: config.force_authn,
        is_passive: config.is_passive,
        name_id_format: config.name_id_format.clone(),
        allow_create: config.allow_create,
        destination: Some(sso_endpoint.location.clone()),
        ..Default::default()
    };

    let authn_request = sp_profile::create_authn_request(&options)
        .map_err(|e| SamlActixError::Internal(format!("failed to create AuthnRequest: {e}")))?;

    let authn_request_xml = authn_request
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize AuthnRequest: {e}")))?;

    // Track the request ID for InResponseTo verification
    config.request_id_tracker.store(&authn_request.base.id);

    // Encode and send via the appropriate binding
    let relay_state = relay_state_value
        .as_deref()
        .and_then(|rs| RelayState::new(rs).ok());

    if binding_pref == "post" {
        let html = gamlastan::bindings::post::post_encode(
            authn_request_xml.as_bytes(),
            true,
            &sso_endpoint.location,
            relay_state.as_ref(),
        );
        Ok(crate::response_adapter::post_binding_response(&html))
    } else {
        let signer_pair = signing_ctx
            .as_ref()
            .map(|ctx| (&ctx.signer, ctx.sig_algorithm.as_str()));
        let redirect_url = gamlastan::bindings::redirect::redirect_encode(&RedirectEncodeParams {
            saml_xml: authn_request_xml.as_bytes(),
            is_request: true,
            destination: &sso_endpoint.location,
            relay_state: relay_state.as_ref(),
            signer: signer_pair,
        })
        .map_err(|e| SamlActixError::Internal(format!("redirect encode failed: {e}")))?;

        Ok(crate::response_adapter::redirect_binding_response(
            &redirect_url,
        ))
    }
}

/// SP Assertion Consumer Service handler: validate the SAML Response from the IdP.
///
/// After validation, responds with a simple JSON result. Applications should
/// replace this handler or use the `AcsCallback` for custom behavior.
async fn sp_acs(
    msg: SamlMessage,
    config: web::Data<SpConfig>,
    acs_callback: Option<web::Data<AcsCallback>>,
    req: HttpRequest,
) -> Result<HttpResponse, SamlActixError> {
    // Parse the SAML XML into a Response
    let xml_str = msg.saml_xml_str()?;
    let doc = uppsala::parse(xml_str).map_err(|e: uppsala::XmlError| {
        SamlActixError::Xml(gamlastan::xml::error::XmlError::ParseError(e))
    })?;
    let response_ref = gamlastan::xml::deserialize::parse_saml::<
        gamlastan::core::protocol::response::ResponseRef<'_>,
    >(&doc)?;
    let response: SamlResponse = response_ref.to_owned();

    // Signature trust is established before profile validation or claim
    // extraction. The validator receives only the IDs that were actually
    // covered by a verified XML-DSig reference.
    let verified_signed_ids = verify_acs_response_signatures(xml_str, &response, &config)?;
    let verified_signed_id_refs: Vec<&str> =
        verified_signed_ids.iter().map(String::as_str).collect();

    // Get the IdP entity ID from metadata
    let expected_idp_entity_id = &config.idp_metadata.entity_id;

    // Look up InResponseTo from the response to verify against tracked request IDs
    let expected_request_id = response
        .base
        .in_response_to
        .as_deref()
        .filter(|id| config.request_id_tracker.consume(id))
        .map(|id| id.to_string());

    // Validate the Response
    let now = Utc::now();
    let authn_result = sp_profile::process_response_with_verified_signatures(
        &response,
        &config.security,
        Some(config.replay_cache.as_ref()),
        &config.entity_id,
        &config.acs_url,
        expected_request_id.as_deref(),
        expected_idp_entity_id,
        &verified_signed_id_refs,
        now,
    )
    .map_err(|e| SamlActixError::Internal(format!("response validation failed: {e}")))?;

    let sp_result = SpAuthnResult {
        authn: authn_result,
        relay_state: msg.relay_state.clone(),
    };

    // If an ACS callback is registered, delegate to it
    if let Some(callback) = acs_callback {
        return Ok(callback(sp_result, &req));
    }

    // Default: return a simple success page
    let name_id = &sp_result.authn.name_id;
    let body = format!(
        "<html><body><h1>Authentication Successful</h1><p>NameID: {name_id}</p></body></html>"
    );
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

/// Verify the XML signatures carried by an ACS response and return the signed IDs.
///
/// This function deliberately verifies against IdP certificates from metadata
/// and never treats inline `KeyInfo` as trust. The returned IDs are later matched
/// to the parsed `Response`/`Assertion` objects, which prevents accepting claims
/// from an XML object that merely contains signature markup.
fn verify_acs_response_signatures(
    xml: &str,
    response: &SamlResponse,
    config: &SpConfig,
) -> Result<Vec<String>, SamlActixError> {
    // Step 1: Determine whether the parsed response contains any XML Signature
    // element that the deserializer recognized on the Response or Assertions.
    // This is only a routing signal; it is not evidence that the signature is
    // valid or trusted.
    let has_signature = response.base.has_signature
        || response
            .assertions
            .iter()
            .any(|assertion| assertion.has_signature);

    // Step 2: Work out whether this deployment requires a signature at all.
    // Either policy means ACS must have cryptographic proof before it can
    // accept the response.
    let signature_required =
        config.security.require_signed_assertions || config.security.require_signed_responses;

    if !has_signature {
        if signature_required {
            // Required signatures must fail here rather than relying on later
            // parsing paths to notice that verification never happened.
            return Err(SamlActixError::Profile(
                gamlastan::profiles::ProfileError::AssertionValidation(
                    "signed response or assertion required but no signature is present".into(),
                ),
            ));
        }

        // Unsigned responses are only allowed when both response and assertion
        // signature requirements are disabled. Return an empty verified-ID set
        // so later validation cannot accidentally treat anything as signed.
        return Ok(Vec::new());
    }

    // Step 3: Build a verifier from trusted IdP metadata. This fails closed if
    // no usable signing certificate is configured, because a signed SAML
    // response without a trusted verification key is not authentic.
    let verifier = trusted_idp_verifier(config)?;

    // Step 4: Verify the exact XML string received by the ACS endpoint, before
    // any authentication result is constructed. The verifier is configured to
    // use trusted metadata keys only, so attacker-controlled inline KeyInfo does
    // not become a trust anchor.
    //
    // `verify_enveloped` validates the signature value and all digest
    // references. A syntactically present but forged `<ds:Signature>` becomes
    // `Invalid` or an error and is rejected before claims are consumed.
    let verify_result = verifier.verify_enveloped(xml).map_err(|e| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            format!("signature verification failed: {e}"),
        ))
    })?;

    let VerifyResult::Valid { references, .. } = verify_result else {
        let reason = match verify_result {
            VerifyResult::Invalid { reason } => reason,
            VerifyResult::Valid { .. } => unreachable!(),
        };
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "signature verification failed: {reason}"
            )),
        ));
    };

    // Step 5: Convert verified XML-DSig references into SAML object IDs. The
    // core validator compares these IDs against the parsed Response and
    // Assertion IDs, binding cryptographic verification to the objects that
    // provide the user's identity and attributes.
    let mut ids = Vec::new();
    for reference in references {
        // Same-document references are normally "#ID". An empty URI signs the
        // document root, which in the ACS path is the SAML Response we parsed.
        let id = if reference.uri.is_empty() {
            Some(response.base.id.as_str())
        } else {
            reference.uri.strip_prefix('#')
        };
        if let Some(id) = id {
            if !ids.iter().any(|existing| existing == id) {
                ids.push(id.to_string());
            }
        }
    }

    // Step 6: A valid signature that does not identify a response/assertion
    // target is not useful for SAML Web SSO. Reject it instead of falling back
    // to signature-presence checks.
    if ids.is_empty() {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(
                "signature verified but did not reference a SAML response or assertion ID".into(),
            ),
        ));
    }

    Ok(ids)
}

/// Build a verifier from trusted IdP signing certificates in metadata.
///
/// Metadata without a usable signing certificate is a configuration error for
/// signed ACS responses: accepting the response would otherwise mean trusting
/// attacker-supplied inline keys or skipping cryptographic verification.
fn trusted_idp_verifier(config: &SpConfig) -> Result<SamlVerifier, SamlActixError> {
    let mut keys = KeysManager::new();
    for idp in config.idp_metadata.idp_sso_descriptors() {
        for cert in idp.signing_certificates_der() {
            // XML-DSig enveloped verification uses trusted certs for
            // certificate-chain trust decisions. Redirect binding verification
            // needs an actual public verification key, so add both views of the
            // same metadata certificate. If the certificate cannot be parsed
            // into a public verification key, fail here with a configuration
            // error instead of surfacing a later "No verification key found".
            let key = loader::load_x509_cert_der(&cert).map_err(|e| {
                SamlActixError::Configuration(format!(
                    "IdP signing certificate cannot be used for verification: {e}"
                ))
            })?;
            keys.add_key(key);
            keys.add_trusted_cert(cert);
        }
    }

    if !keys.has_trusted_certs() {
        return Err(SamlActixError::Configuration(
            "no IdP signing certificate in metadata".into(),
        ));
    }

    Ok(SamlVerifier::with_ds_object_rejection(
        keys,
        config.security.reject_signatures_with_ds_object,
    ))
}

/// Verify an incoming SLO message signature and bind it to the parsed message ID.
///
/// SLO can arrive through HTTP Redirect, where the signature covers the query
/// string, or through POST/SOAP-style XML with an enveloped XML-DSig signature.
/// This helper accepts either form but never accepts unsigned SLO messages in
/// the ready-to-use SP handler.
fn verify_slo_message_signature(
    msg: &SamlMessage,
    xml: &str,
    message_id: &str,
    has_xml_signature: bool,
    config: &SpConfig,
) -> Result<(), SamlActixError> {
    let verifier = if msg.redirect_signature.is_some() || has_xml_signature {
        Some(trusted_idp_verifier(config)?)
    } else {
        None
    };

    if let (Some(sig), Some(verifier)) = (&msg.redirect_signature, verifier.as_ref()) {
        let valid = verifier
            .verify_redirect_query(sig.signature_input.as_bytes(), &sig.signature, &sig.sig_alg)
            .map_err(|e| {
                SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
                    format!("SLO redirect signature verification failed: {e}"),
                ))
            })?;
        if valid {
            return Ok(());
        }
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(
                "SLO redirect signature verification failed".into(),
            ),
        ));
    }

    if !has_xml_signature {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(
                "SLO message must be signed".into(),
            ),
        ));
    }

    // For XML signatures, require the verified same-document reference to name
    // the LogoutRequest/LogoutResponse ID parsed above. That keeps signature
    // verification bound to the object used for logout decisions.
    let verifier = verifier.as_ref().ok_or_else(|| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            "SLO message must be signed".into(),
        ))
    })?;
    let verify_result = verifier.verify_enveloped(xml).map_err(|e| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            format!("SLO XML signature verification failed: {e}"),
        ))
    })?;
    match verify_result {
        VerifyResult::Valid { references, .. } => {
            if references
                .iter()
                .any(|reference| reference.uri.strip_prefix('#') == Some(message_id))
            {
                Ok(())
            } else {
                Err(SamlActixError::Profile(
                    gamlastan::profiles::ProfileError::AssertionValidation(
                        "SLO XML signature did not reference the parsed message ID".into(),
                    ),
                ))
            }
        }
        VerifyResult::Invalid { reason } => Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "SLO XML signature verification failed: {reason}"
            )),
        )),
    }
}

/// Validate issuer and Destination on an IdP-originated LogoutRequest.
fn validate_slo_logout_request(
    request: &LogoutRequest,
    config: &SpConfig,
) -> Result<(), SamlActixError> {
    validate_slo_common(
        request.issuer.as_ref().map(|issuer| issuer.value.as_str()),
        request.destination.as_deref(),
        config,
    )
}

/// Validate issuer, Destination, and InResponseTo on an IdP LogoutResponse.
fn validate_slo_logout_response(
    response: &LogoutResponse,
    config: &SpConfig,
) -> Result<(), SamlActixError> {
    validate_slo_common(
        response.issuer.as_ref().map(|issuer| issuer.value.as_str()),
        response.destination.as_deref(),
        config,
    )?;

    let in_response_to = response.in_response_to.as_deref().ok_or_else(|| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            "LogoutResponse missing InResponseTo".into(),
        ))
    })?;
    if !config.request_id_tracker.consume(in_response_to) {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "LogoutResponse InResponseTo {in_response_to} matches no outstanding LogoutRequest"
            )),
        ));
    }

    if !response.status.is_success() {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::ResponseFailure(
                response
                    .status
                    .status_message
                    .clone()
                    .unwrap_or_else(|| response.status.status_code.value.clone()),
            ),
        ));
    }

    Ok(())
}

/// Validate common SLO trust fields before acting on the message.
fn validate_slo_common(
    issuer: Option<&str>,
    destination: Option<&str>,
    config: &SpConfig,
) -> Result<(), SamlActixError> {
    let issuer = issuer.ok_or_else(|| {
        SamlActixError::Profile(gamlastan::profiles::ProfileError::AssertionValidation(
            "SLO message missing Issuer".into(),
        ))
    })?;
    if issuer != config.idp_metadata.entity_id {
        return Err(SamlActixError::Profile(
            gamlastan::profiles::ProfileError::AssertionValidation(format!(
                "SLO issuer {issuer} does not match IdP {}",
                config.idp_metadata.entity_id
            )),
        ));
    }

    if config.security.verify_destination {
        match destination {
            Some(dest) if dest == config.slo_url => {}
            Some(dest) => {
                return Err(SamlActixError::Profile(
                    gamlastan::profiles::ProfileError::AssertionValidation(format!(
                        "SLO Destination {dest} does not match {}",
                        config.slo_url
                    )),
                ));
            }
            None => {
                return Err(SamlActixError::Profile(
                    gamlastan::profiles::ProfileError::AssertionValidation(
                        "SLO message missing Destination".into(),
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// SP logout initiation handler: create a LogoutRequest and send to IdP.
async fn sp_logout(
    req: HttpRequest,
    config: web::Data<SpConfig>,
) -> Result<HttpResponse, SamlActixError> {
    let query_string = req.query_string();
    let name_id_value = extract_query_param(query_string, "NameID").ok_or_else(|| {
        SamlActixError::Configuration("NameID query parameter required for logout".into())
    })?;
    let session_index = extract_query_param(query_string, "SessionIndex");

    // Find IdP SLO endpoint
    let idp_descriptors = config.idp_metadata.idp_sso_descriptors();
    let idp_desc = idp_descriptors
        .first()
        .ok_or_else(|| SamlActixError::Configuration("no IdP SSO descriptor in metadata".into()))?;

    let slo_endpoint = logout::find_slo_endpoint(
        &idp_desc.sso_base,
        gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
    )
    .ok_or_else(|| SamlActixError::Configuration("no SLO endpoint in IdP metadata".into()))?;

    let name_id = NameId {
        value: name_id_value,
        format: None,
        name_qualifier: None,
        sp_name_qualifier: None,
        sp_provided_id: None,
    };

    let options = logout::SpLogoutRequestOptions {
        sp_entity_id: config.entity_id.clone(),
        name_id,
        session_indexes: session_index.into_iter().collect(),
        reason: Some(logout::reason::USER.to_string()),
        destination: Some(slo_endpoint.location.clone()),
        not_on_or_after: None,
    };

    let logout_request = logout::create_sp_logout_request(&options)
        .map_err(|e| SamlActixError::Internal(format!("failed to create LogoutRequest: {e}")))?;
    config.request_id_tracker.store(&logout_request.id);

    let xml = logout_request
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize LogoutRequest: {e}")))?;

    let redirect_url = gamlastan::bindings::redirect::redirect_encode(&RedirectEncodeParams {
        saml_xml: xml.as_bytes(),
        is_request: true,
        destination: &slo_endpoint.location,
        relay_state: None,
        signer: None,
    })
    .map_err(|e| SamlActixError::Internal(format!("redirect encode failed: {e}")))?;

    Ok(crate::response_adapter::redirect_binding_response(
        &redirect_url,
    ))
}

/// SP Single Logout Service handler: process incoming LogoutRequest or LogoutResponse from IdP.
async fn sp_slo(
    msg: SamlMessage,
    config: web::Data<SpConfig>,
) -> Result<HttpResponse, SamlActixError> {
    let xml_str = msg.saml_xml_str()?;
    let doc = uppsala::parse(xml_str).map_err(|e: uppsala::XmlError| {
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
            // Validate the incoming LogoutRequest
            let req_ref = gamlastan::xml::deserialize::parse_saml::<
                gamlastan::core::protocol::logout::LogoutRequestRef<'_>,
            >(&doc)?;
            let logout_req = req_ref.to_owned();

            let now = Utc::now();
            verify_slo_message_signature(
                &msg,
                xml_str,
                &logout_req.id,
                logout_req.has_signature,
                &config,
            )?;
            validate_slo_logout_request(&logout_req, &config)?;
            logout::validate_logout_request(&logout_req, now, config.security.clock_skew_seconds)
                .map_err(|e| SamlActixError::Internal(format!("invalid LogoutRequest: {e}")))?;

            // Create success response
            let in_response_to = &logout_req.id;
            let response =
                logout::create_logout_response_success(&config.entity_id, in_response_to, None);

            let response_xml = response.to_xml_string().map_err(|e| {
                SamlActixError::Internal(format!("failed to serialize LogoutResponse: {e}"))
            })?;

            // Send via redirect binding back to IdP
            let idp_descriptors = config.idp_metadata.idp_sso_descriptors();
            if let Some(idp_desc) = idp_descriptors.first() {
                if let Some(slo_ep) = logout::find_slo_endpoint(
                    &idp_desc.sso_base,
                    gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                ) {
                    let redirect_url =
                        gamlastan::bindings::redirect::redirect_encode(&RedirectEncodeParams {
                            saml_xml: response_xml.as_bytes(),
                            is_request: false,
                            destination: &slo_ep.location,
                            relay_state: None,
                            signer: None,
                        })
                        .map_err(|e| {
                            SamlActixError::Internal(format!("redirect encode failed: {e}"))
                        })?;

                    return Ok(crate::response_adapter::redirect_binding_response(
                        &redirect_url,
                    ));
                }
            }

            // Fallback: return simple success
            Ok(HttpResponse::Ok().body("Logout completed"))
        }
        "LogoutResponse" => {
            // A LogoutResponse completes an SP-initiated logout only if it is
            // signed by the IdP, targets this SLO endpoint, and correlates to a
            // LogoutRequest ID that this SP actually issued.
            let resp_ref = gamlastan::xml::deserialize::parse_saml::<
                gamlastan::core::protocol::logout::LogoutResponseRef<'_>,
            >(&doc)?;
            let logout_resp = resp_ref.to_owned();
            verify_slo_message_signature(
                &msg,
                xml_str,
                &logout_resp.id,
                logout_resp.has_signature,
                &config,
            )?;
            validate_slo_logout_response(&logout_resp, &config)?;
            Ok(HttpResponse::Ok().body("Logout completed"))
        }
        other => Err(SamlActixError::UnsupportedBinding(format!(
            "unexpected SAML element in SLO: {other}"
        ))),
    }
}

/// SP metadata handler: generate and return the SP's SAML metadata.
async fn sp_metadata(config: web::Data<SpConfig>) -> Result<MetadataXml, SamlActixError> {
    use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::metadata::types::sp::SpSsoDescriptor;

    let sp_sso = SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]),
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
            name_id_formats: if let Some(ref fmt) = config.name_id_format {
                vec![fmt.clone()]
            } else {
                vec![]
            },
        },
        authn_requests_signed: Some(false),
        want_assertions_signed: Some(config.want_assertions_signed),
        assertion_consumer_services: vec![IndexedEndpoint::new_default(
            Endpoint::new(
                gamlastan::profiles::sso::web_browser::bindings::HTTP_POST,
                &config.acs_url,
            ),
            0,
        )],
        attribute_consuming_services: vec![],
    };

    let entity = EntityDescriptor {
        entity_id: config.entity_id.clone(),
        id: None,
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
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };

    let xml = entity
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize metadata: {e}")))?;

    Ok(MetadataXml(xml))
}

/// Simple query parameter extraction from a query string.
fn extract_query_param(query: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(&prefix) {
            // URL-decode the value
            return Some(
                gamlastan::bindings::encoding::url_decode(value)
                    .unwrap_or_else(|_| value.to_string()),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractors::SamlBinding;
    use base64::Engine;
    use chrono::TimeDelta;
    use gamlastan::core::assertion::authn::{AuthnContext, AuthnStatement};
    use gamlastan::core::assertion::conditions::{AudienceRestriction, Conditions};
    use gamlastan::core::assertion::issuer::Issuer;
    use gamlastan::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
    use gamlastan::core::assertion::subject::{
        Subject, SubjectConfirmation, SubjectConfirmationData,
    };
    use gamlastan::core::assertion::types::Assertion;
    use gamlastan::core::constants;
    use gamlastan::core::identifiers::SamlVersion;
    use gamlastan::core::protocol::status::Status;
    use gamlastan::core::protocol::{response::Response, response::ResponseBase};
    use gamlastan::crypto::KeyUsage;
    use gamlastan::metadata::types::endpoint::Endpoint;
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use gamlastan::metadata::types::idp::IdpSsoDescriptor;
    use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
    use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use gamlastan::profiles::sso::sp as core_sp_profile;
    use gamlastan::security::config::SecurityConfig;
    use gamlastan::xml::deserialize::parse_saml;

    const SIGN_CERT_PEM: &str = include_str!("../../gamlastan-mdq/tests/fixtures/sign-cert.pem");
    const SIGN_KEY_PEM: &[u8] = include_bytes!("../../gamlastan-mdq/tests/fixtures/sign-key.pem");
    const OTHER_CERT_PEM: &str = include_str!("../tests/fixtures/other-cert.pem");

    fn test_sp_config() -> SpConfig {
        let idp = IdpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base: RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ]),
                artifact_resolution_services: vec![],
                single_logout_services: vec![Endpoint::new(
                    gamlastan::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                    "https://idp.example.com/slo",
                )],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            want_authn_requests_signed: None,
            single_sign_on_services: vec![],
            name_id_mapping_services: vec![],
            assertion_id_request_services: vec![],
            attribute_profiles: vec![],
            attributes: vec![],
        };
        let metadata = EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![idp],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };
        SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            metadata,
        )
        .with_slo_url("https://sp.example.com/slo")
    }

    fn cert_b64(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.contains("CERTIFICATE"))
            .collect::<String>()
    }

    fn key_info_with_cert(cert: &str) -> String {
        format!(
            r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#
        )
    }

    fn test_sp_config_with_signing_cert(cert: &str) -> SpConfig {
        let mut config = test_sp_config();
        let EntityRoles::Roles { idp_sso, .. } = &mut config.idp_metadata.roles else {
            panic!("test metadata should contain IdP SSO role");
        };
        idp_sso[0]
            .sso_base
            .base
            .key_descriptors
            .push(KeyDescriptor::signing(key_info_with_cert(cert)));
        config
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

    fn test_signature_template(reference_id: &str, cert: &str) -> String {
        format!(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
        )
    }

    fn insert_response_signature_template(xml: &str, response_id: &str) -> String {
        let marker = "</saml:Issuer>";
        let pos = xml.find(marker).expect("response issuer marker") + marker.len();
        let template = test_signature_template(response_id, &cert_b64(SIGN_CERT_PEM));
        format!("{}{}{}", &xml[..pos], template, &xml[pos..])
    }

    fn insert_assertion_signature_template(
        xml: &str,
        assertion_id: &str,
        reference_id: &str,
    ) -> String {
        let id_attr = format!(r#"ID="{assertion_id}""#);
        let assertion_pos = xml.find(&id_attr).expect("assertion ID marker");
        let marker = "</saml:Issuer>";
        let issuer_end = assertion_pos
            + xml[assertion_pos..]
                .find(marker)
                .expect("assertion issuer marker")
            + marker.len();
        let template = test_signature_template(reference_id, &cert_b64(SIGN_CERT_PEM));
        format!("{}{}{}", &xml[..issuer_end], template, &xml[issuer_end..])
    }

    fn make_test_assertion(id: &str, name_id: &str, now: chrono::DateTime<Utc>) -> Assertion {
        Assertion {
            id: id.to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            issuer: Issuer::entity("https://idp.example.com"),
            has_signature: false,
            subject: Some(Subject {
                name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                    value: name_id.to_string(),
                    format: Some(constants::NAMEID_EMAIL.to_string()),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![SubjectConfirmation {
                    method: constants::CM_BEARER.to_string(),
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationData {
                        not_before: None,
                        not_on_or_after: Some(now + TimeDelta::minutes(5)),
                        recipient: Some("https://sp.example.com/acs".to_string()),
                        in_response_to: None,
                        address: None,
                        key_info_x509_certs: vec![],
                    }),
                }],
            }),
            conditions: Some(Conditions {
                not_before: Some(now - TimeDelta::seconds(5)),
                not_on_or_after: Some(now + TimeDelta::minutes(5)),
                audience_restrictions: vec![AudienceRestriction {
                    audiences: vec!["https://sp.example.com".to_string()],
                }],
                one_time_use: false,
                proxy_restriction: None,
            }),
            advice: None,
            authn_statements: vec![AuthnStatement {
                authn_instant: now,
                session_index: Some("_session".to_string()),
                session_not_on_or_after: Some(now + TimeDelta::hours(8)),
                subject_locality: None,
                authn_context: AuthnContext {
                    authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
                    authn_context_decl_ref: None,
                    authenticating_authorities: vec![],
                },
            }],
            authz_decision_statements: vec![],
            attribute_statements: vec![],
        }
    }

    fn make_test_response(
        response_id: &str,
        assertions: Vec<Assertion>,
        now: chrono::DateTime<Utc>,
    ) -> Response {
        Response {
            base: ResponseBase {
                id: response_id.to_string(),
                version: SamlVersion::V2_0,
                issue_instant: now,
                destination: Some("https://sp.example.com/acs".to_string()),
                consent: None,
                issuer: Some(Issuer::entity("https://idp.example.com")),
                has_signature: false,
                in_response_to: None,
                status: Status::success(),
            },
            assertions,
            encrypted_assertions: vec![],
        }
    }

    fn parse_response_xml(xml: &str) -> Response {
        let doc = uppsala::parse(xml).unwrap();
        parse_saml::<gamlastan::core::protocol::response::ResponseRef<'_>>(&doc)
            .unwrap()
            .to_owned()
    }

    #[test]
    fn test_extract_query_param() {
        assert_eq!(
            extract_query_param("RelayState=abc&other=def", "RelayState"),
            Some("abc".to_string())
        );
        assert_eq!(
            extract_query_param("RelayState=abc&other=def", "other"),
            Some("def".to_string())
        );
        assert_eq!(
            extract_query_param("RelayState=abc&other=def", "missing"),
            None
        );
    }

    #[test]
    fn test_extract_query_param_empty() {
        assert_eq!(extract_query_param("", "RelayState"), None);
    }

    #[test]
    fn test_extract_query_param_encoded() {
        assert_eq!(
            extract_query_param("url=https%3A%2F%2Fexample.com", "url"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_sp_signing_context_fields() {
        // Verify the SpSigningContext struct has the expected fields
        // (we can't construct a real signer without keys, so just test the type exists)
        let _sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        // SpSigningContext is a public struct with signer and sig_algorithm fields
        assert!(std::mem::size_of::<SpSigningContext>() > 0);
    }

    #[test]
    fn test_trusted_idp_verifier_rejects_unusable_signing_cert() {
        let mut config = test_sp_config();
        let EntityRoles::Roles { idp_sso, .. } = &mut config.idp_metadata.roles else {
            panic!("test metadata should contain IdP SSO role");
        };
        idp_sso[0]
            .sso_base
            .base
            .key_descriptors
            .push(KeyDescriptor::signing(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#,
            ));

        let err = match trusted_idp_verifier(&config) {
            Ok(_) => panic!("invalid signing certificate should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("cannot be used for verification"));
    }

    #[test]
    fn test_acs_rejects_tampered_response_signature() {
        let now = Utc::now();
        let response = make_test_response(
            "_response",
            vec![make_test_assertion("_assertion", "user@example.com", now)],
            now,
        );
        let unsigned_xml = response.to_xml_string().unwrap();
        let templated_xml = insert_response_signature_template(&unsigned_xml, "_response");
        let signed_xml = test_signer().sign_enveloped(&templated_xml).unwrap();
        let tampered_xml = signed_xml.replace("user@example.com", "attacker@example.com");
        let parsed_response = parse_response_xml(&tampered_xml);
        let config = test_sp_config_with_signing_cert(&cert_b64(SIGN_CERT_PEM));

        let err = verify_acs_response_signatures(&tampered_xml, &parsed_response, &config)
            .expect_err("tampered signed response should be rejected");

        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn test_acs_wrapping_rejects_unsigned_consumed_assertion() {
        let now = Utc::now();
        let response = make_test_response(
            "_response",
            vec![
                make_test_assertion("_attacker_assertion", "attacker@example.com", now),
                make_test_assertion("_signed_assertion", "user@example.com", now),
            ],
            now,
        );
        let unsigned_xml = response.to_xml_string().unwrap();
        let templated_xml = insert_assertion_signature_template(
            &unsigned_xml,
            "_signed_assertion",
            "_signed_assertion",
        );
        let signed_xml = test_signer().sign_enveloped(&templated_xml).unwrap();
        let parsed_response = parse_response_xml(&signed_xml);
        let config = test_sp_config_with_signing_cert(&cert_b64(SIGN_CERT_PEM));

        let verified_ids =
            verify_acs_response_signatures(&signed_xml, &parsed_response, &config).unwrap();
        assert_eq!(verified_ids, vec!["_signed_assertion".to_string()]);
        let verified_id_refs: Vec<&str> = verified_ids.iter().map(String::as_str).collect();

        let result = core_sp_profile::process_response_with_verified_signatures(
            &parsed_response,
            &SecurityConfig::default(),
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            "https://idp.example.com",
            &verified_id_refs,
            now,
        );

        let err = result.expect_err("unsigned attacker assertion must not be consumable");
        assert!(err
            .to_string()
            .contains("Assertion signature required but neither assertion nor response signature was verified"));
    }

    #[test]
    fn test_acs_ignores_inline_key_info_without_matching_metadata_trust() {
        let now = Utc::now();
        let response = make_test_response(
            "_response",
            vec![make_test_assertion("_assertion", "user@example.com", now)],
            now,
        );
        let unsigned_xml = response.to_xml_string().unwrap();
        let templated_xml = insert_response_signature_template(&unsigned_xml, "_response");
        let signed_xml = test_signer().sign_enveloped(&templated_xml).unwrap();
        let parsed_response = parse_response_xml(&signed_xml);

        let wrong_trust_config = test_sp_config_with_signing_cert(&cert_b64(OTHER_CERT_PEM));
        let err =
            verify_acs_response_signatures(&signed_xml, &parsed_response, &wrong_trust_config)
                .expect_err("inline KeyInfo must not override metadata trust");
        assert!(!err.to_string().is_empty());

        let matching_trust_config = test_sp_config_with_signing_cert(&cert_b64(SIGN_CERT_PEM));
        let verified_ids =
            verify_acs_response_signatures(&signed_xml, &parsed_response, &matching_trust_config)
                .unwrap();
        assert_eq!(verified_ids, vec!["_response".to_string()]);
    }

    #[test]
    fn test_slo_unsigned_message_is_rejected_before_metadata_key_lookup() {
        let config = test_sp_config();
        let msg = SamlMessage {
            saml_xml: b"<samlp:LogoutRequest/>".to_vec(),
            relay_state: None,
            is_request: true,
            binding: SamlBinding::HttpRedirect,
            redirect_signature: None,
        };

        let err =
            verify_slo_message_signature(&msg, "<samlp:LogoutRequest/>", "_id", false, &config)
                .unwrap_err();
        assert!(err.to_string().contains("SLO message must be signed"));
    }

    #[test]
    fn test_slo_common_rejects_issuer_and_destination_mismatch() {
        let config = test_sp_config();

        let issuer_err = validate_slo_common(
            Some("https://evil.example.com"),
            Some(&config.slo_url),
            &config,
        )
        .unwrap_err();
        assert!(issuer_err.to_string().contains("does not match IdP"));

        let destination_err = validate_slo_common(
            Some("https://idp.example.com"),
            Some("https://sp.example.com/other"),
            &config,
        )
        .unwrap_err();
        assert!(destination_err.to_string().contains("Destination"));
    }

    #[test]
    fn test_slo_logout_response_requires_matching_in_response_to() {
        let config = test_sp_config();
        config.request_id_tracker.store("_logout_req");
        let response = LogoutResponse {
            id: "_logout_resp".to_string(),
            version: gamlastan::core::identifiers::SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: Some(config.slo_url.clone()),
            consent: None,
            issuer: Some(Issuer::entity("https://idp.example.com")),
            has_signature: false,
            in_response_to: Some("_logout_req".to_string()),
            status: Status::success(),
        };

        validate_slo_logout_response(&response, &config).unwrap();

        let replay = validate_slo_logout_response(&response, &config).unwrap_err();
        assert!(replay
            .to_string()
            .contains("matches no outstanding LogoutRequest"));
    }
}
