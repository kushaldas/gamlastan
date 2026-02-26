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

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;

use swsaml::bindings::redirect::RedirectEncodeParams;
use swsaml::bindings::relay_state::RelayState;
use swsaml::core::assertion::name_id::NameId;
use swsaml::core::protocol::response::Response as SamlResponse;
use swsaml::profiles::logout;
use swsaml::profiles::sso::sp as sp_profile;
use swsaml::profiles::sso::web_browser::{AuthnRequestOptions, AuthnResult};
use swsaml::xml::serialize::SamlSerialize;
use swsaml::xml::uppsala;

use crate::config::SpConfig;
use crate::error::SamlActixError;
use crate::extractors::SamlMessage;
use crate::responders::MetadataXml;

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
        swsaml::profiles::sso::web_browser::bindings::HTTP_POST
    } else {
        swsaml::profiles::sso::web_browser::bindings::HTTP_REDIRECT
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

    // Encode and send via the appropriate binding
    let relay_state = relay_state_value
        .as_deref()
        .and_then(|rs| RelayState::new(rs).ok());

    if binding_pref == "post" {
        let html = swsaml::bindings::post::post_encode(
            authn_request_xml.as_bytes(),
            true,
            &sso_endpoint.location,
            relay_state.as_ref(),
        );
        Ok(crate::response_adapter::post_binding_response(&html))
    } else {
        let redirect_url = swsaml::bindings::redirect::redirect_encode(&RedirectEncodeParams {
            saml_xml: authn_request_xml.as_bytes(),
            is_request: true,
            destination: &sso_endpoint.location,
            relay_state: relay_state.as_ref(),
            signer: None, // TODO: add signing support
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
        SamlActixError::Xml(swsaml::xml::error::XmlError::ParseError(e))
    })?;
    let response_ref = swsaml::xml::deserialize::parse_saml::<
        swsaml::core::protocol::response::ResponseRef<'_>,
    >(&doc)?;
    let response: SamlResponse = response_ref.to_owned();

    // Get the IdP entity ID from metadata
    let expected_idp_entity_id = &config.idp_metadata.entity_id;

    // Validate the Response
    let now = Utc::now();
    let authn_result = sp_profile::process_response(
        &response,
        &config.security,
        Some(config.replay_cache.as_ref()),
        &config.entity_id,
        &config.acs_url,
        None, // TODO: track request IDs for InResponseTo verification
        expected_idp_entity_id,
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
        swsaml::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
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

    let xml = logout_request
        .to_xml_string()
        .map_err(|e| SamlActixError::Internal(format!("failed to serialize LogoutRequest: {e}")))?;

    let redirect_url = swsaml::bindings::redirect::redirect_encode(&RedirectEncodeParams {
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
        SamlActixError::Xml(swsaml::xml::error::XmlError::ParseError(e))
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
            let req_ref = swsaml::xml::deserialize::parse_saml::<
                swsaml::core::protocol::logout::LogoutRequestRef<'_>,
            >(&doc)?;
            let logout_req = req_ref.to_owned();

            let now = Utc::now();
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
                    swsaml::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                ) {
                    let redirect_url =
                        swsaml::bindings::redirect::redirect_encode(&RedirectEncodeParams {
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
            // Process the IdP's response to our LogoutRequest
            // For now, just acknowledge it
            Ok(HttpResponse::Ok().body("Logout completed"))
        }
        other => Err(SamlActixError::UnsupportedBinding(format!(
            "unexpected SAML element in SLO: {other}"
        ))),
    }
}

/// SP metadata handler: generate and return the SP's SAML metadata.
async fn sp_metadata(config: web::Data<SpConfig>) -> Result<MetadataXml, SamlActixError> {
    use swsaml::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use swsaml::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use swsaml::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use swsaml::metadata::types::sp::SpSsoDescriptor;

    let sp_sso = SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]),
            artifact_resolution_services: vec![],
            single_logout_services: if config.slo_url.is_empty() {
                vec![]
            } else {
                vec![
                    Endpoint::new(
                        swsaml::profiles::sso::web_browser::bindings::HTTP_REDIRECT,
                        &config.slo_url,
                    ),
                    Endpoint::new(
                        swsaml::profiles::sso::web_browser::bindings::HTTP_POST,
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
                swsaml::profiles::sso::web_browser::bindings::HTTP_POST,
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
                swsaml::bindings::encoding::url_decode(value).unwrap_or_else(|_| value.to_string()),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
