// SAML 2.0 Web Browser SSO Profile - SP side
//
// SAML Profiles Section 4.1
//
// SP-side operations:
// - create_authn_request: Build AuthnRequest for sending to IdP
// - process_response: Validate and extract identity from Response

use chrono::{DateTime, Utc};

/// Extracted NameID components: (value, format, name_qualifier, sp_name_qualifier).
type ExtractedNameId = (String, Option<String>, Option<String>, Option<String>);

use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameIdOrEncryptedId, NameIdPolicy};

use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::request::{
    AuthnContextComparison, AuthnRequest, RequestBase, RequestedAuthnContext, Scoping,
};
use crate::core::protocol::response::Response;
use crate::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
use crate::metadata::types::idp::IdpSsoDescriptor;
use crate::security::config::SecurityConfig;
use crate::security::replay::ReplayCache;
use crate::security::validation::{AssertionValidator, ValidationParams};

use crate::profiles::error::ProfileError;
use crate::profiles::sso::web_browser::{self, AuthnRequestOptions, AuthnResult};

/// Create an AuthnRequest per SAML Profiles 4.1.4.1.
///
/// Rules enforced:
/// - Issuer MUST be present with SP entity ID
/// - Issuer Format MUST be entity or omitted
/// - Subject MUST NOT contain SubjectConfirmation (if present)
/// - NameIDPolicy with AllowCreate if new identifier creation desired (E14)
pub fn create_authn_request(options: &AuthnRequestOptions) -> Result<AuthnRequest, ProfileError> {
    if options.sp_entity_id.is_empty() {
        return Err(ProfileError::MissingIssuer);
    }

    // Build NameIDPolicy if format or allow_create specified
    let name_id_policy = if options.name_id_format.is_some()
        || options.allow_create
        || options.sp_name_qualifier.is_some()
    {
        Some(NameIdPolicy {
            format: options.name_id_format.clone(),
            sp_name_qualifier: options.sp_name_qualifier.clone(),
            allow_create: options.allow_create,
        })
    } else {
        None
    };

    // Build RequestedAuthnContext if class refs specified
    let requested_authn_context = if !options.authn_context_class_refs.is_empty() {
        Some(RequestedAuthnContext {
            authn_context_class_refs: options.authn_context_class_refs.clone(),
            authn_context_decl_refs: vec![],
            comparison: options
                .authn_context_comparison
                .unwrap_or(AuthnContextComparison::Exact),
        })
    } else {
        None
    };

    // Build Scoping if proxy count or requester IDs specified
    let scoping = if options.proxy_count.is_some() || !options.requester_ids.is_empty() {
        Some(Scoping {
            proxy_count: options.proxy_count,
            idp_list: vec![],
            requester_ids: options.requester_ids.clone(),
        })
    } else {
        None
    };

    Ok(AuthnRequest {
        base: RequestBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: options.destination.clone(),
            consent: None,
            issuer: Some(Issuer::entity(&options.sp_entity_id)),
            has_signature: false,
        },
        subject: None,
        name_id_policy,
        conditions: None,
        requested_authn_context,
        scoping,
        force_authn: options.force_authn,
        is_passive: options.is_passive,
        assertion_consumer_service_index: options.acs_index,
        assertion_consumer_service_url: options.acs_url.clone(),
        protocol_binding: options.protocol_binding.clone(),
        attribute_consuming_service_index: options.attribute_consuming_service_index,
        provider_name: options.provider_name.clone(),
        extensions: options.extensions.clone(),
    })
}

/// Find the best SSO endpoint from IdP metadata for the given binding.
pub fn find_sso_endpoint<'a>(
    idp: &'a IdpSsoDescriptor,
    preferred_binding: &str,
) -> Option<&'a Endpoint> {
    // First try preferred binding
    if let Some(ep) = idp
        .single_sign_on_services
        .iter()
        .find(|e| e.binding == preferred_binding)
    {
        return Some(ep);
    }
    // Fall back to first available
    idp.single_sign_on_services.first()
}

/// Find the default ACS endpoint from SP metadata.
pub fn find_default_acs_endpoint(acs_endpoints: &[IndexedEndpoint]) -> Option<&IndexedEndpoint> {
    // First look for explicitly marked default
    if let Some(ep) = acs_endpoints.iter().find(|e| e.is_default == Some(true)) {
        return Some(ep);
    }
    // Fall back to lowest index
    acs_endpoints.iter().min_by_key(|e| e.index)
}

/// Find an ACS endpoint with the specified binding.
pub fn find_acs_endpoint_by_binding<'a>(
    acs_endpoints: &'a [IndexedEndpoint],
    binding: &str,
) -> Option<&'a IndexedEndpoint> {
    acs_endpoints.iter().find(|e| e.endpoint.binding == binding)
}

/// Process and validate a SAML Response on the SP side.
///
/// Runs the full assertion validation checklist (Section 7.2 of the plan)
/// and extracts the authentication result.
///
/// # Arguments
/// * `response` - The parsed SAML Response
/// * `config` - Security configuration
/// * `replay_cache` - Replay prevention cache
/// * `sp_entity_id` - Our SP entity ID (for audience restriction)
/// * `acs_url` - The ACS URL we received the response on
/// * `expected_request_id` - The AuthnRequest ID we sent (None for unsolicited)
/// * `expected_idp_entity_id` - Expected IdP entity ID (from metadata)
/// * `now` - Current time (for testability)
#[allow(clippy::too_many_arguments)]
pub fn process_response(
    response: &Response,
    config: &SecurityConfig,
    replay_cache: Option<&dyn ReplayCache>,
    sp_entity_id: &str,
    acs_url: &str,
    expected_request_id: Option<&str>,
    expected_idp_entity_id: &str,
    now: DateTime<Utc>,
) -> Result<AuthnResult, ProfileError> {
    process_response_with_verified_signatures(
        response,
        config,
        replay_cache,
        sp_entity_id,
        acs_url,
        expected_request_id,
        expected_idp_entity_id,
        &[],
        now,
    )
}

/// Process and validate a SAML Response with cryptographically verified
/// XML-DSig reference targets supplied by the caller.
///
/// `verified_signed_ids` must contain only IDs returned by a trusted
/// [`crate::crypto::SamlVerifier`] verification of the exact XML response
/// being processed.
#[allow(clippy::too_many_arguments)]
pub fn process_response_with_verified_signatures(
    response: &Response,
    config: &SecurityConfig,
    replay_cache: Option<&dyn ReplayCache>,
    sp_entity_id: &str,
    acs_url: &str,
    expected_request_id: Option<&str>,
    expected_idp_entity_id: &str,
    verified_signed_ids: &[&str],
    now: DateTime<Utc>,
) -> Result<AuthnResult, ProfileError> {
    // Check response status
    if !response.base.status.is_success() {
        return Err(ProfileError::ResponseFailure(
            response
                .base
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.base.status.status_code.value.clone()),
        ));
    }

    // Must have at least one assertion
    if response.assertions.is_empty() && response.encrypted_assertions.is_empty() {
        return Err(ProfileError::NoAssertions);
    }

    // Run the assertion validator
    let validator = if let Some(cache) = replay_cache {
        AssertionValidator::new(config).with_replay_cache(cache)
    } else {
        AssertionValidator::new(config)
    };

    let params = ValidationParams {
        received_url: acs_url,
        expected_idp_entity_id,
        sp_entity_id,
        acs_url,
        expected_request_id,
        client_address: None,
        relay_state: None,
        response_signature_xml: None,
        response_signature_verified: if response.base.has_signature {
            if verified_signed_ids.is_empty() {
                None
            } else {
                Some(verified_signed_ids.contains(&response.base.id.as_str()))
            }
        } else {
            None
        },
        verified_signed_ids,
        current_proxy_depth: 0,
        now,
    };

    let validation_result = validator.validate_response(response, &params);
    if !validation_result.is_valid() {
        let errors: Vec<String> = validation_result
            .failures()
            .iter()
            .map(|c| {
                format!(
                    "{}: {}",
                    c.check_name,
                    c.detail.as_deref().unwrap_or("failed")
                )
            })
            .collect();
        return Err(ProfileError::AssertionValidation(errors.join("; ")));
    }

    // Extract identity from the first assertion with an AuthnStatement
    let assertion = response
        .assertions
        .iter()
        .find(|a| !a.authn_statements.is_empty())
        .ok_or(ProfileError::NoAuthnStatement)?;

    // Extract NameID from Subject
    let (name_id_value, name_id_format, name_qualifier, sp_name_qualifier) =
        extract_name_id(assertion)?;

    // Extract AuthnStatement info
    let authn_stmt = assertion
        .authn_statements
        .first()
        .ok_or(ProfileError::NoAuthnStatement)?;

    // Extract attributes from all assertions
    let attributes: Vec<_> = response
        .assertions
        .iter()
        .flat_map(|a| web_browser::extract_attributes(&a.attribute_statements))
        .collect();

    // Extract IdP entity ID from issuer
    let idp_entity_id = assertion.issuer.value.clone();

    Ok(AuthnResult {
        name_id: name_id_value,
        name_id_format,
        name_qualifier,
        sp_name_qualifier,
        session_index: authn_stmt.session_index.clone(),
        session_not_on_or_after: authn_stmt.session_not_on_or_after,
        authn_instant: authn_stmt.authn_instant,
        authn_context_class_ref: authn_stmt.authn_context.authn_context_class_ref.clone(),
        authn_context_decl_ref: authn_stmt.authn_context.authn_context_decl_ref.clone(),
        authenticating_authorities: authn_stmt.authn_context.authenticating_authorities.clone(),
        attributes,
        idp_entity_id,
        assertion_id: assertion.id.clone(),
        response_id: response.base.id.clone(),
    })
}

/// Extract NameID from assertion's Subject.
fn extract_name_id(
    assertion: &crate::core::assertion::types::Assertion,
) -> Result<ExtractedNameId, ProfileError> {
    let subject = assertion
        .subject
        .as_ref()
        .ok_or(ProfileError::MissingNameId)?;

    match &subject.name_id {
        Some(NameIdOrEncryptedId::NameId(nid)) => Ok((
            nid.value.clone(),
            nid.format.clone(),
            nid.name_qualifier.clone(),
            nid.sp_name_qualifier.clone(),
        )),
        Some(NameIdOrEncryptedId::EncryptedId(_)) => Err(ProfileError::Other(
            "encrypted NameID not yet supported".to_string(),
        )),
        None => Err(ProfileError::MissingNameId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::authn::{AuthnContext, AuthnStatement};
    use crate::core::assertion::conditions::{AudienceRestriction, Conditions};
    use crate::core::assertion::name_id::NameId;
    use crate::core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
    use crate::core::assertion::types::Assertion;
    use crate::core::constants;
    use crate::core::protocol::response::ResponseBase;
    use crate::core::protocol::status::{Status, StatusCode};
    use chrono::TimeDelta;

    #[allow(dead_code)]
    fn make_test_assertion(
        sp_entity_id: &str,
        acs_url: &str,
        request_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Assertion {
        Assertion {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            issuer: Issuer::entity("https://idp.example.com"),
            has_signature: false,
            subject: Some(Subject {
                name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                    value: "user@example.com".to_string(),
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
                        recipient: Some(acs_url.to_string()),
                        in_response_to: request_id.map(|s| s.to_string()),
                        address: None,
                        key_info_x509_certs: vec![],
                    }),
                }],
            }),
            conditions: Some(Conditions {
                not_before: Some(now - TimeDelta::seconds(5)),
                not_on_or_after: Some(now + TimeDelta::minutes(5)),
                audience_restrictions: vec![AudienceRestriction {
                    audiences: vec![sp_entity_id.to_string()],
                }],
                one_time_use: false,
                proxy_restriction: None,
            }),
            advice: None,
            authn_statements: vec![AuthnStatement {
                authn_instant: now,
                session_index: Some("_session_1".to_string()),
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

    #[allow(dead_code)]
    fn make_test_response(assertion: Assertion, request_id: Option<&str>) -> Response {
        Response {
            base: ResponseBase {
                id: SamlId::generate().as_str().to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://sp.example.com/acs".to_string()),
                consent: None,
                issuer: Some(Issuer::entity("https://idp.example.com")),
                has_signature: false,
                in_response_to: request_id.map(|s| s.to_string()),
                status: Status::success(),
            },
            assertions: vec![assertion],
            encrypted_assertions: vec![],
        }
    }

    #[test]
    fn test_create_authn_request_basic() {
        let options = AuthnRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: Some("https://sp.example.com/acs".to_string()),
            destination: Some("https://idp.example.com/sso".to_string()),
            ..Default::default()
        };
        let req = create_authn_request(&options).unwrap();
        assert!(req.base.id.starts_with('_'));
        assert_eq!(req.base.version, SamlVersion::V2_0);
        assert_eq!(
            req.base.issuer.as_ref().unwrap().value,
            "https://sp.example.com"
        );
        assert_eq!(
            req.assertion_consumer_service_url,
            Some("https://sp.example.com/acs".to_string())
        );
        assert!(req.name_id_policy.is_none());
    }

    #[test]
    fn test_create_authn_request_with_policy() {
        let options = AuthnRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            name_id_format: Some(constants::NAMEID_EMAIL.to_string()),
            allow_create: true,
            ..Default::default()
        };
        let req = create_authn_request(&options).unwrap();
        let policy = req.name_id_policy.unwrap();
        assert_eq!(policy.format, Some(constants::NAMEID_EMAIL.to_string()));
        assert!(policy.allow_create);
    }

    #[test]
    fn test_create_authn_request_with_authn_context() {
        let options = AuthnRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            authn_context_class_refs: vec![constants::AUTHN_CONTEXT_PASSWORD.to_string()],
            ..Default::default()
        };
        let req = create_authn_request(&options).unwrap();
        let ctx = req.requested_authn_context.unwrap();
        assert_eq!(ctx.authn_context_class_refs.len(), 1);
        assert_eq!(ctx.comparison, AuthnContextComparison::Exact);
    }

    #[test]
    fn test_create_authn_request_missing_issuer() {
        let options = AuthnRequestOptions::default(); // empty sp_entity_id
        let result = create_authn_request(&options);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_authn_request_with_scoping() {
        let options = AuthnRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            proxy_count: Some(2),
            requester_ids: vec!["https://proxy.example.com".to_string()],
            ..Default::default()
        };
        let req = create_authn_request(&options).unwrap();
        let scoping = req.scoping.unwrap();
        assert_eq!(scoping.proxy_count, Some(2));
        assert_eq!(scoping.requester_ids.len(), 1);
    }

    #[test]
    fn test_find_sso_endpoint_preferred() {
        let idp = IdpSsoDescriptor {
            sso_base: crate::metadata::types::role_descriptor::SsoDescriptorBase {
                base: crate::metadata::types::role_descriptor::RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
                ]),
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            want_authn_requests_signed: None,
            single_sign_on_services: vec![
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "https://idp.example.com/sso/post",
                ),
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "https://idp.example.com/sso/redirect",
                ),
            ],
            name_id_mapping_services: vec![],
            assertion_id_request_services: vec![],
            attribute_profiles: vec![],
            attributes: vec![],
        };

        let ep =
            find_sso_endpoint(&idp, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").unwrap();
        assert!(ep.location.contains("redirect"));

        // Falls back to first
        let ep = find_sso_endpoint(&idp, "urn:oasis:names:tc:SAML:2.0:bindings:SOAP").unwrap();
        assert!(ep.location.contains("post"));
    }

    #[test]
    fn test_find_default_acs_endpoint() {
        let endpoints = vec![
            IndexedEndpoint::new(
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "https://sp.example.com/acs/post",
                ),
                1,
            ),
            IndexedEndpoint::new_default(
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "https://sp.example.com/acs/default",
                ),
                0,
            ),
        ];
        let ep = find_default_acs_endpoint(&endpoints).unwrap();
        assert!(ep.endpoint.location.contains("default"));
    }

    #[test]
    fn test_process_response_failure_status() {
        let response = Response {
            base: ResponseBase {
                id: "_resp1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: None,
                consent: None,
                issuer: None,
                has_signature: false,
                in_response_to: None,
                status: Status {
                    status_code: StatusCode {
                        value: "urn:oasis:names:tc:SAML:2.0:status:Responder".to_string(),
                        sub_status: None,
                    },
                    status_message: Some("Authentication failed".to_string()),
                    status_detail: None,
                },
            },
            assertions: vec![],
            encrypted_assertions: vec![],
        };

        let config = SecurityConfig::permissive();
        let result = process_response(
            &response,
            &config,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            "https://idp.example.com",
            Utc::now(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ProfileError::ResponseFailure(msg) => {
                assert!(msg.contains("Authentication failed"));
            }
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_process_response_no_assertions() {
        let response = Response {
            base: ResponseBase {
                id: "_resp1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: None,
                consent: None,
                issuer: None,
                has_signature: false,
                in_response_to: None,
                status: Status::success(),
            },
            assertions: vec![],
            encrypted_assertions: vec![],
        };

        let config = SecurityConfig::permissive();
        let result = process_response(
            &response,
            &config,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            "https://idp.example.com",
            Utc::now(),
        );
        assert!(matches!(result, Err(ProfileError::NoAssertions)));
    }

    #[test]
    fn test_process_response_rejects_unverified_assertion_signature_markup() {
        let now = Utc::now();
        let mut assertion = make_test_assertion(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            now,
        );
        assertion.has_signature = true;
        let assertion_id = assertion.id.clone();
        let response = make_test_response(assertion, None);
        let config = SecurityConfig::default();

        let result = process_response(
            &response,
            &config,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            "https://idp.example.com",
            now,
        );
        assert!(matches!(result, Err(ProfileError::AssertionValidation(_))));

        let verified_ids = [assertion_id.as_str()];
        let result = process_response_with_verified_signatures(
            &response,
            &config,
            None,
            "https://sp.example.com",
            "https://sp.example.com/acs",
            None,
            "https://idp.example.com",
            &verified_ids,
            now,
        );
        assert!(result.is_ok());
    }
}
