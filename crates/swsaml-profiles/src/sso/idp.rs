// SAML 2.0 Web Browser SSO Profile - IdP side
//
// SAML Profiles Section 4.1
//
// IdP-side operations:
// - process_authn_request: Validate incoming AuthnRequest from SP
// - create_response: Build Response with assertions for SP
// - create_unsolicited_response: Build unsolicited (IdP-initiated) Response

use chrono::{DateTime, TimeDelta, Utc};

use swsaml_core::assertion::attribute::{Attribute, AttributeStatement};
use swsaml_core::assertion::authn::{AuthnContext, AuthnStatement, SubjectLocality};
use swsaml_core::assertion::conditions::{AudienceRestriction, Conditions};
use swsaml_core::assertion::issuer::Issuer;
use swsaml_core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use swsaml_core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use swsaml_core::assertion::types::Assertion;
use swsaml_core::constants;
use swsaml_core::identifiers::{SamlId, SamlVersion};
use swsaml_core::protocol::request::AuthnRequest;
use swsaml_core::protocol::response::{Response, ResponseBase};
use swsaml_core::protocol::status::Status;
use swsaml_metadata::types::sp::SpSsoDescriptor;

use crate::error::ProfileError;
use crate::sso::web_browser::ResponseOptions;

/// Result of processing an AuthnRequest on the IdP side.
#[derive(Debug, Clone)]
pub struct ProcessedAuthnRequest {
    /// The request ID (for InResponseTo).
    pub request_id: String,

    /// SP entity ID (from Issuer).
    pub sp_entity_id: String,

    /// The ACS URL where the response should be sent.
    pub acs_url: String,

    /// The ACS binding to use for the response.
    pub acs_binding: String,

    /// Whether to force re-authentication.
    pub force_authn: bool,

    /// Whether the IdP should not visually interact with the user.
    pub is_passive: bool,

    /// Requested NameID format (from NameIDPolicy).
    pub requested_name_id_format: Option<String>,

    /// Whether creation of new identifiers is allowed (E14).
    pub allow_create: bool,

    /// Requested authentication context class refs.
    pub requested_authn_context_class_refs: Vec<String>,

    /// Authentication context comparison type.
    pub authn_context_comparison: Option<swsaml_core::protocol::request::AuthnContextComparison>,

    /// AttributeConsumingServiceIndex.
    pub attribute_consuming_service_index: Option<u16>,
}

/// Process an incoming AuthnRequest on the IdP side.
///
/// Validates the request structure and extracts parameters needed for
/// authentication and response generation.
///
/// Per Profiles 4.1.4.1:
/// - Verify ACS URL belongs to the SP (MITM prevention)
/// - Respect ForceAuthn and IsPassive
/// - Respect RequestedAuthnContext
pub fn process_authn_request(
    request: &AuthnRequest,
    sp_metadata: Option<&SpSsoDescriptor>,
) -> Result<ProcessedAuthnRequest, ProfileError> {
    // Extract SP entity ID from Issuer
    let sp_entity_id = request
        .base
        .issuer
        .as_ref()
        .ok_or(ProfileError::MissingIssuer)?
        .value
        .clone();

    // Determine ACS URL and binding
    let (acs_url, acs_binding) = resolve_acs_endpoint(request, sp_metadata)?;

    // Extract ForceAuthn and IsPassive
    let force_authn = request.force_authn.unwrap_or(false);
    let is_passive = request.is_passive.unwrap_or(false);

    // Extract NameIDPolicy
    let (requested_name_id_format, allow_create) = match &request.name_id_policy {
        Some(policy) => (policy.format.clone(), policy.allow_create),
        None => (None, false),
    };

    // Extract RequestedAuthnContext
    let (requested_authn_context_class_refs, authn_context_comparison) =
        match &request.requested_authn_context {
            Some(ctx) => (ctx.authn_context_class_refs.clone(), Some(ctx.comparison)),
            None => (vec![], None),
        };

    Ok(ProcessedAuthnRequest {
        request_id: request.base.id.clone(),
        sp_entity_id,
        acs_url,
        acs_binding,
        force_authn,
        is_passive,
        requested_name_id_format,
        allow_create,
        requested_authn_context_class_refs,
        authn_context_comparison,
        attribute_consuming_service_index: request.attribute_consuming_service_index,
    })
}

/// Resolve the ACS endpoint URL and binding from the AuthnRequest and SP metadata.
///
/// Priority:
/// 1. AssertionConsumerServiceURL + ProtocolBinding from request (must be verified against metadata)
/// 2. AssertionConsumerServiceIndex from request
/// 3. Default ACS from SP metadata
fn resolve_acs_endpoint(
    request: &AuthnRequest,
    sp_metadata: Option<&SpSsoDescriptor>,
) -> Result<(String, String), ProfileError> {
    // Option 1: URL directly specified in request
    if let Some(url) = &request.assertion_consumer_service_url {
        let binding = request
            .protocol_binding
            .as_deref()
            .unwrap_or("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        // If we have SP metadata, verify the URL is legitimate
        if let Some(sp) = sp_metadata {
            let found = sp
                .assertion_consumer_services
                .iter()
                .any(|ep| ep.endpoint.location == *url);
            if !found {
                return Err(ProfileError::AcsUrlMismatch);
            }
        }

        return Ok((url.clone(), binding.to_string()));
    }

    // Option 2: Index specified in request
    if let Some(index) = request.assertion_consumer_service_index {
        if let Some(sp) = sp_metadata {
            if let Some(ep) = sp
                .assertion_consumer_services
                .iter()
                .find(|e| e.index == index)
            {
                return Ok((ep.endpoint.location.clone(), ep.endpoint.binding.clone()));
            }
        }
        return Err(ProfileError::NoAcsEndpoint(format!(
            "index {} not found in SP metadata",
            index
        )));
    }

    // Option 3: Default from SP metadata
    if let Some(sp) = sp_metadata {
        let default = crate::sso::sp::find_default_acs_endpoint(&sp.assertion_consumer_services);
        if let Some(ep) = default {
            return Ok((ep.endpoint.location.clone(), ep.endpoint.binding.clone()));
        }
    }

    Err(ProfileError::NoAcsEndpoint(
        "no ACS endpoint could be resolved".to_string(),
    ))
}

/// Create a SAML Response for SP-initiated SSO.
///
/// Per Profiles 4.1.4.2:
/// - At least one Assertion with AuthnStatement
/// - Bearer SubjectConfirmation with Recipient (= ACS URL) + NotOnOrAfter
/// - InResponseTo = request ID
/// - AudienceRestriction with SP entity ID
/// - SessionIndex for SLO support
pub fn create_response(
    options: &ResponseOptions,
    principal_name_id: &NameId,
    now: DateTime<Utc>,
) -> Response {
    let assertion_lifetime = TimeDelta::seconds(options.assertion_lifetime_seconds as i64);
    let not_on_or_after = now + assertion_lifetime;

    // Build SubjectConfirmation (bearer)
    let subject_confirmation = SubjectConfirmation {
        method: constants::CM_BEARER.to_string(),
        name_id: None,
        subject_confirmation_data: Some(SubjectConfirmationData {
            not_before: None,
            not_on_or_after: Some(not_on_or_after),
            recipient: Some(options.acs_url.clone()),
            in_response_to: options.in_response_to.clone(),
            address: options.client_address.clone(),
        }),
    };

    // Build Subject
    let subject = Subject {
        name_id: Some(NameIdOrEncryptedId::NameId(principal_name_id.clone())),
        subject_confirmations: vec![subject_confirmation],
    };

    // Build Conditions with AudienceRestriction
    let conditions = Conditions {
        not_before: Some(now),
        not_on_or_after: Some(not_on_or_after),
        audience_restrictions: vec![AudienceRestriction {
            audiences: vec![options.sp_entity_id.clone()],
        }],
        one_time_use: false,
        proxy_restriction: None,
    };

    // Build AuthnStatement
    let authn_statement = AuthnStatement {
        authn_instant: now,
        session_index: options.session_index.clone(),
        session_not_on_or_after: options.session_not_on_or_after,
        subject_locality: options.client_address.as_ref().map(|addr| SubjectLocality {
            address: Some(addr.clone()),
            dns_name: None,
        }),
        authn_context: AuthnContext {
            authn_context_class_ref: options.authn_context_class_ref.clone(),
            authn_context_decl_ref: None,
            authenticating_authorities: vec![],
        },
    };

    // Build AttributeStatement (if attributes provided)
    let attribute_statements = if options.attributes.is_empty() {
        vec![]
    } else {
        vec![AttributeStatement {
            attributes: options.attributes.clone(),
        }]
    };

    // Build Assertion
    let assertion = Assertion {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: now,
        issuer: Issuer::entity(&options.idp_entity_id),
        has_signature: false,
        subject: Some(subject),
        conditions: Some(conditions),
        authn_statements: vec![authn_statement],
        authz_decision_statements: vec![],
        attribute_statements,
    };

    // Build Response
    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some(options.acs_url.clone()),
            consent: None,
            issuer: Some(Issuer::entity(&options.idp_entity_id)),
            has_signature: false,
            in_response_to: options.in_response_to.clone(),
            status: Status::success(),
        },
        assertions: vec![assertion],
        encrypted_assertions: vec![],
    }
}

/// Create an unsolicited (IdP-initiated) SAML Response.
///
/// Per Profiles 4.1.5:
/// - No InResponseTo
/// - Use default ACS endpoint from metadata
#[allow(clippy::too_many_arguments)]
pub fn create_unsolicited_response(
    idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    principal_name_id: &NameId,
    attributes: &[Attribute],
    authn_context_class_ref: Option<&str>,
    assertion_lifetime_seconds: u64,
    session_index: Option<&str>,
    session_not_on_or_after: Option<DateTime<Utc>>,
    client_address: Option<&str>,
    now: DateTime<Utc>,
) -> Response {
    let options = ResponseOptions {
        idp_entity_id: idp_entity_id.to_string(),
        in_response_to: None, // unsolicited: no InResponseTo
        sp_entity_id: sp_entity_id.to_string(),
        acs_url: acs_url.to_string(),
        assertion_lifetime_seconds,
        session_index: session_index.map(|s| s.to_string()),
        session_not_on_or_after,
        authn_context_class_ref: authn_context_class_ref.map(|s| s.to_string()),
        client_address: client_address.map(|s| s.to_string()),
        attributes: attributes.to_vec(),
    };

    create_response(&options, principal_name_id, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swsaml_core::assertion::name_id::NameIdPolicy;
    use swsaml_core::protocol::request::{
        AuthnContextComparison, RequestBase, RequestedAuthnContext,
    };
    use swsaml_metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use swsaml_metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    fn make_sp_metadata() -> SpSsoDescriptor {
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
            assertion_consumer_services: vec![
                IndexedEndpoint::new_default(
                    Endpoint::new(
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                        "https://sp.example.com/acs/post",
                    ),
                    0,
                ),
                IndexedEndpoint::new(
                    Endpoint::new(
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                        "https://sp.example.com/acs/redirect",
                    ),
                    1,
                ),
            ],
            attribute_consuming_services: vec![],
        }
    }

    fn make_authn_request() -> AuthnRequest {
        AuthnRequest {
            base: RequestBase {
                id: "_req123".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.com/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity("https://sp.example.com")),
                has_signature: false,
            },
            subject: None,
            name_id_policy: Some(NameIdPolicy {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                sp_name_qualifier: None,
                allow_create: true,
            }),
            conditions: None,
            requested_authn_context: Some(RequestedAuthnContext {
                authn_context_class_refs: vec![constants::AUTHN_CONTEXT_PASSWORD.to_string()],
                authn_context_decl_refs: vec![],
                comparison: AuthnContextComparison::Exact,
            }),
            scoping: None,
            force_authn: Some(true),
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs/post".to_string()),
            protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
            attribute_consuming_service_index: None,
            provider_name: Some("Test SP".to_string()),
        }
    }

    #[test]
    fn test_process_authn_request() {
        let request = make_authn_request();
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();

        assert_eq!(result.request_id, "_req123");
        assert_eq!(result.sp_entity_id, "https://sp.example.com");
        assert_eq!(result.acs_url, "https://sp.example.com/acs/post");
        assert!(result.force_authn);
        assert!(!result.is_passive);
        assert_eq!(
            result.requested_name_id_format,
            Some(constants::NAMEID_EMAIL.to_string())
        );
        assert!(result.allow_create);
        assert_eq!(result.requested_authn_context_class_refs.len(), 1);
    }

    #[test]
    fn test_process_authn_request_acs_url_mismatch() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = Some("https://evil.example.com/acs".to_string());
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta));
        assert!(matches!(result, Err(ProfileError::AcsUrlMismatch)));
    }

    #[test]
    fn test_process_authn_request_by_index() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = None;
        request.protocol_binding = None;
        request.assertion_consumer_service_index = Some(1);
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();
        assert_eq!(result.acs_url, "https://sp.example.com/acs/redirect");
    }

    #[test]
    fn test_process_authn_request_default_acs() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = None;
        request.protocol_binding = None;
        request.assertion_consumer_service_index = None;
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();
        assert_eq!(result.acs_url, "https://sp.example.com/acs/post");
    }

    #[test]
    fn test_process_authn_request_missing_issuer() {
        let mut request = make_authn_request();
        request.base.issuer = None;
        let result = process_authn_request(&request, None);
        assert!(matches!(result, Err(ProfileError::MissingIssuer)));
    }

    #[test]
    fn test_create_response() {
        let now = Utc::now();
        let options = ResponseOptions {
            idp_entity_id: "https://idp.example.com".to_string(),
            in_response_to: Some("_req123".to_string()),
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            assertion_lifetime_seconds: 300,
            session_index: Some("_sess1".to_string()),
            session_not_on_or_after: Some(now + TimeDelta::hours(8)),
            authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
            client_address: Some("192.168.1.100".to_string()),
            attributes: vec![Attribute {
                name: "email".to_string(),
                name_format: None,
                friendly_name: None,
                values: vec![],
            }],
        };
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        let response = create_response(&options, &name_id, now);

        // Check Response
        assert!(response.base.status.is_success());
        assert_eq!(response.base.in_response_to, Some("_req123".to_string()));
        assert_eq!(
            response.base.destination,
            Some("https://sp.example.com/acs".to_string())
        );
        assert_eq!(
            response.base.issuer.as_ref().unwrap().value,
            "https://idp.example.com"
        );

        // Check Assertion
        assert_eq!(response.assertions.len(), 1);
        let assertion = &response.assertions[0];
        assert_eq!(assertion.issuer.value, "https://idp.example.com");

        // Check Subject with bearer confirmation
        let subject = assertion.subject.as_ref().unwrap();
        assert_eq!(subject.subject_confirmations.len(), 1);
        let conf = &subject.subject_confirmations[0];
        assert_eq!(conf.method, constants::CM_BEARER);
        let data = conf.subject_confirmation_data.as_ref().unwrap();
        assert_eq!(
            data.recipient,
            Some("https://sp.example.com/acs".to_string())
        );
        assert_eq!(data.in_response_to, Some("_req123".to_string()));

        // Check Conditions
        let conditions = assertion.conditions.as_ref().unwrap();
        assert_eq!(conditions.audience_restrictions.len(), 1);
        assert_eq!(
            conditions.audience_restrictions[0].audiences[0],
            "https://sp.example.com"
        );

        // Check AuthnStatement
        assert_eq!(assertion.authn_statements.len(), 1);
        let stmt = &assertion.authn_statements[0];
        assert_eq!(stmt.session_index, Some("_sess1".to_string()));
        assert_eq!(
            stmt.authn_context.authn_context_class_ref,
            Some(constants::AUTHN_CONTEXT_PASSWORD.to_string())
        );

        // Check AttributeStatement
        assert_eq!(assertion.attribute_statements.len(), 1);
        assert_eq!(assertion.attribute_statements[0].attributes.len(), 1);
    }

    #[test]
    fn test_create_unsolicited_response() {
        let now = Utc::now();
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        let response = create_unsolicited_response(
            "https://idp.example.com",
            "https://sp.example.com",
            "https://sp.example.com/acs",
            &name_id,
            &[],
            Some(constants::AUTHN_CONTEXT_PASSWORD),
            300,
            Some("_sess1"),
            None,
            None,
            now,
        );

        // No InResponseTo for unsolicited
        assert!(response.base.in_response_to.is_none());
        assert!(response.base.status.is_success());

        // Assertion has no InResponseTo in SubjectConfirmationData
        let assertion = &response.assertions[0];
        let conf = &assertion.subject.as_ref().unwrap().subject_confirmations[0];
        assert!(conf
            .subject_confirmation_data
            .as_ref()
            .unwrap()
            .in_response_to
            .is_none());
    }
}
