// SAML 2.0 Assertion Query/Request Profile
//
// SAML Profiles Section 6
//
// Query types (all over SOAP):
// - AuthnQuery: Query for authentication statements
// - AttributeQuery: Query for attribute values
// - AuthzDecisionQuery: Query for authorization decisions
// - AssertionIDRequest: Retrieve assertions by ID

use chrono::Utc;

use crate::core::assertion::attribute::Attribute;
use crate::core::assertion::authz::Action;
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::assertion::subject::Subject;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::query::{
    AssertionIdRequest, AttributeQuery, AuthnQuery, AuthzDecisionQuery,
};
use crate::core::protocol::request::RequestedAuthnContext;
use crate::core::protocol::response::Response;

use crate::profiles::error::ProfileError;

/// Create an AuthnQuery to query for authentication statements.
pub fn create_authn_query(
    entity_id: &str,
    subject_name_id: &NameId,
    session_index: Option<&str>,
    requested_authn_context: Option<RequestedAuthnContext>,
    destination: Option<&str>,
) -> AuthnQuery {
    AuthnQuery {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(subject_name_id.clone())),
            subject_confirmations: vec![],
        },
        session_index: session_index.map(|s| s.to_string()),
        requested_authn_context,
    }
}

/// Create an AttributeQuery to query for attribute values.
///
/// If `attributes` is empty, all attributes are requested.
pub fn create_attribute_query(
    entity_id: &str,
    subject_name_id: &NameId,
    attributes: Vec<Attribute>,
    destination: Option<&str>,
) -> AttributeQuery {
    AttributeQuery {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(subject_name_id.clone())),
            subject_confirmations: vec![],
        },
        attributes,
    }
}

/// Create an AuthzDecisionQuery.
pub fn create_authz_decision_query(
    entity_id: &str,
    subject_name_id: &NameId,
    resource: &str,
    actions: Vec<Action>,
    destination: Option<&str>,
) -> AuthzDecisionQuery {
    AuthzDecisionQuery {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(subject_name_id.clone())),
            subject_confirmations: vec![],
        },
        resource: resource.to_string(),
        actions,
        evidence: None,
    }
}

/// Create an AssertionIDRequest to retrieve assertions by ID.
pub fn create_assertion_id_request(
    entity_id: &str,
    assertion_ids: Vec<String>,
    destination: Option<&str>,
) -> AssertionIdRequest {
    AssertionIdRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        assertion_id_refs: assertion_ids,
    }
}

/// Process a query Response (for AuthnQuery, AttributeQuery, etc.).
///
/// Validates the status and returns assertions.
pub fn process_query_response<'a>(
    response: &'a Response,
    expected_request_id: &str,
) -> Result<&'a [crate::core::assertion::types::Assertion], ProfileError> {
    // Verify InResponseTo
    if let Some(irt) = &response.base.in_response_to {
        if irt != expected_request_id {
            return Err(ProfileError::Other(format!(
                "InResponseTo mismatch: expected {expected_request_id}, got {irt}"
            )));
        }
    }

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

    Ok(&response.assertions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::authz::Action;
    use crate::core::constants;

    fn make_name_id() -> NameId {
        NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    #[test]
    fn test_create_authn_query() {
        let query = create_authn_query(
            "https://sp.example.com",
            &make_name_id(),
            Some("_session1"),
            None,
            Some("https://idp.example.com/authn-query"),
        );
        assert!(query.id.starts_with('_'));
        assert_eq!(query.session_index, Some("_session1".to_string()));
    }

    #[test]
    fn test_create_attribute_query() {
        let attrs = vec![Attribute {
            name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
            name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            friendly_name: Some("eduPersonEntitlement".to_string()),
            values: vec![],
        }];
        let query = create_attribute_query("https://sp.example.com", &make_name_id(), attrs, None);
        assert_eq!(query.attributes.len(), 1);
        assert_eq!(query.attributes[0].name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.7");
    }

    #[test]
    fn test_create_authz_decision_query() {
        let actions = vec![Action {
            namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc".to_string(),
            value: "Read".to_string(),
        }];
        let query = create_authz_decision_query(
            "https://sp.example.com",
            &make_name_id(),
            "https://sp.example.com/resource",
            actions,
            None,
        );
        assert_eq!(query.resource, "https://sp.example.com/resource");
        assert_eq!(query.actions.len(), 1);
    }

    #[test]
    fn test_create_assertion_id_request() {
        let req = create_assertion_id_request(
            "https://sp.example.com",
            vec!["_assert1".to_string(), "_assert2".to_string()],
            None,
        );
        assert_eq!(req.assertion_id_refs.len(), 2);
    }

    #[test]
    fn test_process_query_response_success() {
        let response = Response {
            base: crate::core::protocol::response::ResponseBase {
                id: "_resp1".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: None,
                consent: None,
                issuer: None,
                has_signature: false,
                in_response_to: Some("_req123".to_string()),
                status: crate::core::protocol::status::Status::success(),
            },
            assertions: vec![],
            encrypted_assertions: vec![],
        };
        let result = process_query_response(&response, "_req123").unwrap();
        assert!(result.is_empty());
    }
}
