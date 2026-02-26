// SAML 2.0 Name Identifier Mapping Profile
//
// SAML Profiles Section 4.6
//
// Maps a principal's name identifier between SPs.
// Used to determine a common principal across SPs without revealing the
// persistent identifier. Privacy is maintained via encryption.

use chrono::Utc;

use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId, NameIdPolicy};
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::name_id_mapping::{NameIdMappingRequest, NameIdMappingResponse};
use crate::core::protocol::status::Status;

use crate::profiles::error::ProfileError;

/// Create a NameIDMappingRequest.
///
/// Per Profiles 4.6: The requester provides the NameID of the principal
/// and a NameIDPolicy indicating the desired format for the mapped identifier.
pub fn create_name_id_mapping_request(
    entity_id: &str,
    name_id: &NameId,
    target_format: &str,
    target_sp_name_qualifier: Option<&str>,
    destination: Option<&str>,
) -> NameIdMappingRequest {
    NameIdMappingRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(name_id.clone()),
        name_id_policy: NameIdPolicy {
            format: Some(target_format.to_string()),
            sp_name_qualifier: target_sp_name_qualifier.map(|s| s.to_string()),
            allow_create: true,
        },
    }
}

/// Process a NameIDMappingResponse.
///
/// Returns the mapped NameID on success.
pub fn process_name_id_mapping_response(
    response: &NameIdMappingResponse,
    expected_request_id: &str,
) -> Result<NameIdOrEncryptedId, ProfileError> {
    // Verify InResponseTo
    if let Some(irt) = &response.in_response_to {
        if irt != expected_request_id {
            return Err(ProfileError::NameIdMappingFailed(format!(
                "InResponseTo mismatch: expected {expected_request_id}, got {irt}"
            )));
        }
    }

    if !response.status.is_success() {
        return Err(ProfileError::NameIdMappingFailed(
            response
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.status.status_code.value.clone()),
        ));
    }

    response
        .name_id
        .clone()
        .ok_or(ProfileError::MappingResponseMissingNameId)
}

/// Create a NameIDMappingResponse (IdP side).
pub fn create_name_id_mapping_response(
    entity_id: &str,
    in_response_to: &str,
    mapped_name_id: NameIdOrEncryptedId,
) -> NameIdMappingResponse {
    NameIdMappingResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status: Status::success(),
        name_id: Some(mapped_name_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_create_name_id_mapping_request() {
        let req = create_name_id_mapping_request(
            "https://sp1.example.com",
            &make_name_id(),
            constants::NAMEID_PERSISTENT,
            Some("https://sp2.example.com"),
            Some("https://idp.example.com/mapping"),
        );
        assert!(req.id.starts_with('_'));
        assert_eq!(
            req.name_id_policy.format,
            Some(constants::NAMEID_PERSISTENT.to_string())
        );
        assert_eq!(
            req.name_id_policy.sp_name_qualifier,
            Some("https://sp2.example.com".to_string())
        );
    }

    #[test]
    fn test_process_name_id_mapping_response_success() {
        let mapped = NameIdOrEncryptedId::NameId(NameId {
            value: "mapped-persistent-id".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: Some("https://sp2.example.com".to_string()),
            sp_provided_id: None,
        });
        let response =
            create_name_id_mapping_response("https://idp.example.com", "_req123", mapped);
        let result = process_name_id_mapping_response(&response, "_req123").unwrap();
        match result {
            NameIdOrEncryptedId::NameId(nid) => {
                assert_eq!(nid.value, "mapped-persistent-id");
            }
            _ => panic!("expected NameId"),
        }
    }

    #[test]
    fn test_process_name_id_mapping_response_missing() {
        let response = NameIdMappingResponse {
            id: "_resp1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            in_response_to: Some("_req123".to_string()),
            status: Status::success(),
            name_id: None,
        };
        let result = process_name_id_mapping_response(&response, "_req123");
        assert!(matches!(
            result,
            Err(ProfileError::MappingResponseMissingNameId)
        ));
    }
}
