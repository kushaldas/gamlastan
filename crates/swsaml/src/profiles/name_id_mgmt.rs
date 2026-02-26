// SAML 2.0 Name Identifier Management Profile
//
// SAML Profiles Section 4.5
//
// Allows SPs and IdPs to manage name identifiers:
// - Change identifier value (not format, per E12)
// - Terminate use of an identifier

use chrono::Utc;

use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::name_id_mgmt::{
    ManageNameIdRequest, ManageNameIdResponse, NewIdOrTerminate,
};
use crate::core::protocol::status::Status;

use crate::profiles::error::ProfileError;

/// Create a ManageNameIDRequest to change a name identifier value.
///
/// Per E12: Only the identifier value can be changed, not the format.
pub fn create_change_name_id_request(
    entity_id: &str,
    name_id: &NameId,
    new_value: &str,
    destination: Option<&str>,
) -> ManageNameIdRequest {
    ManageNameIdRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(name_id.clone()),
        new_id_or_terminate: NewIdOrTerminate::NewId(new_value.to_string()),
    }
}

/// Create a ManageNameIDRequest to terminate use of an identifier.
pub fn create_terminate_name_id_request(
    entity_id: &str,
    name_id: &NameId,
    destination: Option<&str>,
) -> ManageNameIdRequest {
    ManageNameIdRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(name_id.clone()),
        new_id_or_terminate: NewIdOrTerminate::Terminate,
    }
}

/// Create a ManageNameIDResponse.
pub fn create_manage_name_id_response(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
    status: Status,
) -> ManageNameIdResponse {
    ManageNameIdResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status,
    }
}

/// Process a ManageNameIDResponse.
pub fn process_manage_name_id_response(
    response: &ManageNameIdResponse,
    expected_request_id: &str,
) -> Result<(), ProfileError> {
    // Verify InResponseTo
    if let Some(irt) = &response.in_response_to {
        if irt != expected_request_id {
            return Err(ProfileError::NameIdManagementFailed(format!(
                "InResponseTo mismatch: expected {expected_request_id}, got {irt}"
            )));
        }
    }

    if !response.status.is_success() {
        return Err(ProfileError::NameIdManagementFailed(
            response
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.status.status_code.value.clone()),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_name_id() -> NameId {
        NameId {
            value: "old-id-value".to_string(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    #[test]
    fn test_create_change_name_id_request() {
        let req = create_change_name_id_request(
            "https://sp.example.com",
            &make_name_id(),
            "new-id-value",
            Some("https://idp.example.com/manage"),
        );
        assert!(req.id.starts_with('_'));
        match &req.new_id_or_terminate {
            NewIdOrTerminate::NewId(v) => assert_eq!(v, "new-id-value"),
            _ => panic!("expected NewId"),
        }
    }

    #[test]
    fn test_create_terminate_name_id_request() {
        let req = create_terminate_name_id_request("https://sp.example.com", &make_name_id(), None);
        assert!(matches!(
            req.new_id_or_terminate,
            NewIdOrTerminate::Terminate
        ));
    }

    #[test]
    fn test_process_manage_name_id_response_success() {
        let resp = create_manage_name_id_response(
            "https://idp.example.com",
            "_req123",
            None,
            Status::success(),
        );
        assert!(process_manage_name_id_response(&resp, "_req123").is_ok());
    }

    #[test]
    fn test_process_manage_name_id_response_failure() {
        let resp = create_manage_name_id_response(
            "https://idp.example.com",
            "_req123",
            None,
            Status {
                status_code: crate::core::protocol::status::StatusCode {
                    value: "urn:oasis:names:tc:SAML:2.0:status:Requester".to_string(),
                    sub_status: None,
                },
                status_message: Some("Not authorized".to_string()),
                status_detail: None,
            },
        );
        let result = process_manage_name_id_response(&resp, "_req123");
        assert!(result.is_err());
    }
}
