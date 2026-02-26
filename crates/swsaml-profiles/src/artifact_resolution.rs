// SAML 2.0 Artifact Resolution Profile
//
// SAML Profiles Section 5 (Artifact Resolution)
//
// ArtifactResolve/ArtifactResponse exchange over SOAP.
// Mutually authenticated and integrity-protected (typically over TLS).

use chrono::Utc;

use swsaml_core::assertion::issuer::Issuer;
use swsaml_core::identifiers::{SamlId, SamlVersion};
use swsaml_core::protocol::artifact::{ArtifactResolve, ArtifactResponse};
use swsaml_core::protocol::status::Status;

use crate::error::ProfileError;

/// Create an ArtifactResolve request.
///
/// Per Profiles 5.1: The artifact must be the base64-encoded artifact value.
/// The request is typically sent over a SOAP binding that is mutually authenticated.
pub fn create_artifact_resolve(
    entity_id: &str,
    artifact: &str,
    destination: Option<&str>,
) -> ArtifactResolve {
    ArtifactResolve {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        artifact: artifact.to_string(),
    }
}

/// Process an ArtifactResponse.
///
/// Validates the response status and returns the contained SAML message bytes.
pub fn process_artifact_response(
    response: &ArtifactResponse,
    expected_request_id: &str,
) -> Result<Option<Vec<u8>>, ProfileError> {
    // Verify InResponseTo
    if let Some(irt) = &response.in_response_to {
        if irt != expected_request_id {
            return Err(ProfileError::ArtifactResolutionFailed(format!(
                "InResponseTo mismatch: expected {}, got {}",
                expected_request_id, irt
            )));
        }
    }

    // Check status
    if !response.status.is_success() {
        return Err(ProfileError::ArtifactResponseFailure(
            response
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.status.status_code.value.clone()),
        ));
    }

    Ok(response.message.clone())
}

/// Create an ArtifactResponse (IdP or SP side).
pub fn create_artifact_response(
    entity_id: &str,
    in_response_to: &str,
    message: Option<Vec<u8>>,
) -> ArtifactResponse {
    ArtifactResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status: Status::success(),
        message,
    }
}

/// Create an error ArtifactResponse.
pub fn create_artifact_response_error(
    entity_id: &str,
    in_response_to: &str,
    error_message: &str,
) -> ArtifactResponse {
    ArtifactResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status: Status {
            status_code: swsaml_core::protocol::status::StatusCode {
                value: "urn:oasis:names:tc:SAML:2.0:status:Requester".to_string(),
                sub_status: None,
            },
            status_message: Some(error_message.to_string()),
            status_detail: None,
        },
        message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_artifact_resolve() {
        let resolve = create_artifact_resolve(
            "https://sp.example.com",
            "AAQAADWNEw5VT7pvfQxF2Cg==",
            Some("https://idp.example.com/artifact"),
        );
        assert!(resolve.id.starts_with('_'));
        assert_eq!(resolve.artifact, "AAQAADWNEw5VT7pvfQxF2Cg==");
        assert_eq!(
            resolve.issuer.as_ref().unwrap().value,
            "https://sp.example.com"
        );
    }

    #[test]
    fn test_process_artifact_response_success() {
        let response = create_artifact_response(
            "https://idp.example.com",
            "_req123",
            Some(b"<samlp:Response>...</samlp:Response>".to_vec()),
        );
        let result = process_artifact_response(&response, "_req123").unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_process_artifact_response_irt_mismatch() {
        let response = create_artifact_response("https://idp.example.com", "_wrong", None);
        let result = process_artifact_response(&response, "_req123");
        assert!(result.is_err());
    }

    #[test]
    fn test_process_artifact_response_error() {
        let response = create_artifact_response_error(
            "https://idp.example.com",
            "_req123",
            "Unknown artifact",
        );
        let result = process_artifact_response(&response, "_req123");
        assert!(matches!(
            result,
            Err(ProfileError::ArtifactResponseFailure(_))
        ));
    }
}
