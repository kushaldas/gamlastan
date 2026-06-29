// SAML 2.0 Artifact Resolution Profile
//
// SAML Profiles Section 5 (Artifact Resolution)
//
// ArtifactResolve/ArtifactResponse exchange over SOAP.
// Mutually authenticated and integrity-protected (typically over TLS).

use chrono::Utc;

use crate::core::assertion::issuer::Issuer;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::artifact::{ArtifactResolve, ArtifactResponse};
use crate::core::protocol::status::Status;

use crate::profiles::error::ProfileError;

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

/// Process a solicited `ArtifactResponse` and return the embedded SAML message
/// bytes on success.
///
/// This is a *solicited* exchange: `expected_request_id` is the `ID` of the
/// [`ArtifactResolve`] the caller sent. The response is accepted only when:
///
/// 1. its `InResponseTo` is **present and equal** to `expected_request_id` — a
///    missing `InResponseTo` is rejected, since absence would let a replayed or
///    substituted response be accepted (CWE-294); and
/// 2. its `Status` is success.
///
/// On success returns `Ok(Some(bytes))` with the resolved SAML message (or
/// `Ok(None)` if the peer returned success with no message). Returns
/// [`ProfileError::ArtifactResolutionFailed`] for a missing/mismatched
/// `InResponseTo`, and [`ProfileError::ArtifactResponseFailure`] for a
/// non-success status.
///
/// Note that this helper only checks correlation and status; the SOAP transport
/// is expected to be mutually authenticated and integrity-protected (typically
/// over TLS), and the caller remains responsible for verifying any signature on
/// the resolved message.
///
/// # Examples
///
/// ```ignore
/// let request = create_artifact_resolve("https://sp.example.com", artifact, None);
/// // ... send `request` over SOAP, receive `response` ...
/// let message = process_artifact_response(&response, &request.id)?;
/// ```
pub fn process_artifact_response(
    response: &ArtifactResponse,
    expected_request_id: &str,
) -> Result<Option<Vec<u8>>, ProfileError> {
    // Verify InResponseTo. This is a *solicited* exchange (the caller passes the
    // ID of the ArtifactResolve it sent), so a missing InResponseTo is not
    // acceptable: previously `if let Some(irt)` skipped the check entirely when
    // absent, letting a replayed or substituted response be accepted. Require it
    // to be present and equal to the outstanding request ID (CWE-294).
    match &response.in_response_to {
        Some(irt) if irt == expected_request_id => {}
        Some(irt) => {
            return Err(ProfileError::ArtifactResolutionFailed(format!(
                "InResponseTo mismatch: expected {expected_request_id}, got {irt}"
            )));
        }
        None => {
            return Err(ProfileError::ArtifactResolutionFailed(format!(
                "ArtifactResponse is missing InResponseTo (expected {expected_request_id})"
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
            status_code: crate::core::protocol::status::StatusCode {
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
    fn test_process_artifact_response_missing_irt_rejected() {
        // Finding #8 regression: a successful solicited response with no
        // InResponseTo must be rejected, not accepted.
        let mut response = create_artifact_response(
            "https://idp.example.com",
            "_req123",
            Some(b"<samlp:Response>...</samlp:Response>".to_vec()),
        );
        response.in_response_to = None;
        let result = process_artifact_response(&response, "_req123");
        assert!(matches!(
            result,
            Err(ProfileError::ArtifactResolutionFailed(_))
        ));
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
