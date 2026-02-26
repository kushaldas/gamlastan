// SAML 2.0 Artifact Resolution types
//
// ArtifactResolve: request to resolve an artifact to the original SAML message.
// ArtifactResponse: response containing the resolved SAML message.

use chrono::{DateTime, Utc};

use crate::assertion::issuer::{Issuer, IssuerRef};
use crate::identifiers::SamlVersion;

use super::status::{Status, StatusRef};

/// Borrowed ArtifactResolve request.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactResolveRef<'a> {
    /// Unique identifier for the request.
    pub id: &'a str,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the request was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<&'a str>,
    /// Consent URI.
    pub consent: Option<&'a str>,
    /// The request issuer.
    pub issuer: Option<IssuerRef<'a>>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
    /// The SAML artifact string (base64-encoded, 44 bytes decoded for type 0x0004).
    pub artifact: &'a str,
}

impl<'a> ArtifactResolveRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> ArtifactResolve {
        ArtifactResolve {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            artifact: self.artifact.to_string(),
        }
    }
}

/// Owned ArtifactResolve request.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactResolve {
    /// Unique identifier for the request.
    pub id: String,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the request was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<String>,
    /// Consent URI.
    pub consent: Option<String>,
    /// The request issuer.
    pub issuer: Option<Issuer>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
    /// The SAML artifact string (base64-encoded).
    pub artifact: String,
}

/// Borrowed ArtifactResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactResponseRef<'a> {
    /// Unique identifier for the response.
    pub id: &'a str,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the response was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<&'a str>,
    /// Consent URI.
    pub consent: Option<&'a str>,
    /// The response issuer.
    pub issuer: Option<IssuerRef<'a>>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
    /// The ID of the request this is in response to.
    pub in_response_to: Option<&'a str>,
    /// The response status.
    pub status: StatusRef<'a>,
    /// The resolved SAML message (opaque raw bytes).
    /// This is the original SAML protocol message that was referenced by the artifact.
    pub message: Option<&'a [u8]>,
}

impl<'a> ArtifactResponseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> ArtifactResponse {
        ArtifactResponse {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            in_response_to: self.in_response_to.map(str::to_string),
            status: self.status.to_owned(),
            message: self.message.map(|m| m.to_vec()),
        }
    }
}

/// Owned ArtifactResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactResponse {
    /// Unique identifier for the response.
    pub id: String,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the response was issued.
    pub issue_instant: DateTime<Utc>,
    /// The intended destination URI.
    pub destination: Option<String>,
    /// Consent URI.
    pub consent: Option<String>,
    /// The response issuer.
    pub issuer: Option<Issuer>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
    /// The ID of the request this is in response to.
    pub in_response_to: Option<String>,
    /// The response status.
    pub status: Status,
    /// The resolved SAML message (opaque raw bytes).
    pub message: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::protocol::status::StatusCodeRef;

    #[test]
    fn test_artifact_resolve_ref_to_owned() {
        let now = chrono::Utc::now();
        let resolve = ArtifactResolveRef {
            id: "_artifact_req_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/artifact"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            artifact: "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzddOYoLXh0LA5NA==",
        };
        let owned = resolve.to_owned();
        assert_eq!(owned.id, "_artifact_req_1");
        assert_eq!(
            owned.artifact,
            "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzddOYoLXh0LA5NA=="
        );
        assert_eq!(
            owned.destination.as_deref(),
            Some("https://idp.example.com/artifact")
        );
    }

    #[test]
    fn test_artifact_response_ref_to_owned() {
        let now = chrono::Utc::now();
        let message_bytes = b"<samlp:Response>...</samlp:Response>";
        let resp = ArtifactResponseRef {
            id: "_artifact_resp_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://idp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            in_response_to: Some("_artifact_req_1"),
            status: StatusRef {
                status_code: StatusCodeRef {
                    value: STATUS_SUCCESS,
                    sub_status: None,
                },
                status_message: None,
                status_detail: None,
            },
            message: Some(message_bytes),
        };
        let owned = resp.to_owned();
        assert_eq!(owned.id, "_artifact_resp_1");
        assert!(owned.status.is_success());
        assert_eq!(owned.in_response_to.as_deref(), Some("_artifact_req_1"));
        assert!(owned.message.is_some());
    }

    #[test]
    fn test_artifact_response_no_message() {
        let now = chrono::Utc::now();
        let resp = ArtifactResponseRef {
            id: "_resp_no_msg",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            in_response_to: None,
            status: StatusRef {
                status_code: StatusCodeRef {
                    value: STATUS_REQUESTER,
                    sub_status: None,
                },
                status_message: Some("Artifact not found"),
                status_detail: None,
            },
            message: None,
        };
        let owned = resp.to_owned();
        assert!(!owned.status.is_success());
        assert!(owned.message.is_none());
        assert_eq!(
            owned.status.status_message.as_deref(),
            Some("Artifact not found")
        );
    }
}
