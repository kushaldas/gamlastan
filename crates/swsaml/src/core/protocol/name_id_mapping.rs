// SAML 2.0 NameID Mapping Request/Response types
//
// NameIDMappingRequest: request to map a NameID from one format/namespace to another.
// NameIDMappingResponse: response containing the mapped NameID.

use chrono::{DateTime, Utc};

use crate::core::assertion::issuer::{Issuer, IssuerRef};
use crate::core::assertion::name_id::{
    NameIdOrEncryptedId, NameIdOrEncryptedIdRef, NameIdPolicy, NameIdPolicyRef,
};
use crate::core::identifiers::SamlVersion;

use super::status::{Status, StatusRef};

/// Borrowed NameIdMappingRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct NameIdMappingRequestRef<'a> {
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
    /// The name identifier to be mapped (NameID or EncryptedID).
    pub name_id: NameIdOrEncryptedIdRef<'a>,
    /// The desired NameID format/policy for the mapped result.
    pub name_id_policy: NameIdPolicyRef<'a>,
}

impl<'a> NameIdMappingRequestRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> NameIdMappingRequest {
        NameIdMappingRequest {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            name_id: self.name_id.to_owned(),
            name_id_policy: self.name_id_policy.to_owned(),
        }
    }
}

/// Owned NameIdMappingRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct NameIdMappingRequest {
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
    /// The name identifier to be mapped (NameID or EncryptedID).
    pub name_id: NameIdOrEncryptedId,
    /// The desired NameID format/policy for the mapped result.
    pub name_id_policy: NameIdPolicy,
}

/// Borrowed NameIdMappingResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct NameIdMappingResponseRef<'a> {
    /// Unique identifier.
    pub id: &'a str,
    /// SAML version.
    pub version: SamlVersion,
    /// Time the response was issued.
    pub issue_instant: DateTime<Utc>,
    /// Destination URI.
    pub destination: Option<&'a str>,
    /// Consent URI.
    pub consent: Option<&'a str>,
    /// Issuer.
    pub issuer: Option<IssuerRef<'a>>,
    /// Whether a digital signature is present.
    pub has_signature: bool,
    /// The ID of the request this is in response to.
    pub in_response_to: Option<&'a str>,
    /// The response status.
    pub status: StatusRef<'a>,
    /// The mapped NameID (NameID or EncryptedID).
    /// Present only when the status is Success.
    pub name_id: Option<NameIdOrEncryptedIdRef<'a>>,
}

impl<'a> NameIdMappingResponseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> NameIdMappingResponse {
        NameIdMappingResponse {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            in_response_to: self.in_response_to.map(str::to_string),
            status: self.status.to_owned(),
            name_id: self.name_id.as_ref().map(|n| n.to_owned()),
        }
    }
}

/// Owned NameIdMappingResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct NameIdMappingResponse {
    pub id: String,
    pub version: SamlVersion,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub consent: Option<String>,
    pub issuer: Option<Issuer>,
    pub has_signature: bool,
    pub in_response_to: Option<String>,
    pub status: Status,
    /// The mapped NameID (NameID or EncryptedID).
    pub name_id: Option<NameIdOrEncryptedId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::name_id::NameIdRef;
    use crate::core::constants::*;
    use crate::core::protocol::status::StatusCodeRef;

    #[test]
    fn test_name_id_mapping_request_ref_to_owned() {
        let now = chrono::Utc::now();
        let req = NameIdMappingRequestRef {
            id: "_nim_req_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/nim"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            name_id: NameIdOrEncryptedIdRef::NameId(NameIdRef {
                value: "user@example.com",
                format: Some(NAMEID_EMAIL),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            }),
            name_id_policy: NameIdPolicyRef {
                format: Some(NAMEID_PERSISTENT),
                sp_name_qualifier: None,
                allow_create: true,
            },
        };
        let owned = req.to_owned();
        assert_eq!(owned.id, "_nim_req_1");
        assert_eq!(
            owned.name_id_policy.format.as_deref(),
            Some(NAMEID_PERSISTENT)
        );
        assert!(owned.name_id_policy.allow_create);
    }

    #[test]
    fn test_name_id_mapping_response_with_result() {
        let now = chrono::Utc::now();
        let resp = NameIdMappingResponseRef {
            id: "_nim_resp_1",
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
            in_response_to: Some("_nim_req_1"),
            status: StatusRef {
                status_code: StatusCodeRef {
                    value: STATUS_SUCCESS,
                    sub_status: None,
                },
                status_message: None,
                status_detail: None,
            },
            name_id: Some(NameIdOrEncryptedIdRef::NameId(NameIdRef {
                value: "mapped-persistent-id-12345",
                format: Some(NAMEID_PERSISTENT),
                name_qualifier: Some("https://idp.example.com"),
                sp_name_qualifier: Some("https://sp.example.com"),
                sp_provided_id: None,
            })),
        };
        let owned = resp.to_owned();
        assert_eq!(owned.id, "_nim_resp_1");
        assert!(owned.status.is_success());
        assert!(owned.name_id.is_some());
    }

    #[test]
    fn test_name_id_mapping_response_failure() {
        let now = chrono::Utc::now();
        let resp = NameIdMappingResponseRef {
            id: "_nim_resp_2",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            in_response_to: Some("_nim_req_2"),
            status: StatusRef {
                status_code: StatusCodeRef {
                    value: STATUS_RESPONDER,
                    sub_status: Some(Box::new(StatusCodeRef {
                        value: STATUS_INVALID_NAMEID_POLICY,
                        sub_status: None,
                    })),
                },
                status_message: Some("Unsupported NameID format mapping"),
                status_detail: None,
            },
            name_id: None,
        };
        let owned = resp.to_owned();
        assert!(!owned.status.is_success());
        assert!(owned.name_id.is_none());
    }
}
