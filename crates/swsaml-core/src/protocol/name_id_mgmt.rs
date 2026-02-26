// SAML 2.0 Manage NameID Request/Response types
//
// ManageNameIDRequest: used to change or terminate a NameID.
// ManageNameIDResponse: response to ManageNameIDRequest.

use chrono::{DateTime, Utc};

use crate::assertion::issuer::{Issuer, IssuerRef};
use crate::assertion::name_id::{NameIdOrEncryptedId, NameIdOrEncryptedIdRef};
use crate::identifiers::SamlVersion;

use super::status::{Status, StatusRef};

/// The new identifier or termination indicator.
#[derive(Debug, Clone, PartialEq)]
pub enum NewIdOrTerminateRef<'a> {
    /// A new NameID value to replace the current one.
    NewId(&'a str),
    /// A new encrypted NameID value.
    NewEncryptedId(&'a [u8]),
    /// Terminate the use of the current NameID.
    Terminate,
}

impl<'a> NewIdOrTerminateRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> NewIdOrTerminate {
        match self {
            NewIdOrTerminateRef::NewId(s) => NewIdOrTerminate::NewId(s.to_string()),
            NewIdOrTerminateRef::NewEncryptedId(b) => NewIdOrTerminate::NewEncryptedId(b.to_vec()),
            NewIdOrTerminateRef::Terminate => NewIdOrTerminate::Terminate,
        }
    }
}

/// Owned variant of the new identifier or termination indicator.
#[derive(Debug, Clone, PartialEq)]
pub enum NewIdOrTerminate {
    /// A new NameID value to replace the current one.
    NewId(String),
    /// A new encrypted NameID value.
    NewEncryptedId(Vec<u8>),
    /// Terminate the use of the current NameID.
    Terminate,
}

/// Borrowed ManageNameIdRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct ManageNameIdRequestRef<'a> {
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
    /// The name identifier to be managed (NameID or EncryptedID).
    pub name_id: NameIdOrEncryptedIdRef<'a>,
    /// The new identifier or a termination indicator.
    pub new_id_or_terminate: NewIdOrTerminateRef<'a>,
}

impl<'a> ManageNameIdRequestRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> ManageNameIdRequest {
        ManageNameIdRequest {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            name_id: self.name_id.to_owned(),
            new_id_or_terminate: self.new_id_or_terminate.to_owned(),
        }
    }
}

/// Owned ManageNameIdRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct ManageNameIdRequest {
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
    /// The name identifier to be managed (NameID or EncryptedID).
    pub name_id: NameIdOrEncryptedId,
    /// The new identifier or a termination indicator.
    pub new_id_or_terminate: NewIdOrTerminate,
}

/// Borrowed ManageNameIdResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct ManageNameIdResponseRef<'a> {
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
}

impl<'a> ManageNameIdResponseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> ManageNameIdResponse {
        ManageNameIdResponse {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            in_response_to: self.in_response_to.map(str::to_string),
            status: self.status.to_owned(),
        }
    }
}

/// Owned ManageNameIdResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct ManageNameIdResponse {
    pub id: String,
    pub version: SamlVersion,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub consent: Option<String>,
    pub issuer: Option<Issuer>,
    pub has_signature: bool,
    pub in_response_to: Option<String>,
    pub status: Status,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion::name_id::NameIdRef;
    use crate::constants::*;
    use crate::protocol::status::StatusCodeRef;

    #[test]
    fn test_manage_name_id_request_with_new_id() {
        let now = chrono::Utc::now();
        let req = ManageNameIdRequestRef {
            id: "_mni_req_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/mni"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            name_id: NameIdOrEncryptedIdRef::NameId(NameIdRef {
                value: "old-user-id",
                format: Some(NAMEID_PERSISTENT),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            }),
            new_id_or_terminate: NewIdOrTerminateRef::NewId("new-user-id"),
        };
        let owned = req.to_owned();
        assert_eq!(owned.id, "_mni_req_1");
        match &owned.new_id_or_terminate {
            NewIdOrTerminate::NewId(s) => assert_eq!(s, "new-user-id"),
            _ => panic!("Expected NewId"),
        }
    }

    #[test]
    fn test_manage_name_id_request_terminate() {
        let now = chrono::Utc::now();
        let req = ManageNameIdRequestRef {
            id: "_mni_req_2",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            name_id: NameIdOrEncryptedIdRef::NameId(NameIdRef {
                value: "user@example.com",
                format: Some(NAMEID_EMAIL),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            }),
            new_id_or_terminate: NewIdOrTerminateRef::Terminate,
        };
        let owned = req.to_owned();
        assert_eq!(owned.new_id_or_terminate, NewIdOrTerminate::Terminate);
    }

    #[test]
    fn test_manage_name_id_response_ref_to_owned() {
        let now = chrono::Utc::now();
        let resp = ManageNameIdResponseRef {
            id: "_mni_resp_1",
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
            in_response_to: Some("_mni_req_1"),
            status: StatusRef {
                status_code: StatusCodeRef {
                    value: STATUS_SUCCESS,
                    sub_status: None,
                },
                status_message: None,
                status_detail: None,
            },
        };
        let owned = resp.to_owned();
        assert_eq!(owned.id, "_mni_resp_1");
        assert!(owned.status.is_success());
        assert_eq!(owned.in_response_to.as_deref(), Some("_mni_req_1"));
    }
}
