// SAML 2.0 LogoutRequest/LogoutResponse types
//
// Per Errata:
// - E10: LogoutRequest Reason is a URI

use chrono::{DateTime, Utc};

use crate::core::assertion::issuer::{Issuer, IssuerRef};
use crate::core::assertion::name_id::{NameIdOrEncryptedId, NameIdOrEncryptedIdRef};
use crate::core::identifiers::SamlVersion;

use super::status::{Status, StatusRef};

/// Borrowed LogoutRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutRequestRef<'a> {
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
    /// Time at which the logout must complete.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// Reason for the logout. Per E10: must be a URI.
    pub reason: Option<&'a str>,
    /// The name identifier of the principal being logged out.
    pub name_id: NameIdOrEncryptedIdRef<'a>,
    /// Session indices to log out.
    pub session_indexes: Vec<&'a str>,
}

impl<'a> LogoutRequestRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> LogoutRequest {
        LogoutRequest {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            not_on_or_after: self.not_on_or_after,
            reason: self.reason.map(str::to_string),
            name_id: self.name_id.to_owned(),
            session_indexes: self.session_indexes.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Owned LogoutRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutRequest {
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
    /// Time at which the logout must complete.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// Reason for the logout. Per E10: must be a URI.
    pub reason: Option<String>,
    /// The name identifier of the principal being logged out.
    pub name_id: NameIdOrEncryptedId,
    /// Session indices to log out.
    pub session_indexes: Vec<String>,
}

/// Borrowed LogoutResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutResponseRef<'a> {
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

impl<'a> LogoutResponseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> LogoutResponse {
        LogoutResponse {
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

/// Owned LogoutResponse.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutResponse {
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
    use crate::core::assertion::name_id::NameIdRef;
    use crate::core::constants::*;

    #[test]
    fn test_logout_request_ref_to_owned() {
        let now = chrono::Utc::now();
        let req = LogoutRequestRef {
            id: "_logout_req_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/slo"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            not_on_or_after: None,
            reason: Some(LOGOUT_REASON_USER),
            name_id: NameIdOrEncryptedIdRef::NameId(NameIdRef {
                value: "user@example.com",
                format: Some(NAMEID_EMAIL),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            }),
            session_indexes: vec!["_session_1", "_session_2"],
        };
        let owned = req.to_owned();
        assert_eq!(owned.id, "_logout_req_1");
        assert_eq!(owned.reason.as_deref(), Some(LOGOUT_REASON_USER));
        assert_eq!(owned.session_indexes.len(), 2);
    }
}
