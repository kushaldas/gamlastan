// SAML 2.0 Response types
//
// Per Errata:
// - E26: Multiple assertions allowed, all from same IdP

use chrono::{DateTime, Utc};

use crate::assertion::issuer::{Issuer, IssuerRef};
use crate::assertion::types::{Assertion, AssertionRef, EncryptedAssertion, EncryptedAssertionRef};
use crate::identifiers::SamlVersion;

use super::status::{Status, StatusRef};

/// Borrowed ResponseBase - common fields for all SAML response messages.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseBaseRef<'a> {
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
}

impl<'a> ResponseBaseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> ResponseBase {
        ResponseBase {
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

/// Owned ResponseBase.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseBase {
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
}

/// Borrowed Response - contains assertions.
/// Per E26: Multiple assertions are allowed, all from the same IdP.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseRef<'a> {
    /// Common response fields.
    pub base: ResponseBaseRef<'a>,
    /// Assertions in the response.
    pub assertions: Vec<AssertionRef<'a>>,
    /// Encrypted assertions in the response.
    pub encrypted_assertions: Vec<EncryptedAssertionRef<'a>>,
}

impl<'a> ResponseRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> Response {
        Response {
            base: self.base.to_owned(),
            assertions: self
                .assertions
                .iter()
                .map(|a: &AssertionRef<'_>| a.to_owned())
                .collect(),
            encrypted_assertions: self
                .encrypted_assertions
                .iter()
                .map(|ea| EncryptedAssertion {
                    raw: ea.raw.to_vec(),
                })
                .collect(),
        }
    }
}

/// Owned Response.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    /// Common response fields.
    pub base: ResponseBase,
    /// Assertions in the response.
    pub assertions: Vec<Assertion>,
    /// Encrypted assertions in the response.
    pub encrypted_assertions: Vec<EncryptedAssertion>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::protocol::status::StatusCodeRef;

    #[test]
    fn test_response_ref_to_owned() {
        let now = chrono::Utc::now();
        let resp = ResponseRef {
            base: ResponseBaseRef {
                id: "_resp_123",
                version: SamlVersion::V2_0,
                issue_instant: now,
                destination: Some("https://sp.example.com/acs"),
                consent: None,
                issuer: Some(IssuerRef {
                    value: "https://idp.example.com",
                    format: None,
                    name_qualifier: None,
                    sp_name_qualifier: None,
                }),
                has_signature: true,
                in_response_to: Some("_req_456"),
                status: StatusRef {
                    status_code: StatusCodeRef {
                        value: STATUS_SUCCESS,
                        sub_status: None,
                    },
                    status_message: None,
                    status_detail: None,
                },
            },
            assertions: vec![],
            encrypted_assertions: vec![],
        };

        let owned = resp.to_owned();
        assert_eq!(owned.base.id, "_resp_123");
        assert_eq!(owned.base.in_response_to.as_deref(), Some("_req_456"));
        assert!(owned.base.status.is_success());
    }
}
