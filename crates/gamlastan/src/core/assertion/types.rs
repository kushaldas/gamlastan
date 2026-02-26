// SAML 2.0 Assertion type
//
// Per Errata:
// - E26: Multiple assertions allowed, all from same IdP

use chrono::{DateTime, Utc};

use super::attribute::{AttributeStatement, AttributeStatementRef};
use super::authn::{AuthnStatement, AuthnStatementRef};
use super::authz::{AuthzDecisionStatement, AuthzDecisionStatementRef};
use super::conditions::{Conditions, ConditionsRef};
use super::issuer::{Issuer, IssuerRef};
use super::subject::{Subject, SubjectRef};
use crate::core::identifiers::SamlVersion;

/// Borrowed Assertion - references into the XML document buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct AssertionRef<'a> {
    /// Unique identifier for the assertion (xs:ID).
    pub id: &'a str,
    /// Time the assertion was issued.
    pub issue_instant: DateTime<Utc>,
    /// SAML version (always 2.0).
    pub version: SamlVersion,
    /// The assertion issuer.
    pub issuer: IssuerRef<'a>,
    /// Whether a digital signature is present on this assertion.
    pub has_signature: bool,
    /// The assertion subject.
    pub subject: Option<SubjectRef<'a>>,
    /// The assertion conditions.
    pub conditions: Option<ConditionsRef<'a>>,
    /// Authentication statements.
    pub authn_statements: Vec<AuthnStatementRef<'a>>,
    /// Authorization decision statements.
    pub authz_decision_statements: Vec<AuthzDecisionStatementRef<'a>>,
    /// Attribute statements.
    pub attribute_statements: Vec<AttributeStatementRef<'a>>,
}

impl<'a> AssertionRef<'a> {
    /// Convert to an owned Assertion.
    pub fn to_owned(&self) -> Assertion {
        Assertion {
            id: self.id.to_string(),
            issue_instant: self.issue_instant,
            version: self.version,
            issuer: self.issuer.to_owned(),
            has_signature: self.has_signature,
            subject: self.subject.as_ref().map(|s| s.to_owned()),
            conditions: self.conditions.as_ref().map(|c| c.to_owned()),
            authn_statements: self.authn_statements.iter().map(|s| s.to_owned()).collect(),
            authz_decision_statements: self
                .authz_decision_statements
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            attribute_statements: self
                .attribute_statements
                .iter()
                .map(|s| s.to_owned())
                .collect(),
        }
    }
}

/// Owned Assertion - for construction, storage, and crossing lifetime boundaries.
#[derive(Debug, Clone, PartialEq)]
pub struct Assertion {
    /// Unique identifier for the assertion (xs:ID).
    pub id: String,
    /// Time the assertion was issued.
    pub issue_instant: DateTime<Utc>,
    /// SAML version (always 2.0).
    pub version: SamlVersion,
    /// The assertion issuer.
    pub issuer: Issuer,
    /// Whether a digital signature is present on this assertion.
    pub has_signature: bool,
    /// The assertion subject.
    pub subject: Option<Subject>,
    /// The assertion conditions.
    pub conditions: Option<Conditions>,
    /// Authentication statements.
    pub authn_statements: Vec<AuthnStatement>,
    /// Authorization decision statements.
    pub authz_decision_statements: Vec<AuthzDecisionStatement>,
    /// Attribute statements.
    pub attribute_statements: Vec<AttributeStatement>,
}

/// An encrypted assertion (opaque encrypted data).
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedAssertionRef<'a> {
    /// The raw encrypted XML element bytes.
    pub raw: &'a [u8],
}

/// Owned encrypted assertion.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedAssertion {
    /// The raw encrypted XML element bytes.
    pub raw: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::authn::{AuthnContextRef, AuthnStatementRef};
    use crate::core::assertion::conditions::{AudienceRestrictionRef, ConditionsRef};
    use crate::core::assertion::issuer::IssuerRef;
    use crate::core::assertion::name_id::{NameIdOrEncryptedIdRef, NameIdRef};
    use crate::core::assertion::subject::{
        SubjectConfirmationDataRef, SubjectConfirmationRef, SubjectRef,
    };
    use crate::core::constants::*;
    use chrono::Utc;

    #[test]
    fn test_assertion_ref_to_owned() {
        let now = Utc::now();
        let assertion_ref = AssertionRef {
            id: "_assertion_123",
            issue_instant: now,
            version: SamlVersion::V2_0,
            issuer: IssuerRef {
                value: "https://idp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            },
            has_signature: true,
            subject: Some(SubjectRef {
                name_id: Some(NameIdOrEncryptedIdRef::NameId(NameIdRef {
                    value: "user@example.com",
                    format: Some(NAMEID_EMAIL),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![SubjectConfirmationRef {
                    method: CM_BEARER,
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationDataRef {
                        not_before: None,
                        not_on_or_after: None,
                        recipient: Some("https://sp.example.com/acs"),
                        in_response_to: Some("_request_456"),
                        address: None,
                    }),
                }],
            }),
            conditions: Some(ConditionsRef {
                not_before: Some(now),
                not_on_or_after: None,
                audience_restrictions: vec![AudienceRestrictionRef {
                    audiences: vec!["https://sp.example.com"],
                }],
                one_time_use: false,
                proxy_restriction: None,
            }),
            authn_statements: vec![AuthnStatementRef {
                authn_instant: now,
                session_index: Some("_session_789"),
                session_not_on_or_after: None,
                subject_locality: None,
                authn_context: AuthnContextRef {
                    authn_context_class_ref: Some(AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT),
                    authn_context_decl_ref: None,
                    authenticating_authorities: vec![],
                },
            }],
            authz_decision_statements: vec![],
            attribute_statements: vec![],
        };

        let owned = assertion_ref.to_owned();
        assert_eq!(owned.id, "_assertion_123");
        assert_eq!(owned.issue_instant, now);
        assert!(owned.version.is_v2_0());
        assert_eq!(owned.issuer.value, "https://idp.example.com");
        assert!(owned.has_signature);
        assert!(owned.subject.is_some());
        assert!(owned.conditions.is_some());
        assert_eq!(owned.authn_statements.len(), 1);
        assert_eq!(
            owned.authn_statements[0].session_index.as_deref(),
            Some("_session_789")
        );
    }
}
