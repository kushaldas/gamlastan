// SAML 2.0 Query/Request types
//
// AssertionIDRequest: request to retrieve assertions by ID.
// AuthnQuery: query for authentication statements.
// AttributeQuery: query for attribute statements.
// AuthzDecisionQuery: query for authorization decision statements.

use chrono::{DateTime, Utc};

use crate::assertion::attribute::{Attribute, AttributeRef};
use crate::assertion::authz::{Action, ActionRef, Evidence, EvidenceRef};
use crate::assertion::issuer::{Issuer, IssuerRef};
use crate::assertion::subject::{Subject, SubjectRef};
use crate::identifiers::SamlVersion;

use super::request::{RequestedAuthnContext, RequestedAuthnContextRef};

// ============================================================================
// AssertionIDRequest
// ============================================================================

/// Borrowed AssertionIdRequest - request to retrieve assertions by their IDs.
#[derive(Debug, Clone, PartialEq)]
pub struct AssertionIdRequestRef<'a> {
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
    /// The assertion IDs being requested (one or more required).
    pub assertion_id_refs: Vec<&'a str>,
}

impl<'a> AssertionIdRequestRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AssertionIdRequest {
        AssertionIdRequest {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            assertion_id_refs: self
                .assertion_id_refs
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Owned AssertionIdRequest.
#[derive(Debug, Clone, PartialEq)]
pub struct AssertionIdRequest {
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
    /// The assertion IDs being requested (one or more required).
    pub assertion_id_refs: Vec<String>,
}

// ============================================================================
// AuthnQuery
// ============================================================================

/// Borrowed AuthnQuery - query for authentication statements about a subject.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnQueryRef<'a> {
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
    /// The subject being queried about (required).
    pub subject: SubjectRef<'a>,
    /// Optional session index to restrict the query.
    pub session_index: Option<&'a str>,
    /// Requested authentication context for filtering results.
    pub requested_authn_context: Option<RequestedAuthnContextRef<'a>>,
}

impl<'a> AuthnQueryRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AuthnQuery {
        AuthnQuery {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            subject: self.subject.to_owned(),
            session_index: self.session_index.map(str::to_string),
            requested_authn_context: self.requested_authn_context.as_ref().map(|r| r.to_owned()),
        }
    }
}

/// Owned AuthnQuery.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnQuery {
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
    /// The subject being queried about (required).
    pub subject: Subject,
    /// Optional session index to restrict the query.
    pub session_index: Option<String>,
    /// Requested authentication context for filtering results.
    pub requested_authn_context: Option<RequestedAuthnContext>,
}

// ============================================================================
// AttributeQuery
// ============================================================================

/// Borrowed AttributeQuery - query for attribute statements about a subject.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeQueryRef<'a> {
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
    /// The subject being queried about (required).
    pub subject: SubjectRef<'a>,
    /// Attributes being requested. Empty means all attributes.
    pub attributes: Vec<AttributeRef<'a>>,
}

impl<'a> AttributeQueryRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AttributeQuery {
        AttributeQuery {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            subject: self.subject.to_owned(),
            attributes: self.attributes.iter().map(|a| a.to_owned()).collect(),
        }
    }
}

/// Owned AttributeQuery.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeQuery {
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
    /// The subject being queried about (required).
    pub subject: Subject,
    /// Attributes being requested. Empty means all attributes.
    pub attributes: Vec<Attribute>,
}

// ============================================================================
// AuthzDecisionQuery
// ============================================================================

/// Borrowed AuthzDecisionQuery - query for authorization decisions about a subject.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzDecisionQueryRef<'a> {
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
    /// The subject being queried about (required).
    pub subject: SubjectRef<'a>,
    /// The resource URI for the authorization decision.
    pub resource: &'a str,
    /// Actions being queried about (one or more required).
    pub actions: Vec<ActionRef<'a>>,
    /// Supporting evidence for the query.
    pub evidence: Option<EvidenceRef<'a>>,
}

impl<'a> AuthzDecisionQueryRef<'a> {
    /// Convert to owned.
    pub fn to_owned(&self) -> AuthzDecisionQuery {
        AuthzDecisionQuery {
            id: self.id.to_string(),
            version: self.version,
            issue_instant: self.issue_instant,
            destination: self.destination.map(str::to_string),
            consent: self.consent.map(str::to_string),
            issuer: self.issuer.as_ref().map(|i| i.to_owned()),
            has_signature: self.has_signature,
            subject: self.subject.to_owned(),
            resource: self.resource.to_string(),
            actions: self.actions.iter().map(|a| a.to_owned()).collect(),
            evidence: self.evidence.as_ref().map(|e| e.to_owned()),
        }
    }
}

/// Owned AuthzDecisionQuery.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzDecisionQuery {
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
    /// The subject being queried about (required).
    pub subject: Subject,
    /// The resource URI for the authorization decision.
    pub resource: String,
    /// Actions being queried about (one or more required).
    pub actions: Vec<Action>,
    /// Supporting evidence for the query.
    pub evidence: Option<Evidence>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion::name_id::{NameIdOrEncryptedIdRef, NameIdRef};
    use crate::constants::*;

    #[test]
    fn test_assertion_id_request_ref_to_owned() {
        let now = chrono::Utc::now();
        let req = AssertionIdRequestRef {
            id: "_aidr_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/assertionid"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            assertion_id_refs: vec!["_assertion_1", "_assertion_2"],
        };
        let owned = req.to_owned();
        assert_eq!(owned.id, "_aidr_1");
        assert_eq!(owned.assertion_id_refs.len(), 2);
        assert_eq!(owned.assertion_id_refs[0], "_assertion_1");
        assert_eq!(owned.assertion_id_refs[1], "_assertion_2");
    }

    #[test]
    fn test_authn_query_ref_to_owned() {
        let now = chrono::Utc::now();
        let query = AuthnQueryRef {
            id: "_aq_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/authnquery"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: false,
            subject: SubjectRef {
                name_id: Some(NameIdOrEncryptedIdRef::NameId(NameIdRef {
                    value: "user@example.com",
                    format: Some(NAMEID_EMAIL),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![],
            },
            session_index: Some("_session_idx_1"),
            requested_authn_context: None,
        };
        let owned = query.to_owned();
        assert_eq!(owned.id, "_aq_1");
        assert_eq!(owned.session_index.as_deref(), Some("_session_idx_1"));
    }

    #[test]
    fn test_attribute_query_ref_to_owned() {
        let now = chrono::Utc::now();
        let query = AttributeQueryRef {
            id: "_attrq_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://idp.example.com/attrquery"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            subject: SubjectRef {
                name_id: Some(NameIdOrEncryptedIdRef::NameId(NameIdRef {
                    value: "persistent-id-12345",
                    format: Some(NAMEID_PERSISTENT),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![],
            },
            attributes: vec![
                AttributeRef {
                    name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
                    name_format: Some(ATTRNAME_FORMAT_URI),
                    friendly_name: Some("eduPersonEntitlement"),
                    values: vec![],
                },
                AttributeRef {
                    name: "urn:oid:0.9.2342.19200300.100.1.3",
                    name_format: Some(ATTRNAME_FORMAT_URI),
                    friendly_name: Some("mail"),
                    values: vec![],
                },
            ],
        };
        let owned = query.to_owned();
        assert_eq!(owned.id, "_attrq_1");
        assert_eq!(owned.attributes.len(), 2);
        assert_eq!(
            owned.attributes[0].friendly_name.as_deref(),
            Some("eduPersonEntitlement")
        );
    }

    #[test]
    fn test_attribute_query_all_attributes() {
        let now = chrono::Utc::now();
        let query = AttributeQueryRef {
            id: "_attrq_2",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            subject: SubjectRef {
                name_id: None,
                subject_confirmations: vec![],
            },
            attributes: vec![], // Empty means request all attributes
        };
        let owned = query.to_owned();
        assert!(owned.attributes.is_empty());
    }

    #[test]
    fn test_authz_decision_query_ref_to_owned() {
        let now = chrono::Utc::now();
        let query = AuthzDecisionQueryRef {
            id: "_adq_1",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some("https://pdp.example.com/authz"),
            consent: None,
            issuer: Some(IssuerRef {
                value: "https://sp.example.com",
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            has_signature: true,
            subject: SubjectRef {
                name_id: Some(NameIdOrEncryptedIdRef::NameId(NameIdRef {
                    value: "user@example.com",
                    format: Some(NAMEID_EMAIL),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![],
            },
            resource: "https://sp.example.com/protected/resource",
            actions: vec![ActionRef {
                namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc",
                value: "Read",
            }],
            evidence: None,
        };
        let owned = query.to_owned();
        assert_eq!(owned.id, "_adq_1");
        assert_eq!(owned.resource, "https://sp.example.com/protected/resource");
        assert_eq!(owned.actions.len(), 1);
        assert_eq!(owned.actions[0].value, "Read");
        assert!(owned.evidence.is_none());
    }

    #[test]
    fn test_authz_decision_query_with_evidence() {
        let now = chrono::Utc::now();
        let query = AuthzDecisionQueryRef {
            id: "_adq_2",
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            subject: SubjectRef {
                name_id: None,
                subject_confirmations: vec![],
            },
            resource: "https://example.com/resource",
            actions: vec![
                ActionRef {
                    namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc",
                    value: "Read",
                },
                ActionRef {
                    namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc",
                    value: "Write",
                },
            ],
            evidence: Some(EvidenceRef {
                assertion_id_refs: vec!["_prev_assertion_1"],
                assertion_uri_refs: vec![],
            }),
        };
        let owned = query.to_owned();
        assert_eq!(owned.actions.len(), 2);
        assert!(owned.evidence.is_some());
        let ev = owned.evidence.unwrap();
        assert_eq!(ev.assertion_id_refs.len(), 1);
        assert_eq!(ev.assertion_id_refs[0], "_prev_assertion_1");
    }
}
