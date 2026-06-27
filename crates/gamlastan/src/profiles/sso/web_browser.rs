// SAML 2.0 Web Browser SSO Profile - Common types and helpers
//
// SAML Profiles Section 4.1

use crate::core::assertion::attribute::{Attribute, AttributeStatement};
use crate::core::assertion::authn::{AuthnContext, AuthnStatement};
use chrono::{DateTime, Utc};

/// Result of a successful SSO authentication (SP-side).
///
/// Returned after processing and validating a SAML Response containing
/// an AuthnStatement. Contains the extracted identity and session information.
#[derive(Debug, Clone)]
pub struct AuthnResult {
    /// The authenticated subject's NameID value.
    pub name_id: String,

    /// The NameID format.
    pub name_id_format: Option<String>,

    /// The NameID name qualifier.
    pub name_qualifier: Option<String>,

    /// The NameID SP name qualifier.
    pub sp_name_qualifier: Option<String>,

    /// Session index from the AuthnStatement (needed for SLO).
    pub session_index: Option<String>,

    /// When the session expires (E79: upper bound).
    pub session_not_on_or_after: Option<DateTime<Utc>>,

    /// The authentication instant.
    pub authn_instant: DateTime<Utc>,

    /// The authentication context class reference.
    pub authn_context_class_ref: Option<String>,

    /// The authentication context declaration reference.
    pub authn_context_decl_ref: Option<String>,

    /// Authenticating authorities (proxied authentication).
    pub authenticating_authorities: Vec<String>,

    /// Attributes from AttributeStatements.
    pub attributes: Vec<Attribute>,

    /// The IdP entity ID (from Issuer).
    pub idp_entity_id: String,

    /// The assertion ID.
    pub assertion_id: String,

    /// The response ID.
    pub response_id: String,
}

/// Options for creating an AuthnRequest (SP-side).
#[derive(Debug, Clone, Default)]
pub struct AuthnRequestOptions {
    /// SP entity ID (used as Issuer).
    pub sp_entity_id: String,

    /// The desired ACS URL (if not using index).
    pub acs_url: Option<String>,

    /// The ACS index (if not using URL).
    pub acs_index: Option<u16>,

    /// The desired protocol binding for the response.
    pub protocol_binding: Option<String>,

    /// Whether to request a new authentication (ForceAuthn).
    pub force_authn: Option<bool>,

    /// Whether the IdP should not interact with the user (IsPassive).
    pub is_passive: Option<bool>,

    /// Desired NameID format.
    pub name_id_format: Option<String>,

    /// Whether to allow creation of new identifiers (E14: create OR associate).
    pub allow_create: bool,

    /// SP name qualifier for NameIDPolicy.
    pub sp_name_qualifier: Option<String>,

    /// Requested authentication context class refs.
    pub authn_context_class_refs: Vec<String>,

    /// Comparison type for requested authn context.
    pub authn_context_comparison: Option<crate::core::protocol::request::AuthnContextComparison>,

    /// Provider name (human-readable SP name).
    pub provider_name: Option<String>,

    /// Destination URL (IdP SSO endpoint).
    pub destination: Option<String>,

    /// Scoping: proxy count limit.
    pub proxy_count: Option<u32>,

    /// Scoping: requester IDs.
    pub requester_ids: Vec<String>,

    /// AttributeConsumingServiceIndex.
    pub attribute_consuming_service_index: Option<u16>,

    /// Raw XML of the `samlp:Extensions` element (including the wrapper).
    /// Must be namespace self-contained; see `profiles::pefim` for a builder.
    pub extensions: Option<String>,
}

/// Options for creating a Response (IdP-side).
#[derive(Debug, Clone)]
pub struct ResponseOptions {
    /// IdP entity ID (used as Issuer).
    pub idp_entity_id: String,

    /// The request ID this response is replying to (None for unsolicited).
    pub in_response_to: Option<String>,

    /// The SP entity ID (audience restriction).
    pub sp_entity_id: String,

    /// The ACS URL (Response Destination + assertion Recipient).
    pub acs_url: String,

    /// How long the assertion should be valid (seconds from now).
    pub assertion_lifetime_seconds: u64,

    /// Whether to include a SessionIndex.
    pub session_index: Option<String>,

    /// Session expiry (E79).
    pub session_not_on_or_after: Option<DateTime<Utc>>,

    /// The authn context class ref for the AuthnStatement.
    pub authn_context_class_ref: Option<String>,

    /// The client's IP address (for SubjectLocality / SubjectConfirmationData Address).
    pub client_address: Option<String>,

    /// Additional attributes to include in an AttributeStatement.
    pub attributes: Vec<Attribute>,
}

/// The two semantically-distinct instants that go into a Response.
///
/// SAML draws a line between *when the document was generated* and *when the
/// principal actually authenticated* to the IdP. The latter may predate the
/// former when an existing SSO session is reused. Conflating them mis-reports
/// authentication freshness (`AuthnStatement/@AuthnInstant`) to SPs that
/// enforce it (e.g. via `RequestedAuthnContext` or `ForceAuthn`).
///
/// Named fields are used -- rather than two positional `DateTime<Utc>`
/// arguments on the builder -- so the two instants cannot be silently
/// transposed at a call site. See ADR 0025.
#[derive(Debug, Clone, Copy)]
pub struct ResponseTimes {
    /// When the Response/Assertion document is generated. Drives the Response
    /// and Assertion `IssueInstant`, `Conditions/@NotBefore`, and every
    /// `NotOnOrAfter` (computed as issue instant + lifetime).
    pub issue_instant: DateTime<Utc>,

    /// When the principal authenticated to the IdP -- possibly from a reused SSO
    /// session, hence possibly earlier than `issue_instant`. Drives
    /// `AuthnStatement/@AuthnInstant`.
    pub authn_instant: DateTime<Utc>,
}

impl ResponseTimes {
    /// Both instants equal `now`: the principal authenticated at the moment the
    /// response is generated (a fresh login). Reproduces the historical
    /// single-`now` behaviour for callers that do not track a separate
    /// authentication time.
    pub fn at(now: DateTime<Utc>) -> Self {
        Self {
            issue_instant: now,
            authn_instant: now,
        }
    }
}

/// Extract attributes from all AttributeStatements in assertions.
pub fn extract_attributes(attribute_statements: &[AttributeStatement]) -> Vec<Attribute> {
    attribute_statements
        .iter()
        .flat_map(|stmt| stmt.attributes.iter().cloned())
        .collect()
}

/// Extract the AuthnContext from the first AuthnStatement.
pub fn extract_authn_context(authn_statements: &[AuthnStatement]) -> Option<&AuthnContext> {
    authn_statements.first().map(|stmt| &stmt.authn_context)
}

/// Extract the session index from the first AuthnStatement.
pub fn extract_session_index(authn_statements: &[AuthnStatement]) -> Option<&str> {
    authn_statements
        .first()
        .and_then(|stmt| stmt.session_index.as_deref())
}

/// Extract session not-on-or-after from the first AuthnStatement.
pub fn extract_session_not_on_or_after(
    authn_statements: &[AuthnStatement],
) -> Option<DateTime<Utc>> {
    authn_statements
        .first()
        .and_then(|stmt| stmt.session_not_on_or_after)
}

/// Binding URI constants for common bindings.
pub mod bindings {
    pub const HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    pub const HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    pub const HTTP_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    pub const SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    pub const PAOS: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::authn::AuthnContext;

    #[test]
    fn test_extract_attributes() {
        let stmts = vec![
            AttributeStatement {
                attributes: vec![
                    Attribute {
                        name: "email".to_string(),
                        name_format: None,
                        friendly_name: None,
                        values: vec![],
                    },
                    Attribute {
                        name: "name".to_string(),
                        name_format: None,
                        friendly_name: None,
                        values: vec![],
                    },
                ],
            },
            AttributeStatement {
                attributes: vec![Attribute {
                    name: "role".to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![],
                }],
            },
        ];
        let attrs = extract_attributes(&stmts);
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].name, "email");
        assert_eq!(attrs[2].name, "role");
    }

    #[test]
    fn test_extract_session_index() {
        let stmts = vec![AuthnStatement {
            authn_instant: Utc::now(),
            session_index: Some("_session_abc".to_string()),
            session_not_on_or_after: None,
            subject_locality: None,
            authn_context: AuthnContext {
                authn_context_class_ref: None,
                authn_context_decl_ref: None,
                authenticating_authorities: vec![],
            },
        }];
        assert_eq!(extract_session_index(&stmts), Some("_session_abc"));
    }

    #[test]
    fn test_extract_session_index_empty() {
        let stmts: Vec<AuthnStatement> = vec![];
        assert_eq!(extract_session_index(&stmts), None);
    }

    #[test]
    fn test_default_authn_request_options() {
        let opts = AuthnRequestOptions::default();
        assert!(opts.sp_entity_id.is_empty());
        assert!(!opts.allow_create);
        assert!(opts.force_authn.is_none());
    }
}
