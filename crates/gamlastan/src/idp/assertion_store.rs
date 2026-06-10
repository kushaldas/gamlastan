// IdP-side store of issued assertions (pysaml2 session-DB equivalent),
// serving the
// AssertionIDRequest and AuthnQuery profiles.
//
// `Server.create_authn_response`-style flows call `store_assertion()` for
// every issued assertion; `create_assertion_id_request_response()` and
// `create_authn_query_response()` then answer back-channel queries from
// the stored material.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use crate::core::assertion::authn::AuthnStatement;
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::NameIdOrEncryptedId;
use crate::core::assertion::subject::Subject;
use crate::core::assertion::types::Assertion;
use crate::core::constants;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::query::{AssertionIdRequest, AuthnQuery};
use crate::core::protocol::response::{Response, ResponseBase};
use crate::core::protocol::status::{Status, StatusCode};

/// Store of issued assertions, queryable by assertion ID and by subject.
///
/// Implement over Redis/SQL for multi-instance IdPs; the in-memory
/// implementation suits single instances and tests.
pub trait AssertionStore: Send + Sync {
    /// Record an issued assertion.
    fn store_assertion(&self, assertion: Assertion);
    /// Fetch an assertion by its ID.
    fn get_assertion(&self, assertion_id: &str) -> Option<Assertion>;
    /// All assertions issued for a subject NameID value.
    fn assertions_for_subject(&self, name_id_value: &str) -> Vec<Assertion>;
    /// Remove an assertion (e.g. after expiry).
    fn remove_assertion(&self, assertion_id: &str);
}

/// In-memory assertion store.
#[derive(Debug, Default)]
pub struct InMemoryAssertionStore {
    by_id: Mutex<HashMap<String, Assertion>>,
    by_subject: Mutex<HashMap<String, Vec<String>>>,
}

impl InMemoryAssertionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

fn subject_value(assertion: &Assertion) -> Option<String> {
    match assertion.subject.as_ref()?.name_id.as_ref()? {
        NameIdOrEncryptedId::NameId(nid) => Some(nid.value.clone()),
        NameIdOrEncryptedId::EncryptedId(_) => None,
    }
}

impl AssertionStore for InMemoryAssertionStore {
    fn store_assertion(&self, assertion: Assertion) {
        let assertion_id = assertion.id.clone();
        let subject = subject_value(&assertion);

        self.by_id
            .lock()
            .unwrap()
            .insert(assertion_id.clone(), assertion);

        if let Some(subject) = subject {
            let mut by_subject = self.by_subject.lock().unwrap();
            let ids = by_subject.entry(subject).or_default();
            // Re-storing the same assertion ID (overwriting in `by_id`) must
            // not duplicate it in the subject index, or `assertions_for_subject`
            // would return the assertion more than once.
            if !ids.contains(&assertion_id) {
                ids.push(assertion_id);
            }
        }
    }

    fn get_assertion(&self, assertion_id: &str) -> Option<Assertion> {
        self.by_id.lock().unwrap().get(assertion_id).cloned()
    }

    fn assertions_for_subject(&self, name_id_value: &str) -> Vec<Assertion> {
        let ids = self
            .by_subject
            .lock()
            .unwrap()
            .get(name_id_value)
            .cloned()
            .unwrap_or_default();

        if ids.is_empty() {
            return vec![];
        }

        let by_id = self.by_id.lock().unwrap();
        ids.into_iter()
            .filter_map(|id| by_id.get(&id).cloned())
            .collect()
    }

    fn remove_assertion(&self, assertion_id: &str) {
        let removed = self.by_id.lock().unwrap().remove(assertion_id);
        if let Some(subject) = removed.as_ref().and_then(subject_value) {
            let mut by_subject = self.by_subject.lock().unwrap();
            let mut remove_subject_entry = false;
            if let Some(ids) = by_subject.get_mut(&subject) {
                ids.retain(|id| id != assertion_id);
                remove_subject_entry = ids.is_empty();
            }
            if remove_subject_entry {
                by_subject.remove(&subject);
            }
        }
    }
}

/// The AuthnStatements stored for a subject, optionally narrowed by
/// session index and acceptable context class refs (pysaml2
/// `get_authn_statements()`).
pub fn get_authn_statements(
    store: &dyn AssertionStore,
    name_id_value: &str,
    session_index: Option<&str>,
    requested_context_class_refs: &[String],
) -> Vec<AuthnStatement> {
    store
        .assertions_for_subject(name_id_value)
        .into_iter()
        .flat_map(|a| a.authn_statements)
        .filter(|stmt| {
            if let Some(wanted) = session_index {
                if stmt.session_index.as_deref() != Some(wanted) {
                    return false;
                }
            }
            if !requested_context_class_refs.is_empty() {
                let class_ref = stmt.authn_context.authn_context_class_ref.as_deref();
                if !class_ref.is_some_and(|c| requested_context_class_refs.iter().any(|r| r == c)) {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn success_response(
    idp_entity_id: &str,
    in_response_to: &str,
    assertions: Vec<Assertion>,
    now: DateTime<Utc>,
) -> Response {
    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: Some(Issuer::entity(idp_entity_id)),
            has_signature: false,
            in_response_to: Some(in_response_to.to_string()),
            status: Status::success(),
        },
        assertions,
        encrypted_assertions: vec![],
    }
}

fn no_authn_context_response(
    idp_entity_id: &str,
    in_response_to: &str,
    now: DateTime<Utc>,
) -> Response {
    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: None,
            consent: None,
            issuer: Some(Issuer::entity(idp_entity_id)),
            has_signature: false,
            in_response_to: Some(in_response_to.to_string()),
            status: Status {
                status_code: StatusCode {
                    value: constants::STATUS_RESPONDER.to_string(),
                    sub_status: Some(Box::new(StatusCode {
                        value: constants::STATUS_NO_AUTHN_CONTEXT.to_string(),
                        sub_status: None,
                    })),
                },
                status_message: None,
                status_detail: None,
            },
        },
        assertions: vec![],
        encrypted_assertions: vec![],
    }
}

/// Answer an AssertionIDRequest from the store (pysaml2
/// `Server.create_assertion_id_request_response()`).
///
/// Returns the previously issued assertions; unknown IDs yield a
/// Requester error response.
pub fn create_assertion_id_request_response(
    store: &dyn AssertionStore,
    request: &AssertionIdRequest,
    idp_entity_id: &str,
    now: DateTime<Utc>,
) -> Response {
    let mut assertions = Vec::with_capacity(request.assertion_id_refs.len());
    for id_ref in &request.assertion_id_refs {
        match store.get_assertion(id_ref) {
            Some(a) => assertions.push(a),
            None => {
                return Response {
                    base: ResponseBase {
                        id: SamlId::generate().as_str().to_string(),
                        version: SamlVersion::V2_0,
                        issue_instant: now,
                        destination: None,
                        consent: None,
                        issuer: Some(Issuer::entity(idp_entity_id)),
                        has_signature: false,
                        in_response_to: Some(request.id.clone()),
                        status: Status {
                            status_code: StatusCode {
                                value: constants::STATUS_REQUESTER.to_string(),
                                sub_status: None,
                            },
                            status_message: Some(format!("unknown assertion ID: {id_ref}")),
                            status_detail: None,
                        },
                    },
                    assertions: vec![],
                    encrypted_assertions: vec![],
                };
            }
        }
    }
    success_response(idp_entity_id, &request.id, assertions, now)
}

/// Answer an AuthnQuery from the store (pysaml2
/// `Server.create_authn_query_response()`).
///
/// Returns an assertion carrying the AuthnStatements previously issued
/// for the queried subject, filtered by the query's SessionIndex and
/// RequestedAuthnContext; an empty match yields a NoAuthnContext error.
pub fn create_authn_query_response(
    store: &dyn AssertionStore,
    query: &AuthnQuery,
    idp_entity_id: &str,
    now: DateTime<Utc>,
) -> Response {
    let Some(NameIdOrEncryptedId::NameId(name_id)) = &query.subject.name_id else {
        return no_authn_context_response(idp_entity_id, &query.id, now);
    };

    let class_refs: Vec<String> = query
        .requested_authn_context
        .as_ref()
        .map(|ctx| ctx.authn_context_class_refs.clone())
        .unwrap_or_default();

    // Pull the previously issued AuthnStatements for this subject and
    // narrow them by the query's SessionIndex / RequestedAuthnContext.
    let statements = get_authn_statements(
        store,
        &name_id.value,
        query.session_index.as_deref(),
        &class_refs,
    );

    if statements.is_empty() {
        return no_authn_context_response(idp_entity_id, &query.id, now);
    }

    let assertion = Assertion {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: now,
        issuer: Issuer::entity(idp_entity_id),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(name_id.clone())),
            subject_confirmations: vec![],
        }),
        conditions: None,
        advice: None,
        authn_statements: statements,
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    };

    success_response(idp_entity_id, &query.id, vec![assertion], now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::authn::AuthnContext;
    use crate::core::assertion::name_id::NameId;
    use crate::profiles::assertion_query::{create_assertion_id_request, create_authn_query};

    const IDP: &str = "https://idp.example.com";

    fn name_id(value: &str) -> NameId {
        NameId {
            value: value.to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    fn assertion(id: &str, subject: &str, session_index: &str, class_ref: &str) -> Assertion {
        Assertion {
            id: id.to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            issuer: Issuer::entity(IDP),
            has_signature: false,
            subject: Some(Subject {
                name_id: Some(NameIdOrEncryptedId::NameId(name_id(subject))),
                subject_confirmations: vec![],
            }),
            conditions: None,
            advice: None,
            authn_statements: vec![AuthnStatement {
                authn_instant: Utc::now(),
                session_index: Some(session_index.to_string()),
                session_not_on_or_after: None,
                subject_locality: None,
                authn_context: AuthnContext {
                    authn_context_class_ref: Some(class_ref.to_string()),
                    authn_context_decl_ref: None,
                    authenticating_authorities: vec![],
                },
            }],
            authz_decision_statements: vec![],
            attribute_statements: vec![],
        }
    }

    #[test]
    fn test_store_and_get() {
        let store = InMemoryAssertionStore::new();
        store.store_assertion(assertion(
            "_a1",
            "alice",
            "_s1",
            constants::AUTHN_CONTEXT_PASSWORD,
        ));
        assert!(store.get_assertion("_a1").is_some());
        assert_eq!(store.assertions_for_subject("alice").len(), 1);

        store.remove_assertion("_a1");
        assert!(store.get_assertion("_a1").is_none());
        assert!(store.assertions_for_subject("alice").is_empty());
    }

    #[test]
    fn test_store_same_id_twice_does_not_duplicate_subject_index() {
        let store = InMemoryAssertionStore::new();
        let a = assertion("_a1", "alice", "_s1", constants::AUTHN_CONTEXT_PASSWORD);
        store.store_assertion(a.clone());
        // Re-storing the same assertion ID (e.g. an update) must not make
        // `assertions_for_subject` return it twice.
        store.store_assertion(a);
        assert_eq!(store.assertions_for_subject("alice").len(), 1);
    }

    #[test]
    fn test_assertion_id_request_response() {
        let store = InMemoryAssertionStore::new();
        store.store_assertion(assertion(
            "_a1",
            "alice",
            "_s1",
            constants::AUTHN_CONTEXT_PASSWORD,
        ));

        let request =
            create_assertion_id_request("https://sp.example.com", vec!["_a1".to_string()], None);
        let response = create_assertion_id_request_response(&store, &request, IDP, Utc::now());
        assert!(response.base.status.is_success());
        assert_eq!(response.assertions.len(), 1);
        assert_eq!(response.assertions[0].id, "_a1");
        assert_eq!(
            response.base.in_response_to.as_deref(),
            Some(request.id.as_str())
        );
    }

    #[test]
    fn test_assertion_id_request_unknown_id() {
        let store = InMemoryAssertionStore::new();
        let request = create_assertion_id_request(
            "https://sp.example.com",
            vec!["_missing".to_string()],
            None,
        );
        let response = create_assertion_id_request_response(&store, &request, IDP, Utc::now());
        assert!(!response.base.status.is_success());
        assert_eq!(
            response.base.status.status_code.value,
            constants::STATUS_REQUESTER
        );
    }

    #[test]
    fn test_authn_query_response_filters() {
        let store = InMemoryAssertionStore::new();
        store.store_assertion(assertion(
            "_a1",
            "alice",
            "_s1",
            constants::AUTHN_CONTEXT_PASSWORD,
        ));
        store.store_assertion(assertion(
            "_a2",
            "alice",
            "_s2",
            constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
        ));

        // No filters: both statements
        let query = create_authn_query(
            "https://sp.example.com",
            &name_id("alice"),
            None,
            None,
            None,
        );
        let response = create_authn_query_response(&store, &query, IDP, Utc::now());
        assert!(response.base.status.is_success());
        assert_eq!(response.assertions[0].authn_statements.len(), 2);

        // Session index filter
        let query = create_authn_query(
            "https://sp.example.com",
            &name_id("alice"),
            Some("_s2"),
            None,
            None,
        );
        let response = create_authn_query_response(&store, &query, IDP, Utc::now());
        let stmts = &response.assertions[0].authn_statements;
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0].authn_context.authn_context_class_ref.as_deref(),
            Some(constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
        );
    }

    #[test]
    fn test_authn_query_no_match_is_no_authn_context() {
        let store = InMemoryAssertionStore::new();
        let query = create_authn_query("https://sp.example.com", &name_id("bob"), None, None, None);
        let response = create_authn_query_response(&store, &query, IDP, Utc::now());
        assert!(!response.base.status.is_success());
        let sub = response
            .base
            .status
            .status_code
            .sub_status
            .as_ref()
            .unwrap();
        assert_eq!(sub.value, constants::STATUS_NO_AUTHN_CONTEXT);
    }
}
