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
use crate::idp::ident::StoreError;

pub mod conformance;

/// Store of issued assertions, queryable by assertion ID and by subject.
///
/// Implement over Redis/SQL for multi-instance IdPs; the in-memory
/// implementation suits single instances and tests.
///
/// Every method is fallible: a backend that cannot answer must return
/// [`StoreError`], not an empty result, so an outage is not mistaken for
/// "no such assertion".
///
/// The query helpers ([`get_authn_statements`],
/// [`create_assertion_id_request_response`], [`create_authn_query_response`]) do
/// not trust the answers: an assertion returned for a subject must be that
/// subject's, and one returned for an ID must have that ID, otherwise the call is
/// a [`StoreError`]. The subject check binds the answer to the NameID *value*
/// that was asked about; it does not decide who may ask. Whether the requester
/// may learn about that subject's assertions is the responder's call. A backend still has to get the rest right - an ID stored
/// again for another subject must leave the old subject's index, removal must
/// clear it, and concurrent stores must not lose entries - and [`conformance`]
/// checks that against a real instance.
pub trait AssertionStore: Send + Sync {
    /// Record an issued assertion.
    fn store_assertion(&self, assertion: Assertion) -> Result<(), StoreError>;
    /// Fetch an assertion by its ID.
    fn get_assertion(&self, assertion_id: &str) -> Result<Option<Assertion>, StoreError>;
    /// All assertions issued for a subject NameID value.
    fn assertions_for_subject(&self, name_id_value: &str) -> Result<Vec<Assertion>, StoreError>;
    /// Remove an assertion (e.g. after expiry).
    fn remove_assertion(&self, assertion_id: &str) -> Result<(), StoreError>;
}

/// In-memory assertion store.
#[derive(Debug, Default)]
pub struct InMemoryAssertionStore {
    state: Mutex<State>,
}

/// Both indexes behind one lock, so they cannot disagree.
#[derive(Debug, Default)]
struct State {
    by_id: HashMap<String, Assertion>,
    by_subject: HashMap<String, Vec<String>>,
}

impl State {
    /// Drop `assertion_id` from the subject index entry for `subject`.
    fn unindex(&mut self, subject: &str, assertion_id: &str) {
        if let Some(ids) = self.by_subject.get_mut(subject) {
            ids.retain(|id| id != assertion_id);
            if ids.is_empty() {
                self.by_subject.remove(subject);
            }
        }
    }
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
    fn store_assertion(&self, assertion: Assertion) -> Result<(), StoreError> {
        let assertion_id = assertion.id.clone();
        let subject = subject_value(&assertion);

        let mut state = self.state.lock().unwrap();
        // Re-storing an ID replaces the assertion, so it must leave the index of
        // whatever subject the old one named: otherwise a lookup for that
        // subject would return an assertion issued to someone else.
        if let Some(previous) = state.by_id.insert(assertion_id.clone(), assertion) {
            if let Some(old_subject) = subject_value(&previous) {
                state.unindex(&old_subject, &assertion_id);
            }
        }
        if let Some(subject) = subject {
            let ids = state.by_subject.entry(subject).or_default();
            if !ids.contains(&assertion_id) {
                ids.push(assertion_id);
            }
        }
        Ok(())
    }

    fn get_assertion(&self, assertion_id: &str) -> Result<Option<Assertion>, StoreError> {
        Ok(self.state.lock().unwrap().by_id.get(assertion_id).cloned())
    }

    fn assertions_for_subject(&self, name_id_value: &str) -> Result<Vec<Assertion>, StoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .by_subject
            .get(name_id_value)
            .into_iter()
            .flatten()
            .filter_map(|id| state.by_id.get(id).cloned())
            .collect())
    }

    fn remove_assertion(&self, assertion_id: &str) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        if let Some(removed) = state.by_id.remove(assertion_id) {
            if let Some(subject) = subject_value(&removed) {
                state.unindex(&subject, assertion_id);
            }
        }
        Ok(())
    }
}

/// Return the currently valid AuthnStatements stored for a subject.
///
/// Assertions without a bounded `Conditions::NotOnOrAfter` value, assertions
/// outside their Conditions window, and expired sessions are omitted. Results
/// can additionally be narrowed by session index and acceptable authentication
/// context class references (pysaml2 `get_authn_statements()`).
///
/// The store is not trusted to have scoped its answer: every assertion it returns
/// must be for `name_id_value`, otherwise the call fails with a [`StoreError`]. An
/// index that is stale or keyed wrongly would otherwise put one subject's
/// authentication statements into an answer about another's. This binds the
/// answer to the value asked about, not to the requester: authorizing the
/// requester (for example by SP entity ID) is up to the caller.
pub fn get_authn_statements(
    store: &dyn AssertionStore,
    name_id_value: &str,
    session_index: Option<&str>,
    requested_context_class_refs: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<AuthnStatement>, StoreError> {
    let assertions = store.assertions_for_subject(name_id_value)?;
    if assertions
        .iter()
        .any(|a| subject_value(a).as_deref() != Some(name_id_value))
    {
        return Err(StoreError::new(
            "the store's assertions_for_subject returned an assertion that is not for the \
             requested subject; refusing to use it",
        ));
    }
    Ok(assertions
        .into_iter()
        .filter(|assertion| {
            assertion.conditions.as_ref().is_some_and(|conditions| {
                let started = conditions
                    .not_before
                    .is_none_or(|not_before| now >= not_before);
                let unexpired = conditions
                    .not_on_or_after
                    .is_some_and(|not_on_or_after| now < not_on_or_after);
                started && unexpired
            })
        })
        .flat_map(|a| a.authn_statements)
        .filter(|stmt| {
            if stmt
                .session_not_on_or_after
                .is_some_and(|not_on_or_after| now >= not_on_or_after)
            {
                return false;
            }
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
        .collect())
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
///
/// The store is not trusted to return the assertion that was asked for: one whose
/// ID differs from the requested one fails the call with a [`StoreError`].
pub fn create_assertion_id_request_response(
    store: &dyn AssertionStore,
    request: &AssertionIdRequest,
    idp_entity_id: &str,
    now: DateTime<Utc>,
) -> Result<Response, StoreError> {
    let mut assertions = Vec::with_capacity(request.assertion_id_refs.len());
    for id_ref in &request.assertion_id_refs {
        match store.get_assertion(id_ref)? {
            Some(a) if a.id == *id_ref => assertions.push(a),
            Some(_) => {
                return Err(StoreError::new(
                    "the store's get_assertion returned a different assertion than the one \
                     requested; refusing to use it",
                ))
            }
            None => {
                return Ok(Response {
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
                });
            }
        }
    }
    Ok(success_response(
        idp_entity_id,
        &request.id,
        assertions,
        now,
    ))
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
) -> Result<Response, StoreError> {
    let Some(NameIdOrEncryptedId::NameId(name_id)) = &query.subject.name_id else {
        return Ok(no_authn_context_response(idp_entity_id, &query.id, now));
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
        now,
    )?;

    if statements.is_empty() {
        return Ok(no_authn_context_response(idp_entity_id, &query.id, now));
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

    Ok(success_response(
        idp_entity_id,
        &query.id,
        vec![assertion],
        now,
    ))
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
            conditions: Some(crate::core::assertion::conditions::Conditions {
                not_before: Some(Utc::now() - chrono::TimeDelta::minutes(1)),
                not_on_or_after: Some(Utc::now() + chrono::TimeDelta::minutes(5)),
                audience_restrictions: vec![],
                one_time_use: false,
                proxy_restriction: None,
            }),
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
        store
            .store_assertion(assertion(
                "_a1",
                "alice",
                "_s1",
                constants::AUTHN_CONTEXT_PASSWORD,
            ))
            .unwrap();
        assert!(store.get_assertion("_a1").unwrap().is_some());
        assert_eq!(store.assertions_for_subject("alice").unwrap().len(), 1);

        store.remove_assertion("_a1").unwrap();
        assert!(store.get_assertion("_a1").unwrap().is_none());
        assert!(store.assertions_for_subject("alice").unwrap().is_empty());
    }

    #[test]
    fn restoring_an_id_for_another_subject_leaves_the_old_subjects_index() {
        let store = InMemoryAssertionStore::new();
        let class = constants::AUTHN_CONTEXT_PASSWORD;
        store
            .store_assertion(assertion("_a1", "alice", "_s1", class))
            .unwrap();
        // Same ID, now naming bob: alice must no longer see it.
        store
            .store_assertion(assertion("_a1", "bob", "_s2", class))
            .unwrap();
        assert!(store.assertions_for_subject("alice").unwrap().is_empty());
        assert_eq!(store.assertions_for_subject("bob").unwrap().len(), 1);
        assert_eq!(
            subject_value(&store.get_assertion("_a1").unwrap().unwrap()).as_deref(),
            Some("bob")
        );
        // Removing it leaves nothing behind in either index.
        store.remove_assertion("_a1").unwrap();
        assert!(store.assertions_for_subject("bob").unwrap().is_empty());
    }

    #[test]
    fn test_store_same_id_twice_does_not_duplicate_subject_index() {
        let store = InMemoryAssertionStore::new();
        let a = assertion("_a1", "alice", "_s1", constants::AUTHN_CONTEXT_PASSWORD);
        store.store_assertion(a.clone()).unwrap();
        // Re-storing the same assertion ID (e.g. an update) must not make
        // `assertions_for_subject` return it twice.
        store.store_assertion(a).unwrap();
        assert_eq!(store.assertions_for_subject("alice").unwrap().len(), 1);
    }

    #[test]
    fn test_assertion_id_request_response() {
        let store = InMemoryAssertionStore::new();
        store
            .store_assertion(assertion(
                "_a1",
                "alice",
                "_s1",
                constants::AUTHN_CONTEXT_PASSWORD,
            ))
            .unwrap();

        let request =
            create_assertion_id_request("https://sp.example.com", vec!["_a1".to_string()], None);
        let response =
            create_assertion_id_request_response(&store, &request, IDP, Utc::now()).unwrap();
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
        let response =
            create_assertion_id_request_response(&store, &request, IDP, Utc::now()).unwrap();
        assert!(!response.base.status.is_success());
        assert_eq!(
            response.base.status.status_code.value,
            constants::STATUS_REQUESTER
        );
    }

    #[test]
    fn test_authn_query_response_filters() {
        let store = InMemoryAssertionStore::new();
        store
            .store_assertion(assertion(
                "_a1",
                "alice",
                "_s1",
                constants::AUTHN_CONTEXT_PASSWORD,
            ))
            .unwrap();
        store
            .store_assertion(assertion(
                "_a2",
                "alice",
                "_s2",
                constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
            ))
            .unwrap();

        // No filters: both statements
        let query = create_authn_query(
            "https://sp.example.com",
            &name_id("alice"),
            None,
            None,
            None,
        );
        let response = create_authn_query_response(&store, &query, IDP, Utc::now()).unwrap();
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
        let response = create_authn_query_response(&store, &query, IDP, Utc::now()).unwrap();
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
        let response = create_authn_query_response(&store, &query, IDP, Utc::now()).unwrap();
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

    /// Verifies that an expired assertion cannot be reissued by AuthnQuery.
    #[test]
    fn test_authn_query_does_not_reissue_expired_statement() {
        let store = InMemoryAssertionStore::new();
        let mut expired = assertion(
            "_expired",
            "alice",
            "_session",
            constants::AUTHN_CONTEXT_PASSWORD,
        );
        expired.conditions.as_mut().unwrap().not_on_or_after =
            Some(Utc::now() - chrono::TimeDelta::seconds(1));
        store.store_assertion(expired).unwrap();
        let query = create_authn_query(
            "https://sp.example.com",
            &name_id("alice"),
            None,
            None,
            None,
        );
        let response = create_authn_query_response(&store, &query, IDP, Utc::now()).unwrap();
        assert!(!response.base.status.is_success());
        assert!(response.assertions.is_empty());
    }

    /// A backend whose index is keyed wrongly: it answers every subject query with
    /// one fixed subject's assertions, and every ID lookup with one fixed assertion.
    struct Misindexed {
        inner: InMemoryAssertionStore,
    }

    impl AssertionStore for Misindexed {
        fn store_assertion(&self, assertion: Assertion) -> Result<(), StoreError> {
            self.inner.store_assertion(assertion)
        }
        fn get_assertion(&self, _: &str) -> Result<Option<Assertion>, StoreError> {
            self.inner.get_assertion("_victim1")
        }
        fn assertions_for_subject(&self, _: &str) -> Result<Vec<Assertion>, StoreError> {
            self.inner.assertions_for_subject("victim")
        }
        fn remove_assertion(&self, id: &str) -> Result<(), StoreError> {
            self.inner.remove_assertion(id)
        }
    }

    fn misindexed() -> Misindexed {
        let inner = InMemoryAssertionStore::new();
        inner
            .store_assertion(assertion(
                "_victim1",
                "victim",
                "_sv",
                constants::AUTHN_CONTEXT_PASSWORD,
            ))
            .unwrap();
        Misindexed { inner }
    }

    #[test]
    fn a_store_that_answers_for_the_wrong_subject_is_refused() {
        let store = misindexed();
        let now = Utc::now();
        let err = get_authn_statements(&store, "mallory", None, &[], now).unwrap_err();
        assert!(
            err.to_string().contains("not for the requested subject"),
            "{err}"
        );

        // The same through the AuthnQuery responder.
        let query = create_authn_query(
            "https://sp.example.com",
            &name_id("mallory"),
            None,
            None,
            None,
        );
        assert!(create_authn_query_response(&store, &query, IDP, now).is_err());

        // The right subject is still answered.
        assert_eq!(
            get_authn_statements(&store, "victim", None, &[], now)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_store_that_returns_a_different_assertion_than_requested_is_refused() {
        let store = misindexed();
        let request =
            create_assertion_id_request("https://sp.example.com", vec!["_other".to_string()], None);
        let err =
            create_assertion_id_request_response(&store, &request, IDP, Utc::now()).unwrap_err();
        assert!(err.to_string().contains("different assertion"), "{err}");
    }
}
