//! A reusable check that an [`AssertionStore`] backend honours the contract the
//! IdP's back-channel responders and logout code rely on.
//!
//! The store records every issued assertion so that an AssertionIDRequest, an
//! AuthnQuery and a logout can find it again. A backend that returns the wrong
//! subject's assertions, keeps a stale index after an assertion is stored again
//! or removed, or loses entries under concurrent writes answers a query about one
//! subject with another's authentication statements. None of that shows up in a
//! unit test against a dict; it shows up on a real backend (Redis, a database),
//! so run this against one in CI.
//!
//! Same shape as the [`IdentityStore`](crate::idp::ident::IdentityStore) suite in
//! [`ident::conformance`](crate::idp::ident::conformance), whose
//! [`ConformanceError`] and [`Options`] it reuses:
//!
//! - [`run`] panics with a description of the first violated rule.
//! - [`check`] / [`check_with`] return the first violation as a
//!   [`ConformanceError`], for a caller that is not a Rust test.
//! - [`check_one`] runs a single check by name; [`CHECKS`] lists the names.
//!
//! `new_store` must return a **fresh, empty** store on every call: each check gets
//! its own.
//!
//! # What this does and does not prove
//!
//! The concurrent checks race threads against one store instance. A backend that
//! serialises every call can pass them without being safe across processes, and a
//! race between separate processes or instances is not detected. Real backends
//! may round timestamps, so assertions are compared by identity, subject and
//! authentication statement, not field for field.

use super::*;
use crate::core::assertion::authn::AuthnContext;
use crate::core::assertion::name_id::NameId;
use crate::idp::ident::conformance::{ConformanceError, Options};
use std::fmt;
use std::sync::Arc;
use std::thread;

const IDP: &str = "https://idp.example.com";

/// The names of every check, in the order [`check`] runs them.
pub const CHECKS: &[&str] = &[
    "missing_assertion_is_absent",
    "store_then_get_round_trips",
    "subject_lookup_is_exact_and_isolated",
    "storing_an_id_again_does_not_duplicate_it",
    "storing_an_id_for_another_subject_moves_it",
    "remove_is_scoped_and_clears_the_subject_index",
    "concurrent_stores_lose_nothing",
    "concurrent_stores_of_one_id_leave_it_under_one_subject",
];

type Outcome = Result<(), String>;

/// Fail the check with a message unless `cond` holds.
macro_rules! ensure {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(format!($($msg)+));
        }
    };
}

/// Fail the check, showing both values, unless `left == right`.
macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($msg:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!(
                "{} (got {left:?}, expected {right:?})",
                format!($($msg)+)
            ));
        }
    }};
}

/// A backend call that failed is a failed check, naming the operation.
fn step<T, E: fmt::Display>(what: &str, result: Result<T, E>) -> Result<T, String> {
    result.map_err(|e| format!("backend call `{what}` failed: {e}"))
}

fn fixture(id: &str, subject: &str, session_index: &str) -> Assertion {
    Assertion {
        id: id.to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        issuer: Issuer::entity(IDP),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: subject.to_string(),
                format: Some(constants::NAMEID_PERSISTENT.to_string()),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
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
                authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
                authn_context_decl_ref: None,
                authenticating_authorities: vec![],
            },
        }],
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    }
}

fn store<S: AssertionStore>(s: &S, a: Assertion) -> Result<(), String> {
    step("store_assertion", s.store_assertion(a))
}

fn ids_for<S: AssertionStore>(s: &S, subject: &str) -> Result<Vec<String>, String> {
    let mut ids: Vec<String> = step("assertions_for_subject", s.assertions_for_subject(subject))?
        .into_iter()
        .map(|a| a.id)
        .collect();
    ids.sort();
    Ok(ids)
}

type CheckFn<S> = fn(S, &Options) -> Outcome;

fn table<S: AssertionStore + 'static>() -> Vec<(&'static str, CheckFn<S>)> {
    let table: Vec<(&'static str, CheckFn<S>)> = vec![
        ("missing_assertion_is_absent", |s, _| {
            missing_assertion_is_absent(&s)
        }),
        ("store_then_get_round_trips", |s, _| {
            store_then_get_round_trips(&s)
        }),
        ("subject_lookup_is_exact_and_isolated", |s, _| {
            subject_lookup_is_exact_and_isolated(&s)
        }),
        ("storing_an_id_again_does_not_duplicate_it", |s, _| {
            storing_an_id_again_does_not_duplicate_it(&s)
        }),
        ("storing_an_id_for_another_subject_moves_it", |s, _| {
            storing_an_id_for_another_subject_moves_it(&s)
        }),
        ("remove_is_scoped_and_clears_the_subject_index", |s, _| {
            remove_is_scoped_and_clears_the_subject_index(&s)
        }),
        (
            "concurrent_stores_lose_nothing",
            concurrent_stores_lose_nothing,
        ),
        (
            "concurrent_stores_of_one_id_leave_it_under_one_subject",
            concurrent_stores_of_one_id_leave_it_under_one_subject,
        ),
    ];
    debug_assert_eq!(
        table.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        CHECKS
    );
    table
}

/// Run every check against stores produced by `new_store`, panicking with a
/// description of the first violated rule.
pub fn run<S, F>(new_store: F)
where
    S: AssertionStore + 'static,
    F: Fn() -> S,
{
    if let Err(e) = check(new_store) {
        panic!("{e}");
    }
}

/// Run every check with default [`Options`], returning the first violation.
pub fn check<S, F>(new_store: F) -> Result<(), ConformanceError>
where
    S: AssertionStore + 'static,
    F: Fn() -> S,
{
    check_with(new_store, &Options::default())
}

/// Run every check, returning the first violation.
pub fn check_with<S, F>(new_store: F, options: &Options) -> Result<(), ConformanceError>
where
    S: AssertionStore + 'static,
    F: Fn() -> S,
{
    for (check, run) in table::<S>() {
        run(new_store(), options).map_err(|message| ConformanceError { check, message })?;
    }
    Ok(())
}

/// Run the single check called `name` (one of [`CHECKS`]) against a store from
/// `new_store`. An unknown name is an error that lists the known ones.
pub fn check_one<S, F>(name: &str, new_store: F, options: &Options) -> Result<(), ConformanceError>
where
    S: AssertionStore + 'static,
    F: Fn() -> S,
{
    match table::<S>().into_iter().find(|(n, _)| *n == name) {
        Some((check, run)) => {
            run(new_store(), options).map_err(|message| ConformanceError { check, message })
        }
        None => Err(ConformanceError {
            check: "check_one",
            message: format!("no check named {name:?}; known checks: {CHECKS:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

/// Nothing stored means nothing found, and removing nothing is not an error.
fn missing_assertion_is_absent<S: AssertionStore>(s: &S) -> Outcome {
    ensure!(
        step("get_assertion", s.get_assertion("_never"))?.is_none(),
        "an assertion that was never stored must read as absent (Ok(None))"
    );
    ensure_eq!(
        ids_for(s, "nobody")?,
        Vec::<String>::new(),
        "a subject with no assertions must yield an empty list, not an error"
    );
    step("remove_assertion", s.remove_assertion("_never"))?;
    Ok(())
}

/// What was stored is found by its ID, readable immediately.
fn store_then_get_round_trips<S: AssertionStore>(s: &S) -> Outcome {
    store(s, fixture("_a1", "alice", "_s1"))?;
    let got = step("get_assertion", s.get_assertion("_a1"))?;
    let Some(got) = got else {
        return Err(
            "an assertion must be readable immediately after it is stored \
                    (read-your-writes; a lagging replica fails this)"
                .to_string(),
        );
    };
    ensure_eq!(
        got.id,
        "_a1".to_string(),
        "the assertion returned has a different ID"
    );
    ensure_eq!(
        subject_value(&got),
        Some("alice".to_string()),
        "the assertion's subject was altered"
    );
    ensure_eq!(
        got.authn_statements
            .first()
            .and_then(|st| st.session_index.clone()),
        Some("_s1".to_string()),
        "the assertion's authentication statement was altered"
    );
    Ok(())
}

/// A subject lookup returns that subject's assertions only: not another
/// subject's, and not one whose subject merely shares a prefix or differs in case.
fn subject_lookup_is_exact_and_isolated<S: AssertionStore>(s: &S) -> Outcome {
    store(s, fixture("_a1", "alice", "_s1"))?;
    store(s, fixture("_a2", "alice", "_s2"))?;
    store(s, fixture("_b1", "bob", "_s3"))?;
    store(s, fixture("_p1", "alice2", "_s4"))?;
    store(s, fixture("_c1", "Alice", "_s5"))?;
    ensure_eq!(
        ids_for(s, "alice")?,
        vec!["_a1".to_string(), "_a2".to_string()],
        "a subject lookup must return exactly that subject's assertions - not another \
         subject's, and not one that only shares a prefix or differs in case"
    );
    ensure_eq!(
        ids_for(s, "bob")?,
        vec!["_b1".to_string()],
        "bob's assertions"
    );
    ensure_eq!(
        ids_for(s, "ali")?,
        Vec::<String>::new(),
        "a prefix of a subject is not that subject"
    );
    Ok(())
}

/// Storing the same ID twice replaces it; it is not listed twice.
fn storing_an_id_again_does_not_duplicate_it<S: AssertionStore>(s: &S) -> Outcome {
    store(s, fixture("_a1", "alice", "_s1"))?;
    store(s, fixture("_a1", "alice", "_s1"))?;
    ensure_eq!(
        ids_for(s, "alice")?,
        vec!["_a1".to_string()],
        "storing an assertion ID twice must not list it twice"
    );
    Ok(())
}

/// An ID names one assertion. Storing it again for a different subject moves it:
/// the old subject must no longer be answered with an assertion issued to someone
/// else.
fn storing_an_id_for_another_subject_moves_it<S: AssertionStore>(s: &S) -> Outcome {
    store(s, fixture("_a1", "alice", "_s1"))?;
    store(s, fixture("_a1", "bob", "_s2"))?;
    ensure_eq!(
        ids_for(s, "alice")?,
        Vec::<String>::new(),
        "an ID stored again for another subject must leave the old subject's index: a \
         lookup for the old subject returned an assertion issued to someone else"
    );
    ensure_eq!(
        ids_for(s, "bob")?,
        vec!["_a1".to_string()],
        "the assertion must be listed under its new subject"
    );
    Ok(())
}

/// `remove_assertion` drops that assertion everywhere, and nothing else.
fn remove_is_scoped_and_clears_the_subject_index<S: AssertionStore>(s: &S) -> Outcome {
    store(s, fixture("_a1", "alice", "_s1"))?;
    store(s, fixture("_a2", "alice", "_s2"))?;
    step("remove_assertion", s.remove_assertion("_a1"))?;
    ensure!(
        step("get_assertion", s.get_assertion("_a1"))?.is_none(),
        "a removed assertion must read as absent"
    );
    ensure_eq!(
        ids_for(s, "alice")?,
        vec!["_a2".to_string()],
        "a removed assertion must also leave its subject's list, and the others must stay"
    );
    Ok(())
}

fn join_all<T>(handles: Vec<thread::JoinHandle<Result<T, String>>>) -> Result<Vec<T>, String> {
    handles
        .into_iter()
        .map(|h| {
            h.join()
                .map_err(|_| "a worker thread panicked".to_string())?
        })
        .collect()
}

/// Concurrent stores for one subject all land: the subject index is not a
/// read-modify-write that loses entries.
fn concurrent_stores_lose_nothing<S>(store: S, options: &Options) -> Outcome
where
    S: AssertionStore + 'static,
{
    let store = Arc::new(store);
    let n = options.threads.max(2);
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<(), String> {
                step(
                    "store_assertion",
                    store.store_assertion(fixture(&format!("_c{i}"), "alice", "_s")),
                )
            })
        })
        .collect();
    join_all(handles)?;
    ensure_eq!(
        ids_for(&*store, "alice")?.len(),
        n,
        "concurrent stores for one subject lost entries - the subject index is updated \
         with a non-atomic read-modify-write"
    );
    Ok(())
}

/// Concurrent stores of one ID under different subjects leave it under exactly
/// one subject, the one `get_assertion` reports: the two indexes agree.
fn concurrent_stores_of_one_id_leave_it_under_one_subject<S>(store: S, options: &Options) -> Outcome
where
    S: AssertionStore + 'static,
{
    let store = Arc::new(store);
    let n = options.threads.max(2);
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<(), String> {
                step(
                    "store_assertion",
                    store.store_assertion(fixture("_contested", &format!("user{i}"), "_s")),
                )
            })
        })
        .collect();
    join_all(handles)?;
    let mut holders = Vec::new();
    for i in 0..n {
        if ids_for(&*store, &format!("user{i}"))?.contains(&"_contested".to_string()) {
            holders.push(format!("user{i}"));
        }
    }
    ensure_eq!(
        holders.len(),
        1,
        "an ID stored concurrently under different subjects must end up under exactly \
         one subject (the indexes disagree)"
    );
    let stored = step("get_assertion", store.get_assertion("_contested"))?;
    ensure_eq!(
        stored.as_ref().and_then(subject_value),
        Some(holders[0].clone()),
        "get_assertion and the subject index disagree about who the assertion is for"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn the_in_memory_store_passes_every_check() {
        run(InMemoryAssertionStore::new);
    }

    /// The pre-fix design: two maps under two locks, bent by flags.
    #[derive(Default)]
    struct Bent {
        by_id: Mutex<HashMap<String, Assertion>>,
        by_subject: Mutex<HashMap<String, Vec<String>>>,
        /// Do not unindex the old subject when an ID is stored again.
        stale_index: bool,
        /// Push the ID again even if listed.
        duplicate: bool,
        /// Match subjects by prefix.
        prefix_subject: bool,
        /// `remove_assertion` does nothing.
        remove_is_noop: bool,
        /// A missing assertion is an error.
        error_on_missing: bool,
        /// Read the index, pause, write it back (a lost update).
        lossy_index: bool,
    }

    impl AssertionStore for Bent {
        fn store_assertion(&self, assertion: Assertion) -> Result<(), StoreError> {
            let id = assertion.id.clone();
            let subject = subject_value(&assertion).unwrap();
            let previous = self.by_id.lock().unwrap().insert(id.clone(), assertion);
            if !self.stale_index {
                if let Some(old) = previous.as_ref().and_then(subject_value) {
                    let mut idx = self.by_subject.lock().unwrap();
                    if let Some(ids) = idx.get_mut(&old) {
                        ids.retain(|i| *i != id);
                    }
                }
            }
            if self.lossy_index {
                let mut ids = self
                    .by_subject
                    .lock()
                    .unwrap()
                    .get(&subject)
                    .cloned()
                    .unwrap_or_default();
                std::thread::sleep(std::time::Duration::from_millis(15));
                ids.push(id);
                self.by_subject.lock().unwrap().insert(subject, ids);
                return Ok(());
            }
            let mut idx = self.by_subject.lock().unwrap();
            let ids = idx.entry(subject).or_default();
            if self.duplicate || !ids.contains(&id) {
                ids.push(id);
            }
            Ok(())
        }
        fn get_assertion(&self, id: &str) -> Result<Option<Assertion>, StoreError> {
            let found = self.by_id.lock().unwrap().get(id).cloned();
            if found.is_none() && self.error_on_missing {
                return Err(StoreError::new("KeyError"));
            }
            Ok(found)
        }
        fn assertions_for_subject(&self, subject: &str) -> Result<Vec<Assertion>, StoreError> {
            let idx = self.by_subject.lock().unwrap();
            let by_id = self.by_id.lock().unwrap();
            let mut out = Vec::new();
            for (key, ids) in idx.iter() {
                let hit = if self.prefix_subject {
                    key.starts_with(subject)
                } else {
                    key == subject
                };
                if hit {
                    out.extend(ids.iter().filter_map(|id| by_id.get(id).cloned()));
                }
            }
            Ok(out)
        }
        fn remove_assertion(&self, id: &str) -> Result<(), StoreError> {
            if self.remove_is_noop {
                return Ok(());
            }
            self.by_id.lock().unwrap().remove(id);
            for ids in self.by_subject.lock().unwrap().values_mut() {
                ids.retain(|i| i != id);
            }
            Ok(())
        }
    }

    fn fails(name: &str, bend: fn() -> Bent) {
        let err = check_one(name, bend, &Options::default()).unwrap_err();
        assert_eq!(err.check, name, "{err}");
    }

    #[test]
    fn a_stale_subject_index_is_caught() {
        fails("storing_an_id_for_another_subject_moves_it", || Bent {
            stale_index: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_duplicating_index_is_caught() {
        // `stale_index` stops the old entry being unindexed first, which would
        // otherwise collapse the duplicate.
        fails("storing_an_id_again_does_not_duplicate_it", || Bent {
            duplicate: true,
            stale_index: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_prefix_matching_subject_lookup_is_caught() {
        fails("subject_lookup_is_exact_and_isolated", || Bent {
            prefix_subject: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_remove_that_does_nothing_is_caught() {
        fails("remove_is_scoped_and_clears_the_subject_index", || Bent {
            remove_is_noop: true,
            ..Default::default()
        });
    }

    #[test]
    fn an_error_on_a_missing_assertion_is_caught() {
        fails("missing_assertion_is_absent", || Bent {
            error_on_missing: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_lossy_subject_index_loses_concurrent_stores() {
        fails("concurrent_stores_lose_nothing", || Bent {
            lossy_index: true,
            ..Default::default()
        });
    }

    #[test]
    fn an_unknown_check_name_lists_the_known_ones() {
        let err = check_one(
            "no_such_check",
            InMemoryAssertionStore::new,
            &Options::default(),
        )
        .unwrap_err();
        assert!(err.message.contains("known checks"), "{err}");
    }
}
