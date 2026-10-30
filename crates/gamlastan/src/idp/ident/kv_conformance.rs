//! A reusable check that a [`KeyValueStore`] backend honours the contract
//! [`Eptid`](crate::idp::Eptid)'s cache relies on.
//!
//! The cache remembers the identifier issued to a subject at an SP, so that a
//! later change of secret or digest cannot change what the SP already knows. A
//! cache that loses, mixes up or lags behind its own writes silently issues a
//! *different* identifier, which the SP maps to a different account. None of that
//! shows up in a unit test against a dict; it shows up under load, on a real
//! backend (Redis, a database), so run this against one in CI.
//!
//! Same shape as the [`IdentityStore`] suite in [`conformance`], whose
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
//! race between separate processes or instances is not detected. Eviction is
//! checked with a bounded number of keys ([`EVICTION_KEYS`]); a cache that evicts
//! only under memory pressure beyond that, or by TTL, needs its own configuration
//! review: **an issued identifier must never expire.**

use super::conformance::{ConformanceError, Options};
use super::*;
use std::fmt;
use std::sync::Arc;
use std::thread;

/// How many keys the eviction check writes and then reads back.
pub const EVICTION_KEYS: usize = 500;

/// The names of every check, in the order [`check`] runs them.
pub const CHECKS: &[&str] = &[
    "missing_key_is_none",
    "set_then_get_round_trips",
    "keys_are_exact",
    "remove_is_scoped",
    "values_are_not_evicted",
    "concurrent_writers_read_their_own_writes",
    "concurrent_writers_to_one_key_leave_a_whole_value",
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

fn get<S: KeyValueStore>(s: &S, key: &str) -> Result<Option<String>, String> {
    step("get", s.get(key))
}

fn set<S: KeyValueStore>(s: &S, key: &str, value: &str) -> Result<(), String> {
    step("set", s.set(key, value.to_string()))
}

type CheckFn<S> = fn(S, &Options) -> Outcome;

fn table<S: KeyValueStore + 'static>() -> Vec<(&'static str, CheckFn<S>)> {
    let table: Vec<(&'static str, CheckFn<S>)> = vec![
        ("missing_key_is_none", |s, _| missing_key_is_none(&s)),
        ("set_then_get_round_trips", |s, _| {
            set_then_get_round_trips(&s)
        }),
        ("keys_are_exact", |s, _| keys_are_exact(&s)),
        ("remove_is_scoped", |s, _| remove_is_scoped(&s)),
        ("values_are_not_evicted", |s, _| values_are_not_evicted(&s)),
        (
            "concurrent_writers_read_their_own_writes",
            concurrent_writers_read_their_own_writes,
        ),
        (
            "concurrent_writers_to_one_key_leave_a_whole_value",
            concurrent_writers_to_one_key_leave_a_whole_value,
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
    S: KeyValueStore + 'static,
    F: Fn() -> S,
{
    if let Err(e) = check(new_store) {
        panic!("{e}");
    }
}

/// Run every check with default [`Options`], returning the first violation.
pub fn check<S, F>(new_store: F) -> Result<(), ConformanceError>
where
    S: KeyValueStore + 'static,
    F: Fn() -> S,
{
    check_with(new_store, &Options::default())
}

/// Run every check, returning the first violation.
pub fn check_with<S, F>(new_store: F, options: &Options) -> Result<(), ConformanceError>
where
    S: KeyValueStore + 'static,
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
    S: KeyValueStore + 'static,
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

/// An absent key is `Ok(None)`: a cache miss, not an error.
fn missing_key_is_none<S: KeyValueStore>(s: &S) -> Outcome {
    ensure_eq!(
        get(s, "eptid:never-written")?,
        None,
        "a key that was never written must read as absent (Ok(None)), not as an \
         error or an empty value"
    );
    Ok(())
}

/// What was set is what is read back, and a later set replaces it. Values are
/// opaque strings.
fn set_then_get_round_trips<S: KeyValueStore>(s: &S) -> Outcome {
    set(s, "k", "first")?;
    ensure_eq!(
        get(s, "k")?,
        Some("first".to_string()),
        "a value must be readable immediately after it is set (read-your-writes; a \
         lagging replica or an asynchronous write fails this)"
    );
    set(s, "k", "second")?;
    ensure_eq!(
        get(s, "k")?,
        Some("second".to_string()),
        "a second set must replace the first"
    );
    let long = "x".repeat(64 * 1024);
    for value in [
        "",
        "https://idp.example!https://sp.example!abc",
        "åäö ✓ 日本語",
        &long,
    ] {
        set(s, "opaque", value)?;
        ensure_eq!(
            get(s, "opaque")?,
            Some(value.to_string()),
            "a value is an opaque string and must round-trip unchanged (length {})",
            value.len()
        );
    }
    Ok(())
}

/// A key means exactly itself: no case folding, no prefix matching, no
/// special-character handling. EPTID keys are
/// `eptid:<idp>__<sp>__<user>`, built from entity IDs and user identifiers.
fn keys_are_exact<S: KeyValueStore>(s: &S) -> Outcome {
    let keys = [
        "a",
        "A",
        "ab",
        "a ",
        " a",
        "a.b",
        "a$b",
        "a/b",
        "a:b",
        "a!b",
        "a__b",
        "a%62",
        "a\u{e5}",
        "\u{1f511}",
        "eptid:https://idp.example__https://sp.example__alice",
        "eptid:https://idp.example__https://sp.example__alice2",
        "eptid:https://idp.example__https://sp.example__Alice",
    ];
    for (i, key) in keys.iter().enumerate() {
        set(s, key, &format!("value-{i}"))?;
    }
    for (i, key) in keys.iter().enumerate() {
        ensure_eq!(
            get(s, key)?,
            Some(format!("value-{i}")),
            "key {key:?} must read back its own value: a key must not collide with \
             another that differs only in case, a prefix, whitespace or a special \
             character"
        );
    }
    // Every lookup above hits a stored key, so a backend that matches prefixes or
    // substrings can pass if it happens to meet the exact key first. These keys
    // were never written but are a prefix or a suffix of one that was.
    for probe in [
        "a_",
        "b",
        "_b",
        "eptid:https://idp.example__https://sp.example__ali",
        "ptid:https://idp.example__https://sp.example__alice",
    ] {
        debug_assert!(!keys.contains(&probe));
        ensure_eq!(
            get(s, probe)?,
            None,
            "key {probe:?} was never written but is a prefix or suffix of one that was: \
             a lookup must not match part of a key"
        );
    }
    Ok(())
}

/// `remove` drops that key only, and removing an absent key is not an error.
fn remove_is_scoped<S: KeyValueStore>(s: &S) -> Outcome {
    set(s, "keep", "1")?;
    set(s, "drop", "2")?;
    step("remove", s.remove("drop"))?;
    ensure_eq!(get(s, "drop")?, None, "a removed key must read as absent");
    ensure_eq!(
        get(s, "keep")?,
        Some("1".to_string()),
        "removing one key must not affect another"
    );
    step("remove", s.remove("never-written"))?;
    Ok(())
}

/// An issued identifier must not expire or be evicted: the cache exists so that
/// the SP keeps seeing the value it was first given. A cache with a size limit or
/// a TTL silently re-derives, and a re-derivation can differ.
fn values_are_not_evicted<S: KeyValueStore>(s: &S) -> Outcome {
    for i in 0..EVICTION_KEYS {
        set(s, &format!("evict:{i}"), &format!("value-{i}"))?;
    }
    for i in 0..EVICTION_KEYS {
        ensure_eq!(
            get(s, &format!("evict:{i}"))?,
            Some(format!("value-{i}")),
            "a value set earlier was lost after {EVICTION_KEYS} keys were written - \
             the cache evicts, and an evicted EPTID is re-derived (possibly differently)"
        );
    }
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

/// Concurrent writers on distinct keys each read back exactly what they wrote,
/// and nothing is lost.
fn concurrent_writers_read_their_own_writes<S>(store: S, options: &Options) -> Outcome
where
    S: KeyValueStore + 'static,
{
    let store = Arc::new(store);
    let threads = options.threads.max(2);
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<(), String> {
                let key = format!("writer:{t}");
                for round in 0..20 {
                    let value = format!("thread{t}-round{round}");
                    set(&*store, &key, &value)?;
                    let read = get(&*store, &key)?;
                    ensure_eq!(
                        read,
                        Some(value.clone()),
                        "thread {t} did not read back the value it had just written (round \
                         {round}) - writes are not visible to the writer, or another \
                         thread's write landed on this key"
                    );
                }
                Ok(())
            })
        })
        .collect();
    join_all(handles)?;
    for t in 0..threads {
        ensure_eq!(
            get(&*store, &format!("writer:{t}"))?,
            Some(format!("thread{t}-round19")),
            "a concurrent write was lost"
        );
    }
    Ok(())
}

/// Concurrent writers to one key leave one whole value, never a merge, a torn
/// value or an absent key.
fn concurrent_writers_to_one_key_leave_a_whole_value<S>(store: S, options: &Options) -> Outcome
where
    S: KeyValueStore + 'static,
{
    let store = Arc::new(store);
    let threads = options.threads.max(2);
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<(), String> {
                // Long enough that a non-atomic write could tear.
                set(&*store, "contended", &format!("{t}:").repeat(512))
            })
        })
        .collect();
    join_all(handles)?;
    let value = get(&*store, "contended")?;
    let whole = value
        .as_deref()
        .is_some_and(|v| (0..threads).any(|t| v == format!("{t}:").repeat(512)));
    ensure!(
        whole,
        "after concurrent writes to one key the value must be exactly one writer's value, \
         got {} bytes",
        value.map_or(0, |v| v.len())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn mem() -> InMemoryKeyValueStore {
        InMemoryKeyValueStore::new()
    }

    #[test]
    fn the_in_memory_store_passes_every_check() {
        run(mem);
    }

    /// A map behind a lock whose behaviour a test bends.
    #[derive(Default)]
    struct Bent {
        map: Mutex<HashMap<String, String>>,
        /// Fold the case of keys (a case-insensitive collation).
        fold_case: bool,
        /// Answer a lookup from any stored key that starts with the asked one.
        prefix_match: bool,
        /// Keep only the most recent N keys.
        capacity: Option<usize>,
        order: Mutex<Vec<String>>,
        /// `remove` does nothing.
        remove_is_noop: bool,
        /// A missing key is an error rather than `None` (a KeyError turned into one).
        error_on_missing: bool,
        /// Writes become visible only after the next write (a lagging replica).
        lag: bool,
        pending: Mutex<Vec<(String, String)>>,
        /// Reads and writes are two steps with a pause between (a torn update).
        merge_values: bool,
    }

    impl Bent {
        fn key(&self, k: &str) -> String {
            if self.fold_case {
                k.to_lowercase()
            } else {
                k.to_string()
            }
        }
    }

    impl KeyValueStore for Bent {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            let key = self.key(key);
            let map = self.map.lock().unwrap();
            if self.prefix_match {
                return Ok(map
                    .iter()
                    .find(|(stored, _)| stored.starts_with(&key))
                    .map(|(_, v)| v.clone()));
            }
            match map.get(&key) {
                Some(v) => Ok(Some(v.clone())),
                None if self.error_on_missing => Err(StoreError::new("KeyError")),
                None => Ok(None),
            }
        }
        fn set(&self, key: &str, value: String) -> Result<(), StoreError> {
            let key = self.key(key);
            if self.lag {
                // Apply what was written before, then queue this one.
                let mut pending = self.pending.lock().unwrap();
                let mut map = self.map.lock().unwrap();
                for (k, v) in pending.drain(..) {
                    map.insert(k, v);
                }
                pending.push((key, value));
                return Ok(());
            }
            let mut map = self.map.lock().unwrap();
            if self.merge_values {
                map.entry(key).or_default().push_str(&value);
                return Ok(());
            }
            if let Some(cap) = self.capacity {
                let mut order = self.order.lock().unwrap();
                order.retain(|k| *k != key);
                order.push(key.clone());
                while order.len() > cap {
                    let evicted = order.remove(0);
                    map.remove(&evicted);
                }
            }
            map.insert(key, value);
            Ok(())
        }
        fn remove(&self, key: &str) -> Result<(), StoreError> {
            if self.remove_is_noop {
                return Ok(());
            }
            self.map.lock().unwrap().remove(&self.key(key));
            Ok(())
        }
    }

    fn fails(check_name: &str, bend: fn() -> Bent) {
        let err = check_one(check_name, bend, &Options::default()).unwrap_err();
        assert_eq!(err.check, check_name, "{err}");
    }

    #[test]
    fn a_store_that_errors_on_a_missing_key_is_caught() {
        fails("missing_key_is_none", || Bent {
            error_on_missing: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_lagging_store_fails_read_your_writes() {
        fails("set_then_get_round_trips", || Bent {
            lag: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_store_that_folds_case_or_matches_prefixes_is_caught() {
        fails("keys_are_exact", || Bent {
            fold_case: true,
            ..Default::default()
        });
        fails("keys_are_exact", || Bent {
            prefix_match: true,
            ..Default::default()
        });
    }

    #[test]
    fn a_remove_that_does_nothing_is_caught() {
        fails("remove_is_scoped", || Bent {
            remove_is_noop: true,
            ..Default::default()
        });
    }

    #[test]
    fn an_evicting_store_is_caught() {
        fails("values_are_not_evicted", || Bent {
            capacity: Some(100),
            ..Default::default()
        });
    }

    #[test]
    fn a_store_that_merges_concurrent_values_is_caught() {
        fails("concurrent_writers_to_one_key_leave_a_whole_value", || {
            Bent {
                merge_values: true,
                ..Default::default()
            }
        });
    }

    #[test]
    fn an_unknown_check_name_lists_the_known_ones() {
        let err = check_one("no_such_check", mem, &Options::default()).unwrap_err();
        assert!(err.message.contains("known checks"), "{err}");
        assert_eq!(err.check, "check_one");
    }

    #[test]
    fn a_backend_failure_is_a_failed_check_not_a_panic() {
        struct Down;
        impl KeyValueStore for Down {
            fn get(&self, _: &str) -> Result<Option<String>, StoreError> {
                Err(StoreError::new("unreachable"))
            }
            fn set(&self, _: &str, _: String) -> Result<(), StoreError> {
                Err(StoreError::new("unreachable"))
            }
            fn remove(&self, _: &str) -> Result<(), StoreError> {
                Err(StoreError::new("unreachable"))
            }
        }
        let err = check(|| Down).unwrap_err();
        assert!(err.message.contains("unreachable"), "{err}");
    }
}
