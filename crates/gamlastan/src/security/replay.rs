//! Replay cache support for SAML assertion IDs.
//!
//! SAML Web SSO requires assertion IDs to be single-use within their validity
//! window. [`ReplayCache`] is the storage abstraction used by
//! [`crate::security::AssertionValidator`]. [`InMemoryReplayCache`] is suitable
//! for tests and single-process deployments; multi-instance deployments should
//! implement the trait over shared storage.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for replay detection caches.
///
/// Implementations must be safe for concurrent use (the trait requires no
/// specific threading guarantee, but the `InMemoryReplayCache` uses a Mutex).
pub trait ReplayCache: Send + Sync {
    /// Check if the given ID has been seen before, and if not, insert it
    /// with the given expiry time.
    ///
    /// Returns `true` if the ID is new (not a replay).
    /// Returns `false` if the ID was already seen (replay detected).
    fn check_and_insert(&self, id: &str, expiry: DateTime<Utc>) -> bool;

    /// Remove expired entries from the cache.
    fn cleanup(&self);
}

/// In-memory replay cache using a HashMap protected by a Mutex.
///
/// Suitable for single-process deployments. For distributed systems,
/// implement `ReplayCache` with Redis/Memcached/database backing.
pub struct InMemoryReplayCache {
    state: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    entries: HashMap<String, DateTime<Utc>>,
    next_expiry: Option<DateTime<Utc>>,
}

impl InMemoryReplayCache {
    /// Create a new empty replay cache.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ReplayState::default()),
        }
    }

    /// Get the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.state.lock().unwrap().entries.is_empty()
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(&self, id: &str, expiry: DateTime<Utc>) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Utc::now();

        // Ready handlers insert automatically but do not have a maintenance
        // loop. Use the earliest known expiry to avoid scanning the live map on
        // every insertion while still pruning expired distinct IDs promptly.
        if state.next_expiry.is_some_and(|next| next <= now) {
            state
                .entries
                .retain(|_, existing_expiry| *existing_expiry > now);
            state.next_expiry = state.entries.values().copied().min();
        }

        // Check if the ID already exists and hasn't expired
        if let Some(existing_expiry) = state.entries.get(id) {
            if *existing_expiry > now {
                // ID exists and hasn't expired - this is a replay
                return false;
            }
            // ID exists but has expired - treat as new
        }

        // Insert/update the entry
        state.entries.insert(id.to_string(), expiry);
        state.next_expiry = Some(state.next_expiry.map_or(expiry, |next| next.min(expiry)));
        true
    }

    fn cleanup(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Utc::now();
        state.entries.retain(|_, expiry| *expiry > now);
        state.next_expiry = state.entries.values().copied().min();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn test_new_id_accepted() {
        let cache = InMemoryReplayCache::new();
        let expiry = Utc::now() + TimeDelta::seconds(300);
        assert!(cache.check_and_insert("_assertion_1", expiry));
    }

    #[test]
    fn test_duplicate_id_rejected() {
        let cache = InMemoryReplayCache::new();
        let expiry = Utc::now() + TimeDelta::seconds(300);
        assert!(cache.check_and_insert("_assertion_1", expiry));
        assert!(!cache.check_and_insert("_assertion_1", expiry));
    }

    #[test]
    fn test_different_ids_accepted() {
        let cache = InMemoryReplayCache::new();
        let expiry = Utc::now() + TimeDelta::seconds(300);
        assert!(cache.check_and_insert("_assertion_1", expiry));
        assert!(cache.check_and_insert("_assertion_2", expiry));
    }

    #[test]
    fn test_expired_id_reaccepted() {
        let cache = InMemoryReplayCache::new();
        // Insert with an already-expired time
        let past_expiry = Utc::now() - TimeDelta::seconds(10);
        assert!(cache.check_and_insert("_assertion_1", past_expiry));
        // Same ID should be accepted again because the previous entry expired
        let future_expiry = Utc::now() + TimeDelta::seconds(300);
        assert!(cache.check_and_insert("_assertion_1", future_expiry));
    }

    #[test]
    fn test_cleanup_removes_expired() {
        let cache = InMemoryReplayCache::new();
        let past_expiry = Utc::now() - TimeDelta::seconds(10);
        let future_expiry = Utc::now() + TimeDelta::seconds(300);
        cache.check_and_insert("_valid", future_expiry);
        cache.check_and_insert("_expired", past_expiry);
        assert_eq!(cache.len(), 2);

        cache.cleanup();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insertion_prunes_distinct_expired_ids() {
        let cache = InMemoryReplayCache::new();
        let past_expiry = Utc::now() - TimeDelta::seconds(10);
        let future_expiry = Utc::now() + TimeDelta::seconds(300);
        cache.check_and_insert("_expired_1", past_expiry);
        cache.check_and_insert("_expired_2", past_expiry);
        cache.check_and_insert("_valid", future_expiry);

        assert_eq!(cache.len(), 1);
        assert!(!cache.check_and_insert("_valid", future_expiry));
    }

    #[test]
    fn test_empty_cache() {
        let cache = InMemoryReplayCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_default() {
        let cache = InMemoryReplayCache::default();
        assert!(cache.is_empty());
    }
}
