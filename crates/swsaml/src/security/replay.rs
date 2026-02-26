// SAML 2.0 Replay cache
//
// Prevents assertion replay attacks by tracking previously seen assertion IDs.
// Per Profiles 4.1.4.5: Assertion ID must not have been previously used within
// the validity window.

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
    entries: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl InMemoryReplayCache {
    /// Create a new empty replay cache.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Get the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache for InMemoryReplayCache {
    fn check_and_insert(&self, id: &str, expiry: DateTime<Utc>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let now = Utc::now();

        // Check if the ID already exists and hasn't expired
        if let Some(existing_expiry) = entries.get(id) {
            if *existing_expiry > now {
                // ID exists and hasn't expired - this is a replay
                return false;
            }
            // ID exists but has expired - treat as new
        }

        // Insert/update the entry
        entries.insert(id.to_string(), expiry);
        true
    }

    fn cleanup(&self) {
        let mut entries = self.entries.lock().unwrap();
        let now = Utc::now();
        entries.retain(|_, expiry| *expiry > now);
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
        cache.check_and_insert("_expired", past_expiry);
        cache.check_and_insert("_valid", future_expiry);
        assert_eq!(cache.len(), 2);

        cache.cleanup();
        assert_eq!(cache.len(), 1);
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
