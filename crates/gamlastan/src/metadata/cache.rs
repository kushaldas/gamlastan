// SAML 2.0 Metadata - Caching
//
// Per saml-metadata-2.0-os Section 4.3 (with E94 corrections)
//
// E94: Cache staleness != validity.
// - cacheDuration controls re-fetch timing.
// - validUntil controls metadata validity.
// - Stale metadata (past cacheDuration but before validUntil) remains valid and MAY be used.
// - Invalid metadata (past validUntil) MUST NOT be used.
//
// E76: For nested elements, smaller value takes precedence.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::types::entity_descriptor::EntityDescriptor;

/// Cached metadata entry, tracking fetch time and metadata.
///
/// Separates cache staleness from validity per E94.
#[derive(Debug, Clone)]
pub struct CachedMetadata {
    /// The metadata itself.
    pub metadata: EntityDescriptor,
    /// When the metadata was fetched.
    pub fetched_at: DateTime<Utc>,
    /// The cache duration, if specified.
    pub cache_duration: Option<Duration>,
    /// The valid-until datetime, if specified.
    pub valid_until: Option<DateTime<Utc>>,
}

impl CachedMetadata {
    /// Create a new cached metadata entry.
    pub fn new(
        metadata: EntityDescriptor,
        fetched_at: DateTime<Utc>,
        cache_duration: Option<Duration>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        CachedMetadata {
            metadata,
            fetched_at,
            cache_duration,
            valid_until,
        }
    }

    /// Check if the cached metadata is stale (past cacheDuration) per E94.
    ///
    /// Stale metadata MAY still be used if it is valid (validUntil not reached).
    pub fn is_cache_stale(&self, now: DateTime<Utc>) -> bool {
        if let Some(duration) = self.cache_duration {
            let stale_at = self.fetched_at + duration;
            now >= stale_at
        } else {
            // No cacheDuration => never stale based on duration alone
            false
        }
    }

    /// Check if the metadata is valid (not past validUntil) per E94.
    ///
    /// Invalid metadata MUST NOT be used.
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        if let Some(valid_until) = self.valid_until {
            now < valid_until
        } else {
            // No validUntil => metadata remains valid indefinitely
            true
        }
    }

    /// Check if the metadata should be refreshed.
    ///
    /// Returns true if either stale or invalid.
    pub fn should_refresh(&self, now: DateTime<Utc>) -> bool {
        self.is_cache_stale(now) || !self.is_valid(now)
    }
}

/// Trait for metadata storage backends.
pub trait MetadataStore {
    /// Get cached metadata for an entity ID.
    fn get(&self, entity_id: &str) -> Option<&CachedMetadata>;

    /// Store metadata for an entity ID.
    fn put(&mut self, entity_id: String, metadata: CachedMetadata);

    /// Remove metadata for an entity ID.
    fn remove(&mut self, entity_id: &str) -> Option<CachedMetadata>;

    /// Remove all expired metadata.
    fn purge_expired(&mut self, now: DateTime<Utc>);
}

/// In-memory metadata cache.
#[derive(Debug, Default)]
pub struct MetadataCache {
    entries: HashMap<String, CachedMetadata>,
}

impl MetadataCache {
    /// Create a new empty metadata cache.
    pub fn new() -> Self {
        MetadataCache {
            entries: HashMap::new(),
        }
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl MetadataStore for MetadataCache {
    fn get(&self, entity_id: &str) -> Option<&CachedMetadata> {
        self.entries.get(entity_id)
    }

    fn put(&mut self, entity_id: String, metadata: CachedMetadata) {
        self.entries.insert(entity_id, metadata);
    }

    fn remove(&mut self, entity_id: &str) -> Option<CachedMetadata> {
        self.entries.remove(entity_id)
    }

    fn purge_expired(&mut self, now: DateTime<Utc>) {
        self.entries.retain(|_, cached| cached.is_valid(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use chrono::TimeZone;

    fn dummy_entity(entity_id: &str) -> EntityDescriptor {
        EntityDescriptor {
            entity_id: entity_id.to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        }
    }

    #[test]
    fn test_cache_stale_not_invalid() {
        // E94: stale but still valid metadata
        let fetched_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let valid_until = Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap();
        let cache_duration = Duration::from_secs(3600); // 1 hour

        let cached = CachedMetadata::new(
            dummy_entity("https://example.com"),
            fetched_at,
            Some(cache_duration),
            Some(valid_until),
        );

        // 2 hours after fetch: stale but valid
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 2, 0, 0).unwrap();
        assert!(cached.is_cache_stale(now));
        assert!(cached.is_valid(now));
        assert!(cached.should_refresh(now));
    }

    #[test]
    fn test_cache_not_stale_not_invalid() {
        let fetched_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let valid_until = Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap();
        let cache_duration = Duration::from_secs(3600);

        let cached = CachedMetadata::new(
            dummy_entity("https://example.com"),
            fetched_at,
            Some(cache_duration),
            Some(valid_until),
        );

        // 30 minutes after fetch: not stale, valid
        let now = Utc.with_ymd_and_hms(2025, 1, 1, 0, 30, 0).unwrap();
        assert!(!cached.is_cache_stale(now));
        assert!(cached.is_valid(now));
        assert!(!cached.should_refresh(now));
    }

    #[test]
    fn test_cache_invalid() {
        let fetched_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let valid_until = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();

        let cached = CachedMetadata::new(
            dummy_entity("https://example.com"),
            fetched_at,
            None,
            Some(valid_until),
        );

        // After validUntil: invalid, MUST NOT be used
        let now = Utc.with_ymd_and_hms(2025, 7, 1, 0, 0, 0).unwrap();
        assert!(!cached.is_cache_stale(now)); // no cache duration => not stale
        assert!(!cached.is_valid(now)); // past validUntil => invalid
    }

    #[test]
    fn test_cache_no_expiry() {
        let fetched_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let cached =
            CachedMetadata::new(dummy_entity("https://example.com"), fetched_at, None, None);

        let now = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        assert!(!cached.is_cache_stale(now));
        assert!(cached.is_valid(now));
    }

    #[test]
    fn test_metadata_cache_basic() {
        let mut cache = MetadataCache::new();
        assert!(cache.is_empty());

        let now = Utc::now();
        cache.put(
            "https://example.com".to_string(),
            CachedMetadata::new(dummy_entity("https://example.com"), now, None, None),
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.get("https://example.com").is_some());
        assert!(cache.get("https://other.com").is_none());
    }

    #[test]
    fn test_metadata_cache_purge() {
        let mut cache = MetadataCache::new();
        let now = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();

        // Entity 1: valid
        let valid = Utc.with_ymd_and_hms(2025, 12, 31, 0, 0, 0).unwrap();
        cache.put(
            "valid".to_string(),
            CachedMetadata::new(dummy_entity("valid"), now, None, Some(valid)),
        );

        // Entity 2: expired
        let expired = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        cache.put(
            "expired".to_string(),
            CachedMetadata::new(dummy_entity("expired"), now, None, Some(expired)),
        );

        assert_eq!(cache.len(), 2);
        cache.purge_expired(now);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("valid").is_some());
        assert!(cache.get("expired").is_none());
    }
}
