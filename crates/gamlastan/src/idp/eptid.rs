// eduPersonTargetedID generation (pysaml2 `Eptid` equivalent).
//
// Generates a deterministic, per-(IdP, SP, user) opaque identifier of the
// form `idp-entity-id!sp-entity-id!hash` and caches it in a pluggable
// store so the same subject always receives the same value.
//
// Divergence from pysaml2: the default hash is SHA-256 instead of MD5, so the
// generated values differ from a pysaml2 deployment with the same secret
// (they are stable within gamlastan). A guarded PySAML2 MD5 compatibility mode
// exists for migrations that must keep already-issued identifiers byte-stable;
// prefer importing previously issued values into the store when possible.

use crate::attribute_map::eptid_attribute;
use crate::core::assertion::attribute::Attribute;
use crate::core::assertion::name_id::NameId;
use crate::core::constants;
use crate::crypto::digest::sha256;
use crate::idp::ident::{to_hex, IdentityStore, InMemoryIdentityStore};

use md5::{Digest, Md5};

/// Digest profile used for generated EPTID values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EptidDigest {
    /// gamlastan default: SHA-256 over `user_id || sp_entity_id || secret`.
    #[default]
    Sha256,
    /// Legacy PySAML2 formula: MD5 over `user_id || sp_entity_id || secret`.
    ///
    /// This exists only for migration compatibility with already-issued
    /// EPTIDs. Constructors reject it unless `allow_legacy_md5` is set.
    Pysaml2Md5Legacy,
}

/// EPTID generation options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptidOptions {
    /// Digest profile to use.
    pub digest: EptidDigest,
    /// Required guard for [`EptidDigest::Pysaml2Md5Legacy`].
    pub allow_legacy_md5: bool,
}

impl Default for EptidOptions {
    fn default() -> Self {
        Self {
            digest: EptidDigest::Sha256,
            allow_legacy_md5: false,
        }
    }
}

impl EptidOptions {
    /// Default SHA-256 EPTID generation.
    pub fn sha256() -> Self {
        Self::default()
    }

    /// PySAML2 MD5 EPTID compatibility.
    ///
    /// Pass `allow_legacy_md5 = true` only for a deliberate compatibility
    /// profile. The constructor still validates the guard.
    pub fn pysaml2_md5_legacy(allow_legacy_md5: bool) -> Self {
        Self {
            digest: EptidDigest::Pysaml2Md5Legacy,
            allow_legacy_md5,
        }
    }
}

/// EPTID configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EptidConfigError {
    /// Legacy MD5 was requested without the explicit guard.
    #[error("legacy PySAML2 MD5 EPTID requires allow_legacy_md5 = true")]
    LegacyMd5RequiresExplicitAllow,
}

/// eduPersonTargetedID generator (pysaml2 `Eptid`).
pub struct Eptid<S: IdentityStore = InMemoryIdentityStore> {
    secret: String,
    store: S,
    options: EptidOptions,
}

impl Eptid<InMemoryIdentityStore> {
    /// Create a generator with an in-memory cache.
    pub fn new(secret: impl Into<String>) -> Self {
        Eptid::with_store(InMemoryIdentityStore::new(), secret)
    }

    /// Create a generator with explicit options and an in-memory cache.
    pub fn try_new_with_options(
        secret: impl Into<String>,
        options: EptidOptions,
    ) -> Result<Self, EptidConfigError> {
        Eptid::try_with_store_options(InMemoryIdentityStore::new(), secret, options)
    }
}

impl<S: IdentityStore> Eptid<S> {
    /// Create a generator over a custom store (pysaml2 `EptidShelve`
    /// analogue — back it with Redis/SQL for persistence).
    pub fn with_store(store: S, secret: impl Into<String>) -> Self {
        Eptid {
            secret: secret.into(),
            store,
            options: EptidOptions::default(),
        }
    }

    /// Create a generator over a custom store with explicit options.
    pub fn try_with_store_options(
        store: S,
        secret: impl Into<String>,
        options: EptidOptions,
    ) -> Result<Self, EptidConfigError> {
        validate_options(options)?;
        Ok(Eptid {
            secret: secret.into(),
            store,
            options,
        })
    }

    fn make(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> String {
        let mut input = Vec::new();
        input.extend_from_slice(user_id.as_bytes());
        input.extend_from_slice(sp_entity_id.as_bytes());
        input.extend_from_slice(self.secret.as_bytes());
        let hash = match self.options.digest {
            EptidDigest::Sha256 => {
                let digest = sha256(&input).expect("SHA-256 is always available");
                to_hex(&digest)
            }
            EptidDigest::Pysaml2Md5Legacy => {
                let mut digest = Md5::new();
                digest.update(&input);
                to_hex(digest.finalize().as_ref())
            }
        };
        format!("{idp_entity_id}!{sp_entity_id}!{hash}")
    }

    fn cache_key(idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> String {
        format!("eptid:{idp_entity_id}__{sp_entity_id}__{user_id}")
    }

    /// Get (or create and remember) the eduPersonTargetedID value for a
    /// subject at an SP (pysaml2 `Eptid.get()`).
    pub fn get(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> String {
        let key = Self::cache_key(idp_entity_id, sp_entity_id, user_id);
        if let Some(cached) = self.store.get(&key) {
            return cached;
        }
        let value = self.make(idp_entity_id, sp_entity_id, user_id);
        self.store.set(&key, value.clone());
        value
    }

    /// The EPTID as a persistent NameID (the canonical wire form:
    /// NameQualifier = IdP, SPNameQualifier = SP).
    pub fn name_id(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> NameId {
        NameId {
            value: self.get(idp_entity_id, sp_entity_id, user_id),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(idp_entity_id.to_string()),
            sp_name_qualifier: Some(sp_entity_id.to_string()),
            sp_provided_id: None,
        }
    }

    /// The EPTID as a complete NameID-valued `saml:Attribute`.
    pub fn attribute(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> Attribute {
        eptid_attribute(vec![self.name_id(idp_entity_id, sp_entity_id, user_id)])
    }
}

fn validate_options(options: EptidOptions) -> Result<(), EptidConfigError> {
    if options.digest == EptidDigest::Pysaml2Md5Legacy && !options.allow_legacy_md5 {
        return Err(EptidConfigError::LegacyMd5RequiresExplicitAllow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const IDP: &str = "https://idp.example.com";
    const SP: &str = "https://sp.example.com";

    #[derive(Clone, Default)]
    struct SharedStore {
        map: Arc<Mutex<HashMap<String, String>>>,
    }

    impl IdentityStore for SharedStore {
        fn get(&self, key: &str) -> Option<String> {
            self.map.lock().unwrap().get(key).cloned()
        }

        fn set(&self, key: &str, value: String) {
            self.map.lock().unwrap().insert(key.to_string(), value);
        }

        fn remove(&self, key: &str) {
            self.map.lock().unwrap().remove(key);
        }
    }

    #[test]
    fn test_deterministic_and_cached() {
        let eptid = Eptid::new("s3cr3t");
        let a = eptid.get(IDP, SP, "alice");
        let b = eptid.get(IDP, SP, "alice");
        assert_eq!(a, b);
        assert!(a.starts_with(&format!("{IDP}!{SP}!")));
    }

    #[test]
    fn test_differs_per_sp_and_user() {
        let eptid = Eptid::new("s3cr3t");
        let a = eptid.get(IDP, SP, "alice");
        let other_sp = eptid.get(IDP, "https://other.example.com", "alice");
        let bob = eptid.get(IDP, SP, "bob");
        assert_ne!(a, other_sp);
        assert_ne!(a, bob);
    }

    #[test]
    fn test_differs_per_secret() {
        let one = Eptid::new("one").get(IDP, SP, "alice");
        let two = Eptid::new("two").get(IDP, SP, "alice");
        assert_ne!(one, two);
    }

    #[test]
    fn test_legacy_md5_requires_explicit_guard() {
        let err =
            match Eptid::try_new_with_options("s3cr3t", EptidOptions::pysaml2_md5_legacy(false)) {
                Ok(_) => panic!("legacy MD5 without guard should fail"),
                Err(err) => err,
            };
        assert_eq!(err, EptidConfigError::LegacyMd5RequiresExplicitAllow);
    }

    #[test]
    fn test_legacy_md5_matches_pysaml2_eptid() {
        let eptid =
            Eptid::try_new_with_options("s3cr3t", EptidOptions::pysaml2_md5_legacy(true)).unwrap();
        assert_eq!(
            eptid.get(IDP, SP, "alice"),
            "https://idp.example.com!https://sp.example.com!f6ecff9c9e19881f47d0078989d14d59"
        );
    }

    #[test]
    fn test_shared_store_keeps_idps_separate() {
        let store = SharedStore::default();
        let first = Eptid::with_store(store.clone(), "s3cr3t");
        let second = Eptid::with_store(store, "s3cr3t");

        let a = first.get(IDP, SP, "alice");
        let b = second.get("https://idp2.example.com", SP, "alice");

        assert_ne!(a, b);
        assert!(a.starts_with(&format!("{IDP}!{SP}!")));
        assert!(b.starts_with("https://idp2.example.com!https://sp.example.com!"));
    }

    #[test]
    fn test_name_id_and_attribute_form() {
        let eptid = Eptid::new("s3cr3t");
        let nid = eptid.name_id(IDP, SP, "alice");
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_PERSISTENT));
        assert_eq!(nid.name_qualifier.as_deref(), Some(IDP));
        assert_eq!(nid.sp_name_qualifier.as_deref(), Some(SP));

        let attr = eptid.attribute(IDP, SP, "alice");
        assert_eq!(attr.name, crate::attribute_map::EPTID_OID);
        assert_eq!(attr.values.len(), 1);
    }
}
