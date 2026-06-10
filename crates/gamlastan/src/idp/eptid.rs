// eduPersonTargetedID generation (pysaml2 `Eptid` equivalent).
//
// Generates a deterministic, per-(IdP, SP, user) opaque identifier of the
// form `idp-entity-id!sp-entity-id!hash` and caches it in a pluggable
// store so the same subject always receives the same value.
//
// Divergence from pysaml2: the hash is SHA-256 instead of MD5, so the
// generated values differ from a pysaml2 deployment with the same secret
// (they are stable within gamlastan). MD5 is avoided on principle; if you
// migrate from pysaml2, import the previously issued values into the
// store instead of recomputing them.

use crate::attribute_map::eptid_attribute;
use crate::core::assertion::attribute::Attribute;
use crate::core::assertion::name_id::NameId;
use crate::core::constants;
use crate::crypto::digest::sha256;
use crate::idp::ident::{to_hex, IdentityStore, InMemoryIdentityStore};

/// eduPersonTargetedID generator (pysaml2 `Eptid`).
pub struct Eptid<S: IdentityStore = InMemoryIdentityStore> {
    secret: String,
    store: S,
}

impl Eptid<InMemoryIdentityStore> {
    /// Create a generator with an in-memory cache.
    pub fn new(secret: impl Into<String>) -> Self {
        Eptid::with_store(InMemoryIdentityStore::new(), secret)
    }
}

impl<S: IdentityStore> Eptid<S> {
    /// Create a generator over a custom store (pysaml2 `EptidShelve`
    /// analogue — back it with Redis/SQL for persistence).
    pub fn with_store(store: S, secret: impl Into<String>) -> Self {
        Eptid {
            secret: secret.into(),
            store,
        }
    }

    fn make(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> String {
        let mut input = Vec::new();
        input.extend_from_slice(user_id.as_bytes());
        input.extend_from_slice(sp_entity_id.as_bytes());
        input.extend_from_slice(self.secret.as_bytes());
        let digest = sha256(&input).expect("SHA-256 is always available");
        format!("{idp_entity_id}!{sp_entity_id}!{}", to_hex(&digest))
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
