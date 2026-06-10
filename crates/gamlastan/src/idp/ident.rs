// IdP identity database: NameID generation and management
// (pysaml2 `IdentDB` equivalent).
//
// Maintains the bidirectional mapping between local user ids and the
// NameIDs issued to relying parties, generates transient/persistent
// NameIDs honoring an incoming `NameIDPolicy`, and implements the server
// side of the ManageNameID and NameIDMapping profiles on top of it.
//
// The storage backend is pluggable via `IdentityStore`; the in-memory
// implementation suits single-instance deployments and tests.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;

use crate::core::assertion::name_id::{NameId, NameIdPolicy};
use crate::core::constants;
use crate::core::protocol::name_id_mgmt::NewIdOrTerminate;
use crate::crypto::digest::sha256;

/// Errors from identity-database operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentError {
    /// The NameID is not associated with any local principal.
    #[error("unknown NameID: no local principal for '{0}'")]
    UnknownNameId(String),

    /// The NameIDPolicy forbids creating a new identifier (AllowCreate).
    #[error("NameIDPolicy does not allow creating a new identifier")]
    CreateNotAllowed,

    /// No NameID format could be determined.
    #[error("no NameID format requested and no default configured")]
    NoFormat,

    /// The operation is not supported (e.g. NewEncryptedID).
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
}

/// Pluggable key/value backend for the identity database.
///
/// Implement this over Redis/SQL/etc. for multi-instance deployments.
pub trait IdentityStore: Send + Sync {
    /// Fetch a value.
    fn get(&self, key: &str) -> Option<String>;
    /// Store a value.
    fn set(&self, key: &str, value: String);
    /// Remove a value.
    fn remove(&self, key: &str);
}

/// In-memory identity store.
#[derive(Debug, Default)]
pub struct InMemoryIdentityStore {
    map: Mutex<HashMap<String, String>>,
}

impl InMemoryIdentityStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for InMemoryIdentityStore {
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

// ── NameID coding (pysaml2 `code()` / `decode()`) ──────────────────────────

const CODE_FIELDS: usize = 5;

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            ' ' => out.push_str("%20"),
            ',' => out.push_str("%2C"),
            '=' => out.push_str("%3D"),
            _ => out.push(c),
        }
    }
    out
}

fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }

        let Some(a) = chars.next() else {
            out.push('%');
            break;
        };
        let Some(b) = chars.next() else {
            out.push('%');
            out.push(a);
            break;
        };

        match (a.to_ascii_uppercase(), b.to_ascii_uppercase()) {
            ('2', '0') => out.push(' '),
            ('2', '5') => out.push('%'),
            ('2', 'C') => out.push(','),
            ('3', 'D') => out.push('='),
            _ => {
                out.push('%');
                out.push(a);
                out.push(b);
            }
        }
    }

    out
}

/// Serialize a NameID into the compact storage form
/// (`index=value` pairs, comma separated; pysaml2-compatible field order).
pub fn code_name_id(name_id: &NameId) -> String {
    let fields: [Option<&str>; CODE_FIELDS] = [
        name_id.name_qualifier.as_deref(),
        name_id.sp_name_qualifier.as_deref(),
        name_id.format.as_deref(),
        name_id.sp_provided_id.as_deref(),
        Some(name_id.value.as_str()),
    ];
    fields
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            v.filter(|v| !v.is_empty())
                .map(|v| format!("{i}={}", quote(v)))
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse the compact storage form back into a NameID.
pub fn decode_name_id(coded: &str) -> NameId {
    let mut fields: [Option<String>; CODE_FIELDS] = Default::default();
    for part in coded.split(',') {
        if let Some((idx, value)) = part.split_once('=') {
            if let Ok(i) = idx.parse::<usize>() {
                if i < CODE_FIELDS {
                    fields[i] = Some(unquote(value));
                }
            }
        }
    }
    let [name_qualifier, sp_name_qualifier, format, sp_provided_id, value] = fields;
    NameId {
        value: value.unwrap_or_default(),
        format,
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    }
}

// ── IdentDb ─────────────────────────────────────────────────────────────────

const FORWARD_PREFIX: &str = "user:";
const REVERSE_PREFIX: &str = "nameid:";

/// The identity database (pysaml2 `IdentDB`).
pub struct IdentDb<S: IdentityStore = InMemoryIdentityStore> {
    store: S,
    /// The IdP entity ID, used as the default NameQualifier.
    name_qualifier: String,
    /// Domain appended to generated email-format NameIDs.
    domain: Option<String>,
}

impl IdentDb<InMemoryIdentityStore> {
    /// Create an in-memory identity database.
    pub fn in_memory(idp_entity_id: impl Into<String>) -> Self {
        IdentDb::new(InMemoryIdentityStore::new(), idp_entity_id)
    }
}

impl<S: IdentityStore> IdentDb<S> {
    /// Create an identity database over a custom store.
    pub fn new(store: S, idp_entity_id: impl Into<String>) -> Self {
        IdentDb {
            store,
            name_qualifier: idp_entity_id.into(),
            domain: None,
        }
    }

    /// Set the domain used for email-format NameIDs.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    fn forward_key(user_id: &str) -> String {
        format!("{FORWARD_PREFIX}{user_id}")
    }

    fn reverse_key(value: &str) -> String {
        format!("{REVERSE_PREFIX}{value}")
    }

    /// All NameIDs stored for a local user.
    pub fn name_ids_for(&self, user_id: &str) -> Vec<NameId> {
        self.store
            .get(&Self::forward_key(user_id))
            .map(|joined| joined.split(' ').map(decode_name_id).collect())
            .unwrap_or_default()
    }

    /// Associate a NameID with a local user (pysaml2 `store()`).
    ///
    /// Maintains both directions: user -> issued NameIDs (forward) and
    /// NameID value -> user (reverse, used by `find_local_id`).
    pub fn store(&self, user_id: &str, name_id: &NameId) {
        let coded = code_name_id(name_id);
        let key = Self::forward_key(user_id);
        let mut entries: Vec<String> = self
            .store
            .get(&key)
            .map(|joined| joined.split(' ').map(str::to_string).collect())
            .unwrap_or_default();
        if !entries.contains(&coded) {
            entries.push(coded);
        }
        self.store.set(&key, entries.join(" "));
        self.store
            .set(&Self::reverse_key(&name_id.value), user_id.to_string());
    }

    /// The local user a NameID was issued to (pysaml2 `find_local_id()`).
    pub fn find_local_id(&self, name_id: &NameId) -> Option<String> {
        self.store.get(&Self::reverse_key(&name_id.value))
    }

    /// Find an existing non-transient NameID for (user, SP, IdP)
    /// (pysaml2 `match_local_id()`).
    pub fn match_local_id(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Option<NameId> {
        self.name_ids_for(user_id).into_iter().find(|nid| {
            if nid.format.as_deref() == Some(constants::NAMEID_TRANSIENT) {
                return false;
            }
            let sp_match = match sp_name_qualifier {
                Some(spq) => nid.sp_name_qualifier.as_deref() == Some(spq),
                None => nid.sp_name_qualifier.is_none(),
            };
            let nq_match = match name_qualifier {
                Some(nq) => nid.name_qualifier.as_deref() == Some(nq),
                None => nid.name_qualifier.is_none(),
            };
            sp_match && nq_match
        })
    }

    /// Generate a fresh opaque identifier value (pysaml2 `create_id()`).
    fn create_id(
        &self,
        format: &str,
        name_qualifier: Option<&str>,
        sp_name_qualifier: Option<&str>,
    ) -> String {
        loop {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            let mut input = seed.to_vec();
            input.extend_from_slice(format.as_bytes());
            input.extend_from_slice(name_qualifier.unwrap_or("").as_bytes());
            input.extend_from_slice(sp_name_qualifier.unwrap_or("").as_bytes());
            let digest = sha256(&input).expect("SHA-256 is always available");
            let id = to_hex(&digest);
            // Build the final stored value (email format appends `@domain`)
            // *before* the collision check, otherwise the check tests a key
            // that is never stored and a rare collision would silently
            // overwrite the reverse mapping.
            let value = if format == constants::NAMEID_EMAIL {
                let domain = self.domain.as_deref().unwrap_or("idp.example.org");
                format!("{id}@{domain}")
            } else {
                id
            };
            if self.store.get(&Self::reverse_key(&value)).is_none() {
                return value;
            }
        }
    }

    /// Create and store a new NameID of the given format
    /// (pysaml2 `get_nameid()`); persistent format reuses an existing
    /// association when one exists.
    pub fn get_nameid(
        &self,
        user_id: &str,
        format: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> NameId {
        // Persistent identifiers must stay stable per (user, SP): reuse an
        // existing association instead of minting a new value (E78).
        if format == constants::NAMEID_PERSISTENT {
            if let Some(existing) = self.match_local_id(user_id, sp_name_qualifier, name_qualifier)
            {
                return existing;
            }
        }

        // `create_id` already applies the email-format `@domain` suffix and
        // guarantees the value is free in the reverse index.
        let value = self.create_id(format, name_qualifier, sp_name_qualifier);

        let name_id = NameId {
            value,
            format: Some(format.to_string()),
            name_qualifier: name_qualifier.map(str::to_string),
            sp_name_qualifier: sp_name_qualifier.map(str::to_string),
            sp_provided_id: None,
        };
        self.store(user_id, &name_id);
        name_id
    }

    /// Generate a transient NameID (pysaml2 `transient_nameid()`).
    pub fn transient_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
        self.get_nameid(
            user_id,
            constants::NAMEID_TRANSIENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Get-or-create a persistent NameID (pysaml2 `persistent_nameid()`).
    pub fn persistent_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
        self.get_nameid(
            user_id,
            constants::NAMEID_PERSISTENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Construct a NameID for `user_id` honoring the request's
    /// `NameIDPolicy` (pysaml2 `construct_nameid()`).
    ///
    /// - Format: `NameIDPolicy/@Format`, else `default_format` (typically
    ///   from the [release policy](crate::idp::policy::ReleasePolicy)).
    /// - SPNameQualifier: `NameIDPolicy/@SPNameQualifier`, else the SP
    ///   entity ID.
    /// - NameQualifier: this IdP's entity ID.
    /// - AllowCreate (E14): when false, only an existing identifier may be
    ///   returned for the persistent format.
    pub fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError> {
        let format = name_id_policy
            .and_then(|p| p.format.as_deref())
            .or(default_format)
            .ok_or(IdentError::NoFormat)?;
        let sp_name_qualifier = name_id_policy
            .and_then(|p| p.sp_name_qualifier.as_deref())
            .unwrap_or(sp_entity_id);

        if format == constants::NAMEID_PERSISTENT {
            let allow_create = name_id_policy.map(|p| p.allow_create).unwrap_or(false);
            let existing = self.match_local_id(
                user_id,
                Some(sp_name_qualifier),
                Some(self.name_qualifier.as_str()),
            );
            match existing {
                Some(nid) => return Ok(nid),
                None if !allow_create => return Err(IdentError::CreateNotAllowed),
                None => {}
            }
        }

        Ok(self.get_nameid(
            user_id,
            format,
            Some(sp_name_qualifier),
            Some(self.name_qualifier.as_str()),
        ))
    }

    /// Forget a NameID (pysaml2 `remove_remote()`).
    pub fn remove_remote(&self, name_id: &NameId) {
        let coded = code_name_id(name_id);
        if let Some(user_id) = self.find_local_id(name_id) {
            let key = Self::forward_key(&user_id);
            if let Some(joined) = self.store.get(&key) {
                let remaining: Vec<&str> = joined.split(' ').filter(|c| *c != coded).collect();
                if remaining.is_empty() {
                    self.store.remove(&key);
                } else {
                    self.store.set(&key, remaining.join(" "));
                }
            }
        }
        self.store.remove(&Self::reverse_key(&name_id.value));
    }

    /// Forget every NameID for a local user (pysaml2 `remove_local()`).
    pub fn remove_local(&self, user_id: &str) {
        for nid in self.name_ids_for(user_id) {
            self.store.remove(&Self::reverse_key(&nid.value));
        }
        self.store.remove(&Self::forward_key(user_id));
    }

    /// Apply a ManageNameIDRequest to the database (pysaml2
    /// `handle_manage_name_id_request()`); returns the updated NameID.
    ///
    /// - `NewID`: record the SP-provided identifier (`SPProvidedID`).
    /// - `Terminate`: drop the SP-provided identifier and terminate the
    ///   association for federation purposes.
    pub fn handle_manage_name_id_request(
        &self,
        name_id: &NameId,
        operation: &NewIdOrTerminate,
    ) -> Result<NameId, IdentError> {
        let user_id = self
            .find_local_id(name_id)
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let mut updated = name_id.clone();
        match operation {
            NewIdOrTerminate::NewId(new_id) => {
                updated.sp_provided_id = Some(new_id.clone());
            }
            NewIdOrTerminate::NewEncryptedId(_) => {
                return Err(IdentError::Unsupported(
                    "NewEncryptedID requires decryption before calling \
                     handle_manage_name_id_request",
                ));
            }
            NewIdOrTerminate::Terminate => {
                updated.sp_provided_id = None;
                self.remove_remote(name_id);
                return Ok(updated);
            }
        }

        self.remove_remote(name_id);
        self.store(&user_id, &updated);
        Ok(updated)
    }

    /// Resolve a NameIDMappingRequest against the database (pysaml2
    /// `handle_name_id_mapping_request()`).
    ///
    /// Returns an existing NameID matching the requested policy, or
    /// creates one when `AllowCreate` permits.
    pub fn handle_name_id_mapping_request(
        &self,
        name_id: &NameId,
        name_id_policy: &NameIdPolicy,
    ) -> Result<NameId, IdentError> {
        let user_id = self
            .find_local_id(name_id)
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let wanted_format = name_id_policy.format.as_deref();
        let wanted_spq = name_id_policy.sp_name_qualifier.as_deref();
        if let Some(existing) = self.name_ids_for(&user_id).into_iter().find(|nid| {
            (wanted_format.is_none() || nid.format.as_deref() == wanted_format)
                && (wanted_spq.is_none() || nid.sp_name_qualifier.as_deref() == wanted_spq)
        }) {
            return Ok(existing);
        }

        if !name_id_policy.allow_create {
            return Err(IdentError::CreateNotAllowed);
        }

        let format = wanted_format.unwrap_or(constants::NAMEID_PERSISTENT);
        Ok(self.get_nameid(
            &user_id,
            format,
            wanted_spq,
            Some(self.name_qualifier.as_str()),
        ))
    }
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDP: &str = "https://idp.example.com";
    const SP: &str = "https://sp.example.com";

    fn db() -> IdentDb {
        IdentDb::in_memory(IDP)
    }

    #[test]
    fn test_code_decode_roundtrip() {
        let nid = NameId {
            value: "abc %25,=%123".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            sp_provided_id: Some("sp alias %25".to_string()),
        };
        let coded = code_name_id(&nid);
        assert!(!coded.contains(' '));
        let back = decode_name_id(&coded);
        assert_eq!(back, nid);
    }

    #[test]
    fn test_store_roundtrip_with_space_in_name_id_fields() {
        let db = db();
        let nid = NameId {
            value: "Alice Smith %25".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            sp_provided_id: Some("sp alias".to_string()),
        };

        db.store("alice", &nid);

        assert_eq!(db.name_ids_for("alice"), vec![nid.clone()]);
        assert_eq!(db.find_local_id(&nid).as_deref(), Some("alice"));
    }

    #[test]
    fn test_transient_unique_each_time() {
        let db = db();
        let a = db.transient_nameid("alice", Some(SP));
        let b = db.transient_nameid("alice", Some(SP));
        assert_ne!(a.value, b.value);
        assert_eq!(a.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        assert_eq!(db.find_local_id(&a).as_deref(), Some("alice"));
        assert_eq!(db.find_local_id(&b).as_deref(), Some("alice"));
    }

    #[test]
    fn test_persistent_is_stable() {
        let db = db();
        let a = db.persistent_nameid("alice", Some(SP));
        let b = db.persistent_nameid("alice", Some(SP));
        assert_eq!(a.value, b.value);
        // different SP gets a different persistent id
        let c = db.persistent_nameid("alice", Some("https://other.example.com"));
        assert_ne!(a.value, c.value);
    }

    #[test]
    fn test_construct_nameid_honors_policy_format() {
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&policy), None)
            .unwrap();
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        assert_eq!(nid.sp_name_qualifier.as_deref(), Some(SP));
        assert_eq!(nid.name_qualifier.as_deref(), Some(IDP));
    }

    #[test]
    fn test_construct_nameid_default_format() {
        let db = db();
        let nid = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .unwrap_err();
        // persistent + no policy => allow_create false => no new id
        assert!(matches!(nid, IdentError::CreateNotAllowed));
    }

    #[test]
    fn test_construct_persistent_allow_create_e14() {
        let db = db();
        let no_create = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        };
        assert!(matches!(
            db.construct_nameid("alice", SP, Some(&no_create), None),
            Err(IdentError::CreateNotAllowed)
        ));

        let create = NameIdPolicy {
            allow_create: true,
            ..no_create.clone()
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&create), None)
            .unwrap();

        // E14: with AllowCreate=false an *existing* identifier may be used
        let again = db
            .construct_nameid("alice", SP, Some(&no_create), None)
            .unwrap();
        assert_eq!(nid.value, again.value);
    }

    #[test]
    fn test_no_format_error() {
        let db = db();
        assert!(matches!(
            db.construct_nameid("alice", SP, None, None),
            Err(IdentError::NoFormat)
        ));
    }

    #[test]
    fn test_remove_remote_and_local() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP));
        db.remove_remote(&nid);
        assert!(db.find_local_id(&nid).is_none());
        assert!(db.name_ids_for("alice").is_empty());

        let n1 = db.persistent_nameid("alice", Some(SP));
        let n2 = db.transient_nameid("alice", Some(SP));
        db.remove_local("alice");
        assert!(db.find_local_id(&n1).is_none());
        assert!(db.find_local_id(&n2).is_none());
    }

    #[test]
    fn test_manage_name_id_new_id_and_terminate() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP));

        let updated = db
            .handle_manage_name_id_request(&nid, &NewIdOrTerminate::NewId("sp-alias".to_string()))
            .unwrap();
        assert_eq!(updated.sp_provided_id.as_deref(), Some("sp-alias"));
        assert_eq!(db.find_local_id(&updated).as_deref(), Some("alice"));
        let stored = db.match_local_id("alice", Some(SP), Some(IDP)).unwrap();
        assert_eq!(stored.sp_provided_id.as_deref(), Some("sp-alias"));

        db.handle_manage_name_id_request(&updated, &NewIdOrTerminate::Terminate)
            .unwrap();
        assert!(db.find_local_id(&updated).is_none());
    }

    #[test]
    fn test_manage_name_id_unknown() {
        let db = db();
        let stranger = NameId {
            value: "nobody".to_string(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        assert!(matches!(
            db.handle_manage_name_id_request(&stranger, &NewIdOrTerminate::Terminate),
            Err(IdentError::UnknownNameId(_))
        ));
    }

    #[test]
    fn test_name_id_mapping() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP));

        // Map to another SP, creation allowed
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: Some("https://other.example.com".to_string()),
            allow_create: true,
        };
        let mapped = db.handle_name_id_mapping_request(&nid, &policy).unwrap();
        assert_eq!(
            mapped.sp_name_qualifier.as_deref(),
            Some("https://other.example.com")
        );
        assert_ne!(mapped.value, nid.value);

        // Second request returns the same mapping
        let mapped2 = db.handle_name_id_mapping_request(&nid, &policy).unwrap();
        assert_eq!(mapped.value, mapped2.value);

        // Creation forbidden for a third SP
        let strict = NameIdPolicy {
            sp_name_qualifier: Some("https://third.example.com".to_string()),
            allow_create: false,
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
        };
        assert!(matches!(
            db.handle_name_id_mapping_request(&nid, &strict),
            Err(IdentError::CreateNotAllowed)
        ));
    }

    #[test]
    fn test_email_format_uses_domain() {
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP));
        assert!(nid.value.ends_with("@example.org"));
    }

    #[test]
    fn test_email_format_reverse_mapping_uses_full_value() {
        // The collision check and the reverse index must both key on the
        // final `local-part@domain` value, so the issued email NameID resolves
        // back to its local principal.
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP));
        assert!(nid.value.contains('@'));
        assert_eq!(db.find_local_id(&nid).as_deref(), Some("alice"));
    }
}
