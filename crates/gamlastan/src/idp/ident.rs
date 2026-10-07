// IdP identity database: NameID generation and management
// (pysaml2 `IdentDB` equivalent).
//
// Maintains the bidirectional mapping between local user ids and the
// NameIDs issued to relying parties, generates transient/persistent
// NameIDs honoring an incoming `NameIDPolicy`, and implements the server
// side of the ManageNameID and NameIDMapping profiles on top of it.
//
// Transient NameIDs are minted fresh on every issuance and, by default, are
// *not* persisted to the store: per SAML Core §8.3.7 a transient identifier is
// one-time-use and MUST NOT be reused, so it has no reverse-lookup need in the
// SSO flow. Persisting them would grow the identity store without bound (the
// default per-SP format is transient, so every response would add an entry
// that is never read back). Persistent and other durable formats are stored.
// A deployment whose back-channel logout must resolve a transient NameID to its
// user opts in with `IdentDb::with_persist_transient`.
//
// The storage backend is pluggable via `IdentityStore`; the in-memory
// implementation suits single-instance deployments and tests.

use std::collections::HashMap;
use std::sync::Mutex;

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

    /// The storage backend failed. This is an operational fault, not a
    /// refusal: callers must not turn it into a protocol denial.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// A durable (non-transient) NameID of this format already exists for this
    /// user and `(SPNameQualifier, NameQualifier)`; a second cannot be recorded.
    #[error(
        "a NameID of this format already exists for this user and (SPNameQualifier, NameQualifier)"
    )]
    DurableExists,

    /// The NameID value already belongs to a different user. A record is never
    /// moved from one user to another: that would let the second user log in as
    /// the first at every SP that has seen the value.
    #[error("the NameID value already belongs to a different user")]
    ValueTaken,
}

impl From<InsertError> for IdentError {
    /// For [`IdentityStore::replace`], which conflicts on the durable tuple or on
    /// a value another user holds.
    fn from(e: InsertError) -> Self {
        match e {
            InsertError::DurableExists => IdentError::DurableExists,
            InsertError::ValueTaken => IdentError::ValueTaken,
            InsertError::Store(e) => IdentError::Store(e),
        }
    }
}

/// How many fresh values `IdentDb` mints before giving up on a backend that
/// keeps rejecting them. A real collision of 256-bit values does not happen, so
/// reaching this means the backend is broken, and looping on it would hold the
/// request thread forever.
const MAX_MINT_ATTEMPTS: usize = 8;

fn mint_exhausted(why: &str) -> StoreError {
    StoreError::new(format!(
        "could not mint an unused NameID in {MAX_MINT_ATTEMPTS} attempts: {why}"
    ))
}

/// A storage backend failed (connection lost, timeout, query error, ...).
///
/// Distinct from a *conflict*: a NameID value that is already taken is an
/// expected outcome of the uniqueness constraints and is reported as
/// [`InsertError::ValueTaken`], which callers retry with a fresh value (a bounded
/// number of times). A
/// `StoreError` is never retried blindly; it means the store could not answer,
/// and treating it as "not found" would, for example, mint a second
/// "stable" persistent identifier for a user who already has one.
#[derive(Debug, thiserror::Error)]
#[error("store backend error: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    /// Wrap a backend error.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        StoreError(source.into())
    }
}

/// Why an insert into an [`IdentityStore`] did not happen.
#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    /// The NameID value is already in use by another record.
    #[error("NameID value already in use")]
    ValueTaken,
    /// The record is durable (any format except transient), and the user
    /// already has a record of the same format for the same
    /// `(SPNameQualifier, NameQualifier)`. There can be only one:
    /// `get_or_insert_durable` is how to obtain it.
    #[error(
        "a NameID of this format already exists for this user and (SPNameQualifier, NameQualifier)"
    )]
    DurableExists,
    /// The backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Criteria for [`IdentityStore::find`] (pysaml2 `IdentDB.find_nameid`).
///
/// A `None` field matches any record. A `Some` field requires the record's
/// field to equal it exactly, so a record that lacks the field does not match.
/// This differs from [`IdentityStore::find_durable`], where a `None`
/// qualifier means "the record has no such qualifier".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameIdFilter {
    /// Required NameID format.
    pub format: Option<String>,
    /// Required `SPNameQualifier`.
    pub sp_name_qualifier: Option<String>,
    /// Required `NameQualifier`.
    pub name_qualifier: Option<String>,
    /// Required `SPProvidedID`.
    pub sp_provided_id: Option<String>,
}

impl NameIdFilter {
    /// Whether `name_id` satisfies every field that is set.
    pub fn matches(&self, name_id: &NameId) -> bool {
        fn ok(wanted: &Option<String>, actual: &Option<String>) -> bool {
            wanted
                .as_deref()
                .is_none_or(|w| actual.as_deref() == Some(w))
        }
        // An absent format is `unspecified`.
        let format_ok = self
            .format
            .as_deref()
            .is_none_or(|w| effective_format(name_id) == w);
        format_ok
            && ok(&self.sp_name_qualifier, &name_id.sp_name_qualifier)
            && ok(&self.name_qualifier, &name_id.name_qualifier)
            && ok(&self.sp_provided_id, &name_id.sp_provided_id)
    }
}

/// Plain key/value backend.
///
/// Used where a mapping needs no cross-record atomicity, such as
/// [`Eptid`](crate::idp::Eptid)'s deterministic eduPersonTargetedID cache.
/// NameID storage needs stronger guarantees and uses [`IdentityStore`].
pub trait KeyValueStore: Send + Sync {
    /// Fetch a value.
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    /// Store a value.
    fn set(&self, key: &str, value: String) -> Result<(), StoreError>;
    /// Remove a value.
    fn remove(&self, key: &str) -> Result<(), StoreError>;
}

/// In-memory [`KeyValueStore`].
#[derive(Debug, Default)]
pub struct InMemoryKeyValueStore {
    map: Mutex<HashMap<String, String>>,
}

impl InMemoryKeyValueStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyValueStore for InMemoryKeyValueStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: String) -> Result<(), StoreError> {
        self.map.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Pluggable backend for [`IdentDb`]: one record per (user, NameID)
/// association.
///
/// Implement this over your database (Mongo, SQL, ...). Each method is a
/// single-record operation, so there is nothing to coordinate across keys or
/// documents: atomicity comes from two uniqueness constraints the backend
/// must enforce.
///
/// * the NameID **value** is unique across all records, and
/// * among **durable** records - every format except transient - `(user,
///   sp_name_qualifier, name_qualifier, format)` is unique.
///
/// Without them, two concurrent first requests for the same (user, SP, format)
/// can both insert and mint two different "stable" identifiers, and nothing in
/// this crate can detect it - they must be real constraints in the store (a
/// unique index, a `UNIQUE` constraint, partial on `format != transient`), not
/// application-level checks. Transient records are exempt: they are
/// one-time-use, and `IdentDb::with_persist_transient` may store many. Run [`conformance`] against a real instance to check a backend.
///
/// There are deliberately no default write methods: a non-atomic default
/// would silently leave those races open on a multi-instance deployment.
///
/// Every method is fallible. A backend that cannot answer must return
/// [`StoreError`], never an empty result: "no record" and "could not look"
/// are different answers, and conflating them would mint a second durable
/// identifier for a user who already has one.
pub trait IdentityStore: Send + Sync {
    /// Every NameID associated with `user_id`, in unspecified order.
    fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError>;

    /// The user a NameID value belongs to.
    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError>;

    /// Every NameID of `user_id` that satisfies `filter`, in unspecified order
    /// (pysaml2 `find_nameid`). Overridable to push the filter down to an
    /// index or query; the default filters [`for_user`](Self::for_user).
    fn find(&self, user_id: &str, filter: &NameIdFilter) -> Result<Vec<NameId>, StoreError> {
        Ok(self
            .for_user(user_id)?
            .into_iter()
            .filter(|n| filter.matches(n))
            .collect())
    }

    /// The user's durable NameID of `format` for `(sp_name_qualifier,
    /// name_qualifier)`, if one exists. `None` for a qualifier means the record
    /// has no such qualifier. A transient `format` never matches. A record
    /// stored without a format counts as `NAMEID_UNSPECIFIED`, for this lookup
    /// and for the uniqueness constraint. Overridable
    /// to push the lookup down to an index; the default filters
    /// [`for_user`](Self::for_user).
    fn find_durable(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
        format: &str,
    ) -> Result<Option<NameId>, StoreError> {
        Ok(self
            .for_user(user_id)?
            .into_iter()
            .find(|n| is_durable_match(n, sp_name_qualifier, name_qualifier, format)))
    }

    /// Atomically return the user's existing durable NameID with the same
    /// `(sp_name_qualifier, name_qualifier, format)` as `candidate`, or insert
    /// `candidate` and return it. `Err(InsertError::ValueTaken)` if the record
    /// would be inserted but its value is already in use. For a transient
    /// `candidate`, which has no uniqueness constraint, this is a plain insert.
    fn get_or_insert_durable(
        &self,
        user_id: &str,
        candidate: NameId,
    ) -> Result<NameId, InsertError>;

    /// Insert a freshly minted NameID. `Err(InsertError::ValueTaken)` if any
    /// record already has this value. `Err(InsertError::DurableExists)` if
    /// the record is durable (any format except transient) and `user_id`
    /// already has a record of that format for the same
    /// `(sp_name_qualifier, name_qualifier)`: the second uniqueness constraint
    /// holds on every write path, not only on
    /// [`get_or_insert_durable`](Self::get_or_insert_durable).
    fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError>;

    /// Insert the record, or overwrite the record with this value if `user_id`
    /// already owns it. Records are keyed by value, so this changes a record's
    /// *other* fields in place (e.g. a ManageNameID `NewID` sets `SPProvidedID`
    /// on the same NameID value). It cannot give a durable record a new value: a
    /// different value is a different record. Durable identifiers are meant to
    /// stay stable, and rotating one is not an operation this trait offers
    /// (`remove` followed by `insert` is not atomic).
    ///
    /// A value held by a **different** user is `Err(InsertError::ValueTaken)`
    /// and left untouched: a record is never reassigned, because that would let
    /// the new user log in as the old one at every SP that has seen the value. A
    /// backend gets this from the unique index on the value (an upsert filtered
    /// on `(value, user_id)` reports a duplicate key). It also holds the same
    /// durable constraint as [`insert`](Self::insert):
    /// `Err(InsertError::DurableExists)` if the write would leave `user_id`
    /// with a second durable record (a different value) of the same format for
    /// the same `(sp_name_qualifier, name_qualifier)`. Updating the existing
    /// record in place is fine.
    fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError>;

    /// Remove the record with this value, if any.
    fn remove(&self, value: &str) -> Result<(), StoreError>;

    /// Remove every record belonging to `user_id`.
    fn remove_all(&self, user_id: &str) -> Result<(), StoreError>;
}

/// The format `name_id` has: its own, or `unspecified` when absent (SAML Core
/// 8.3: an omitted `Format` means `nameid-format:unspecified`).
fn effective_format(name_id: &NameId) -> &str {
    name_id
        .format
        .as_deref()
        .unwrap_or(constants::NAMEID_UNSPECIFIED)
}

/// Whether `nid` is a durable NameID of `format` with exactly these qualifiers
/// (`None` matching only a record that has no such qualifier). A transient
/// `format` is never durable, so never matches. A record with no format is
/// `unspecified`.
pub(crate) fn is_durable_match(
    nid: &NameId,
    sp_name_qualifier: Option<&str>,
    name_qualifier: Option<&str>,
    format: &str,
) -> bool {
    format != constants::NAMEID_TRANSIENT
        && effective_format(nid) == format
        && nid.sp_name_qualifier.as_deref() == sp_name_qualifier
        && nid.name_qualifier.as_deref() == name_qualifier
}

/// The format of `name_id` if it is durable: anything but transient. An absent
/// format is `unspecified`, which is durable.
fn durable_format(name_id: &NameId) -> Option<&str> {
    Some(effective_format(name_id)).filter(|f| *f != constants::NAMEID_TRANSIENT)
}

/// Whether writing `name_id` for `user_id` would leave the user with a second
/// durable record of the same format for the same `(sp_name_qualifier,
/// name_qualifier)`: it is durable, and a *different* value already holds that
/// slot.
fn durable_tuple_taken(records: &[(String, NameId)], user_id: &str, name_id: &NameId) -> bool {
    let Some(format) = durable_format(name_id) else {
        return false;
    };
    records.iter().any(|(user, existing)| {
        user == user_id
            && existing.value != name_id.value
            && is_durable_match(
                existing,
                name_id.sp_name_qualifier.as_deref(),
                name_id.name_qualifier.as_deref(),
                format,
            )
    })
}

/// In-memory [`IdentityStore`] for tests, examples and single-instance
/// deployments. Every method takes one lock, so atomicity is trivial; lookups
/// are linear scans, which a real backend replaces with indexes.
#[derive(Debug, Default)]
pub struct InMemoryIdentityStore {
    records: Mutex<Vec<(String, NameId)>>,
}

impl InMemoryIdentityStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for InMemoryIdentityStore {
    fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
        let records = self.records.lock().unwrap();
        Ok(records
            .iter()
            .filter(|(user, _)| user == user_id)
            .map(|(_, nid)| nid.clone())
            .collect())
    }

    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
        let records = self.records.lock().unwrap();
        Ok(records
            .iter()
            .find(|(_, nid)| nid.value == value)
            .map(|(user, _)| user.clone()))
    }

    fn get_or_insert_durable(
        &self,
        user_id: &str,
        candidate: NameId,
    ) -> Result<NameId, InsertError> {
        let mut records = self.records.lock().unwrap();
        if let Some(format) = durable_format(&candidate) {
            if let Some((_, existing)) = records.iter().find(|(user, nid)| {
                user == user_id
                    && is_durable_match(
                        nid,
                        candidate.sp_name_qualifier.as_deref(),
                        candidate.name_qualifier.as_deref(),
                        format,
                    )
            }) {
                return Ok(existing.clone());
            }
        }
        if records.iter().any(|(_, nid)| nid.value == candidate.value) {
            return Err(InsertError::ValueTaken);
        }
        records.push((user_id.to_string(), candidate.clone()));
        Ok(candidate)
    }

    fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
        let mut records = self.records.lock().unwrap();
        if records.iter().any(|(_, nid)| nid.value == name_id.value) {
            return Err(InsertError::ValueTaken);
        }
        if durable_tuple_taken(&records, user_id, &name_id) {
            return Err(InsertError::DurableExists);
        }
        records.push((user_id.to_string(), name_id));
        Ok(())
    }

    fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
        let mut records = self.records.lock().unwrap();
        if records
            .iter()
            .any(|(owner, nid)| nid.value == name_id.value && owner != user_id)
        {
            return Err(InsertError::ValueTaken);
        }
        if durable_tuple_taken(&records, user_id, &name_id) {
            return Err(InsertError::DurableExists);
        }
        match records
            .iter_mut()
            .find(|(_, nid)| nid.value == name_id.value)
        {
            Some(slot) => *slot = (user_id.to_string(), name_id),
            None => records.push((user_id.to_string(), name_id)),
        }
        Ok(())
    }

    fn remove(&self, value: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .unwrap()
            .retain(|(_, nid)| nid.value != value);
        Ok(())
    }

    fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .unwrap()
            .retain(|(user, _)| user != user_id);
        Ok(())
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

/// The identity database (pysaml2 `IdentDB`).
pub struct IdentDb<S: IdentityStore = InMemoryIdentityStore> {
    store: S,
    /// The IdP entity ID, used as the default NameQualifier.
    name_qualifier: String,
    /// Domain appended to generated email-format NameIDs.
    domain: Option<String>,
    /// Also store transient NameIDs (off by default; see
    /// [`with_persist_transient`](Self::with_persist_transient)).
    persist_transient: bool,
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
            persist_transient: false,
        }
    }

    /// Set the domain used for email-format NameIDs.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Also store transient NameIDs (default: off).
    ///
    /// By default a transient NameID is minted and returned without being
    /// stored. It is one-time-use (SAML Core §8.3.7) and the default per-SP
    /// format is transient, so storing every one would grow the store without
    /// bound. The cost of that default is that
    /// [`find_local_id`](Self::find_local_id) cannot resolve a transient
    /// NameID, which a back-channel (SOAP) LogoutRequest carrying one needs in
    /// order to find the user.
    ///
    /// Turning this on makes each transient NameID a record, so it resolves.
    /// Three consequences:
    ///
    /// - The record trait has no expiry. A transient record is useless once
    ///   its session ends, so the backend must expire them (a TTL index, a
    ///   periodic purge), or the store grows by one record per response.
    /// - Issuing a transient NameID then needs the store to be reachable.
    /// - A stored transient is still one-time-use: a NameIDMapping request
    ///   never reuses one.
    pub fn with_persist_transient(mut self, persist: bool) -> Self {
        self.persist_transient = persist;
        self
    }

    /// The NameIDs stored for a local user that satisfy `filter` (pysaml2
    /// `find_nameid()`).
    pub fn find_nameid(
        &self,
        user_id: &str,
        filter: &NameIdFilter,
    ) -> Result<Vec<NameId>, StoreError> {
        self.store.find(user_id, filter)
    }

    /// All NameIDs stored for a local user.
    pub fn name_ids_for(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
        self.store.for_user(user_id)
    }

    /// Associate a NameID with a local user (pysaml2 `store()`), replacing
    /// any record that already has the same value, so it updates that
    /// NameID's other fields in place rather than changing its value.
    ///
    /// Fails with [`IdentError::ValueTaken`] if the value already belongs to a
    /// different user (a record is never moved between users), and with
    /// [`IdentError::DurableExists`] if `name_id` is durable
    /// and the user already has a different NameID of that format for the same
    /// `(SPNameQualifier, NameQualifier)`; use
    /// [`persistent_nameid`](Self::persistent_nameid) to obtain that one. A
    /// persistent identifier cannot be rotated through this method.
    pub fn store(&self, user_id: &str, name_id: &NameId) -> Result<(), IdentError> {
        Ok(self.store.replace(user_id, name_id.clone())?)
    }

    /// The local user a NameID was issued to (pysaml2 `find_local_id()`).
    pub fn find_local_id(&self, name_id: &NameId) -> Result<Option<String>, StoreError> {
        self.store.user_for(&name_id.value)
    }

    /// Find an existing *persistent* NameID for (user, SP, IdP) (pysaml2
    /// `IdentMDB.match_local_id()` — the production Mongo-backed store eduID
    /// runs, which filters on `name_id.format == NAMEID_FORMAT_PERSISTENT`
    /// explicitly, not pysaml2's looser shelve-backed base `IdentDB`, which
    /// merely excludes transient).
    ///
    /// Matching on "not transient" instead of "is persistent" would return
    /// any other previously-issued non-transient NameID for this (user, SP,
    /// IdP) — e.g. an `email`-format one — labeled with *that* format, not
    /// persistent, even though the caller asked for a persistent identifier.
    pub fn match_local_id(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Result<Option<NameId>, StoreError> {
        self.store.find_durable(
            user_id,
            sp_name_qualifier,
            name_qualifier,
            constants::NAMEID_PERSISTENT,
        )
    }

    /// Generate a fresh opaque identifier value (pysaml2 `create_id()`).
    ///
    /// The free-check here is only an optimisation: the store's `insert` /
    /// `get_or_insert_durable` enforce value uniqueness atomically, and a
    /// collision that slips in between is retried by the caller. It is skipped
    /// (`check_free = false`) for identifiers that are never stored, so issuing
    /// one does not depend on the store being reachable.
    fn create_id(
        &self,
        format: &str,
        name_qualifier: Option<&str>,
        sp_name_qualifier: Option<&str>,
        check_free: bool,
    ) -> Result<String, StoreError> {
        for _ in 0..MAX_MINT_ATTEMPTS {
            let mut seed = [0u8; 32];
            rand::fill(&mut seed);
            let mut input = seed.to_vec();
            input.extend_from_slice(format.as_bytes());
            input.extend_from_slice(name_qualifier.unwrap_or("").as_bytes());
            input.extend_from_slice(sp_name_qualifier.unwrap_or("").as_bytes());
            let digest = sha256(&input).expect("SHA-256 is always available");
            let id = to_hex(&digest);
            // Build the final stored value (email format appends `@domain`)
            // *before* the collision check, so the check tests the value
            // that is actually stored.
            let value = if format == constants::NAMEID_EMAIL {
                let domain = self.domain.as_deref().unwrap_or("idp.example.org");
                format!("{id}@{domain}")
            } else {
                id
            };
            if !check_free || self.store.user_for(&value)?.is_none() {
                return Ok(value);
            }
        }
        Err(mint_exhausted(
            "every freshly minted value was already in use",
        ))
    }

    /// Get or create the NameID of the given format (pysaml2 `get_nameid()`).
    ///
    /// Every durable format (anything except transient: persistent, email,
    /// unspecified, ...) is stable per `(user, SP, NameQualifier, format)`: an
    /// existing record is returned rather than a new value minted, and two
    /// concurrent first requests converge on one. (0.9.x minted and stored a
    /// fresh value on every call for the non-persistent durable formats, so an
    /// email-format NameID changed at each login and the store grew with each
    /// response.)
    ///
    /// Transient identifiers are minted fresh and, unless
    /// [`with_persist_transient`](Self::with_persist_transient) is set,
    /// returned *without* being
    /// stored: they are one-time-use (SAML Core §8.3.7) and never need a
    /// reverse lookup, so persisting them would only grow the store without
    /// bound (the default per-SP format is transient, so every response
    /// would otherwise add an entry that is never read back). All other
    /// formats are stored and reused. The rule is "persist iff the identifier
    /// is ever reverse-looked-up or reused"; if a future one-time-use format is
    /// added, generalize the transient check to a set of non-persisted
    /// formats.
    pub fn get_nameid(
        &self,
        user_id: &str,
        format: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
        // A durable identifier must stay stable per (user, SP, format): reuse
        // an existing association instead of minting a new value (E78). The
        // read is the fast path for a returning user; the atomic
        // get-or-insert below is what makes two concurrent *first* requests
        // converge on one identifier.
        let durable = format != constants::NAMEID_TRANSIENT;
        if durable {
            if let Some(existing) =
                self.store
                    .find_durable(user_id, sp_name_qualifier, name_qualifier, format)?
            {
                return Ok(existing);
            }
        }

        let stored = durable || self.persist_transient;
        for _ in 0..MAX_MINT_ATTEMPTS {
            let value = self.create_id(format, name_qualifier, sp_name_qualifier, stored)?;
            let name_id = NameId {
                value,
                format: Some(format.to_string()),
                name_qualifier: name_qualifier.map(str::to_string),
                sp_name_qualifier: sp_name_qualifier.map(str::to_string),
                sp_provided_id: None,
            };

            if durable {
                match self.store.get_or_insert_durable(user_id, name_id) {
                    Ok(winner) => return Ok(winner),
                    Err(InsertError::ValueTaken) => continue,
                    Err(InsertError::Store(e)) => return Err(e),
                    // It must hand back the existing record, never refuse.
                    Err(InsertError::DurableExists) => {
                        return Err(StoreError::new(
                            "the backend reported DurableExists from get_or_insert_durable",
                        ))
                    }
                }
            }
            if !stored {
                return Ok(name_id);
            }
            match self.store.insert(user_id, name_id.clone()) {
                Ok(()) => return Ok(name_id),
                Err(InsertError::ValueTaken) => continue,
                Err(InsertError::Store(e)) => return Err(e),
                // Only a durable record can hit this, and those take the
                // get_or_insert_durable path above; what reaches here is a
                // transient one, which has no uniqueness constraint.
                Err(InsertError::DurableExists) => {
                    return Err(StoreError::new(
                        "the backend reported DurableExists for a transient record",
                    ))
                }
            }
        }
        Err(mint_exhausted("the backend kept reporting ValueTaken"))
    }

    /// Generate a transient NameID (pysaml2 `transient_nameid()`).
    pub fn transient_nameid(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
        self.get_nameid(
            user_id,
            constants::NAMEID_TRANSIENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Get-or-create a persistent NameID (pysaml2 `persistent_nameid()`).
    pub fn persistent_nameid(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
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
    /// - AllowCreate (E14): when an explicit `NameIDPolicy` sets it to false,
    ///   only an existing identifier may be returned for the persistent
    ///   format. A request with *no* `NameIDPolicy` at all does not impose
    ///   that constraint - the IdP's configured default format applies and the
    ///   IdP is permitted to mint it.
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
            // Only an explicit NameIDPolicy with AllowCreate=false forbids
            // creating a new identifier. A request with no NameIDPolicy at all
            // (name_id_policy is None) means the IdP's configured default
            // format applies, and the IdP is permitted to mint that default -
            // it must not be treated as AllowCreate=false, or a persistent
            // default would deny every first-time subject whose request omits
            // NameIDPolicy.
            let allow_create = name_id_policy.map(|p| p.allow_create).unwrap_or(true);
            let existing = self.match_local_id(
                user_id,
                Some(sp_name_qualifier),
                Some(self.name_qualifier.as_str()),
            )?;
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
        )?)
    }

    /// Forget a NameID (pysaml2 `remove_remote()`).
    pub fn remove_remote(&self, name_id: &NameId) -> Result<(), StoreError> {
        self.store.remove(&name_id.value)
    }

    /// Forget every NameID for a local user (pysaml2 `remove_local()`).
    pub fn remove_local(&self, user_id: &str) -> Result<(), StoreError> {
        self.store.remove_all(user_id)
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
            .find_local_id(name_id)?
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
                self.remove_remote(name_id)?;
                return Ok(updated);
            }
        }

        self.store.replace(&user_id, updated.clone())?;
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
            .find_local_id(name_id)?
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let wanted_format = name_id_policy.format.as_deref();
        let wanted_spq = name_id_policy.sp_name_qualifier.as_deref();
        let filter = NameIdFilter {
            format: wanted_format.map(str::to_string),
            sp_name_qualifier: wanted_spq.map(str::to_string),
            ..Default::default()
        };
        // A transient identifier is one-time-use and must not be reused, even
        // when persist_transient keeps it in the store.
        if let Some(existing) = self
            .find_nameid(&user_id, &filter)?
            .into_iter()
            .find(|nid| nid.format.as_deref() != Some(constants::NAMEID_TRANSIENT))
        {
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
        )?)
    }
}

/// Object-safe view of [`IdentDb::construct_nameid`], so a caller that only
/// needs NameID construction can hold `dyn NameIdConstructor` instead of a
/// concrete `IdentDb<S>` — freeing it from committing to one `IdentityStore`
/// implementation at the type level.
///
/// [`idp::orchestrator::ResponseEngine`](crate::idp::orchestrator::ResponseEngine)
/// uses this: without it, `ResponseEngine` would need to stay generic over
/// `S: IdentityStore`, which a ready-made framework integration (a fixed
/// function signature registered as a route handler) cannot parameterize
/// per-application — hardcoding the default `InMemoryIdentityStore` would
/// shut out a Redis/SQL-backed store, the documented multi-instance seam.
pub trait NameIdConstructor: Send + Sync {
    /// See [`IdentDb::construct_nameid`].
    fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError>;
}

impl<S: IdentityStore> NameIdConstructor for IdentDb<S> {
    fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError> {
        IdentDb::construct_nameid(self, user_id, sp_entity_id, name_id_policy, default_format)
    }
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub mod conformance;

#[cfg(test)]
mod tests {
    use super::*;

    const IDP: &str = "https://idp.example.com";
    const SP: &str = "https://sp.example.com";

    fn db() -> IdentDb {
        IdentDb::in_memory(IDP)
    }

    #[test]
    fn in_memory_identity_store_passes_the_conformance_suite() {
        conformance::run(InMemoryIdentityStore::new);
    }

    /// Delegates to a store that does not enforce the persistent tuple on
    /// `insert`/`replace` (the reference in-memory store now does, which would
    /// mask the race these doubles model), except where a test overrides a
    /// method to model a backend that forgot a uniqueness constraint.
    #[derive(Default)]
    struct BrokenStore {
        inner: PartialConstraintStore,
        no_value_uniqueness: bool,
        check_then_insert: bool,
    }

    impl IdentityStore for BrokenStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            self.inner.for_user(user_id)
        }
        fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
            self.inner.user_for(value)
        }
        fn get_or_insert_durable(
            &self,
            user_id: &str,
            candidate: NameId,
        ) -> Result<NameId, InsertError> {
            if self.check_then_insert {
                // Look, release, then write: what a backend without a unique
                // index does. Widen the window so the race is certain.
                if let Some(existing) = self.inner.find_durable(
                    user_id,
                    candidate.sp_name_qualifier.as_deref(),
                    candidate.name_qualifier.as_deref(),
                    candidate.format.as_deref().unwrap_or_default(),
                )? {
                    return Ok(existing);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
                // Value uniqueness still holds; only the persistent
                // (user, SP) tuple has no constraint behind this check.
                self.inner.insert(user_id, candidate.clone())?;
                return Ok(candidate);
            }
            self.inner.get_or_insert_durable(user_id, candidate)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            if self.no_value_uniqueness {
                // Upsert by value with no ownership check: what a backend
                // without a unique index on the value does.
                let mut records = self.inner.records.lock().unwrap();
                match records
                    .iter_mut()
                    .find(|(_, nid)| nid.value == name_id.value)
                {
                    Some(slot) => *slot = (user_id.to_string(), name_id),
                    None => records.push((user_id.to_string(), name_id)),
                }
                return Ok(());
            }
            self.inner.insert(user_id, name_id)
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.inner.replace(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.inner.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.inner.remove_all(user_id)
        }
    }

    /// A backend that cannot answer: every operation fails. Models an outage.
    struct DownStore;

    fn down() -> StoreError {
        StoreError::new("backend unreachable")
    }

    impl IdentityStore for DownStore {
        fn for_user(&self, _: &str) -> Result<Vec<NameId>, StoreError> {
            Err(down())
        }
        fn user_for(&self, _: &str) -> Result<Option<String>, StoreError> {
            Err(down())
        }
        fn get_or_insert_durable(&self, _: &str, _: NameId) -> Result<NameId, InsertError> {
            Err(down().into())
        }
        fn insert(&self, _: &str, _: NameId) -> Result<(), InsertError> {
            Err(down().into())
        }
        fn replace(&self, _: &str, _: NameId) -> Result<(), InsertError> {
            Err(down().into())
        }
        fn remove(&self, _: &str) -> Result<(), StoreError> {
            Err(down())
        }
        fn remove_all(&self, _: &str) -> Result<(), StoreError> {
            Err(down())
        }
    }

    #[test]
    fn an_outage_is_an_error_not_a_missing_record() {
        let db = IdentDb::new(DownStore, IDP);
        // The lookup that decides "does this user already have a persistent
        // identifier?" must fail, not answer "no" and let a second one be minted.
        assert!(db.persistent_nameid("alice", Some(SP)).is_err());
        assert!(db.match_local_id("alice", Some(SP), Some(IDP)).is_err());
        assert!(db
            .find_local_id(&NameId {
                value: "v".into(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None
            })
            .is_err());
        assert!(db.name_ids_for("alice").is_err());
        assert!(db.remove_local("alice").is_err());
        assert!(matches!(
            db.construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT)),
            Err(IdentError::Store(_))
        ));
    }

    #[test]
    fn issuing_a_transient_nameid_does_not_need_the_store() {
        // Transients are never stored, so an outage must not block them.
        let db = IdentDb::new(DownStore, IDP);
        let nid = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
    }

    /// A backend that enforces the persistent `(user, SP, NameQualifier)`
    /// constraint only in `get_or_insert_durable`, as the in-memory store
    /// once did: `insert` (when `guard_insert` is off) and `replace` accept a
    /// second persistent record. Value uniqueness holds.
    #[derive(Default)]
    struct PartialConstraintStore {
        records: Mutex<Vec<(String, NameId)>>,
        guard_insert: bool,
    }

    impl IdentityStore for PartialConstraintStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            let records = self.records.lock().unwrap();
            Ok(records
                .iter()
                .filter(|(user, _)| user == user_id)
                .map(|(_, nid)| nid.clone())
                .collect())
        }
        fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
            let records = self.records.lock().unwrap();
            Ok(records
                .iter()
                .find(|(_, nid)| nid.value == value)
                .map(|(user, _)| user.clone()))
        }
        fn get_or_insert_durable(
            &self,
            user_id: &str,
            candidate: NameId,
        ) -> Result<NameId, InsertError> {
            let mut records = self.records.lock().unwrap();
            if let Some((_, existing)) = records.iter().find(|(user, nid)| {
                user == user_id
                    && is_durable_match(
                        nid,
                        candidate.sp_name_qualifier.as_deref(),
                        candidate.name_qualifier.as_deref(),
                        candidate.format.as_deref().unwrap_or_default(),
                    )
            }) {
                return Ok(existing.clone());
            }
            if records.iter().any(|(_, nid)| nid.value == candidate.value) {
                return Err(InsertError::ValueTaken);
            }
            records.push((user_id.to_string(), candidate.clone()));
            Ok(candidate)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            let mut records = self.records.lock().unwrap();
            if records.iter().any(|(_, nid)| nid.value == name_id.value) {
                return Err(InsertError::ValueTaken);
            }
            if self.guard_insert && durable_tuple_taken(&records, user_id, &name_id) {
                return Err(InsertError::DurableExists);
            }
            records.push((user_id.to_string(), name_id));
            Ok(())
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            let mut records = self.records.lock().unwrap();
            match records
                .iter_mut()
                .find(|(_, nid)| nid.value == name_id.value)
            {
                Some((owner, _)) if owner != user_id => return Err(InsertError::ValueTaken),
                Some(slot) => *slot = (user_id.to_string(), name_id),
                None => records.push((user_id.to_string(), name_id)),
            }
            Ok(())
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.records
                .lock()
                .unwrap()
                .retain(|(_, nid)| nid.value != value);
            Ok(())
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.records
                .lock()
                .unwrap()
                .retain(|(user, _)| user != user_id);
            Ok(())
        }
    }

    fn persistent_nid(value: &str, sp: &str) -> NameId {
        NameId {
            value: value.to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: Some(sp.to_string()),
            sp_provided_id: None,
        }
    }

    #[test]
    fn the_reference_store_enforces_the_persistent_constraint_on_every_write_path() {
        let store = InMemoryIdentityStore::new();
        store
            .get_or_insert_durable("alice", persistent_nid("p1", SP))
            .unwrap();
        // A second persistent record for the same (user, SP, NameQualifier),
        // by value-distinct `insert` or `replace`, is refused...
        assert!(matches!(
            store.insert("alice", persistent_nid("p2", SP)),
            Err(InsertError::DurableExists)
        ));
        assert!(matches!(
            store.replace("alice", persistent_nid("p3", SP)),
            Err(InsertError::DurableExists)
        ));
        assert_eq!(store.for_user("alice").unwrap().len(), 1);
        // ...while another SP, another user, another format, and an in-place
        // update of the existing record are not.
        store
            .insert(
                "alice",
                persistent_nid("p4", "https://other-sp.example.com"),
            )
            .unwrap();
        store.insert("bob", persistent_nid("p5", SP)).unwrap();
        store.replace("alice", persistent_nid("p1", SP)).unwrap();
        // A value another user holds is never moved to them, whatever it is.
        assert!(matches!(
            store.replace("bob", persistent_nid("p4", "https://other-sp.example.com")),
            Err(InsertError::ValueTaken)
        ));
        assert!(matches!(
            store.replace("bob", persistent_nid("p1", SP)),
            Err(InsertError::ValueTaken)
        ));
        assert_eq!(store.user_for("p1").unwrap().as_deref(), Some("alice"));
        // A fresh value for a user who already has a persistent one for the SP
        // is still the durable conflict.
        assert!(matches!(
            store.replace("bob", persistent_nid("p6", SP)),
            Err(InsertError::DurableExists)
        ));
    }

    #[test]
    fn store_refuses_a_second_persistent_nameid_for_the_same_user_and_sp() {
        let db = db();
        let first = db.persistent_nameid("alice", Some(SP)).unwrap();
        // pysaml2's `store()` must not be a way to mint a second "stable" id.
        let second = NameId {
            value: "another-value".to_string(),
            ..first.clone()
        };
        assert!(matches!(
            db.store("alice", &second),
            Err(IdentError::DurableExists)
        ));
        assert_eq!(db.name_ids_for("alice").unwrap(), vec![first.clone()]);
        // Storing the existing identifier again (an update) is fine.
        db.store("alice", &first).unwrap();
    }

    #[test]
    fn conformance_catches_a_backend_that_only_guards_get_or_insert_persistent() {
        let err = conformance::check(PartialConstraintStore::default).unwrap_err();
        assert_eq!(err.check, "durable_is_unique_on_every_write_path");
        assert!(
            err.message.contains("insert accepted a second persistent"),
            "{err}"
        );
    }

    #[test]
    fn conformance_catches_a_backend_that_guards_insert_but_not_replace() {
        let err = conformance::check(|| PartialConstraintStore {
            guard_insert: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.check, "durable_is_unique_on_every_write_path");
        assert!(
            err.message.contains("replace accepted a second persistent"),
            "{err}"
        );
    }

    /// A backend that reports `ValueTaken` for every `get_or_insert_durable`,
    /// including for a value nothing else holds.
    #[derive(Default)]
    struct AlwaysTakenStore(PartialConstraintStore);

    impl IdentityStore for AlwaysTakenStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            self.0.for_user(user_id)
        }
        fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
            self.0.user_for(value)
        }
        fn get_or_insert_durable(&self, _: &str, _: NameId) -> Result<NameId, InsertError> {
            Err(InsertError::ValueTaken)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.insert(user_id, name_id)
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.replace(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.0.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.0.remove_all(user_id)
        }
    }

    /// A backend that says every value is already in use.
    #[derive(Default)]
    struct EveryValueInUseStore(PartialConstraintStore);

    impl IdentityStore for EveryValueInUseStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            self.0.for_user(user_id)
        }
        fn user_for(&self, _: &str) -> Result<Option<String>, StoreError> {
            Ok(Some("someone".to_string()))
        }
        fn get_or_insert_durable(&self, u: &str, n: NameId) -> Result<NameId, InsertError> {
            self.0.get_or_insert_durable(u, n)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.insert(user_id, name_id)
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.replace(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.0.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.0.remove_all(user_id)
        }
    }

    /// A backend whose `replace` moves a record to whichever user asks.
    #[derive(Default)]
    struct ReassigningStore(InMemoryIdentityStore);

    impl IdentityStore for ReassigningStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            self.0.for_user(user_id)
        }
        fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
            self.0.user_for(value)
        }
        fn get_or_insert_durable(&self, u: &str, n: NameId) -> Result<NameId, InsertError> {
            self.0.get_or_insert_durable(u, n)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.insert(user_id, name_id)
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            self.0.remove(&name_id.value)?;
            self.0.insert(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.0.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.0.remove_all(user_id)
        }
    }

    #[test]
    fn a_record_is_never_moved_to_another_user() {
        // Through IdentDb::store ...
        let db = IdentDb::in_memory(IDP);
        let nid = db
            .get_nameid("alice", constants::NAMEID_PERSISTENT, Some(SP), Some(IDP))
            .unwrap();
        assert!(matches!(db.store("bob", &nid), Err(IdentError::ValueTaken)));
        assert_eq!(db.find_local_id(&nid).unwrap().as_deref(), Some("alice"));
        // ... and the owner can still update it in place.
        db.store("alice", &nid).unwrap();

        // The conformance suite catches a backend that reassigns.
        let err = conformance::check_one(
            "replace_upserts_by_value",
            ReassigningStore::default,
            &conformance::Options::default(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("moved a record to another user"),
            "{err}"
        );
    }

    #[test]
    fn minting_against_a_lying_backend_gives_up_with_an_error() {
        // Both loops are bounded: one that retries after ValueTaken, and the
        // free-value check inside the minting helper.
        let db = IdentDb::new(AlwaysTakenStore::default(), IDP);
        let err = db
            .get_nameid("alice", constants::NAMEID_PERSISTENT, Some(SP), Some(IDP))
            .unwrap_err();
        assert!(err.to_string().contains("attempts"), "{err}");

        let db = IdentDb::new(EveryValueInUseStore::default(), IDP);
        let err = db
            .get_nameid("alice", constants::NAMEID_PERSISTENT, Some(SP), Some(IDP))
            .unwrap_err();
        assert!(err.to_string().contains("attempts"), "{err}");
    }

    #[test]
    fn a_backend_that_always_reports_value_taken_fails_the_check_instead_of_hanging() {
        // The concurrent check used to retry a ValueTaken with the same
        // candidate, which never ends against a backend that always says so.
        let err = conformance::check_one(
            "concurrent_get_or_insert_converges_on_one_identifier",
            AlwaysTakenStore::default,
            &conformance::Options { threads: 2 },
        )
        .unwrap_err();
        assert!(err.message.contains("reported ValueTaken"), "{err}");
    }

    #[test]
    fn check_returns_the_violation_instead_of_panicking() {
        let err = conformance::check(|| BrokenStore {
            no_value_uniqueness: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.check, "value_is_unique");
        assert!(
            err.message
                .contains("a value already in use must be rejected"),
            "{err}"
        );
        // Displays as `check: message`, and is a std error.
        assert!(err.to_string().starts_with("value_is_unique: "));
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn every_listed_check_can_be_run_by_name() {
        let options = conformance::Options::default();
        for name in conformance::CHECKS {
            conformance::check_one(name, InMemoryIdentityStore::new, &options)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let err = conformance::check_one("no_such_check", InMemoryIdentityStore::new, &options)
            .unwrap_err();
        assert!(
            err.message.contains("value_is_unique"),
            "lists known checks: {err}"
        );
    }

    #[test]
    fn a_single_check_names_the_constraint_a_backend_is_missing() {
        let options = conformance::Options::default();
        let broken = || BrokenStore {
            check_then_insert: true,
            ..Default::default()
        };
        // Only the persistent-tuple check fails; the value-uniqueness one passes.
        assert!(conformance::check_one("value_is_unique", broken, &options).is_ok());
        let err = conformance::check_one(
            "concurrent_get_or_insert_converges_on_one_identifier",
            broken,
            &options,
        )
        .unwrap_err();
        assert!(err
            .message
            .contains("minted different persistent identifiers"));
    }

    #[test]
    fn a_backend_failure_is_a_failed_check_not_a_panic_or_a_lost_race() {
        let options = conformance::Options::default();
        let err = conformance::check_one("value_is_unique", || DownStore, &options).unwrap_err();
        assert!(
            err.message.contains("backend call `insert` failed"),
            "{err}"
        );
        // The concurrent check must not count an outage as "someone lost the
        // race", which would make a dead backend look like it has one winner.
        let err = conformance::check_one(
            "concurrent_insert_of_one_value_has_one_winner",
            || DownStore,
            &options,
        )
        .unwrap_err();
        assert!(
            err.message.contains("backend call `insert` failed"),
            "{err}"
        );
    }

    #[test]
    fn the_concurrent_checks_honour_the_thread_count() {
        let options = conformance::Options { threads: 2 };
        conformance::check_with(InMemoryIdentityStore::new, &options).unwrap();
        // A count below the minimum still races at least two workers.
        let options = conformance::Options { threads: 0 };
        conformance::check_with(InMemoryIdentityStore::new, &options).unwrap();
    }

    #[test]
    #[should_panic(expected = "a value already in use must be rejected")]
    fn conformance_catches_a_backend_without_value_uniqueness() {
        conformance::run(|| BrokenStore {
            no_value_uniqueness: true,
            ..Default::default()
        });
    }

    // A check-then-insert backend has no persistent constraint on its write
    // paths, so the whole suite now stops at the deterministic
    // `durable_is_unique_on_every_write_path` check before it reaches the
    // racing ones. The race itself is still proven on its own by
    // `a_single_check_names_the_constraint_a_backend_is_missing`.
    #[test]
    #[should_panic(expected = "durable_is_unique_on_every_write_path")]
    fn conformance_catches_a_check_then_insert_backend() {
        conformance::run(|| BrokenStore {
            check_then_insert: true,
            ..Default::default()
        });
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

        db.store("alice", &nid).unwrap();

        assert_eq!(db.name_ids_for("alice").unwrap(), vec![nid.clone()]);
        assert_eq!(db.find_local_id(&nid).unwrap().as_deref(), Some("alice"));
    }

    #[test]
    fn test_transient_unique_each_time() {
        let db = db();
        let a = db.transient_nameid("alice", Some(SP)).unwrap();
        let b = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_ne!(a.value, b.value);
        assert_eq!(a.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        // Transient identifiers are one-time-use and not persisted, so they
        // must not be reverse-looked-up and must not accumulate in the store
        // (the default per-SP format is transient, so every response would
        // otherwise grow the identity store without bound).
        assert_eq!(db.find_local_id(&a).unwrap(), None);
        assert_eq!(db.find_local_id(&b).unwrap(), None);
        assert!(db.name_ids_for("alice").unwrap().is_empty());
    }

    #[test]
    fn find_nameid_filters_a_users_records() {
        let db = db();
        let persistent = db.persistent_nameid("alice", Some(SP)).unwrap();
        db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        db.persistent_nameid("bob", Some(SP)).unwrap();

        let all = db.find_nameid("alice", &NameIdFilter::default()).unwrap();
        assert_eq!(all.len(), 2, "only alice's records");

        let only_persistent = db
            .find_nameid(
                "alice",
                &NameIdFilter {
                    format: Some(constants::NAMEID_PERSISTENT.to_string()),
                    sp_name_qualifier: Some(SP.to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(only_persistent, vec![persistent]);
    }

    #[test]
    fn durable_non_persistent_formats_are_stable_not_minted_anew() {
        // 0.9.x minted and stored a fresh value on every call for email and
        // unspecified, so the identifier changed at each login and the store
        // grew with each response. Like persistent, they are stable per
        // (user, SP, format).
        let db = db();
        for format in [constants::NAMEID_EMAIL, constants::NAMEID_UNSPECIFIED] {
            let policy = NameIdPolicy {
                format: Some(format.to_string()),
                sp_name_qualifier: None,
                allow_create: true,
            };
            let mut values = std::collections::HashSet::new();
            for _ in 0..5 {
                let nid = db
                    .construct_nameid("alice", SP, Some(&policy), None)
                    .unwrap();
                assert_eq!(nid.format.as_deref(), Some(format));
                values.insert(nid.value);
            }
            assert_eq!(values.len(), 1, "{format}: the same identifier every time");
        }
        // One record per format, not one per call.
        assert_eq!(db.name_ids_for("alice").unwrap().len(), 2);

        // Different SP, different user and different format are different
        // identifiers.
        let for_sp = |user: &str, sp: &str, format: &str| {
            db.get_nameid(user, format, Some(sp), Some(IDP))
                .unwrap()
                .value
        };
        let base = for_sp("alice", SP, constants::NAMEID_EMAIL);
        assert_ne!(
            base,
            for_sp(
                "alice",
                "https://other-sp.example.com",
                constants::NAMEID_EMAIL
            )
        );
        assert_ne!(base, for_sp("bob", SP, constants::NAMEID_EMAIL));
        assert_ne!(base, for_sp("alice", SP, constants::NAMEID_PERSISTENT));
    }

    #[test]
    fn concurrent_first_requests_for_a_durable_format_converge_on_one_identifier() {
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || {
                    db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
                        .unwrap()
                        .value
                })
            })
            .collect();
        let values: Vec<String> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(values.iter().all(|v| v == &values[0]), "{values:?}");
        assert_eq!(db.name_ids_for("alice").unwrap().len(), 1);
    }

    #[test]
    fn store_refuses_a_second_nameid_of_a_durable_format_for_the_same_user_and_sp() {
        let db = db();
        let first = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        let second = NameId {
            value: "another@idp.example.org".to_string(),
            ..first.clone()
        };
        assert!(matches!(
            db.store("alice", &second),
            Err(IdentError::DurableExists)
        ));
        db.store("alice", &first).unwrap();
        assert_eq!(db.name_ids_for("alice").unwrap(), vec![first]);
    }

    #[test]
    fn persist_transient_makes_a_transient_nameid_resolvable() {
        let db = IdentDb::in_memory(IDP).with_persist_transient(true);
        let a = db.transient_nameid("alice", Some(SP)).unwrap();
        let b = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_ne!(a.value, b.value, "each issuance is still a fresh value");
        assert_eq!(db.find_local_id(&a).unwrap().as_deref(), Some("alice"));
        assert_eq!(db.find_local_id(&b).unwrap().as_deref(), Some("alice"));
        assert_eq!(db.name_ids_for("alice").unwrap().len(), 2);
        // A stored transient is never mistaken for the persistent identifier.
        assert!(db
            .match_local_id("alice", Some(SP), Some(IDP))
            .unwrap()
            .is_none());
        db.remove_remote(&a).unwrap();
        assert_eq!(db.find_local_id(&a).unwrap(), None);
        db.remove_local("alice").unwrap();
        assert_eq!(db.find_local_id(&b).unwrap(), None);
    }

    #[test]
    fn a_stored_transient_is_never_reused_by_a_nameid_mapping_request() {
        let db = IdentDb::in_memory(IDP).with_persist_transient(true);
        let t = db.transient_nameid("alice", Some(SP)).unwrap();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            allow_create: true,
        };
        let mapped = db.handle_name_id_mapping_request(&t, &policy).unwrap();
        assert_ne!(
            mapped.value, t.value,
            "a transient identifier is one-time-use and must not be handed out again"
        );
    }

    #[test]
    fn persist_transient_needs_the_store() {
        let db = IdentDb::new(DownStore, IDP).with_persist_transient(true);
        assert!(db.transient_nameid("alice", Some(SP)).is_err());
    }

    #[test]
    fn repeated_transient_issuance_does_not_grow_the_store() {
        // Regression for the review finding "transient identifiers accumulate
        // without cleanup": the default per-SP NameID format is transient, and
        // every successful response (including repeated reuse of one session)
        // mints a fresh transient. Because a transient is one-time-use and
        // never reverse-looked-up, none of them may be persisted - otherwise
        // the identity store grows without bound for the IdP's most common
        // configuration. Drive construct_nameid (the orchestrator's path) with
        // the transient default repeatedly and assert the store stays empty.
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let mut values = Vec::new();
        for _ in 0..50 {
            let nid = db
                .construct_nameid("alice", SP, Some(&policy), None)
                .unwrap();
            values.push(nid.value.clone());
        }
        // Each issuance is still a fresh, unique value...
        let unique = values.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(values.len(), unique.len());
        // ...and none of them accumulated in either index.
        assert!(db.name_ids_for("alice").unwrap().is_empty());
    }

    #[test]
    fn test_persistent_is_stable() {
        let db = db();
        let a = db.persistent_nameid("alice", Some(SP)).unwrap();
        let b = db.persistent_nameid("alice", Some(SP)).unwrap();
        assert_eq!(a.value, b.value);
        // different SP gets a different persistent id
        let c = db
            .persistent_nameid("alice", Some("https://other.example.com"))
            .unwrap();
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
        // Regression for the review finding "Missing NameIDPolicy incorrectly
        // disables persistent NameID creation": a request with no NameIDPolicy
        // at all must not be treated as AllowCreate=false. When the IdP's
        // configured default format is persistent, a first-time subject whose
        // request omits NameIDPolicy must be minted the default, not denied.
        let db = db();
        let nid = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .expect("no NameIDPolicy + persistent default must mint the default");
        assert_eq!(
            nid.format.as_deref(),
            Some(constants::NAMEID_PERSISTENT),
            "the IdP's configured default format must be honored"
        );
        // And it is stable: a second request for the same (user, SP) reuses it.
        let again = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .unwrap();
        assert_eq!(nid.value, again.value);
    }

    #[test]
    fn test_persistent_lookup_is_format_aware() {
        // Regression: a persistent request must not reuse an earlier
        // non-transient NameID of a *different* format for the same (user,
        // SP) pair. Sequential format requests against one shared store -
        // the realistic production shape, unlike a fresh store per format.
        let db = db();
        let email = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert_eq!(email.format.as_deref(), Some(constants::NAMEID_EMAIL));

        let create = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let persistent = db
            .construct_nameid("alice", SP, Some(&create), None)
            .expect("allow_create=true mints a fresh persistent id");
        assert_eq!(
            persistent.format.as_deref(),
            Some(constants::NAMEID_PERSISTENT),
            "a persistent request must not come back labeled with an earlier, \
             unrelated format"
        );
        assert_ne!(
            persistent.value, email.value,
            "a persistent request must not reuse the email-format identifier's value"
        );

        // And it's genuinely stable: asking again returns the same persistent
        // identifier, not a fresh one each time.
        let again = db
            .construct_nameid("alice", SP, Some(&create), None)
            .unwrap();
        assert_eq!(persistent.value, again.value);
    }

    #[test]
    fn test_allow_create_false_does_not_block_non_persistent_formats() {
        // Decided behavior (not a bug): AllowCreate (E14) is only meaningful
        // for the persistent format, matching pysaml2's own
        // construct_nameid()/persistent_nameid() split - transient/email/
        // unspecified/custom formats have no "existing identifier to reuse"
        // concept in the same sense and are minted fresh regardless of
        // AllowCreate. See ProcessedAuthnRequest::has_name_id_policy's doc.
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_EMAIL.to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&policy), None)
            .expect("AllowCreate=false must not block a non-persistent format");
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_EMAIL));
    }

    #[test]
    fn concurrent_persistent_requests_for_the_same_user_and_sp_mint_only_one_identifier() {
        // Regression: construct_nameid/get_nameid's persistent path used to
        // be a plain check-then-create (match_local_id, then create_id +
        // store), so two concurrent requests for the same (user, SP) could
        // both observe "no existing association" and each mint a different
        // persistent identifier - violating the "stable per (user, SP)"
        // invariant (E78) the very first time it mattered. The
        // atomic get_or_insert_durable closes this.
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || db.persistent_nameid("alice", Some(SP)).unwrap())
            })
            .collect();

        let values: Vec<String> = threads
            .into_iter()
            .map(|t| t.join().unwrap().value)
            .collect();

        let first = &values[0];
        assert!(
            values.iter().all(|v| v == first),
            "concurrent persistent requests for the same (user, SP) must all \
             resolve to the same identifier, got: {values:?}"
        );

        // Exactly one persistent NameID was stored for (alice, SP), not one
        // per thread that lost the race.
        let persistent_entries: Vec<_> = db
            .name_ids_for("alice")
            .unwrap()
            .into_iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        assert_eq!(persistent_entries.len(), 1);
    }

    #[test]
    fn concurrent_persistent_and_durable_issuance_do_not_clobber_each_other() {
        // A persistent mint and the durable non-persistent formats (email) are
        // separate records. Running them concurrently for one user must leave
        // exactly one persistent record and every email record: neither kind
        // may drop or merge the other. (Transient identifiers are not stored
        // by default, so they do not exercise this path.)
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.persistent_nameid("alice", Some(SP)).unwrap();
            }));
        }
        for i in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.get_nameid(
                    "alice",
                    constants::NAMEID_EMAIL,
                    Some(&format!("{SP}/{i}")),
                    Some(IDP),
                )
                .unwrap();
            }));
        }
        for t in threads {
            t.join().unwrap();
        }

        let entries = db.name_ids_for("alice").unwrap();
        let persistent: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        let email: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_EMAIL))
            .collect();
        assert_eq!(
            persistent.len(),
            1,
            "persistent entry must survive: {entries:?}"
        );
        assert_eq!(
            email.len(),
            8,
            "every durable non-persistent issuance must survive: {entries:?}"
        );
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
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();
        db.remove_remote(&nid).unwrap();
        assert!(db.find_local_id(&nid).unwrap().is_none());
        assert!(db.name_ids_for("alice").unwrap().is_empty());

        let n1 = db.persistent_nameid("alice", Some(SP)).unwrap();
        let n2 = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        db.remove_local("alice").unwrap();
        assert!(db.find_local_id(&n1).unwrap().is_none());
        assert!(db.find_local_id(&n2).unwrap().is_none());
    }

    #[test]
    fn test_manage_name_id_new_id_and_terminate() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();

        let updated = db
            .handle_manage_name_id_request(&nid, &NewIdOrTerminate::NewId("sp-alias".to_string()))
            .unwrap();
        assert_eq!(updated.sp_provided_id.as_deref(), Some("sp-alias"));
        assert_eq!(
            db.find_local_id(&updated).unwrap().as_deref(),
            Some("alice")
        );
        let stored = db
            .match_local_id("alice", Some(SP), Some(IDP))
            .unwrap()
            .unwrap();
        assert_eq!(stored.sp_provided_id.as_deref(), Some("sp-alias"));

        db.handle_manage_name_id_request(&updated, &NewIdOrTerminate::Terminate)
            .unwrap();
        assert!(db.find_local_id(&updated).unwrap().is_none());
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
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();

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
        let nid = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert!(nid.value.ends_with("@example.org"));
    }

    #[test]
    fn test_email_format_reverse_mapping_uses_full_value() {
        // The collision check and the reverse index must both key on the
        // final `local-part@domain` value, so the issued email NameID resolves
        // back to its local principal.
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert!(nid.value.contains('@'));
        assert_eq!(db.find_local_id(&nid).unwrap().as_deref(), Some("alice"));
    }
}
