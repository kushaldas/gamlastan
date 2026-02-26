// SAML 2.0 Name ID security management
//
// Per Errata:
// - E78: Persistent identifiers MUST never be reassigned to a different principal.
// - E14: AllowCreate means the IdP may create a new identifier OR associate
//         an existing identifier with the principal (not just create).

use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for tracking persistent identifier assignments (E78).
///
/// Implementations ensure that a persistent identifier is never reassigned
/// to a different principal.
pub trait PersistentIdStore: Send + Sync {
    /// Record or verify a persistent ID assignment.
    ///
    /// - `name_id` is the persistent identifier value.
    /// - `sp_entity_id` is the SP that received this identifier.
    /// - `principal` is a local identifier for the authenticated user.
    ///
    /// Returns `Ok(())` if the assignment is valid (new or matches existing).
    /// Returns `Err(message)` if the ID was previously assigned to a different principal.
    fn check_and_record(
        &self,
        name_id: &str,
        sp_entity_id: &str,
        principal: &str,
    ) -> Result<(), String>;
}

/// In-memory persistent ID store.
///
/// Uses a composite key of (name_id, sp_entity_id) mapping to the principal.
/// For production, implement `PersistentIdStore` with database backing.
pub struct InMemoryPersistentIdStore {
    // Key: (name_id, sp_entity_id), Value: principal
    assignments: Mutex<HashMap<(String, String), String>>,
}

impl InMemoryPersistentIdStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            assignments: Mutex::new(HashMap::new()),
        }
    }

    /// Get the number of tracked assignments.
    pub fn len(&self) -> usize {
        self.assignments.lock().unwrap().len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.assignments.lock().unwrap().is_empty()
    }
}

impl Default for InMemoryPersistentIdStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentIdStore for InMemoryPersistentIdStore {
    fn check_and_record(
        &self,
        name_id: &str,
        sp_entity_id: &str,
        principal: &str,
    ) -> Result<(), String> {
        let mut assignments = self.assignments.lock().unwrap();
        let key = (name_id.to_string(), sp_entity_id.to_string());

        if let Some(existing_principal) = assignments.get(&key) {
            if existing_principal != principal {
                return Err(format!(
                    "Persistent ID '{}' for SP '{}' was previously assigned to principal '{}', \
                     cannot reassign to '{}' (E78)",
                    name_id, sp_entity_id, existing_principal, principal
                ));
            }
            // Same principal - OK
            Ok(())
        } else {
            // New assignment
            assignments.insert(key, principal.to_string());
            Ok(())
        }
    }
}

/// Interpret the AllowCreate flag per E14.
///
/// Per E14: AllowCreate="true" means the IdP is permitted to:
/// - Create a new identifier for the principal, OR
/// - Associate an existing identifier with the principal.
///
/// Per E14: AllowCreate="false" (or absent) means the IdP MUST NOT create
/// a new identifier, but MAY return an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowCreateAction {
    /// IdP may create a new identifier or associate an existing one.
    CreateOrAssociate,
    /// IdP must use an existing identifier only.
    ExistingOnly,
}

/// Interpret the AllowCreate flag value.
pub fn interpret_allow_create(allow_create: Option<bool>) -> AllowCreateAction {
    match allow_create {
        Some(true) => AllowCreateAction::CreateOrAssociate,
        _ => AllowCreateAction::ExistingOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_assignment() {
        let store = InMemoryPersistentIdStore::new();
        assert!(store
            .check_and_record("_pid_123", "https://sp.example.com", "alice")
            .is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_same_assignment_ok() {
        let store = InMemoryPersistentIdStore::new();
        store
            .check_and_record("_pid_123", "https://sp.example.com", "alice")
            .unwrap();
        // Same assignment again should succeed
        assert!(store
            .check_and_record("_pid_123", "https://sp.example.com", "alice")
            .is_ok());
    }

    #[test]
    fn test_reassignment_rejected() {
        let store = InMemoryPersistentIdStore::new();
        store
            .check_and_record("_pid_123", "https://sp.example.com", "alice")
            .unwrap();
        // Different principal - should fail (E78)
        let result = store.check_and_record("_pid_123", "https://sp.example.com", "bob");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("E78"));
    }

    #[test]
    fn test_different_sp_same_id_ok() {
        let store = InMemoryPersistentIdStore::new();
        store
            .check_and_record("_pid_123", "https://sp1.example.com", "alice")
            .unwrap();
        // Same ID but different SP - different namespace, OK
        assert!(store
            .check_and_record("_pid_123", "https://sp2.example.com", "bob")
            .is_ok());
    }

    #[test]
    fn test_different_id_same_sp_ok() {
        let store = InMemoryPersistentIdStore::new();
        store
            .check_and_record("_pid_123", "https://sp.example.com", "alice")
            .unwrap();
        // Different ID for same SP - OK
        assert!(store
            .check_and_record("_pid_456", "https://sp.example.com", "bob")
            .is_ok());
    }

    #[test]
    fn test_empty_store() {
        let store = InMemoryPersistentIdStore::new();
        assert!(store.is_empty());
    }

    #[test]
    fn test_allow_create_true() {
        assert_eq!(
            interpret_allow_create(Some(true)),
            AllowCreateAction::CreateOrAssociate
        );
    }

    #[test]
    fn test_allow_create_false() {
        assert_eq!(
            interpret_allow_create(Some(false)),
            AllowCreateAction::ExistingOnly
        );
    }

    #[test]
    fn test_allow_create_none() {
        assert_eq!(
            interpret_allow_create(None),
            AllowCreateAction::ExistingOnly
        );
    }
}
