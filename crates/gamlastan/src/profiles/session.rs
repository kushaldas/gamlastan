// SAML 2.0 Session management for profile operations
//
// Provides a SessionStore trait for IdPs to track session participants
// and propagate logout requests.

use chrono::{DateTime, Utc};

use crate::core::assertion::name_id::NameId;
use crate::core::constants::NAMEID_UNSPECIFIED;

/// A participant in a SAML session (typically an SP that received an assertion).
#[derive(Debug, Clone)]
pub struct SessionParticipant {
    /// Entity ID of the session participant (SP).
    pub entity_id: String,

    /// The NameID value used for this participant.
    pub name_id_value: String,

    /// The NameID format used for this participant.
    pub name_id_format: Option<String>,

    /// NameID name qualifier.
    pub name_qualifier: Option<String>,

    /// NameID SP name qualifier.
    pub sp_name_qualifier: Option<String>,

    /// SP-provided identifier component of the participant NameID.
    pub sp_provided_id: Option<String>,

    /// The session index(es) associated with this participant.
    pub session_indexes: Vec<String>,

    /// SLO endpoint URL for this participant (from metadata).
    pub slo_url: Option<String>,

    /// SLO binding for this participant.
    pub slo_binding: Option<String>,

    /// When this participant's session expires (E79: upper bound).
    pub session_not_on_or_after: Option<DateTime<Utc>>,
}

/// A SAML session tracked by the IdP.
#[derive(Debug, Clone)]
pub struct SamlSession {
    /// Unique session identifier (e.g., the SessionIndex from AuthnStatement).
    pub session_index: String,

    /// The principal's NameID value.
    pub principal_name_id: String,

    /// The principal's NameID format.
    pub principal_name_id_format: Option<String>,

    /// Authentication instant.
    pub authn_instant: DateTime<Utc>,

    /// Authentication context class reference.
    pub authn_context_class_ref: Option<String>,

    /// Session expiry (E79: upper bound).
    pub session_not_on_or_after: Option<DateTime<Utc>>,

    /// All SPs that participate in this session.
    pub participants: Vec<SessionParticipant>,
}

/// Trait for session storage and retrieval.
///
/// Implementations manage IdP-side session state. The IdP creates sessions
/// when issuing assertions and uses them during Single Logout to propagate
/// logout requests to all session participants.
pub trait SessionStore: Send + Sync {
    /// Create a new session. Returns the session index.
    fn create_session(&self, session: SamlSession) -> String;

    /// Look up a session by session index.
    fn get_session(&self, session_index: &str) -> Option<SamlSession>;

    /// Look up all sessions for a given principal NameID.
    fn get_sessions_by_name_id(&self, name_id: &str) -> Vec<SamlSession>;

    /// Look up sessions in which the authenticated requester is a participant
    /// with the exact request NameID and, when supplied, SessionIndex.
    ///
    /// The default preserves source compatibility for custom stores while
    /// filtering their legacy principal lookup. Stores supporting
    /// participant-specific pseudonymous NameIDs should override this method.
    fn get_sessions_for_participant(
        &self,
        requester_entity_id: &str,
        name_id: &NameId,
        session_indexes: &[String],
    ) -> Vec<SamlSession> {
        self.get_sessions_by_name_id(&name_id.value)
            .into_iter()
            .filter(|session| {
                session.participants.iter().any(|participant| {
                    participant_matches(participant, requester_entity_id, name_id, session_indexes)
                })
            })
            .collect()
    }

    /// Add a participant to an existing session.
    fn add_participant(&self, session_index: &str, participant: SessionParticipant) -> bool;

    /// Remove a participant from a session (after successful logout).
    fn remove_participant(&self, session_index: &str, entity_id: &str) -> bool;

    /// Destroy a session entirely.
    fn destroy_session(&self, session_index: &str) -> bool;

    /// Remove all expired sessions.
    fn cleanup_expired(&self);
}

/// In-memory session store for testing and simple deployments.
pub struct InMemorySessionStore {
    sessions: std::sync::Mutex<std::collections::HashMap<String, SamlSession>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Returns the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Returns true if there are no active sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.lock().unwrap().is_empty()
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn create_session(&self, session: SamlSession) -> String {
        let index = session.session_index.clone();
        self.sessions.lock().unwrap().insert(index.clone(), session);
        index
    }

    fn get_session(&self, session_index: &str) -> Option<SamlSession> {
        self.sessions.lock().unwrap().get(session_index).cloned()
    }

    fn get_sessions_by_name_id(&self, name_id: &str) -> Vec<SamlSession> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.principal_name_id == name_id)
            .cloned()
            .collect()
    }

    fn get_sessions_for_participant(
        &self,
        requester_entity_id: &str,
        name_id: &NameId,
        session_indexes: &[String],
    ) -> Vec<SamlSession> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|session| {
                session.participants.iter().any(|participant| {
                    participant_matches(participant, requester_entity_id, name_id, session_indexes)
                })
            })
            .cloned()
            .collect()
    }

    fn add_participant(&self, session_index: &str, participant: SessionParticipant) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_index) {
            session.participants.push(participant);
            true
        } else {
            false
        }
    }

    fn remove_participant(&self, session_index: &str, entity_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_index) {
            let before = session.participants.len();
            session.participants.retain(|p| p.entity_id != entity_id);
            session.participants.len() < before
        } else {
            false
        }
    }

    fn destroy_session(&self, session_index: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .remove(session_index)
            .is_some()
    }

    fn cleanup_expired(&self) {
        let now = Utc::now();
        self.sessions.lock().unwrap().retain(|_, session| {
            session
                .session_not_on_or_after
                .is_none_or(|expiry| now < expiry)
        });
    }
}

fn participant_matches(
    participant: &SessionParticipant,
    requester_entity_id: &str,
    name_id: &NameId,
    session_indexes: &[String],
) -> bool {
    participant.entity_id == requester_entity_id
        && participant.name_id_value == name_id.value
        // SAML Core defines an omitted Format as the SAML 1.1
        // "unspecified" URI, so those two wire representations identify the
        // same participant.
        && participant
            .name_id_format
            .as_deref()
            .unwrap_or(NAMEID_UNSPECIFIED)
            == name_id.format.as_deref().unwrap_or(NAMEID_UNSPECIFIED)
        && participant.name_qualifier == name_id.name_qualifier
        && participant.sp_name_qualifier == name_id.sp_name_qualifier
        && participant.sp_provided_id == name_id.sp_provided_id
        && (session_indexes.is_empty()
            || session_indexes
                .iter()
                .any(|index| participant.session_indexes.contains(index)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn make_participant(entity_id: &str) -> SessionParticipant {
        SessionParticipant {
            entity_id: entity_id.to_string(),
            name_id_value: "user@example.com".to_string(),
            name_id_format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
            session_indexes: vec!["_idx1".to_string()],
            slo_url: Some(format!("https://{entity_id}/slo")),
            slo_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".to_string()),
            session_not_on_or_after: None,
        }
    }

    fn make_session(index: &str) -> SamlSession {
        SamlSession {
            session_index: index.to_string(),
            principal_name_id: "user@example.com".to_string(),
            principal_name_id_format: None,
            authn_instant: Utc::now(),
            authn_context_class_ref: None,
            session_not_on_or_after: Some(Utc::now() + TimeDelta::hours(8)),
            participants: vec![],
        }
    }

    #[test]
    fn test_create_and_get_session() {
        let store = InMemorySessionStore::new();
        let session = make_session("_sess1");
        store.create_session(session);

        assert_eq!(store.len(), 1);
        let retrieved = store.get_session("_sess1").unwrap();
        assert_eq!(retrieved.session_index, "_sess1");
        assert_eq!(retrieved.principal_name_id, "user@example.com");
    }

    #[test]
    fn test_get_sessions_by_name_id() {
        let store = InMemorySessionStore::new();
        store.create_session(make_session("_s1"));
        store.create_session(make_session("_s2"));

        let mut other = make_session("_s3");
        other.principal_name_id = "other@example.com".to_string();
        store.create_session(other);

        let sessions = store.get_sessions_by_name_id("user@example.com");
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn participant_lookup_binds_requester_name_id_and_session_index() {
        let store = InMemorySessionStore::new();
        let mut session = make_session("_s1");
        session.principal_name_id = "internal-principal".to_string();
        session.participants = vec![make_participant("https://sp.example.com")];
        store.create_session(session);
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        assert_eq!(
            store
                .get_sessions_for_participant(
                    "https://sp.example.com",
                    &name_id,
                    &["_idx1".to_string()]
                )
                .len(),
            1
        );
        assert!(store
            .get_sessions_for_participant(
                "https://other-sp.example.com",
                &name_id,
                &["_idx1".to_string()]
            )
            .is_empty());
        assert!(store
            .get_sessions_for_participant(
                "https://sp.example.com",
                &name_id,
                &["_different".to_string()]
            )
            .is_empty());
    }

    #[test]
    fn participant_lookup_normalizes_omitted_unspecified_name_id_format() {
        let store = InMemorySessionStore::new();
        let mut session = make_session("_s1");
        session.participants = vec![make_participant("https://sp.example.com")];
        store.create_session(session);

        let explicit_unspecified = NameId {
            value: "user@example.com".to_string(),
            format: Some(NAMEID_UNSPECIFIED.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        assert_eq!(
            store
                .get_sessions_for_participant("https://sp.example.com", &explicit_unspecified, &[])
                .len(),
            1
        );

        let mut explicit_participant = make_participant("https://sp.example.com");
        explicit_participant.name_id_format = Some(NAMEID_UNSPECIFIED.to_string());
        let mut reverse_session = make_session("_s2");
        reverse_session.participants = vec![explicit_participant];
        store.create_session(reverse_session);
        let omitted = NameId {
            format: None,
            ..explicit_unspecified.clone()
        };
        assert_eq!(
            store
                .get_sessions_for_participant("https://sp.example.com", &omitted, &[])
                .len(),
            2
        );

        let different_format = NameId {
            format: Some(crate::core::constants::NAMEID_EMAIL.to_string()),
            ..omitted
        };
        assert!(store
            .get_sessions_for_participant("https://sp.example.com", &different_format, &[])
            .is_empty());
    }

    #[test]
    fn test_add_and_remove_participant() {
        let store = InMemorySessionStore::new();
        store.create_session(make_session("_sess1"));

        assert!(store.add_participant("_sess1", make_participant("sp1.example.com")));
        assert!(store.add_participant("_sess1", make_participant("sp2.example.com")));

        let session = store.get_session("_sess1").unwrap();
        assert_eq!(session.participants.len(), 2);

        assert!(store.remove_participant("_sess1", "sp1.example.com"));
        let session = store.get_session("_sess1").unwrap();
        assert_eq!(session.participants.len(), 1);
        assert_eq!(session.participants[0].entity_id, "sp2.example.com");
    }

    #[test]
    fn test_destroy_session() {
        let store = InMemorySessionStore::new();
        store.create_session(make_session("_sess1"));
        assert_eq!(store.len(), 1);

        assert!(store.destroy_session("_sess1"));
        assert_eq!(store.len(), 0);
        assert!(!store.destroy_session("_sess1")); // already gone
    }

    #[test]
    fn test_cleanup_expired() {
        let store = InMemorySessionStore::new();

        let mut expired = make_session("_expired");
        expired.session_not_on_or_after = Some(Utc::now() - TimeDelta::hours(1));
        store.create_session(expired);

        store.create_session(make_session("_active"));
        assert_eq!(store.len(), 2);

        store.cleanup_expired();
        assert_eq!(store.len(), 1);
        assert!(store.get_session("_active").is_some());
        assert!(store.get_session("_expired").is_none());
    }

    #[test]
    fn test_nonexistent_session() {
        let store = InMemorySessionStore::new();
        assert!(store.get_session("_none").is_none());
        assert!(!store.add_participant("_none", make_participant("sp")));
        assert!(!store.remove_participant("_none", "sp"));
    }
}
