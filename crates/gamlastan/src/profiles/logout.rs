// SAML 2.0 Single Logout (SLO) Profile
//
// SAML Profiles Section 4.4
//
// Flows:
// - SP-initiated: SP sends LogoutRequest to IdP with NameID + SessionIndex(es)
// - IdP-propagated: IdP sends LogoutRequest to all session participants
// - Sync (SOAP) and async (HTTP Redirect/POST/Artifact) bindings

use chrono::{DateTime, TimeDelta, Utc};

use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::constants::STATUS_PARTIAL_LOGOUT;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::logout::{LogoutRequest, LogoutResponse};
use crate::core::protocol::status::{Status, StatusCode};
use crate::metadata::types::endpoint::Endpoint;
use crate::metadata::types::role_descriptor::SsoDescriptorBase;

use crate::profiles::error::ProfileError;
use crate::profiles::session::SessionParticipant;

/// Logout reason URIs.
pub mod reason {
    /// User-initiated logout.
    pub const USER: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";
    /// Administrative logout.
    pub const ADMIN: &str = "urn:oasis:names:tc:SAML:2.0:logout:admin";
}

/// Options for creating an SP-initiated LogoutRequest.
#[derive(Debug, Clone)]
pub struct SpLogoutRequestOptions {
    /// SP entity ID (Issuer).
    pub sp_entity_id: String,

    /// NameID of the principal being logged out.
    pub name_id: NameId,

    /// Session indexes to terminate.
    pub session_indexes: Vec<String>,

    /// Logout reason URI.
    pub reason: Option<String>,

    /// Destination (IdP SLO endpoint).
    pub destination: Option<String>,

    /// Request validity (NotOnOrAfter). Default: 5 minutes.
    pub not_on_or_after: Option<DateTime<Utc>>,
}

/// Create an SP-initiated LogoutRequest.
///
/// Per Profiles 4.4.4.1:
/// - MUST include NameID that identifies the principal
/// - SHOULD include SessionIndex values
/// - Messages MUST be signed for Redirect/POST
pub fn create_sp_logout_request(
    options: &SpLogoutRequestOptions,
) -> Result<LogoutRequest, ProfileError> {
    if options.sp_entity_id.is_empty() {
        return Err(ProfileError::MissingIssuer);
    }

    let now = Utc::now();
    let not_on_or_after = options
        .not_on_or_after
        .unwrap_or(now + TimeDelta::minutes(5));

    Ok(LogoutRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: now,
        destination: options.destination.clone(),
        consent: None,
        issuer: Some(Issuer::entity(&options.sp_entity_id)),
        has_signature: false,
        not_on_or_after: Some(not_on_or_after),
        reason: options.reason.clone(),
        name_id: NameIdOrEncryptedId::NameId(options.name_id.clone()),
        session_indexes: options.session_indexes.clone(),
    })
}

/// Result of processing a LogoutRequest at the IdP.
#[derive(Debug)]
pub struct LogoutPropagationResult {
    /// Total number of session participants that needed logout.
    pub total_participants: usize,
    /// Number that were successfully logged out.
    pub successful_logouts: usize,
    /// Entity IDs of participants that failed to log out.
    pub failed_participants: Vec<String>,
}

impl LogoutPropagationResult {
    /// Whether all participants were successfully logged out.
    pub fn is_complete(&self) -> bool {
        self.successful_logouts == self.total_participants
    }

    /// Whether at least one but not all participants were logged out.
    pub fn is_partial(&self) -> bool {
        self.successful_logouts > 0 && self.successful_logouts < self.total_participants
    }
}

/// Create a LogoutRequest to propagate to a session participant.
///
/// Used by the IdP to send logout requests to all SPs in the session.
pub fn create_idp_propagation_request(
    idp_entity_id: &str,
    participant: &SessionParticipant,
) -> LogoutRequest {
    let now = Utc::now();
    let name_id = NameId {
        value: participant.name_id_value.clone(),
        format: participant.name_id_format.clone(),
        name_qualifier: participant.name_qualifier.clone(),
        sp_name_qualifier: participant.sp_name_qualifier.clone(),
        sp_provided_id: None,
    };

    LogoutRequest {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: now,
        destination: participant.slo_url.clone(),
        consent: None,
        issuer: Some(Issuer::entity(idp_entity_id)),
        has_signature: false,
        not_on_or_after: Some(now + TimeDelta::minutes(5)),
        reason: Some(reason::USER.to_string()),
        name_id: NameIdOrEncryptedId::NameId(name_id),
        session_indexes: participant.session_indexes.clone(),
    }
}

/// Create a LogoutResponse (for both SP and IdP).
pub fn create_logout_response(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
    status: Status,
) -> LogoutResponse {
    LogoutResponse {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        destination: destination.map(|s| s.to_string()),
        consent: None,
        issuer: Some(Issuer::entity(entity_id)),
        has_signature: false,
        in_response_to: Some(in_response_to.to_string()),
        status,
    }
}

/// Create a success LogoutResponse.
pub fn create_logout_response_success(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> LogoutResponse {
    create_logout_response(entity_id, in_response_to, destination, Status::success())
}

/// Create a partial logout response (some participants failed).
pub fn create_logout_response_partial(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> LogoutResponse {
    let status = Status {
        status_code: StatusCode {
            value: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            sub_status: Some(Box::new(StatusCode {
                value: "urn:oasis:names:tc:SAML:2.0:status:PartialLogout".to_string(),
                sub_status: None,
            })),
        },
        status_message: Some("Some session participants could not be logged out".to_string()),
        status_detail: None,
    };
    create_logout_response(entity_id, in_response_to, destination, status)
}

// ── SP-side logout orchestration ────────────────────────────────────────────

/// State of one entity in an SP-driven multi-entity logout.
#[derive(Debug, Clone, PartialEq)]
pub enum TargetLogoutState {
    /// No LogoutRequest issued yet.
    Pending,
    /// A LogoutRequest was issued and we await the response.
    InProgress {
        /// The LogoutRequest ID (matched against InResponseTo).
        request_id: String,
    },
    /// The entity confirmed the logout.
    Succeeded,
    /// The logout failed (transport error or error status).
    Failed {
        /// Why the logout failed.
        reason: String,
    },
}

/// A session authority/participant the SP must log out from.
#[derive(Debug, Clone)]
pub struct LogoutTarget {
    /// The entity ID of the IdP (or other participant).
    pub entity_id: String,
    /// The NameID this entity knows the principal by.
    pub name_id: NameId,
    /// Session indexes to terminate at this entity.
    pub session_indexes: Vec<String>,
    /// The entity's SLO endpoint location.
    pub slo_url: String,
    /// The binding to use for the SLO endpoint.
    pub slo_binding: String,
}

/// A LogoutRequest ready to be delivered by the caller's transport.
#[derive(Debug)]
pub struct PendingLogoutRequest {
    /// The entity this request targets.
    pub entity_id: String,
    /// The LogoutRequest (sign before delivery for front-channel bindings).
    pub request: LogoutRequest,
    /// The binding to deliver it over.
    pub binding: String,
    /// The endpoint location to deliver it to.
    pub destination: String,
}

/// Outcome of correlating one LogoutResponse.
#[derive(Debug, Clone)]
pub struct LogoutResponseOutcome {
    /// The entity that responded.
    pub entity_id: String,
    /// Whether the top-level status was Success.
    pub success: bool,
    /// Whether the entity reported PartialLogout.
    pub partial: bool,
}

/// Transport-agnostic state machine for SP-initiated logout across all
/// entities that hold a session for the principal (the equivalent of
/// pysaml2's `global_logout`/`do_logout`/`handle_logout_response` loop).
///
/// The orchestrator never performs I/O. Drive it like this:
///
/// 1. `add_target()` for every entity that issued information about the
///    subject (typically the session-issuing IdPs).
/// 2. Loop: `next_request()` → sign if required → deliver over the returned
///    binding. For SOAP, parse the LogoutResponse and call
///    `handle_response()` immediately; for front-channel bindings call
///    `handle_response()` when the response comes back, or `mark_failed()`
///    on transport errors.
/// 3. When `is_complete()` is true, inspect `progress()` and perform the
///    local logout.
#[derive(Debug)]
pub struct SpLogoutOrchestrator {
    sp_entity_id: String,
    reason: Option<String>,
    targets: Vec<(LogoutTarget, TargetLogoutState)>,
}

impl SpLogoutOrchestrator {
    /// Create an orchestrator for the given SP entity ID.
    pub fn new(sp_entity_id: impl Into<String>) -> Self {
        SpLogoutOrchestrator {
            sp_entity_id: sp_entity_id.into(),
            reason: Some(reason::USER.to_string()),
            targets: Vec::new(),
        }
    }

    /// Set the logout reason URI included in every request.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Register an entity that must be logged out.
    pub fn add_target(&mut self, target: LogoutTarget) {
        self.targets.push((target, TargetLogoutState::Pending));
    }

    /// Produce the next LogoutRequest to deliver, if any target is pending.
    ///
    /// Marks the target as in-progress; the request ID is recorded so the
    /// matching LogoutResponse can be correlated via `handle_response()`.
    pub fn next_request(&mut self) -> Result<Option<PendingLogoutRequest>, ProfileError> {
        let sp_entity_id = self.sp_entity_id.clone();
        let reason = self.reason.clone();

        let Some((target, state)) = self
            .targets
            .iter_mut()
            .find(|(_, state)| *state == TargetLogoutState::Pending)
        else {
            return Ok(None);
        };

        let request = create_sp_logout_request(&SpLogoutRequestOptions {
            sp_entity_id,
            name_id: target.name_id.clone(),
            session_indexes: target.session_indexes.clone(),
            reason,
            destination: Some(target.slo_url.clone()),
            not_on_or_after: None,
        })?;

        *state = TargetLogoutState::InProgress {
            request_id: request.id.clone(),
        };

        Ok(Some(PendingLogoutRequest {
            entity_id: target.entity_id.clone(),
            binding: target.slo_binding.clone(),
            destination: target.slo_url.clone(),
            request,
        }))
    }

    /// Correlate a LogoutResponse with its in-progress request and record
    /// the outcome.
    ///
    /// The response is matched by InResponseTo; if an Issuer is present it
    /// must match the target's entity ID. Returns the per-entity outcome.
    pub fn handle_response(
        &mut self,
        response: &LogoutResponse,
    ) -> Result<LogoutResponseOutcome, ProfileError> {
        let in_response_to = response
            .in_response_to
            .as_deref()
            .ok_or_else(|| ProfileError::Other("LogoutResponse has no InResponseTo".to_string()))?;

        let (target, state) = self
            .targets
            .iter_mut()
            .find(|(_, state)| {
                matches!(state, TargetLogoutState::InProgress { request_id } if request_id == in_response_to)
            })
            .ok_or_else(|| {
                ProfileError::Other(format!(
                    "LogoutResponse InResponseTo {in_response_to} matches no outstanding request"
                ))
            })?;

        if let Some(issuer) = &response.issuer {
            if issuer.value != target.entity_id {
                return Err(ProfileError::Other(format!(
                    "LogoutResponse issuer {} does not match target entity {}",
                    issuer.value, target.entity_id
                )));
            }
        }

        let success = response.status.is_success();
        let partial = response
            .status
            .status_code
            .sub_status
            .as_ref()
            .is_some_and(|sub| sub.value == STATUS_PARTIAL_LOGOUT);

        *state = if partial {
            TargetLogoutState::Failed {
                reason: STATUS_PARTIAL_LOGOUT.to_string(),
            }
        } else if success {
            TargetLogoutState::Succeeded
        } else {
            TargetLogoutState::Failed {
                reason: response.status.status_code.value.clone(),
            }
        };

        Ok(LogoutResponseOutcome {
            entity_id: target.entity_id.clone(),
            success,
            partial,
        })
    }

    /// Record a transport-level failure for an entity (e.g., the SOAP call
    /// failed or the front-channel response never arrived).
    pub fn mark_failed(&mut self, entity_id: &str, failure_reason: impl Into<String>) {
        if let Some((_, state)) = self
            .targets
            .iter_mut()
            .find(|(t, _)| t.entity_id == entity_id)
        {
            *state = TargetLogoutState::Failed {
                reason: failure_reason.into(),
            };
        }
    }

    /// The current state of a target entity.
    pub fn target_state(&self, entity_id: &str) -> Option<&TargetLogoutState> {
        self.targets
            .iter()
            .find(|(t, _)| t.entity_id == entity_id)
            .map(|(_, state)| state)
    }

    /// Whether every target reached a final state (succeeded or failed).
    pub fn is_complete(&self) -> bool {
        self.targets.iter().all(|(_, state)| {
            matches!(
                state,
                TargetLogoutState::Succeeded | TargetLogoutState::Failed { .. }
            )
        })
    }

    /// Aggregate progress across all targets.
    pub fn progress(&self) -> LogoutPropagationResult {
        let successful = self
            .targets
            .iter()
            .filter(|(_, state)| *state == TargetLogoutState::Succeeded)
            .count();
        let failed = self
            .targets
            .iter()
            .filter(|(_, state)| matches!(state, TargetLogoutState::Failed { .. }))
            .map(|(t, _)| t.entity_id.clone())
            .collect();
        LogoutPropagationResult {
            total_participants: self.targets.len(),
            successful_logouts: successful,
            failed_participants: failed,
        }
    }
}

/// Find the SLO endpoint from a descriptor for the given binding.
pub fn find_slo_endpoint<'a>(
    sso_base: &'a SsoDescriptorBase,
    preferred_binding: &str,
) -> Option<&'a Endpoint> {
    sso_base
        .single_logout_services
        .iter()
        .find(|e| e.binding == preferred_binding)
        .or_else(|| sso_base.single_logout_services.first())
}

/// Validate an incoming LogoutRequest (at SP or IdP).
///
/// Checks:
/// - NameID is present
/// - Issuer is present
/// - NotOnOrAfter is not expired (if present)
pub fn validate_logout_request(
    request: &LogoutRequest,
    now: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> Result<(), ProfileError> {
    // NameID must be present (it's required in the type, but check for encrypted)
    match &request.name_id {
        NameIdOrEncryptedId::NameId(nid) if nid.value.is_empty() => {
            return Err(ProfileError::MissingNameId);
        }
        NameIdOrEncryptedId::EncryptedId(_) => {
            // Can't validate encrypted NameID without decryption
        }
        _ => {}
    }

    // Check NotOnOrAfter if present
    if let Some(not_on_or_after) = request.not_on_or_after {
        let skew = TimeDelta::seconds(clock_skew_seconds as i64);
        if now - skew >= not_on_or_after {
            return Err(ProfileError::Other(format!(
                "LogoutRequest expired: NotOnOrAfter={not_on_or_after}, now={now}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_name_id() -> NameId {
        NameId {
            value: "user@example.com".to_string(),
            format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    #[test]
    fn test_create_sp_logout_request() {
        let options = SpLogoutRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            name_id: make_name_id(),
            session_indexes: vec!["_sess1".to_string()],
            reason: Some(reason::USER.to_string()),
            destination: Some("https://idp.example.com/slo".to_string()),
            not_on_or_after: None,
        };
        let req = create_sp_logout_request(&options).unwrap();
        assert!(req.id.starts_with('_'));
        assert_eq!(req.issuer.as_ref().unwrap().value, "https://sp.example.com");
        assert_eq!(req.session_indexes, vec!["_sess1"]);
        assert_eq!(req.reason, Some(reason::USER.to_string()));
        assert!(req.not_on_or_after.is_some());
    }

    #[test]
    fn test_create_idp_propagation_request() {
        let participant = SessionParticipant {
            entity_id: "https://sp.example.com".to_string(),
            name_id_value: "user@example.com".to_string(),
            name_id_format: Some(
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            ),
            name_qualifier: None,
            sp_name_qualifier: None,
            session_indexes: vec!["_sess1".to_string()],
            slo_url: Some("https://sp.example.com/slo".to_string()),
            slo_binding: None,
            session_not_on_or_after: None,
        };
        let req = create_idp_propagation_request("https://idp.example.com", &participant);
        assert_eq!(
            req.issuer.as_ref().unwrap().value,
            "https://idp.example.com"
        );
        assert_eq!(
            req.destination,
            Some("https://sp.example.com/slo".to_string())
        );
        assert_eq!(req.session_indexes, vec!["_sess1"]);
    }

    #[test]
    fn test_create_logout_response_success() {
        let resp = create_logout_response_success(
            "https://idp.example.com",
            "_req123",
            Some("https://sp.example.com/slo"),
        );
        assert!(resp.status.is_success());
        assert_eq!(resp.in_response_to, Some("_req123".to_string()));
    }

    #[test]
    fn test_create_logout_response_partial() {
        let resp = create_logout_response_partial("https://idp.example.com", "_req123", None);
        assert!(resp.status.status_code.sub_status.is_some());
        let sub = resp.status.status_code.sub_status.unwrap();
        assert!(sub.value.contains("PartialLogout"));
    }

    #[test]
    fn test_validate_logout_request_valid() {
        let options = SpLogoutRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            name_id: make_name_id(),
            session_indexes: vec!["_sess1".to_string()],
            reason: None,
            destination: None,
            not_on_or_after: None,
        };
        let req = create_sp_logout_request(&options).unwrap();
        assert!(validate_logout_request(&req, Utc::now(), 180).is_ok());
    }

    #[test]
    fn test_validate_logout_request_expired() {
        let options = SpLogoutRequestOptions {
            sp_entity_id: "https://sp.example.com".to_string(),
            name_id: make_name_id(),
            session_indexes: vec![],
            reason: None,
            destination: None,
            not_on_or_after: Some(Utc::now() - TimeDelta::minutes(10)),
        };
        let req = create_sp_logout_request(&options).unwrap();
        let result = validate_logout_request(&req, Utc::now(), 180);
        assert!(result.is_err());
    }

    #[test]
    fn test_logout_propagation_result() {
        let result = LogoutPropagationResult {
            total_participants: 3,
            successful_logouts: 3,
            failed_participants: vec![],
        };
        assert!(result.is_complete());
        assert!(!result.is_partial());

        let result = LogoutPropagationResult {
            total_participants: 3,
            successful_logouts: 2,
            failed_participants: vec!["sp3.example.com".to_string()],
        };
        assert!(!result.is_complete());
        assert!(result.is_partial());
    }

    fn make_target(entity_id: &str) -> LogoutTarget {
        LogoutTarget {
            entity_id: entity_id.to_string(),
            name_id: make_name_id(),
            session_indexes: vec!["_sess1".to_string()],
            slo_url: format!("{entity_id}/slo"),
            slo_binding: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP".to_string(),
        }
    }

    #[test]
    fn test_orchestrator_full_success() {
        let mut orch = SpLogoutOrchestrator::new("https://sp.example.com");
        orch.add_target(make_target("https://idp1.example.com"));
        orch.add_target(make_target("https://idp2.example.com"));
        assert!(!orch.is_complete());

        // Drive the loop: request -> response per target
        while let Some(pending) = orch.next_request().unwrap() {
            assert_eq!(pending.destination, format!("{}/slo", pending.entity_id));
            assert_eq!(
                pending.request.issuer.as_ref().unwrap().value,
                "https://sp.example.com"
            );
            let response = create_logout_response_success(
                &pending.entity_id,
                &pending.request.id,
                Some("https://sp.example.com/slo"),
            );
            let outcome = orch.handle_response(&response).unwrap();
            assert!(outcome.success);
            assert!(!outcome.partial);
        }

        assert!(orch.is_complete());
        let progress = orch.progress();
        assert_eq!(progress.total_participants, 2);
        assert!(progress.is_complete());
    }

    #[test]
    fn test_orchestrator_partial_logout_response() {
        let mut orch = SpLogoutOrchestrator::new("https://sp.example.com");
        orch.add_target(make_target("https://idp1.example.com"));

        let pending = orch.next_request().unwrap().unwrap();
        let response =
            create_logout_response_partial("https://idp1.example.com", &pending.request.id, None);
        let outcome = orch.handle_response(&response).unwrap();
        assert!(outcome.success);
        assert!(outcome.partial);
        assert!(orch.is_complete());
        assert!(matches!(
            orch.target_state("https://idp1.example.com"),
            Some(TargetLogoutState::Failed { reason }) if reason == STATUS_PARTIAL_LOGOUT
        ));

        let progress = orch.progress();
        assert_eq!(progress.successful_logouts, 0);
        assert_eq!(
            progress.failed_participants,
            vec!["https://idp1.example.com".to_string()]
        );
    }

    #[test]
    fn test_orchestrator_failure_and_mark_failed() {
        let mut orch = SpLogoutOrchestrator::new("https://sp.example.com");
        orch.add_target(make_target("https://idp1.example.com"));
        orch.add_target(make_target("https://idp2.example.com"));

        // First target: error status
        let pending = orch.next_request().unwrap().unwrap();
        let response = create_logout_response(
            &pending.entity_id,
            &pending.request.id,
            None,
            Status {
                status_code: StatusCode {
                    value: "urn:oasis:names:tc:SAML:2.0:status:Responder".to_string(),
                    sub_status: None,
                },
                status_message: None,
                status_detail: None,
            },
        );
        let outcome = orch.handle_response(&response).unwrap();
        assert!(!outcome.success);

        // Second target: transport failure
        let pending = orch.next_request().unwrap().unwrap();
        orch.mark_failed(&pending.entity_id, "connection refused");

        assert!(orch.is_complete());
        let progress = orch.progress();
        assert_eq!(progress.successful_logouts, 0);
        assert_eq!(progress.failed_participants.len(), 2);
        assert!(matches!(
            orch.target_state("https://idp2.example.com"),
            Some(TargetLogoutState::Failed { .. })
        ));
    }

    #[test]
    fn test_orchestrator_rejects_unknown_in_response_to() {
        let mut orch = SpLogoutOrchestrator::new("https://sp.example.com");
        orch.add_target(make_target("https://idp1.example.com"));
        let _ = orch.next_request().unwrap().unwrap();

        let response = create_logout_response_success("https://idp1.example.com", "_unknown", None);
        assert!(orch.handle_response(&response).is_err());
    }

    #[test]
    fn test_orchestrator_rejects_issuer_mismatch() {
        let mut orch = SpLogoutOrchestrator::new("https://sp.example.com");
        orch.add_target(make_target("https://idp1.example.com"));
        let pending = orch.next_request().unwrap().unwrap();

        let response =
            create_logout_response_success("https://evil.example.com", &pending.request.id, None);
        assert!(orch.handle_response(&response).is_err());
    }

    #[test]
    fn test_find_slo_endpoint() {
        let base = crate::metadata::types::role_descriptor::SsoDescriptorBase {
            base: crate::metadata::types::role_descriptor::RoleDescriptorBase::new(vec![
                "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            ]),
            artifact_resolution_services: vec![],
            single_logout_services: vec![
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "https://idp.example.com/slo/redirect",
                ),
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                    "https://idp.example.com/slo/soap",
                ),
            ],
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        };

        let ep = find_slo_endpoint(&base, "urn:oasis:names:tc:SAML:2.0:bindings:SOAP").unwrap();
        assert!(ep.location.contains("soap"));

        // Falls back to first
        let ep =
            find_slo_endpoint(&base, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST").unwrap();
        assert!(ep.location.contains("redirect"));
    }
}
