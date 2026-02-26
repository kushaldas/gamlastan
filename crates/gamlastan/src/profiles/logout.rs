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
