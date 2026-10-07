//! IdP response orchestration: composes the IdP primitives into the SAML Web
//! Browser SSO response-assembly flow.
//!
//! The [`ResponseEngine`] holds the deployment-specific pieces — the release
//! policy, the identity database, the authn broker, the assertion store, and
//! the signer — and exposes two entry points:
//!
//! - [`check_request`] — a pure, no-I/O decision over the ForceAuthn ×
//!   IsPassive × RequestedAuthnContext matrix. It answers the one question the
//!   application must answer: "do I have a session, and which method
//!   established it?"
//! - [`create_authn_response`] / [`create_denial_response`] — assemble and
//!   sign the actual response.
//!
//! The load-bearing distinction (see the module's ADR) is that **what varies
//! by deployment is where released attributes and identity facts come from;
//! what must not vary is how a compliant `Response` is assembled from them**.
//! The release decision is the only injected seam ([`AttributeRelease`]);
//! everything downstream — NameID construction, authn-context matching,
//! audience/conditions, session index and lifetime, and signed protocol
//! errors — is the fixed correctness core.
//!
//! # Defaults to review before production
//!
//! Some defaults are permissive on purpose, to match pysaml2. Each has a switch;
//! decide each one for a production IdP rather than inherit it:
//!
//! - **Attribute release.** With no rule covering an SP (entity categories,
//!   attributes requested in its metadata, restrictions), every attribute the
//!   application supplies is released. Configure the rules, or fail closed with
//!   [`PolicyEntry::with_deny_unconfigured_release`](crate::idp::policy::PolicyEntry::with_deny_unconfigured_release).
//! - **NameID formats.** Any requested format (up to
//!   [`MAX_NAMEID_FORMAT_LEN`](crate::idp::policy::MAX_NAMEID_FORMAT_LEN) bytes) is
//!   accepted, and every non-transient one is stored, so an SP that invents format
//!   strings grows the identity store by one record per string. Set
//!   [`PolicyEntry::with_supported_nameid_formats`](crate::idp::policy::PolicyEntry::with_supported_nameid_formats)
//!   (`ISSUABLE_NAMEID_FORMATS` is a starting set).
//! - **Signing.** Nothing configured signs the assertion. With an HSM, list only
//!   the token's signature method in any
//!   [`SigningPreference`](crate::crypto::SigningPreference).
//! - **Transient NameIDs** are not stored, so a back-channel logout cannot
//!   resolve one unless
//!   [`IdentDb::with_persist_transient`](crate::idp::IdentDb::with_persist_transient)
//!   is set.
//!
//! # What the application must still enforce
//!
//! The engine decides from the processed request, which deliberately leaves out
//! two things an application may need to act on. Read them from the original
//! [`AuthnRequest`](crate::core::protocol::request::AuthnRequest) before
//! calling [`create_authn_response`]:
//!
//! - **`Scoping`** (`ProxyCount`, `IDPList`, `RequesterID`). An originating IdP may
//!   ignore it. A **proxying** IdP must not forward a request it was told not to
//!   (SAML Core 3.4.1.2); the engine never forwards, so it cannot know.
//! - **The requested `Subject`**, via `AuthnRequest::requested_subject`. The
//!   engine issues for whoever authenticated and does not compare them with the
//!   principal the SP named, because mapping a NameID to a local user is
//!   deployment-specific. An application that cannot honour a requested subject
//!   should refuse the request, as `example-idp` does.
//!
//! The `gamlastan-actix` `AuthnSubjectCallback` receives the parsed request for
//! this reason.
//!
//! # Example
//!
//! ```
//! use gamlastan::idp::orchestrator::{
//!     check_request, AuthnMethodRef, Disposition, EstablishedSession, ResponseEngine,
//!     ResponseParams,
//! };
//! use gamlastan::idp::{AuthnBroker, IdentDb, ReleasePolicy};
//!
//! // A broker with a password method at level 1.
//! let mut broker = AuthnBroker::new();
//! broker.add(
//!     "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
//!     "/login/password",
//!     1,
//!     None,
//! );
//!
//! // No session and no IsPassive: the request must be authenticated.
//! let idents = IdentDb::in_memory("https://idp.example.org/metadata");
//! let decisions = ReleasePolicy::new();
//! let engine = ResponseEngine {
//!     idp_entity_id: "https://idp.example.org/metadata",
//!     decisions: &decisions,
//!     release: &decisions,
//!     idents: &idents,
//!     broker: &broker,
//!     assertions: None,
//!     signer: &gamlastan::crypto::SamlSigner::new(gamlastan::crypto::KeysManager::new()),
//!     cert_der_b64: "",
//! };
//!
//! let params = test_params();
//! let disposition = check_request(&engine, &params, None);
//! assert!(matches!(disposition, Disposition::Authenticate { .. }));
//!
//! // A reusable session (no ForceAuthn, method satisfies the request) is reused.
//! let session = EstablishedSession {
//!     subject_id: "alice".to_string(),
//!     authn_method: AuthnMethodRef::Inline {
//!         class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
//!         authn_authority: None,
//!     },
//!     authn_instant: chrono::Utc::now(),
//!     session_index: "_sess_1".to_string(),
//! };
//! let disposition = check_request(&engine, &params, Some(&session));
//! assert!(matches!(disposition, Disposition::ReuseSession { .. }));
//!
//! fn test_params() -> ResponseParams {
//!     use gamlastan::core::assertion::issuer::Issuer;
//!     use gamlastan::core::identifiers::SamlVersion;
//!     use gamlastan::core::protocol::request::{AuthnRequest, RequestBase};
//!     use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
//!     use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
//!     use gamlastan::metadata::types::sp::SpSsoDescriptor;
//!     use gamlastan::profiles::sso::idp::process_authn_request;
//!
//!     let sp = SpSsoDescriptor {
//!         sso_base: SsoDescriptorBase {
//!             base: RoleDescriptorBase::new(vec![
//!                 "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
//!             ]),
//!             artifact_resolution_services: vec![],
//!             single_logout_services: vec![],
//!             manage_name_id_services: vec![],
//!             name_id_formats: vec![],
//!         },
//!         authn_requests_signed: None,
//!         want_assertions_signed: Some(true),
//!         assertion_consumer_services: vec![IndexedEndpoint::new_default(
//!             Endpoint::new(
//!                 "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
//!                 "https://sp.example.org/acs",
//!             ),
//!             0,
//!         )],
//!         attribute_consuming_services: vec![],
//!     };
//!     let request = AuthnRequest {
//!         base: RequestBase {
//!             id: "_req1".to_string(),
//!             version: SamlVersion::V2_0,
//!             issue_instant: chrono::Utc::now(),
//!             destination: Some("https://idp.example.org/sso".to_string()),
//!             consent: None,
//!             issuer: Some(Issuer::entity("https://sp.example.org/metadata")),
//!             has_signature: false,
//!         },
//!         subject: None,
//!         name_id_policy: None,
//!         conditions: None,
//!         requested_authn_context: None,
//!         scoping: None,
//!         force_authn: None,
//!         is_passive: None,
//!         assertion_consumer_service_index: None,
//!         assertion_consumer_service_url: Some("https://sp.example.org/acs".to_string()),
//!         protocol_binding: Some(
//!             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
//!         ),
//!         attribute_consuming_service_index: None,
//!         provider_name: None,
//!         extensions: None,
//!     };
//!     let processed = process_authn_request(&request, &sp, false).unwrap();
//!     ResponseParams {
//!         processed,
//!         sp_sso: sp,
//!         sp_entity: None,
//!     }
//! }
//! ```

pub mod denial;
pub mod params;
pub mod release;
pub mod respond;

#[cfg(test)]
mod tests;

pub use denial::Denial;
pub use params::{
    AuthenticatedSubject, AuthnMethodRef, DeniedResponse, Disposition, EstablishedSession,
    IssuedResponse, ResponseOutcome, ResponseParams,
};
pub use release::{AttributeRelease, ChainedRelease, PassThroughRelease};
pub use respond::{check_request, create_authn_response, create_denial_response, ResponseEngine};
