//! Parameters and results for the response orchestrator.
//!
//! The application supplies what only it knows — the authenticated subject,
//! the established session, the processed request and SP metadata — and the
//! engine derives the `NameId`, released attributes, and authn context, then
//! assembles and signs the response. These types are the contract between the
//! two.

use chrono::{DateTime, Utc};

use crate::core::assertion::attribute::Attribute;
use crate::core::assertion::name_id::NameId;
use crate::idp::authn_broker::AuthnMethod;
use crate::metadata::types::entity_descriptor::EntityDescriptor;
use crate::metadata::types::sp::SpSsoDescriptor;
use crate::profiles::error::ProfileError;
use crate::profiles::sso::idp::ProcessedAuthnRequest;

use super::denial::Denial;

/// A reference to the authentication method that actually ran.
///
/// The application reports *what* authenticated the principal; the engine
/// resolves it to an authn context class ref (and, for a proxy, the
/// authenticating authority) through the [`AuthnBroker`](crate::idp::authn_broker::AuthnBroker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthnMethodRef {
    /// The application supplies the class ref (and optional authenticating
    /// authority) directly, without a broker registration.
    ///
    /// For a proxy that already knows the upstream authority, or an IdP whose
    /// login flow does not go through the broker.
    Inline {
        /// The AuthnContext class ref to report.
        class_ref: String,
        /// The authenticating authority to report, if not this IdP.
        authn_authority: Option<String>,
    },
    /// A reference to a method registered in the broker.
    ///
    /// The engine resolves the class ref and authority from the registration.
    BrokerReference(String),
}

impl AuthnMethodRef {
    /// Resolve this reference against the broker.
    ///
    /// `Inline` is returned as-is. `BrokerReference` looks up the
    /// registration; `None` means the reference names no registered method
    /// (a stale or mistyped reference — e.g. `BrokerReference` naming a
    /// registration that was renamed or removed after a session was
    /// established). A `BrokerReference` is an opaque registration ID, not
    /// itself an AuthnContext class ref, so it must never be treated as one:
    /// callers must fail rather than substitute the reference string as the
    /// class ref, which would let a stale/mistyped reference silently
    /// become a bogus AuthnContextClassRef in a signed assertion.
    pub fn resolve(
        &self,
        broker: &crate::idp::authn_broker::AuthnBroker,
    ) -> Option<(String, Option<String>)> {
        match self {
            AuthnMethodRef::Inline {
                class_ref,
                authn_authority,
            } => Some((class_ref.clone(), authn_authority.clone())),
            AuthnMethodRef::BrokerReference(reference) => broker
                .get(reference)
                .map(|method| (method.class_ref.clone(), method.authn_authority.clone())),
        }
    }
}

/// The authenticated subject, as supplied by the application.
///
/// This is the inverted application contract: the application supplies the
/// *identity facts* (subject id, raw attributes, which method ran, when, and
/// the session index) and the engine derives the `NameId`, released
/// attributes, and authn context.
#[derive(Debug, Clone)]
pub struct AuthenticatedSubject {
    /// The local subject identifier, opaque to gamlastan.
    pub subject_id: String,
    /// The subject's attributes, pre-release and unfiltered.
    pub attributes: Vec<Attribute>,
    /// The authentication method that actually ran.
    pub authn_method: AuthnMethodRef,
    /// When the principal authenticated to the IdP. `None` means "now" (a
    /// fresh login); set the session's authentication time when reusing a
    /// session so `AuthnStatement/@AuthnInstant` reflects the real moment.
    pub authn_instant: Option<DateTime<Utc>>,
    /// The session index (used for SLO).
    pub session_index: Option<String>,
}

/// An established SSO session, as known to the application.
///
/// `check_request` uses this to decide whether a request can be satisfied
/// without re-authenticating. The application answers exactly one question:
/// "do I have a session, and which method established it?"
#[derive(Debug, Clone)]
pub struct EstablishedSession {
    /// The local subject identifier the session belongs to.
    pub subject_id: String,
    /// The authentication method that established the session.
    pub authn_method: AuthnMethodRef,
    /// When the principal authenticated to establish the session.
    pub authn_instant: DateTime<Utc>,
    /// The session index.
    pub session_index: String,
}

/// The request and metadata context for assembling a response.
///
/// Wraps the processed AuthnRequest together with the trusted SP metadata the
/// request was validated against. The engine reads the SP's entity categories,
/// `subject-id:req`, and `AttributeConsumingService` requirements from here.
#[derive(Debug, Clone)]
pub struct ResponseParams {
    /// The validated, processed AuthnRequest.
    pub processed: ProcessedAuthnRequest,
    /// The trusted SP SSO descriptor the request was bound to.
    pub sp_sso: SpSsoDescriptor,
    /// The full trusted SP entity descriptor (for entity categories and
    /// `subject-id:req`). May be `None` when only the SSO descriptor is
    /// available; the engine then treats the SP as having no categories.
    pub sp_entity: Option<EntityDescriptor>,
}

impl ResponseParams {
    /// Build parameters, checking that `sp_entity` (when given) is the SP the
    /// request was validated for.
    ///
    /// The engine reads entity categories and `subject-id:req` from the
    /// descriptor, and they decide what is released, so a descriptor for a
    /// different SP would release attributes under the wrong policy. The
    /// fields are public, so [`create_authn_response`] and
    /// [`create_denial_response`] repeat this check; this constructor reports
    /// the mistake where the parameters are built.
    ///
    /// [`create_authn_response`]: super::create_authn_response
    /// [`create_denial_response`]: super::create_denial_response
    pub fn new(
        processed: ProcessedAuthnRequest,
        sp_sso: SpSsoDescriptor,
        sp_entity: Option<EntityDescriptor>,
    ) -> Result<Self, ProfileError> {
        let params = ResponseParams {
            processed,
            sp_sso,
            sp_entity,
        };
        params.check_bound()?;
        Ok(params)
    }

    /// Build parameters from the trusted SP entity descriptor alone, taking the
    /// SAML 2.0 SP role from that same descriptor, so the role and the entity
    /// cannot come from different SPs. Errors if the descriptor is not the SP
    /// the request was validated for, or has no SAML 2.0 SP role.
    pub fn from_entity(
        processed: ProcessedAuthnRequest,
        entity: EntityDescriptor,
    ) -> Result<Self, ProfileError> {
        let sp_sso = entity
            .saml2_sp_sso_descriptor()
            .cloned()
            .ok_or_else(|| ProfileError::NoAcsEndpoint(entity.entity_id.clone()))?;
        ResponseParams::new(processed, sp_sso, Some(entity))
    }

    /// Check that the entity descriptor, if present, is for the SP the request
    /// came from, and that `sp_sso` is one of that entity's own SP roles (the
    /// role's `AttributeConsumingService`s, `WantAssertionsSigned` and
    /// algorithm extensions are trusted, so it must not come from another SP).
    pub(super) fn check_bound(&self) -> Result<(), ProfileError> {
        let Some(entity) = &self.sp_entity else {
            return Ok(());
        };
        if entity.entity_id != self.processed.sp_entity_id {
            return Err(ProfileError::SpEntityMismatch {
                request: self.processed.sp_entity_id.clone(),
                descriptor: entity.entity_id.clone(),
            });
        }
        if !entity.sp_sso_descriptors().contains(&self.sp_sso) {
            return Err(ProfileError::SpRoleMismatch {
                entity_id: entity.entity_id.clone(),
            });
        }
        Ok(())
    }

    /// The SP's published entity categories (empty when no entity descriptor).
    pub fn sp_entity_categories(&self) -> Vec<String> {
        self.sp_entity
            .as_ref()
            .map(|e| e.entity_categories())
            .unwrap_or_default()
    }

    /// The SP's `subject-id:req` metadata signal.
    pub fn subject_id_req(&self) -> crate::idp::entity_category::SubjectIdReq {
        use crate::idp::entity_category::{SubjectIdReq, SUBJECT_ID_REQ_ATTR};
        self.sp_entity
            .as_ref()
            .map(|e| {
                SubjectIdReq::from_metadata_values(&e.entity_attribute_values(SUBJECT_ID_REQ_ATTR))
            })
            .unwrap_or_default()
    }

    /// The raw AuthnRequest's `NameIDPolicy`, if the request carried one.
    ///
    /// Reconstructed from the flattened `ProcessedAuthnRequest` fields. The
    /// `has_name_id_policy` flag distinguishes "no NameIDPolicy" from a policy
    /// whose `Format` is absent (both would otherwise flatten to `None`).
    pub fn name_id_policy(&self) -> Option<crate::core::assertion::name_id::NameIdPolicy> {
        if !self.processed.has_name_id_policy {
            return None;
        }
        Some(crate::core::assertion::name_id::NameIdPolicy {
            format: self.processed.requested_name_id_format.clone(),
            sp_name_qualifier: self.processed.requested_sp_name_qualifier.clone(),
            allow_create: self.processed.allow_create,
        })
    }

    /// The raw AuthnRequest's `RequestedAuthnContext`, if any, including any
    /// `AuthnContextDeclRef`s. A request that names only declarations, or an
    /// empty element, is still a constraint, so this does not return `None` for
    /// it (the engine denies both: see
    /// [`ProcessedAuthnRequest::requested_authn_context_decl_refs`]).
    pub fn requested_authn_context(
        &self,
    ) -> Option<crate::core::protocol::request::RequestedAuthnContext> {
        // Present-but-empty (the comparison records the element was there) is
        // still a constraint, a malformed one the engine refuses; only a request
        // with no element at all is "no constraint".
        if self.processed.requested_authn_context_class_refs.is_empty()
            && self.processed.requested_authn_context_decl_refs.is_empty()
            && self.processed.authn_context_comparison.is_none()
        {
            return None;
        }
        Some(crate::core::protocol::request::RequestedAuthnContext {
            authn_context_class_refs: self.processed.requested_authn_context_class_refs.clone(),
            authn_context_decl_refs: self.processed.requested_authn_context_decl_refs.clone(),
            comparison: self
                .processed
                .authn_context_comparison
                .unwrap_or(crate::core::protocol::request::AuthnContextComparison::Exact),
        })
    }
}

/// The disposition of a request, as decided by `check_request`.
///
/// This is the pure, no-I/O outcome of the ForceAuthn × IsPassive × ACR
/// matrix. It tells the application what to do next: reuse the session,
/// authenticate (and with which methods), or deny.
#[derive(Debug, Clone)]
pub enum Disposition {
    /// The request can be satisfied by reusing the existing session.
    ReuseSession {
        /// The session to reuse.
        session: EstablishedSession,
    },
    /// The principal must authenticate.
    ///
    /// `methods` are the broker-picked authentication methods satisfying the
    /// request's `RequestedAuthnContext` (strongest preference first), so the
    /// application can present the right login options.
    Authenticate {
        /// The authentication methods satisfying the request.
        methods: Vec<AuthnMethod>,
    },
    /// The request cannot be satisfied and must be denied with a signed
    /// protocol error.
    Deny {
        /// The denial reason.
        denial: Denial,
    },
}

/// A fully assembled, signed response ready for delivery.
///
/// Carries the audit-relevant identifiers (response/assertion IDs, NameID,
/// session index, expiry) alongside the signed XML, so a downstream consumer
/// (e.g. eduID's Kantara-compliance audit log) can record the issuance without
/// re-parsing the XML.
#[derive(Debug, Clone)]
pub struct IssuedResponse {
    /// The signed response XML, ready to deliver over a binding.
    pub xml: String,
    /// The Response element's `ID`.
    pub response_id: String,
    /// The Assertion element's `ID` (for audit logging).
    pub assertion_id: Option<String>,
    /// The NameID issued to the subject.
    pub name_id: NameId,
    /// The session index (for SLO).
    pub session_index: Option<String>,
    /// The assertion's `NotOnOrAfter`.
    pub not_on_or_after: DateTime<Utc>,
    /// The names of the released attributes (names only, never values).
    pub released_attribute_names: Vec<String>,
}

/// A signed protocol-error response, ready for delivery.
///
/// Separate from [`IssuedResponse`] because a denial has no assertion, no
/// subject and no session: it carries only what exists.
#[derive(Debug, Clone)]
pub struct DeniedResponse {
    /// The signed response XML, ready to deliver over a binding.
    pub xml: String,
    /// The Response element's `ID`.
    pub response_id: String,
}

/// The outcome of assembling a response.
///
/// `Issued` is a successful response; `Denied` is a signed protocol error.
/// Programming/configuration faults are `Err(ProfileError)`, not an outcome.
// One value per response, returned and consumed at once, so the size gap between
// the variants costs nothing; boxing `Issued` would only complicate matching.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum ResponseOutcome {
    /// A successful, signed response.
    Issued(IssuedResponse),
    /// A signed protocol error.
    Denied {
        /// The denial reason.
        denial: Denial,
        /// The signed error response.
        response: DeniedResponse,
    },
}
