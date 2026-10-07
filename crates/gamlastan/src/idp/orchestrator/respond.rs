//! The fixed correctness core: request-constraint checking and response
//! assembly.
//!
//! [`check_request`] is pure and I/O-free — it holds the whole ForceAuthn ×
//! IsPassive × RequestedAuthnContext matrix, so it is the cheapest thing to
//! test exhaustively. [`create_authn_response`] and
//! [`create_denial_response`] perform the actual assembly in a fixed order.

use chrono::{TimeDelta, Utc};

use crate::core::assertion::name_id::NameId;
use crate::core::protocol::response::Response;
use crate::idp::assertion_store::AssertionStore;
use crate::idp::authn_broker::AuthnBroker;
use crate::idp::ident::NameIdConstructor;
use crate::idp::policy::{sp_attribute_requirements, PolicyError, ReleasePolicy};
use crate::profiles::error::ProfileError;
use crate::profiles::sso::idp::{create_error_response, create_response, sign_response_xml_with};
use crate::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use crate::xml::serialize::SamlSerialize;

use super::denial::Denial;
use super::params::{
    AuthenticatedSubject, DeniedResponse, Disposition, EstablishedSession, IssuedResponse,
    ResponseParams,
};
use super::release::AttributeRelease;

/// The response-assembly engine.
///
/// Holds the deployment-specific pieces and the fixed correctness core. The
/// `release` seam is often `decisions` again (an originating IdP applies its
/// `ReleasePolicy`); a proxy passes a
/// [`PassThroughRelease`](super::PassThroughRelease) or
/// [`ChainedRelease`](super::ChainedRelease) instead.
///
/// `idents` is `dyn NameIdConstructor` rather than a concrete
/// `IdentDb<S: IdentityStore>` so this type carries no `IdentityStore`
/// generic — a ready-made framework integration (a fixed function signature
/// registered as a route handler) cannot parameterize that per-application;
/// type-erasing it here means a Redis/SQL-backed `IdentDb` works there too,
/// not just the default in-memory store.
pub struct ResponseEngine<'a> {
    /// This IdP's entity ID (used as the response/assertion `Issuer`).
    pub idp_entity_id: &'a str,
    /// The per-SP decisions: lifetime, NameID format, signing targets, and
    /// `fail_on_missing_requested`.
    pub decisions: &'a ReleasePolicy,
    /// The attribute-release seam. Often `decisions` again.
    pub release: &'a dyn AttributeRelease,
    /// The identity database (NameID construction), type-erased over its
    /// `IdentityStore` backend.
    pub idents: &'a dyn NameIdConstructor,
    /// The authn broker (RequestedAuthnContext matching).
    pub broker: &'a AuthnBroker,
    /// The assertion store, if back-channel queries must be answerable.
    pub assertions: Option<&'a dyn AssertionStore>,
    /// The signer for the response/assertion.
    pub signer: &'a crate::crypto::SamlSigner,
    /// The base64 DER signing certificate for `<ds:KeyInfo>`.
    pub cert_der_b64: &'a str,
}

/// Decide what to do with a request, without any I/O.
///
/// This is the pure core of the ForceAuthn × IsPassive × RequestedAuthnContext
/// matrix. The application answers exactly one question — "do I have a session,
/// and which method established it?" — by passing `session` (or `None`).
///
/// The decision order:
/// 1. If `IsPassive` and there is no reusable session (no session, or
///    `ForceAuthn` defeated reuse, or the session's method does not satisfy the
///    requested context), deny with [`Denial::NoPassive`].
/// 2. If a session exists, is not defeated by `ForceAuthn`, and its method
///    satisfies the requested context, [`Disposition::ReuseSession`].
/// 3. Otherwise, if the broker has methods satisfying the request,
///    [`Disposition::Authenticate`] with those methods.
/// 4. Otherwise (a context was requested and none is available), deny with
///    [`Denial::NoAuthnContext`].
pub fn check_request(
    engine: &ResponseEngine,
    params: &ResponseParams,
    session: Option<&EstablishedSession>,
) -> Disposition {
    let processed = &params.processed;

    // A requested authn-context constraint that cannot be matched is refused,
    // not treated as unconstrained, which would reuse any session or issue any
    // class ref.
    if unmatchable_authn_context(processed) {
        return Disposition::Deny {
            denial: Denial::NoAuthnContext,
        };
    }

    let requested = params.requested_authn_context();
    let picked = engine.broker.pick(requested.as_ref());
    let session_lifetime = engine.decisions.session_lifetime(&processed.sp_entity_id);
    let now = Utc::now();

    // A reusable session is one that exists, has not passed its own absolute
    // expiry (authn_instant + session_lifetime - independent of whatever
    // SessionNotOnOrAfter a *previous* response asserted, which must not
    // extend this), is not defeated by ForceAuthn, and whose establishing
    // method satisfies the requested context.
    let reusable = session.filter(|s| {
        now < s.authn_instant + session_lifetime
            && !processed.force_authn
            && session_satisfies(engine.broker, requested.as_ref(), s)
    });

    if processed.is_passive {
        return match reusable {
            Some(session) => Disposition::ReuseSession {
                session: session.clone(),
            },
            None => Disposition::Deny {
                denial: Denial::NoPassive,
            },
        };
    }

    if let Some(session) = reusable {
        return Disposition::ReuseSession {
            session: session.clone(),
        };
    }

    // No reusable session: authenticate, unless a context was requested and the
    // broker has nothing that satisfies it. An empty broker is not a statement
    // that nothing can, but only for `exact`: a deployment using only
    // `AuthnMethodRef::Inline` (a proxy, or a login flow outside the broker)
    // registers nothing, and `create_authn_response` accepts an inline method
    // whose class ref literally matches an exact request. Offer no methods and
    // let the callback authenticate; the response-time check enforces it. The
    // other comparisons need the broker's strength ordering, so with nothing
    // registered they can never be satisfied: deny before the user logs in.
    let inline_can_satisfy = engine.broker.is_empty()
        && requested.as_ref().is_some_and(|r| {
            r.comparison == crate::core::protocol::request::AuthnContextComparison::Exact
        });
    if picked.is_empty() && requested.is_some() && !inline_can_satisfy {
        return Disposition::Deny {
            denial: Denial::NoAuthnContext,
        };
    }

    // `AuthnBroker::pick` preserves registration order, not strength; sort
    // strongest-first so a caller that simply takes the first offered method
    // gets the strongest one, matching this variant's documented contract.
    let mut methods: Vec<_> = picked.into_iter().cloned().collect();
    methods.sort_by_key(|m| std::cmp::Reverse(m.level));

    Disposition::Authenticate { methods }
}

/// Whether the request carries a `RequestedAuthnContext` the engine cannot
/// match, so it must be refused rather than treated as unconstrained.
///
/// - It names an `AuthnContextDeclRef`: an `AuthnMethod` carries a class ref
///   only, so a declaration cannot be shown to be met.
/// - The element is present (`authn_context_comparison` is set whenever it is)
///   but names no class or declaration ref at all. The schema requires at
///   least one, so this is malformed; `process_authn_request` rejects it, and
///   this covers parameters built by hand.
fn unmatchable_authn_context(processed: &crate::profiles::sso::idp::ProcessedAuthnRequest) -> bool {
    !processed.requested_authn_context_decl_refs.is_empty()
        || (processed.requested_authn_context_class_refs.is_empty()
            && processed.authn_context_comparison.is_some())
}

/// Whether an established session's method satisfies the requested context.
///
/// The session's method is resolved to a class ref and checked against the
/// broker's picked set for the request. With no requested context, any session
/// is acceptable. A session whose method reference no longer resolves against
/// the broker (a stale or mistyped `BrokerReference`) is treated as not
/// satisfying the request - failing closed into re-authentication rather than
/// reusing a session whose actual class ref cannot be determined.
fn session_satisfies(
    broker: &AuthnBroker,
    requested: Option<&crate::core::protocol::request::RequestedAuthnContext>,
    session: &EstablishedSession,
) -> bool {
    let Some((class_ref, _authority)) = session.authn_method.resolve(broker) else {
        return false;
    };
    class_ref_satisfies(broker, requested, &class_ref)
}

/// Whether a resolved authn context class ref satisfies the requested
/// context. With no constraint (or nothing registered), any class ref is
/// acceptable only when nothing was requested.
fn class_ref_satisfies(
    broker: &AuthnBroker,
    requested: Option<&crate::core::protocol::request::RequestedAuthnContext>,
    class_ref: &str,
) -> bool {
    // No RequestedAuthnContext means the SP imposed no constraint at all -
    // any class ref is acceptable, regardless of what the broker happens to
    // have registered (an inline/ad-hoc method never registered in the
    // broker must not be rejected just because the broker also has an
    // `unspecified` baseline).
    let Some(requested) = requested else {
        return true;
    };
    // For "exact", a literal match against the requested class refs
    // (saml-core-2.0-os 3.3.2.2.1) satisfies the request without the broker
    // having a registration for the class ref at all: AuthnMethodRef::Inline
    // is documented as usable without any broker registration, and
    // pick_by_class_ref's exact branch only considers registered methods, so
    // consulting the broker first would reject an otherwise-exact inline method.
    if requested.comparison == crate::core::protocol::request::AuthnContextComparison::Exact
        && requested
            .authn_context_class_refs
            .iter()
            .any(|c| c == class_ref)
    {
        return true;
    }
    // Anything else is the broker's call. For "exact" that is what honours
    // `AuthnBroker::allow_exact_level_matching(true)`: `check_request` offers
    // same-level methods in that mode, so the response must accept the method
    // that was offered, not deny it after the user has authenticated.
    broker
        .pick(Some(requested))
        .iter()
        .any(|m| m.class_ref == class_ref)
}

/// Assemble and sign a successful response for an authenticated subject.
///
/// Fixed order:
/// 1. resolve the SP's required/optional attributes (→
///    [`Denial::InvalidAttributeConsumingServiceIndex`] for an explicit,
///    unrecognized index);
/// 2. run the release seam;
/// 3. check `fail_on_missing_requested` (→ [`Denial::MissingRequiredAttributes`]);
/// 4. resolve the authn context from the subject's method and check it
///    satisfies the request (→ [`Denial::NoAuthnContext`]), before anything
///    can be stored;
/// 5. construct the NameID (→ [`Denial::InvalidNameIdPolicy`] /
///    [`Denial::NameIdCreationNotAllowed`]);
/// 6. build `ResponseOptions`;
/// 7. sign per `decisions.sign(sp).resolve(want_assertions_signed)`;
/// 8. store the assertion (if a store is present);
/// 9. return the [`IssuedResponse`].
///
/// A protocol refusal is returned as
/// [`ResponseOutcome::Denied`](super::ResponseOutcome::Denied) with a signed
/// error response; only programming/configuration faults are `Err`.
pub fn create_authn_response(
    engine: &ResponseEngine,
    params: &ResponseParams,
    subject: &AuthenticatedSubject,
) -> Result<super::ResponseOutcome, ProfileError> {
    params.check_bound()?;
    let processed = &params.processed;
    let sp = &params.sp_sso;

    // `check_request` already refuses an authn-context constraint that cannot
    // be matched; refuse it here too, before anything is minted or stored, for
    // a caller that skipped `check_request`.
    if unmatchable_authn_context(processed) {
        return denied(engine, params, &Denial::NoAuthnContext);
    }

    // 1. Resolve the SP's attribute requirements (indexed or default
    //    service). An explicit index naming no declared service is a
    //    protocol error, not silently "no requirements" — falling through
    //    would bypass that service's own attribute scoping and, for an SP
    //    with no entity categories configured, release the subject's entire
    //    attribute set instead.
    if let Some(index) = processed.attribute_consuming_service_index {
        if !sp
            .attribute_consuming_services
            .iter()
            .any(|s| s.index == index)
        {
            return denied(
                engine,
                params,
                &Denial::InvalidAttributeConsumingServiceIndex,
            );
        }
    }
    let (required, optional) =
        sp_attribute_requirements(sp, processed.attribute_consuming_service_index);

    // 2. Run the release seam. A missing-required-attribute/value refusal is
    //    the SP's own AttributeConsumingService being unsatisfiable — a
    //    protocol denial, not a programming/configuration fault. Only a
    //    genuine release misconfiguration (e.g. an invalid restriction
    //    pattern) is a `ProfileError`.
    let released = match engine.release.release(
        subject.attributes.clone(),
        &processed.sp_entity_id,
        &params.sp_entity_categories(),
        &required,
        &optional,
        params.subject_id_req(),
    ) {
        Ok(attrs) => attrs,
        Err(
            PolicyError::MissingRequiredAttribute(_) | PolicyError::MissingRequiredValue { .. },
        ) => {
            return denied(engine, params, &Denial::MissingRequiredAttributes);
        }
        Err(e) => {
            return Err(ProfileError::Other(format!(
                "attribute release failed: {e}"
            )))
        }
    };

    // 3. fail_on_missing_requested: verify required attributes/values
    //    actually survived release, independent of which `AttributeRelease`
    //    ran. `ReleasePolicy::release` already validates this internally (and
    //    would have taken the branch above instead), but a pass-through or
    //    custom release does not, so this check must not depend on which
    //    implementation was injected.
    if engine
        .decisions
        .fail_on_missing_requested(&processed.sp_entity_id)
        && !required.is_empty()
        && engine
            .decisions
            .validate_required_attributes(&released, &required)
            .is_err()
    {
        return denied(engine, params, &Denial::MissingRequiredAttributes);
    }

    // 4. Resolve the authn context from the subject's method, and verify it
    //    actually satisfies what the SP requested. `check_request` only
    //    offers methods that would satisfy the request via `Disposition`; it
    //    cannot guarantee which method the application ultimately used to
    //    authenticate the subject it hands back here, so that has to be
    //    checked again at the point the response is actually assembled.
    let (class_ref, authority) = subject.authn_method.resolve(engine.broker).ok_or_else(|| {
        ProfileError::Other(
            "AuthenticatedSubject.authn_method names a BrokerReference that is not \
             registered in this engine's AuthnBroker"
                .to_string(),
        )
    })?;
    if !class_ref_satisfies(
        engine.broker,
        params.requested_authn_context().as_ref(),
        &class_ref,
    ) {
        return denied(engine, params, &Denial::NoAuthnContext);
    }

    // `check_request` approved a reused session against its own clock reading;
    // the application callback may have run past the session's absolute expiry
    // since. An assertion whose SessionNotOnOrAfter is already past is rejected
    // by every SP validator, so refuse it here, before anything is stored.
    if let Some(authn_instant) = subject.authn_instant {
        let session_lifetime = engine.decisions.session_lifetime(&processed.sp_entity_id);
        if authn_instant + session_lifetime <= Utc::now() {
            return denied(engine, params, &Denial::AuthnFailed);
        }
    }

    // 5. Construct the NameID, honouring the request's NameIDPolicy and the
    //    IdP's default format. A NameID refusal is a protocol denial.
    let name_id = match construct_name_id(engine, params, subject) {
        Ok(name_id) => name_id,
        Err(NameIdFailure::Denied(denial)) => return denied(engine, params, &denial),
        // A backend failure is an operational fault, not something the SP
        // caused: surface it as an error rather than a signed denial.
        Err(NameIdFailure::Fault(e)) => return Err(e),
    };

    // 6. Build the response options. Assertion and session lifetimes are
    //    independent: the assertion's own validity window is typically
    //    short, while the SSO session it establishes is usually meant to
    //    outlive any one assertion (E79).
    let now = Utc::now();
    let lifetime = engine.decisions.lifetime(&processed.sp_entity_id);
    let assertion_lifetime_seconds = lifetime.num_seconds().max(0) as u64;
    let session_lifetime = engine.decisions.session_lifetime(&processed.sp_entity_id);
    // Derived from the subject's actual authn_instant (the original
    // authentication time for a reused session; "now" for a fresh one), not
    // from "now" unconditionally - otherwise reusing a session pushes its
    // absolute expiry further out on every response, turning a fixed cap
    // into an indefinitely-sliding window.
    let session_not_on_or_after = Some(subject.authn_instant.unwrap_or(now) + session_lifetime);
    let options = ResponseOptions {
        idp_entity_id: engine.idp_entity_id.to_string(),
        in_response_to: Some(processed.request_id.clone()),
        sp_entity_id: processed.sp_entity_id.clone(),
        acs_url: processed.acs_url.clone(),
        assertion_lifetime_seconds,
        session_index: subject.session_index.clone(),
        session_not_on_or_after,
        authn_context_class_ref: Some(class_ref),
        client_address: None,
        attributes: released.clone(),
        authenticating_authorities: authority.into_iter().collect(),
    };

    // 7. Sign per the per-SP sign targets, resolved against the SP's
    //    WantAssertionsSigned.
    let want_assertions_signed = sp.want_assertions_signed.unwrap_or(false);
    let sign = engine
        .decisions
        .sign(&processed.sp_entity_id)
        .resolve(want_assertions_signed);

    // Build the (unsigned) response once so the audit identifiers and the
    // stored assertion match the signed XML exactly, then sign that XML.
    let response = create_response(
        &options,
        &name_id,
        ResponseTimes {
            issue_instant: now,
            authn_instant: subject.authn_instant.unwrap_or(now),
        },
    );
    let response_id = response.base.id.clone();
    let assertion_id = response.assertions.first().map(|a| a.id.clone());
    let xml = response
        .to_xml_string()
        .map_err(|e| ProfileError::Other(format!("failed to serialize Response: {e}")))?;
    let signed_xml = sign_response_xml_with(
        &xml,
        engine.signer,
        engine.cert_der_b64,
        &response_id,
        assertion_id.as_deref(),
        sign.sign_assertion,
        sign.sign_response,
        &signing_algorithms(engine, params),
    )?;

    // 8. Store the assertion for back-channel queries, if a store is present.
    if let Some(store) = engine.assertions {
        if let Some(assertion) = response.assertions.first() {
            store.store_assertion(assertion.clone())?;
        }
    }

    // 9. Return the issued response with its audit identifiers, using the
    //    same normalized (whole-second, non-negative) lifetime that went
    //    into the wire assertion so the two cannot disagree.
    let not_on_or_after = now + TimeDelta::seconds(assertion_lifetime_seconds as i64);
    let released_attribute_names = released.iter().map(|a| a.name.clone()).collect();
    Ok(super::ResponseOutcome::Issued(IssuedResponse {
        xml: signed_xml,
        response_id,
        assertion_id,
        name_id,
        session_index: subject.session_index.clone(),
        not_on_or_after,
        released_attribute_names,
    }))
}

/// Assemble and sign a denial (protocol error) response.
///
/// The Response envelope is signed **unconditionally** — an unsigned denial is
/// trivially forgeable — regardless of the per-SP `SignTargets`.
pub fn create_denial_response(
    engine: &ResponseEngine,
    params: &ResponseParams,
    denial: &Denial,
) -> Result<DeniedResponse, ProfileError> {
    params.check_bound()?;
    let processed = &params.processed;
    let now = Utc::now();

    let response: Response = create_error_response(
        engine.idp_entity_id,
        Some(&processed.request_id),
        &processed.acs_url,
        denial.status(),
        now,
    );
    let response_id = response.base.id.clone();
    let xml = response
        .to_xml_string()
        .map_err(|e| ProfileError::Other(format!("failed to serialize denial Response: {e}")))?;

    // Denials always sign the Response envelope.
    let signed_xml = sign_response_xml_with(
        &xml,
        engine.signer,
        engine.cert_der_b64,
        &response_id,
        None,
        false,
        true,
        &signing_algorithms(engine, params),
    )?;

    Ok(DeniedResponse {
        xml: signed_xml,
        response_id,
    })
}

/// Build a `ResponseOutcome::Denied` for the given denial.
fn denied(
    engine: &ResponseEngine,
    params: &ResponseParams,
    denial: &Denial,
) -> Result<super::ResponseOutcome, ProfileError> {
    let response = create_denial_response(engine, params, denial)?;
    Ok(super::ResponseOutcome::Denied {
        denial: *denial,
        response,
    })
}

/// The signature and digest algorithms for this response: the SP's configured
/// preference (see [`PolicyEntry::with_signing_preference`](crate::idp::policy::PolicyEntry::with_signing_preference))
/// resolved against what the SP advertises in its metadata.
///
/// The advertisement is an untrusted claim: it only chooses among the IdP's own
/// configured entries (see [`SigningPreference`](crate::crypto::SigningPreference)).
/// With no preference configured this is the signer's default.
pub(super) fn signing_algorithms(
    engine: &ResponseEngine,
    params: &ResponseParams,
) -> crate::crypto::SigningAlgorithms {
    let (signature, digest) = sp_advertised_algorithms(params);
    engine
        .decisions
        .signing_preference(&params.processed.sp_entity_id)
        .resolve(&signature, &digest)
}

/// The `(signature, digest)` algorithm URIs the SP advertises for this
/// response, from `alg:SigningMethod` and `alg:DigestMethod` respectively: the entity-level
/// `Extensions` plus the SAML 2.0 SP role the request was bound to
/// (`params.sp_sso`).
///
/// Not `EntityDescriptor::supported_algorithms`, which aggregates every IdP and
/// SP role of the entity and says single-role callers must filter: an algorithm
/// advertised only by an IdP role, or by another SP role (a SAML 1.1
/// descriptor), would otherwise be selected for this SAML 2.0 SP.
pub(super) fn sp_advertised_algorithms(params: &ResponseParams) -> (Vec<String>, Vec<String>) {
    use crate::metadata::types::md_extensions::MdExtensions;
    let entity_ext = params
        .sp_entity
        .as_ref()
        .and_then(|entity| entity.extensions.as_ref());
    let role_ext = params.sp_sso.sso_base.base.extensions.as_ref();
    let mut signature: Vec<String> = Vec::new();
    let mut digest: Vec<String> = Vec::new();
    for ext in [entity_ext, role_ext].into_iter().flatten() {
        let md = MdExtensions::from_extensions(ext);
        for (out, algs) in [
            (&mut signature, md.signing_methods),
            (&mut digest, md.digest_methods),
        ] {
            for alg in algs {
                if !out.contains(&alg) {
                    out.push(alg);
                }
            }
        }
    }
    (signature, digest)
}

/// Why NameID construction did not produce a NameID.
enum NameIdFailure {
    /// The request asked for something the IdP refuses: a protocol denial.
    Denied(Denial),
    /// The identity store failed: an operational fault, not a denial.
    Fault(ProfileError),
}

/// Construct the NameID for the subject, honouring the request's NameIDPolicy
/// and the IdP's default format. Maps `IdentError` to the appropriate denial,
/// except a store failure, which stays an error.
fn construct_name_id(
    engine: &ResponseEngine,
    params: &ResponseParams,
    subject: &AuthenticatedSubject,
) -> Result<NameId, NameIdFailure> {
    let policy = params.name_id_policy();

    // Per saml-core-2.0-os 8.3.7, SPNameQualifier names "the service
    // provider or affiliation of providers for whom the identifier was
    // generated" - it may legitimately differ from the requester only when
    // the requester is a verified member of that affiliation
    // (AffiliationDescriptor). This crate does not implement affiliation
    // membership verification, so honouring an attacker-supplied qualifier
    // for a *different* entity would let SP A request SP B's persistent
    // identifier for the same subject by simply setting
    // NameIDPolicy/@SPNameQualifier to SP B's entity ID - defeating
    // pairwise-identifier scoping. Reject any qualifier other than the
    // requester's own (verified) entity ID.
    if let Some(spq) = policy.as_ref().and_then(|p| p.sp_name_qualifier.as_deref()) {
        if spq != params.processed.sp_entity_id {
            return Err(NameIdFailure::Denied(Denial::InvalidNameIdPolicy));
        }
    }

    // The effective format - the requested one, else the SP's default - must be
    // one this IdP issues to this SP. A refused *request* is InvalidNameIDPolicy
    // (SAML Core 3.4.1.1), before anything is minted or stored; without this
    // any format string was honoured, minted and recorded. A refused *default*
    // is a configuration fault (the SP asked for nothing unusual), so it is an
    // error, not a denial.
    let default_format = engine
        .decisions
        .nameid_format(&params.processed.sp_entity_id);
    let requested_format = policy.as_ref().and_then(|p| p.format.as_deref());
    let effective = requested_format.unwrap_or(default_format.as_str());
    if !engine
        .decisions
        .supports_nameid_format(&params.processed.sp_entity_id, effective)
    {
        return Err(match requested_format {
            Some(_) => NameIdFailure::Denied(Denial::InvalidNameIdPolicy),
            None => NameIdFailure::Fault(ProfileError::Other(format!(
                "the default NameID format {effective:?} configured for {} cannot be issued",
                params.processed.sp_entity_id
            ))),
        });
    }

    // The default per-SP format is transient, and a transient is minted fresh
    // on every call - including repeated reuse of the same session. That is
    // fine for the identity store because, by default, `IdentDb` does not
    // persist transient identifiers (they are one-time-use per SAML Core
    // §8.3.7 and never need a reverse lookup); only durable formats
    // (persistent, email, ...) are stored. See `IdentDb::get_nameid`. Without
    // that, every successful response would grow the store without bound. A
    // deployment that needs to resolve a transient NameID back to its user
    // (back-channel logout) opts in with `IdentDb::with_persist_transient`.
    engine
        .idents
        .construct_nameid(
            &subject.subject_id,
            &params.processed.sp_entity_id,
            policy.as_ref(),
            Some(default_format.as_str()),
        )
        .map_err(|e| match e {
            crate::idp::ident::IdentError::CreateNotAllowed => {
                NameIdFailure::Denied(Denial::NameIdCreationNotAllowed)
            }
            crate::idp::ident::IdentError::Store(e) => NameIdFailure::Fault(e.into()),
            _ => NameIdFailure::Denied(Denial::InvalidNameIdPolicy),
        })
}
