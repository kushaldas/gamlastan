//! Parse a metadata document, verify its signature, select the requested
//! entity, and enforce the required role.

use std::time::Duration;

use chrono::{DateTime, Utc};

use gamlastan::core::namespace::SAML_METADATA_NS;
use gamlastan::crypto::{SamlVerifier, VerifyResult};
use gamlastan::metadata::{
    EntitiesDescriptorRef, EntityDescriptor, EntityDescriptorRef, MetadataChildRef, MetadataError,
    MetadataSigningProfile,
};
use gamlastan::xml::{parse_saml, uppsala, XmlError};

use crate::client::{RequiredRole, Trust};
use crate::error::MdqError;
use crate::transform::parse_xs_duration;

/// An entity selected from an aggregate, paired with the cache hints
/// accumulated from the enclosing `EntitiesDescriptor` layers.
type SelectedEntity = (EntityDescriptor, Option<Duration>, Option<DateTime<Utc>>);

/// A resolved entity plus the cache hints carried by the document.
pub(crate) struct Resolved {
    pub entity: EntityDescriptor,
    pub cache_duration: Option<Duration>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Parse `xml`, verify (when `trust` has certs), select `requested_entity_id`
/// from an aggregate if needed, enforce `required_role`, and confirm the
/// resolved entity actually matches `requested_entity_id`.
///
/// `allow_unverified` permits a no-cert client to accept metadata that cannot be
/// signature-verified; with it `false`, a no-cert client errors instead.
pub(crate) fn parse_verify_select(
    xml: &str,
    requested_entity_id: &str,
    trust: &Trust,
    required_role: RequiredRole,
    allow_unverified: bool,
    now: DateTime<Utc>,
) -> Result<Resolved, MdqError> {
    let doc = uppsala::parse(xml).map_err(|e| MdqError::Parse(XmlError::ParseError(e)))?;
    let root = doc.document_element().ok_or(XmlError::EmptyDocument)?;
    let elem = doc.element(root).ok_or(XmlError::NotAnElement)?;

    if elem.matches_name_ns(SAML_METADATA_NS, "EntityDescriptor") {
        let ed_ref = parse_saml::<EntityDescriptorRef<'_>>(&doc)?;
        verify_if_configured(
            trust,
            xml,
            ed_ref.has_signature,
            ed_ref.id,
            allow_unverified,
        )?;
        let entity = ed_ref.to_owned();
        finish(entity, requested_entity_id, required_role, None, None, now)
    } else if elem.matches_name_ns(SAML_METADATA_NS, "EntitiesDescriptor") {
        let es_ref = parse_saml::<EntitiesDescriptorRef<'_>>(&doc)?;
        verify_if_configured(
            trust,
            xml,
            es_ref.has_signature,
            es_ref.id,
            allow_unverified,
        )?;
        let (entity, agg_cache_duration, agg_valid_until) =
            select_entity(&es_ref, requested_entity_id, None, None)?
                .ok_or_else(|| MdqError::EntityNotFound(requested_entity_id.to_string()))?;
        finish(
            entity,
            requested_entity_id,
            required_role,
            agg_cache_duration,
            agg_valid_until,
            now,
        )
    } else {
        Err(MdqError::UnexpectedRoot)
    }
}

fn select_entity(
    entities: &EntitiesDescriptorRef<'_>,
    requested_entity_id: &str,
    inherited_cache_duration: Option<Duration>,
    inherited_valid_until: Option<DateTime<Utc>>,
) -> Result<Option<SelectedEntity>, MdqError> {
    let aggregate_cache_duration = combine_duration(
        inherited_cache_duration,
        entities.cache_duration.map(parse_xs_duration).transpose()?,
    );
    let aggregate_valid_until = combine_valid_until(inherited_valid_until, entities.valid_until);

    for child in &entities.children {
        match child {
            MetadataChildRef::Entity(entity) if entity.entity_id == requested_entity_id => {
                return Ok(Some((
                    entity.as_ref().to_owned(),
                    aggregate_cache_duration,
                    aggregate_valid_until,
                )));
            }
            MetadataChildRef::Entities(nested) => {
                if let Some(found) = select_entity(
                    nested,
                    requested_entity_id,
                    aggregate_cache_duration,
                    aggregate_valid_until,
                )? {
                    return Ok(Some(found));
                }
            }
            MetadataChildRef::Entity(_) => {}
        }
    }

    Ok(None)
}

/// Confirm the resolved entityID matches what was requested, apply role gating,
/// and resolve the effective cache hints.
fn finish(
    entity: EntityDescriptor,
    requested_entity_id: &str,
    required_role: RequiredRole,
    parent_cache_duration: Option<Duration>,
    parent_valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<Resolved, MdqError> {
    // The signature only attests that the federation vouches for this document,
    // not that it is the answer to *this* query. Bind request to response so an
    // untrusted MDQ server cannot substitute a different (but validly signed)
    // entity. The aggregate path already selects by entityID; this also guards
    // the single-EntityDescriptor path.
    if entity.entity_id != requested_entity_id {
        return Err(MdqError::EntityIdMismatch {
            requested: requested_entity_id.to_string(),
            returned: entity.entity_id.clone(),
        });
    }
    if !role_ok(&entity, required_role) {
        return Err(MdqError::RoleMissing(required_role));
    }
    let child_cache_duration = entity
        .cache_duration
        .as_deref()
        .map(parse_xs_duration)
        .transpose()?;
    let cache_duration = combine_duration(child_cache_duration, parent_cache_duration);
    let valid_until = combine_valid_until(entity.valid_until, parent_valid_until);
    reject_if_expired(valid_until, now)?;
    Ok(Resolved {
        entity,
        cache_duration,
        valid_until,
    })
}

fn combine_duration(left: Option<Duration>, right: Option<Duration>) -> Option<Duration> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn combine_valid_until(
    left: Option<DateTime<Utc>>,
    right: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn reject_if_expired(
    valid_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), MdqError> {
    if let Some(valid_until) = valid_until {
        if now >= valid_until {
            return Err(MdqError::Metadata(MetadataError::Expired(
                valid_until.to_rfc3339(),
            )));
        }
    }
    Ok(())
}

fn role_ok(entity: &EntityDescriptor, role: RequiredRole) -> bool {
    match role {
        RequiredRole::Any => true,
        RequiredRole::Idp => entity.is_idp(),
        RequiredRole::Sp => entity.is_sp(),
    }
}

/// When trust certs are configured, enforce the signing profile and verify the
/// enveloped signature. With no certs configured, accept the document only if
/// `allow_unverified` is set (the caller warns once); otherwise refuse.
fn verify_if_configured(
    trust: &Trust,
    xml: &str,
    has_signature: bool,
    signed_id: Option<&str>,
    allow_unverified: bool,
) -> Result<(), MdqError> {
    if !trust.has_certs() {
        if allow_unverified {
            return Ok(());
        }
        return Err(MdqError::VerificationNotConfigured);
    }
    if !has_signature {
        return Err(MdqError::Unsigned);
    }
    let id = signed_id.ok_or_else(|| {
        MdqError::SignatureInvalid("signed element has no ID attribute".to_string())
    })?;

    MetadataSigningProfile::validate_signature_profile(xml, id)?;

    let verifier = SamlVerifier::new(trust.keys().clone());
    match verifier
        .verify_enveloped(xml)
        .map_err(|e| MdqError::SignatureInvalid(e.to_string()))?
    {
        VerifyResult::Valid { .. } => Ok(()),
        VerifyResult::Invalid { reason } => Err(MdqError::SignatureInvalid(reason)),
    }
}
