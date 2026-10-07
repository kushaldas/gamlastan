//! The attribute-release seam for the response orchestrator.
//!
//! Deployments legitimately source the released attribute set differently:
//! an originating IdP applies federation policy ([`ReleasePolicy`] plus entity
//! categories), while a proxy receives attributes already filtered by an
//! upstream pipeline and may add a per-requester layer. [`AttributeRelease`]
//! is the seam that lets the engine serve both shapes without mandating
//! `ReleasePolicy`. Everything downstream of this seam — NameID construction,
//! authn-context matching, assembly, signing — is the fixed correctness core.
//!
//! Three implementations ship:
//!
//! - [`ReleasePolicy`] itself (the full engine) — for originating IdPs;
//! - [`PassThroughRelease`] — the identity, for pre-filtered inputs;
//! - [`ChainedRelease`] — a composition of two, for a proxy that applies an
//!   upstream release and then a per-requester layer.
//!
//! A blanket impl makes `Arc<T>` usable wherever `T` is, so a release policy
//! shared across threads can be handed to the engine directly.

use std::sync::Arc;

use crate::core::assertion::attribute::Attribute;
use crate::idp::entity_category::SubjectIdReq;
use crate::idp::policy::{PolicyError, ReleasePolicy};
use crate::metadata::types::sp::RequestedAttribute;

/// Decides which of the held attributes are released to a given SP.
///
/// This is the only step in the orchestrator that varies by deployment. The
/// method mirrors [`ReleasePolicy::filter`] so the full engine can be used
/// verbatim as the release decision.
pub trait AttributeRelease: Send + Sync {
    /// Release `attributes` for `sp_entity_id`.
    ///
    /// `sp_entity_categories` are the SP's published entity categories;
    /// `required`/`optional` are the SP's `RequestedAttribute`s (already
    /// resolved from its `AttributeConsumingService`); `subject_id_req` is the
    /// SP's `subject-id:req` metadata signal.
    fn release(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError>;
}

/// The full release engine, used by originating IdPs.
///
/// With no rule configured for an SP it releases every attribute the
/// application supplied (see [`ReleasePolicy`]'s "Default release");
/// [`PolicyEntry::with_deny_unconfigured_release`](crate::idp::policy::PolicyEntry::with_deny_unconfigured_release)
/// makes it release nothing instead.
impl AttributeRelease for ReleasePolicy {
    fn release(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        self.filter(
            attributes,
            sp_entity_id,
            sp_entity_categories,
            required,
            optional,
            subject_id_req,
        )
    }
}

/// The identity release: returns the input unchanged.
///
/// For a proxy that has already filtered attributes upstream (e.g. tunnelbana's
/// per-requester pipeline) and wants the engine to handle only the fixed
/// correctness core.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThroughRelease;

impl PassThroughRelease {
    /// Create a pass-through release.
    pub fn new() -> Self {
        Self
    }
}

impl AttributeRelease for PassThroughRelease {
    fn release(
        &self,
        attributes: Vec<Attribute>,
        _sp_entity_id: &str,
        _sp_entity_categories: &[String],
        _required: &[RequestedAttribute],
        _optional: &[RequestedAttribute],
        _subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        Ok(attributes)
    }
}

/// A composition of two release decisions: run `first`, then `second` on the
/// result.
///
/// For a proxy that applies an upstream release (e.g. the federation policy)
/// and then a per-requester layer.
#[derive(Debug, Clone)]
pub struct ChainedRelease<A, B> {
    first: A,
    second: B,
}

impl<A, B> ChainedRelease<A, B> {
    /// Create a chained release: `first` runs, then `second` on its output.
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A, B> AttributeRelease for ChainedRelease<A, B>
where
    A: AttributeRelease,
    B: AttributeRelease,
{
    fn release(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        let after_first = self.first.release(
            attributes,
            sp_entity_id,
            sp_entity_categories,
            required,
            optional,
            subject_id_req,
        )?;
        self.second.release(
            after_first,
            sp_entity_id,
            sp_entity_categories,
            required,
            optional,
            subject_id_req,
        )
    }
}

/// A shared release policy is usable wherever a release is, so a policy held
/// behind an `Arc` (e.g. shared across handler threads) can be passed to the
/// engine without cloning.
impl<T: AttributeRelease + ?Sized> AttributeRelease for Arc<T> {
    fn release(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        (**self).release(
            attributes,
            sp_entity_id,
            sp_entity_categories,
            required,
            optional,
            subject_id_req,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::attribute::AttributeValue;
    use crate::core::constants;
    use crate::idp::policy::PolicyEntry;
    use crate::profiles::attribute::x500::mail_attribute;

    fn mail(name: &str) -> Attribute {
        mail_attribute(&[name])
    }

    fn requested(name: &str, required: bool) -> RequestedAttribute {
        RequestedAttribute {
            attribute: Attribute {
                name: name.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: None,
                values: vec![],
            },
            is_required: Some(required),
        }
    }

    #[test]
    fn pass_through_returns_input_unchanged() {
        let release = PassThroughRelease::new();
        let attrs = vec![mail("alice@example.com")];
        let out = release
            .release(
                attrs.clone(),
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out, attrs);
    }

    #[test]
    fn release_policy_impl_filters() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", None)])
                .unwrap(),
        );
        let attrs = vec![
            mail("alice@example.com"),
            Attribute {
                name: "urn:oid:2.5.4.3".to_string(),
                name_format: None,
                friendly_name: Some("cn".to_string()),
                values: vec![AttributeValue::String("Alice".to_string())],
            },
        ];
        let out = policy
            .release(
                attrs,
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        // Only `mail` is named in the restrictions; `cn` is dropped.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn chained_release_applies_first_then_second() {
        // First: restrict to `mail` only. Second: pass-through (identity).
        let first = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", None)])
                .unwrap(),
        );
        let second = PassThroughRelease::new();
        let chained = ChainedRelease::new(first, second);

        let attrs = vec![
            mail("alice@example.com"),
            Attribute {
                name: "urn:oid:2.5.4.3".to_string(),
                name_format: None,
                friendly_name: Some("cn".to_string()),
                values: vec![AttributeValue::String("Alice".to_string())],
            },
        ];
        let out = chained
            .release(
                attrs,
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn chained_release_second_can_narrow_first() {
        // First: pass-through (keep everything). Second: restrict to `mail`.
        let first = PassThroughRelease::new();
        let second = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", None)])
                .unwrap(),
        );
        let chained = ChainedRelease::new(first, second);

        let attrs = vec![
            mail("alice@example.com"),
            Attribute {
                name: "urn:oid:2.5.4.3".to_string(),
                name_format: None,
                friendly_name: Some("cn".to_string()),
                values: vec![AttributeValue::String("Alice".to_string())],
            },
        ];
        let out = chained
            .release(
                attrs,
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn arc_release_delegates() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", None)])
                .unwrap(),
        );
        let shared: Arc<ReleasePolicy> = Arc::new(policy);
        let out = shared
            .release(
                vec![mail("alice@example.com")],
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn required_attribute_is_passed_through_the_seam() {
        // A required attribute the SP asked for must survive a pass-through
        // release (the engine's fail_on_missing_requested check runs downstream).
        let release = PassThroughRelease::new();
        let required = vec![requested("urn:oid:0.9.2342.19200300.100.1.3", true)];
        let out = release
            .release(
                vec![mail("alice@example.com")],
                "https://sp.example.com",
                &[],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
    }
}
