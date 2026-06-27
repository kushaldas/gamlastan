// IdP attribute release policy engine (pysaml2 `Policy` equivalent).
//
// A `ReleasePolicy` holds per-SP entries plus a `default` entry. Each entry
// can constrain:
// - which attributes (and which values, via regexes) are released,
// - entity-category based release (see `idp::entity_category`),
// - assertion lifetime, NameID format, attribute NameFormat,
// - signing behavior (response / assertion / on demand),
// - whether missing SP-required attributes are an error.
//
// Attribute names are matched on their *local* (friendly) names,
// case-insensitively, resolved through an `AttributeConverterSet` so that
// wire names (`urn:oid:...`) and FriendlyNames both work.

use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use regex::Regex;

use crate::attribute_map::AttributeConverterSet;
use crate::core::assertion::attribute::{Attribute, AttributeValue};
use crate::core::constants;
use crate::idp::entity_category::{
    releasable_attributes_owned, EntityCategoryPolicy, OwnedEntityCategoryPolicy, SubjectIdReq,
};
use crate::metadata::types::entity_descriptor::EntityDescriptor;
use crate::metadata::types::sp::{RequestedAttribute, SpSsoDescriptor};

/// Errors raised by policy evaluation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A required attribute is missing (pysaml2 `MissingValue`).
    #[error("required attribute missing: '{0}'")]
    MissingRequiredAttribute(String),

    /// A required attribute value is missing (pysaml2 `MissingValue`).
    #[error("required value missing for attribute '{attribute}'")]
    MissingRequiredValue {
        /// The attribute whose required values could not be satisfied.
        attribute: String,
    },

    /// An attribute value restriction pattern failed to compile.
    #[error("invalid restriction pattern '{pattern}': {message}")]
    InvalidPattern {
        /// The offending pattern.
        pattern: String,
        /// The regex error.
        message: String,
    },
}

/// Which messages the IdP signs for an SP (`"sign"` in pysaml2 policy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignTargets {
    /// Always sign the Response envelope.
    pub response: bool,
    /// Always sign the Assertion.
    pub assertion: bool,
    /// Sign the assertion when the SP asks for it (`WantAssertionsSigned`
    /// in SP metadata) — pysaml2's `"on_demand"`.
    pub on_demand: bool,
}

impl SignTargets {
    /// Resolve the on-demand part against the SP's metadata flag.
    pub fn resolve(self, sp_wants_assertions_signed: bool) -> ResolvedSignTargets {
        ResolvedSignTargets {
            sign_response: self.response,
            sign_assertion: self.assertion || (self.on_demand && sp_wants_assertions_signed),
        }
    }
}

/// The concrete signing decision for one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSignTargets {
    /// Sign the Response envelope.
    pub sign_response: bool,
    /// Sign the Assertion.
    pub sign_assertion: bool,
}

/// Per-value restriction: `None` releases any value, otherwise a value is
/// released when at least one regex matches at the start of the value
/// (Python `re.match` semantics).
type ValueRestriction = Option<Vec<Regex>>;

/// One policy entry (per SP, or the `default`).
#[derive(Debug, Clone, Default)]
pub struct PolicyEntry {
    attribute_restrictions: Option<HashMap<String, ValueRestriction>>,
    lifetime: Option<TimeDelta>,
    nameid_format: Option<String>,
    name_form: Option<String>,
    sign: Option<SignTargets>,
    fail_on_missing_requested: Option<bool>,
    entity_categories: Option<Vec<OwnedEntityCategoryPolicy>>,
}

impl PolicyEntry {
    /// Create an empty entry (everything inherited / default).
    pub fn new() -> Self {
        PolicyEntry::default()
    }

    /// Restrict release to the given attributes. Each `(name, patterns)`
    /// pair names a local attribute (case-insensitive) and optionally a
    /// list of value patterns (anchored at the start of the value, like
    /// Python's `re.match`); `None` releases all values.
    pub fn with_attribute_restrictions(
        mut self,
        restrictions: &[(&str, Option<&[&str]>)],
    ) -> Result<Self, PolicyError> {
        let mut map = HashMap::new();
        for (name, patterns) in restrictions {
            let compiled = match patterns {
                None => None,
                Some(pats) => {
                    let mut regexes = Vec::with_capacity(pats.len());
                    for pat in *pats {
                        let anchored = format!("^(?:{pat})");
                        regexes.push(Regex::new(&anchored).map_err(|e| {
                            PolicyError::InvalidPattern {
                                pattern: (*pat).to_string(),
                                message: e.to_string(),
                            }
                        })?);
                    }
                    Some(regexes)
                }
            };
            map.insert(name.to_lowercase(), compiled);
        }
        self.attribute_restrictions = Some(map);
        Ok(self)
    }

    /// Set the assertion lifetime.
    pub fn with_lifetime(mut self, lifetime: TimeDelta) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Set the NameID format issued to this SP.
    pub fn with_nameid_format(mut self, format: impl Into<String>) -> Self {
        self.nameid_format = Some(format.into());
        self
    }

    /// Set the attribute NameFormat used in assertions for this SP.
    pub fn with_name_form(mut self, name_form: impl Into<String>) -> Self {
        self.name_form = Some(name_form.into());
        self
    }

    /// Set the signing targets.
    pub fn with_sign(mut self, sign: SignTargets) -> Self {
        self.sign = Some(sign);
        self
    }

    /// Set whether missing SP-required attributes abort response building.
    pub fn with_fail_on_missing_requested(mut self, fail: bool) -> Self {
        self.fail_on_missing_requested = Some(fail);
        self
    }

    /// Enable entity-category based release with the given shipped policies
    /// (e.g. [`crate::idp::entity_category::SWAMID`]). Each is cloned into its
    /// owned form; to mix in deployment-defined categories use
    /// [`PolicyEntry::with_owned_entity_categories`].
    pub fn with_entity_categories(mut self, policies: Vec<&'static EntityCategoryPolicy>) -> Self {
        self.entity_categories = Some(policies.iter().map(|p| p.as_owned()).collect());
        self
    }

    /// Enable entity-category based release with caller-built, runtime
    /// [`OwnedEntityCategoryPolicy`] values - the path for developer-defined
    /// custom entity categories. Start from scratch with
    /// [`OwnedEntityCategoryPolicy::new`], or extend a shipped policy with
    /// [`OwnedEntityCategoryPolicy::extend_from_static`].
    pub fn with_owned_entity_categories(
        mut self,
        policies: Vec<OwnedEntityCategoryPolicy>,
    ) -> Self {
        self.entity_categories = Some(policies);
        self
    }
}

/// The IdP-side attribute release policy (pysaml2 `Policy`).
///
/// Entry resolution per knob: the SP-specific entry, then `"default"`,
/// then a built-in default (transient NameID, URI name format, 1h
/// lifetime, no signing, fail on missing required attributes).
#[derive(Debug, Default)]
pub struct ReleasePolicy {
    entries: HashMap<String, PolicyEntry>,
    converters: AttributeConverterSet,
    /// SP entity ID -> its `registrationAuthority`. When an SP has no entry of
    /// its own, policy resolution falls back to the entry keyed on its
    /// registration authority (pysaml2 `Policy.get`: SP > registration
    /// authority > default) before the global `default`.
    registration_authorities: HashMap<String, String>,
}

/// The key under which the fallback entry is stored.
pub const DEFAULT_ENTRY: &str = "default";

impl ReleasePolicy {
    /// An empty policy (built-in defaults for every SP).
    pub fn new() -> Self {
        ReleasePolicy {
            entries: HashMap::new(),
            converters: AttributeConverterSet::with_default_maps(),
            registration_authorities: HashMap::new(),
        }
    }

    /// Create a policy with a `default` entry.
    pub fn with_default(entry: PolicyEntry) -> Self {
        let mut policy = ReleasePolicy::new();
        policy.entries.insert(DEFAULT_ENTRY.to_string(), entry);
        policy
    }

    /// Add or replace the entry for an SP entity ID (or `"default"`).
    pub fn insert(&mut self, sp_entity_id: impl Into<String>, entry: PolicyEntry) {
        self.entries.insert(sp_entity_id.into(), entry);
    }

    /// Use a custom attribute converter set for local-name resolution.
    pub fn with_converters(mut self, converters: AttributeConverterSet) -> Self {
        self.converters = converters;
        self
    }

    /// Record an SP's `registrationAuthority` so policy resolution can fall back
    /// to a per-registration-authority entry (keyed on the authority URI) when
    /// the SP has no entry of its own.
    pub fn set_registration_authority(
        &mut self,
        sp_entity_id: impl Into<String>,
        registration_authority: impl Into<String>,
    ) {
        self.registration_authorities
            .insert(sp_entity_id.into(), registration_authority.into());
    }

    /// Builder form of [`ReleasePolicy::set_registration_authority`].
    pub fn with_registration_authority(
        mut self,
        sp_entity_id: impl Into<String>,
        registration_authority: impl Into<String>,
    ) -> Self {
        self.set_registration_authority(sp_entity_id, registration_authority);
        self
    }

    /// Record an SP's registration authority straight from its metadata (reads
    /// `mdrpi:RegistrationInfo/@registrationAuthority`). No-op when the metadata
    /// declares none.
    pub fn register_sp_metadata(&mut self, entity: &EntityDescriptor) {
        if let Some(ra) = entity.registration_authority() {
            self.set_registration_authority(entity.entity_id.clone(), ra);
        }
    }

    /// Resolve a knob: SP entry first, then the SP's registration-authority
    /// entry, then `default` (pysaml2 `Policy.get` precedence).
    fn get<T, F: Fn(&PolicyEntry) -> Option<T>>(&self, sp_entity_id: &str, f: F) -> Option<T> {
        self.get_ref(sp_entity_id, f)
    }

    /// Borrowing form of [`ReleasePolicy::get`]: resolves with the same
    /// SP > registration authority > default precedence but lets `f` return a
    /// borrow into the resolved [`PolicyEntry`], so large fields (the owned
    /// entity-category policies, the restriction map) are read by reference
    /// instead of cloned on every request.
    fn get_ref<'a, T, F: Fn(&'a PolicyEntry) -> Option<T>>(
        &'a self,
        sp_entity_id: &str,
        f: F,
    ) -> Option<T> {
        self.entries
            .get(sp_entity_id)
            .and_then(&f)
            .or_else(|| {
                self.registration_authorities
                    .get(sp_entity_id)
                    .and_then(|ra| self.entries.get(ra))
                    .and_then(&f)
            })
            .or_else(|| self.entries.get(DEFAULT_ENTRY).and_then(&f))
    }

    /// NameID format for the SP (default: transient).
    pub fn nameid_format(&self, sp_entity_id: &str) -> String {
        self.get(sp_entity_id, |e| e.nameid_format.clone())
            .unwrap_or_else(|| constants::NAMEID_TRANSIENT.to_string())
    }

    /// Attribute NameFormat for the SP (default: URI).
    pub fn name_form(&self, sp_entity_id: &str) -> String {
        self.get(sp_entity_id, |e| e.name_form.clone())
            .unwrap_or_else(|| constants::ATTRNAME_FORMAT_URI.to_string())
    }

    /// Assertion lifetime for the SP (default: 1 hour).
    pub fn lifetime(&self, sp_entity_id: &str) -> TimeDelta {
        self.get(sp_entity_id, |e| e.lifetime)
            .unwrap_or_else(|| TimeDelta::hours(1))
    }

    /// Assertion NotOnOrAfter for the SP (pysaml2 `not_on_or_after`).
    pub fn not_on_or_after(&self, sp_entity_id: &str, now: DateTime<Utc>) -> DateTime<Utc> {
        now + self.lifetime(sp_entity_id)
    }

    /// Signing targets for the SP (default: nothing).
    pub fn sign(&self, sp_entity_id: &str) -> SignTargets {
        self.get(sp_entity_id, |e| e.sign).unwrap_or_default()
    }

    /// Whether a missing required attribute is an error (default: true).
    pub fn fail_on_missing_requested(&self, sp_entity_id: &str) -> bool {
        self.get(sp_entity_id, |e| e.fail_on_missing_requested)
            .unwrap_or(true)
    }

    /// The local (lowercased) name of a wire attribute.
    fn local_key(&self, attribute: &Attribute) -> String {
        self.converters
            .local_name(attribute)
            .unwrap_or_else(|| attribute.name.clone())
            .to_lowercase()
    }

    fn matching_requested_attribute(
        &self,
        attributes: &[Attribute],
        requested: &RequestedAttribute,
    ) -> Option<Attribute> {
        let req_local = self.local_key(&requested.attribute);
        let req_wire = requested.attribute.name.to_lowercase();

        // Assertion parsing does not merge duplicate Attribute elements,
        // so collect every input attribute mapping to this requested name
        // (by local or wire name) rather than just the first.
        let mut matched = attributes.iter().filter(|attr| {
            self.local_key(attr) == req_local || attr.name.to_lowercase() == req_wire
        });

        let mut released = matched.next()?.clone();
        for extra in matched {
            for v in &extra.values {
                if !released.values.contains(v) {
                    released.values.push(v.clone());
                }
            }
        }

        Some(released)
    }

    fn validate_required_attributes(
        &self,
        attributes: &[Attribute],
        required: &[RequestedAttribute],
    ) -> Result<(), PolicyError> {
        for requested in required {
            let Some(mut matched) = self.matching_requested_attribute(attributes, requested) else {
                return Err(PolicyError::MissingRequiredAttribute(
                    requested.attribute.name.clone(),
                ));
            };

            let wanted: Vec<String> = requested
                .attribute
                .values
                .iter()
                .filter_map(value_text)
                .collect();
            if !wanted.is_empty() {
                matched
                    .values
                    .retain(|v| value_text(v).is_some_and(|t| wanted.contains(&t)));
                if matched.values.is_empty() {
                    return Err(PolicyError::MissingRequiredValue {
                        attribute: requested.attribute.name.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Filter attributes for release to `sp_entity_id`
    /// (pysaml2 `Policy.filter`).
    ///
    /// Pipeline:
    /// 1. entity-category release rules, when configured for this SP
    ///    (`sp_entity_categories` are the SP's published categories);
    /// 2. otherwise, required/optional matching against the SP's
    ///    `RequestedAttribute`s (honoring `fail_on_missing_requested`);
    /// 3. the entry's attribute/value restrictions;
    /// 4. subject-id / pairwise-id mutual exclusion when the SP's
    ///    `subject-id:req` is `any` (pysaml2 PR #987).
    ///
    /// `subject_id_req` is the SP's requested subject identifier, read from its
    /// `subject-id:req` metadata entity attribute
    /// (see [`SubjectIdReq::from_metadata_values`]).
    pub fn filter(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        let mut result = attributes;
        let fail_on_missing_requested = self.fail_on_missing_requested(sp_entity_id);

        // Step 1: entity-category release rules take precedence over
        // per-attribute requested/optional matching when configured. Borrow the
        // resolved policy set rather than cloning it on every request.
        let categories = self.get_ref(sp_entity_id, |e| e.entity_categories.as_deref());
        if let Some(policies) = categories {
            let required_local: Vec<String> = required
                .iter()
                .map(|r| self.local_key(&r.attribute))
                .collect();
            let policy_refs: Vec<&OwnedEntityCategoryPolicy> = policies.iter().collect();
            let released =
                releasable_attributes_owned(&policy_refs, sp_entity_categories, &required_local);
            result.retain(|attr| released.contains(&self.local_key(attr)));
        } else if !required.is_empty() || !optional.is_empty() {
            // Step 2: release only what the SP asked for in its
            // AttributeConsumingService (or the explicit lists given here).
            result =
                self.filter_on_attributes(result, required, optional, fail_on_missing_requested)?;
        }

        // Step 3: the IdP's own attribute/value restrictions always apply.
        if let Some(restrictions) =
            self.get_ref(sp_entity_id, |e| e.attribute_restrictions.as_ref())
        {
            result = self.filter_attribute_value_assertions(result, restrictions);
        }

        // Step 4: pysaml2 PR #987 — when the SP requests subject-id with
        // requirement "any" and both subject-id and pairwise-id are about to be
        // released, keep only the privacy-preserving pairwise-id. Other
        // metadata values are intentionally left unchanged; the profile defines
        // the signal but leaves asserting-party response unspecified.
        if subject_id_req == SubjectIdReq::Any {
            let mut has_subject_id = false;
            let mut has_pairwise_id = false;

            for attr in &result {
                match self.local_key(attr).as_str() {
                    "subject-id" => has_subject_id = true,
                    "pairwise-id" => has_pairwise_id = true,
                    _ => {}
                }

                if has_subject_id && has_pairwise_id {
                    break;
                }
            }

            if has_subject_id && has_pairwise_id {
                result.retain(|a| self.local_key(a) != "subject-id");
            }
        }

        if fail_on_missing_requested && !required.is_empty() {
            self.validate_required_attributes(&result, required)?;
        }

        Ok(result)
    }

    /// Filter against the SP's metadata-declared attribute requirements
    /// (pysaml2 `Policy.restrict`).
    ///
    /// Extracts required/optional `RequestedAttribute`s from the SP's
    /// `AttributeConsumingService` (the indexed one when `acs_index` is
    /// given, else the default) and calls [`ReleasePolicy::filter`].
    pub fn restrict(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_metadata: Option<&SpSsoDescriptor>,
        sp_entity_categories: &[String],
        acs_index: Option<u16>,
        subject_id_req: SubjectIdReq,
    ) -> Result<Vec<Attribute>, PolicyError> {
        let (required, optional) = match sp_metadata {
            Some(sp) => sp_attribute_requirements(sp, acs_index),
            None => (vec![], vec![]),
        };
        self.filter(
            attributes,
            sp_entity_id,
            sp_entity_categories,
            &required,
            &optional,
            subject_id_req,
        )
    }

    /// Match attributes against required/optional `RequestedAttribute`s
    /// (pysaml2 `filter_on_attributes`). Only requested attributes are
    /// released; requested values (when present) narrow the released values.
    pub fn filter_on_attributes(
        &self,
        attributes: Vec<Attribute>,
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
        fail_on_unfulfilled: bool,
    ) -> Result<Vec<Attribute>, PolicyError> {
        let mut result: Vec<Attribute> = Vec::new();

        for (requested, must) in required
            .iter()
            .map(|r| (r, true))
            .chain(optional.iter().map(|r| (r, false)))
        {
            let Some(mut released) = self.matching_requested_attribute(&attributes, requested)
            else {
                if must && fail_on_unfulfilled {
                    return Err(PolicyError::MissingRequiredAttribute(
                        requested.attribute.name.clone(),
                    ));
                }
                continue;
            };

            let wanted: Vec<String> = requested
                .attribute
                .values
                .iter()
                .filter_map(value_text)
                .collect();
            if !wanted.is_empty() {
                released
                    .values
                    .retain(|v| value_text(v).is_some_and(|t| wanted.contains(&t)));
                if must && released.values.is_empty() {
                    return Err(PolicyError::MissingRequiredValue {
                        attribute: requested.attribute.name.clone(),
                    });
                }
            }

            // Merge duplicate RequestedAttribute entries for the same
            // attribute instead of releasing it twice.
            match result
                .iter_mut()
                .find(|a| self.local_key(a) == self.local_key(&released))
            {
                Some(existing) => {
                    for v in released.values {
                        if !existing.values.contains(&v) {
                            existing.values.push(v);
                        }
                    }
                }
                None => result.push(released),
            }
        }

        Ok(result)
    }

    /// Apply attribute/value restrictions (pysaml2
    /// `filter_attribute_value_assertions`): attributes not named are
    /// dropped; a `None` restriction keeps all values; regex restrictions
    /// keep matching values and drop the attribute if none remain.
    pub fn filter_attribute_value_assertions(
        &self,
        attributes: Vec<Attribute>,
        restrictions: &HashMap<String, ValueRestriction>,
    ) -> Vec<Attribute> {
        let mut result = Vec::new();
        for mut attr in attributes {
            // Attributes not named in the restrictions map are never released.
            let Some(restriction) = restrictions.get(&self.local_key(&attr)) else {
                continue;
            };
            match restriction {
                None => result.push(attr),
                Some(regexes) => {
                    attr.values.retain(|v| {
                        value_text(v).is_some_and(|t| regexes.iter().any(|re| re.is_match(&t)))
                    });
                    dedup_values(&mut attr.values);
                    if !attr.values.is_empty() {
                        result.push(attr);
                    }
                }
            }
        }
        result
    }

    /// Release no more than the receiver asked for (pysaml2
    /// `filter_on_demands`): every required attribute (and value) must be
    /// present, and everything not required or optional is dropped.
    ///
    /// `required`/`optional` map local names to required values.
    pub fn filter_on_demands(
        &self,
        mut attributes: Vec<Attribute>,
        required: &HashMap<String, Vec<String>>,
        optional: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<Attribute>, PolicyError> {
        for (name, values) in required {
            let key = name.to_lowercase();
            let Some(attr) = attributes.iter().find(|a| self.local_key(a) == key) else {
                return Err(PolicyError::MissingRequiredAttribute(name.clone()));
            };
            let have: Vec<String> = attr.values.iter().filter_map(value_text).collect();
            for v in values {
                if !have.contains(v) {
                    return Err(PolicyError::MissingRequiredValue {
                        attribute: name.clone(),
                    });
                }
            }
        }

        let allowed: Vec<String> = required
            .keys()
            .chain(optional.keys())
            .map(|k| k.to_lowercase())
            .collect();
        attributes.retain(|a| allowed.contains(&self.local_key(a)));
        Ok(attributes)
    }

    /// Keep only attributes whose wire representation the SP asked for
    /// (pysaml2 `filter_on_wire_representation`).
    pub fn filter_on_wire_representation(
        &self,
        attributes: Vec<Attribute>,
        required: &[Attribute],
        optional: &[Attribute],
    ) -> Vec<Attribute> {
        attributes
            .into_iter()
            .filter(|attr| {
                required
                    .iter()
                    .chain(optional.iter())
                    .any(|req| req.name.eq_ignore_ascii_case(&attr.name))
            })
            .collect()
    }
}

/// Extract (required, optional) `RequestedAttribute`s from the SP's
/// `AttributeConsumingService` (pysaml2 `Server.wants` /
/// `attribute_requirement`).
///
/// Selects the service with the given index, else the default one, else the
/// lowest index.
pub fn sp_attribute_requirements(
    sp: &SpSsoDescriptor,
    index: Option<u16>,
) -> (Vec<RequestedAttribute>, Vec<RequestedAttribute>) {
    let services = &sp.attribute_consuming_services;
    let service = match index {
        Some(i) => services.iter().find(|s| s.index == i),
        None => services
            .iter()
            .find(|s| s.is_default == Some(true))
            .or_else(|| services.iter().min_by_key(|s| s.index)),
    };

    let Some(service) = service else {
        return (vec![], vec![]);
    };

    let (required, optional): (Vec<_>, Vec<_>) = service
        .requested_attributes
        .iter()
        .cloned()
        .partition(|ra| ra.is_required == Some(true));
    (required, optional)
}

/// Textual rendering of an attribute value for comparison/matching.
fn value_text(value: &AttributeValue) -> Option<String> {
    match value {
        AttributeValue::String(s) => Some(s.clone()),
        AttributeValue::Integer(i) => Some(i.to_string()),
        AttributeValue::Boolean(b) => Some(b.to_string()),
        AttributeValue::DateTime(s) => Some(s.clone()),
        AttributeValue::NameId(n) => Some(n.value.clone()),
        AttributeValue::Base64(_) | AttributeValue::Xml(_) | AttributeValue::Null => None,
    }
}

fn dedup_values(values: &mut Vec<AttributeValue>) {
    let mut seen: Vec<AttributeValue> = Vec::new();
    values.retain(|v| {
        if seen.contains(v) {
            false
        } else {
            seen.push(v.clone());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::entity_category::{COCO_V1, EDUGAIN, REFEDS, REFEDS_RESEARCH_AND_SCHOLARSHIP};
    use crate::profiles::attribute::x500::{eppn_attribute, mail_attribute};

    fn requested(name: &str, friendly: Option<&str>, required: bool) -> RequestedAttribute {
        RequestedAttribute {
            attribute: Attribute {
                name: name.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: friendly.map(str::to_string),
                values: vec![],
            },
            is_required: Some(required),
        }
    }

    fn requested_with_values(
        name: &str,
        friendly: Option<&str>,
        required: bool,
        values: &[&str],
    ) -> RequestedAttribute {
        RequestedAttribute {
            attribute: Attribute {
                name: name.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: friendly.map(str::to_string),
                values: values
                    .iter()
                    .map(|value| AttributeValue::String((*value).to_string()))
                    .collect(),
            },
            is_required: Some(required),
        }
    }

    #[test]
    fn test_defaults() {
        let policy = ReleasePolicy::new();
        assert_eq!(
            policy.nameid_format("https://sp.example.com"),
            constants::NAMEID_TRANSIENT
        );
        assert_eq!(
            policy.name_form("https://sp.example.com"),
            constants::ATTRNAME_FORMAT_URI
        );
        assert_eq!(
            policy.lifetime("https://sp.example.com"),
            TimeDelta::hours(1)
        );
        assert!(policy.fail_on_missing_requested("https://sp.example.com"));
        assert_eq!(
            policy.sign("https://sp.example.com"),
            SignTargets::default()
        );
    }

    #[test]
    fn test_entry_resolution_sp_overrides_default() {
        let mut policy = ReleasePolicy::with_default(
            PolicyEntry::new().with_nameid_format(constants::NAMEID_PERSISTENT),
        );
        policy.insert(
            "https://sp2.example.com",
            PolicyEntry::new().with_nameid_format(constants::NAMEID_EMAIL),
        );

        assert_eq!(
            policy.nameid_format("https://sp1.example.com"),
            constants::NAMEID_PERSISTENT
        );
        assert_eq!(
            policy.nameid_format("https://sp2.example.com"),
            constants::NAMEID_EMAIL
        );
    }

    #[test]
    fn test_attribute_restrictions_value_regex() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[
                    ("mail", Some(&[r".*@example\.com"])),
                    ("givenName", None),
                ])
                .unwrap(),
        );

        let attrs = vec![
            mail_attribute(&["alice@example.com", "alice@evil.org"]),
            eppn_attribute("alice@example.com"),
        ];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();

        // eppn is not listed -> dropped; mail keeps only the matching value
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
        assert_eq!(out[0].values.len(), 1);
        assert_eq!(out[0].values[0].as_str(), Some("alice@example.com"));
    }

    #[test]
    fn test_regex_is_anchored_like_python_match() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", Some(&["alice"]))])
                .unwrap(),
        );
        let attrs = vec![mail_attribute(&["alice@example.com", "malice@example.com"])];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        // re.match semantics: only values starting with "alice"
        assert_eq!(out[0].values.len(), 1);
        assert_eq!(out[0].values[0].as_str(), Some("alice@example.com"));
    }

    #[test]
    fn test_filter_on_attributes_required_missing_fails() {
        let policy = ReleasePolicy::new();
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];
        let err = policy
            .filter(
                vec![eppn_attribute("a@example.org")],
                "https://sp.example.com",
                &[],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap_err();
        assert!(matches!(err, PolicyError::MissingRequiredAttribute(_)));
    }

    #[test]
    fn test_filter_on_attributes_releases_only_requested() {
        let policy = ReleasePolicy::new();
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];
        let optional = vec![requested(
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
            None, // resolved through the shipped saml_uri map
            false,
        )];
        let attrs = vec![
            mail_attribute(&["a@example.com"]),
            eppn_attribute("a@example.org"),
            crate::profiles::attribute::x500::cn_attribute(&["Alice"]),
        ];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &[],
                &required,
                &optional,
                SubjectIdReq::None,
            )
            .unwrap();
        let names: Vec<_> = out
            .iter()
            .map(|a| a.friendly_name.clone().unwrap_or_default())
            .collect();
        assert_eq!(out.len(), 2);
        assert!(names.contains(&"mail".to_string()));
        assert!(names.contains(&"eduPersonPrincipalName".to_string()));
    }

    #[test]
    fn test_filter_on_attributes_unions_duplicate_input_attributes() {
        // Two separate Attribute elements both mapping to `mail` (assertion
        // parsing does not merge them) must contribute all their values.
        let policy = ReleasePolicy::new();
        let optional = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            false,
        )];
        let attrs = vec![
            mail_attribute(&["alice@example.com"]),
            mail_attribute(&["alice@work.example"]),
        ];
        let out = policy
            .filter_on_attributes(attrs, &[], &optional, false)
            .unwrap();
        assert_eq!(out.len(), 1);
        let vals: Vec<&str> = out[0].values.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(vals, vec!["alice@example.com", "alice@work.example"]);
    }

    #[test]
    fn test_filter_no_fail_when_disabled() {
        let policy =
            ReleasePolicy::with_default(PolicyEntry::new().with_fail_on_missing_requested(false));
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];
        let out = policy
            .filter(
                vec![],
                "https://sp.example.com",
                &[],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_filter_rechecks_required_attributes_after_restrictions() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_attribute_restrictions(&[("mail", Some(&[r".*@other\.example"]))])
                .unwrap(),
        );
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];

        let err = policy
            .filter(
                vec![mail_attribute(&["alice@example.com"])],
                "https://sp.example.com",
                &[],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            PolicyError::MissingRequiredAttribute(ref attribute)
                if attribute == "urn:oid:0.9.2342.19200300.100.1.3"
        ));
    }

    #[test]
    fn test_filter_rechecks_required_values_after_entity_category_restrictions() {
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new()
                .with_entity_categories(vec![&REFEDS])
                .with_attribute_restrictions(&[("mail", Some(&[r".*@work\.example"]))])
                .unwrap(),
        );
        let required = vec![requested_with_values(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
            &["alice@example.com"],
        )];

        let err = policy
            .filter(
                vec![mail_attribute(&["alice@example.com", "alice@work.example"])],
                "https://sp.example.com",
                &[REFEDS_RESEARCH_AND_SCHOLARSHIP.to_string()],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            PolicyError::MissingRequiredValue { ref attribute }
                if attribute == "urn:oid:0.9.2342.19200300.100.1.3"
        ));
    }

    #[test]
    fn test_entity_category_release_refeds() {
        let policy =
            ReleasePolicy::with_default(PolicyEntry::new().with_entity_categories(vec![&REFEDS]));
        let attrs = vec![
            mail_attribute(&["a@example.com"]),
            crate::profiles::attribute::x500::cn_attribute(&["Alice"]),
        ];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &[REFEDS_RESEARCH_AND_SCHOLARSHIP.to_string()],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        // mail is in R&S, cn is not
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn test_entity_category_coco_only_required() {
        let policy =
            ReleasePolicy::with_default(PolicyEntry::new().with_entity_categories(vec![&EDUGAIN]));
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];
        let attrs = vec![
            mail_attribute(&["a@example.com"]),
            eppn_attribute("a@example.org"),
        ];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &[COCO_V1.to_string()],
                &required,
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        // CoCo + only_required: eppn (not required by the SP) is withheld
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    #[test]
    fn test_registration_authority_resolution_precedence() {
        // default releases nothing extra; the registration-authority entry
        // signs responses; the SP-specific entry overrides the RA entry.
        let mut policy = ReleasePolicy::new();
        policy.insert(
            DEFAULT_ENTRY,
            PolicyEntry::new().with_lifetime(TimeDelta::hours(1)),
        );
        policy.insert(
            "http://www.swamid.se/",
            PolicyEntry::new().with_lifetime(TimeDelta::minutes(10)),
        );
        policy.insert(
            "https://special.example.com",
            PolicyEntry::new().with_lifetime(TimeDelta::minutes(5)),
        );

        // SP with a SWAMID registration authority but no own entry -> RA entry.
        policy.set_registration_authority("https://sp.swamid.example", "http://www.swamid.se/");
        assert_eq!(
            policy.lifetime("https://sp.swamid.example"),
            TimeDelta::minutes(10)
        );

        // SP with its own entry -> own entry wins over the RA entry.
        policy.set_registration_authority("https://special.example.com", "http://www.swamid.se/");
        assert_eq!(
            policy.lifetime("https://special.example.com"),
            TimeDelta::minutes(5)
        );

        // SP with an unknown registration authority -> falls through to default.
        policy.set_registration_authority("https://other.example", "http://other.federation/");
        assert_eq!(
            policy.lifetime("https://other.example"),
            TimeDelta::hours(1)
        );
    }

    #[test]
    fn test_register_sp_metadata_reads_registration_authority() {
        use crate::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
        use crate::metadata::types::extensions::Extensions;

        let entity = EntityDescriptor {
            entity_id: "https://sp.swamid.example".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: Some(Extensions::new(
                r#"<mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationAuthority="http://www.swamid.se/"/>"#
                    .to_string(),
            )),
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };

        let mut policy = ReleasePolicy::new();
        policy.insert(
            "http://www.swamid.se/",
            PolicyEntry::new().with_lifetime(TimeDelta::minutes(10)),
        );
        policy.register_sp_metadata(&entity);
        assert_eq!(
            policy.lifetime("https://sp.swamid.example"),
            TimeDelta::minutes(10)
        );
    }

    #[test]
    fn test_custom_owned_entity_category_release() {
        use crate::idp::entity_category::{OwnedEntityCategoryPolicy, OwnedEntityCategoryRule};

        // A deployment-defined entity category, built entirely at runtime.
        let custom = OwnedEntityCategoryPolicy::new("eduid-local").with_rule(
            OwnedEntityCategoryRule::new(["https://eduid.se/category/staff"], ["mail"]),
        );
        let policy = ReleasePolicy::with_default(
            PolicyEntry::new().with_owned_entity_categories(vec![custom]),
        );
        let attrs = vec![
            mail_attribute(&["a@example.com"]),
            crate::profiles::attribute::x500::cn_attribute(&["Alice"]),
        ];
        let out = policy
            .filter(
                attrs,
                "https://sp.example.com",
                &["https://eduid.se/category/staff".to_string()],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
    }

    fn subject_identifier(name: &str, friendly: &str, value: &str) -> Attribute {
        Attribute {
            name: name.to_string(),
            name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            friendly_name: Some(friendly.to_string()),
            values: vec![AttributeValue::String(value.to_string())],
        }
    }

    #[test]
    fn test_subject_id_req_any_prefers_pairwise() {
        use crate::idp::entity_category::{PAIRWISE_ID_ATTR, SUBJECT_ID_ATTR};
        let policy = ReleasePolicy::new();
        let attrs = || {
            vec![
                subject_identifier(SUBJECT_ID_ATTR, "subject-id", "alice@example.com"),
                subject_identifier(PAIRWISE_ID_ATTR, "pairwise-id", "opaque@example.com"),
                mail_attribute(&["alice@example.com"]),
            ]
        };

        // req == any: subject-id dropped, pairwise-id (and mail) kept.
        let out = policy
            .filter(
                attrs(),
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::Any,
            )
            .unwrap();
        let names: Vec<_> = out.iter().filter_map(|a| a.friendly_name.clone()).collect();
        assert!(names.contains(&"pairwise-id".to_string()));
        assert!(names.contains(&"mail".to_string()));
        assert!(!names.contains(&"subject-id".to_string()));

        // Non-`any` leaves the release set unchanged by design: the metadata
        // signal does not define asserting-party behavior for those values.
        let out = policy
            .filter(
                attrs(),
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::None,
            )
            .unwrap();
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn test_subject_id_req_any_keeps_lone_subject_id() {
        use crate::idp::entity_category::SUBJECT_ID_ATTR;
        let policy = ReleasePolicy::new();
        // Only subject-id present: nothing to prefer, so it is kept.
        let out = policy
            .filter(
                vec![subject_identifier(
                    SUBJECT_ID_ATTR,
                    "subject-id",
                    "alice@example.com",
                )],
                "https://sp.example.com",
                &[],
                &[],
                &[],
                SubjectIdReq::Any,
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("subject-id"));
    }

    #[test]
    fn test_sign_targets_on_demand() {
        let targets = SignTargets {
            response: true,
            assertion: false,
            on_demand: true,
        };
        let resolved = targets.resolve(true);
        assert!(resolved.sign_response);
        assert!(resolved.sign_assertion);
        let resolved = targets.resolve(false);
        assert!(!resolved.sign_assertion);
    }

    #[test]
    fn test_filter_on_demands() {
        let policy = ReleasePolicy::new();
        let mut required = HashMap::new();
        required.insert("mail".to_string(), vec!["a@example.com".to_string()]);
        let optional = HashMap::new();

        let attrs = vec![
            mail_attribute(&["a@example.com"]),
            eppn_attribute("a@example.org"),
        ];
        let out = policy
            .filter_on_demands(attrs.clone(), &required, &optional)
            .unwrap();
        assert_eq!(out.len(), 1);

        let mut bad = HashMap::new();
        bad.insert("mail".to_string(), vec!["other@example.com".to_string()]);
        assert!(policy.filter_on_demands(attrs, &bad, &optional).is_err());
    }

    #[test]
    fn test_invalid_pattern_is_error() {
        let err = PolicyEntry::new()
            .with_attribute_restrictions(&[("mail", Some(&["("]))])
            .unwrap_err();
        assert!(matches!(err, PolicyError::InvalidPattern { .. }));
    }
}
