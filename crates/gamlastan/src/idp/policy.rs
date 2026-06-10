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
use crate::idp::entity_category::{releasable_attributes, EntityCategoryPolicy};
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
    entity_categories: Option<Vec<&'static EntityCategoryPolicy>>,
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

    /// Enable entity-category based release with the given policies
    /// (see [`crate::idp::entity_category`]).
    pub fn with_entity_categories(mut self, policies: Vec<&'static EntityCategoryPolicy>) -> Self {
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
}

/// The key under which the fallback entry is stored.
pub const DEFAULT_ENTRY: &str = "default";

impl ReleasePolicy {
    /// An empty policy (built-in defaults for every SP).
    pub fn new() -> Self {
        ReleasePolicy {
            entries: HashMap::new(),
            converters: AttributeConverterSet::with_default_maps(),
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

    /// Resolve a knob: SP entry first, then `default`.
    fn get<T, F: Fn(&PolicyEntry) -> Option<T>>(&self, sp_entity_id: &str, f: F) -> Option<T> {
        self.entries
            .get(sp_entity_id)
            .and_then(&f)
            .or_else(|| self.entries.get(DEFAULT_ENTRY).and_then(&f))
            .or_else(|| self.entries.get("").and_then(&f))
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

    /// Filter attributes for release to `sp_entity_id`
    /// (pysaml2 `Policy.filter`).
    ///
    /// Pipeline:
    /// 1. entity-category release rules, when configured for this SP
    ///    (`sp_entity_categories` are the SP's published categories);
    /// 2. otherwise, required/optional matching against the SP's
    ///    `RequestedAttribute`s (honoring `fail_on_missing_requested`);
    /// 3. the entry's attribute/value restrictions.
    pub fn filter(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: &[String],
        required: &[RequestedAttribute],
        optional: &[RequestedAttribute],
    ) -> Result<Vec<Attribute>, PolicyError> {
        let mut result = attributes;

        // Step 1: entity-category release rules take precedence over
        // per-attribute requested/optional matching when configured.
        let categories = self.get(sp_entity_id, |e| e.entity_categories.clone());
        if let Some(policies) = categories {
            let required_local: Vec<String> = required
                .iter()
                .map(|r| self.local_key(&r.attribute))
                .collect();
            let released = releasable_attributes(&policies, sp_entity_categories, &required_local);
            result.retain(|attr| released.contains(&self.local_key(attr)));
        } else if !required.is_empty() || !optional.is_empty() {
            // Step 2: release only what the SP asked for in its
            // AttributeConsumingService (or the explicit lists given here).
            result = self.filter_on_attributes(
                result,
                required,
                optional,
                self.fail_on_missing_requested(sp_entity_id),
            )?;
        }

        // Step 3: the IdP's own attribute/value restrictions always apply.
        if let Some(restrictions) = self.get(sp_entity_id, |e| e.attribute_restrictions.clone()) {
            result = self.filter_attribute_value_assertions(result, &restrictions);
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
            let req_local = self.local_key(&requested.attribute);
            let req_wire = requested.attribute.name.to_lowercase();

            let matched = attributes.iter().find(|attr| {
                self.local_key(attr) == req_local || attr.name.to_lowercase() == req_wire
            });

            let Some(attr) = matched else {
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
            let mut released = attr.clone();
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
            .filter(attrs, "https://sp.example.com", &[], &[], &[])
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
            .filter(attrs, "https://sp.example.com", &[], &[], &[])
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
            .filter(attrs, "https://sp.example.com", &[], &required, &optional)
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
    fn test_filter_no_fail_when_disabled() {
        let policy =
            ReleasePolicy::with_default(PolicyEntry::new().with_fail_on_missing_requested(false));
        let required = vec![requested(
            "urn:oid:0.9.2342.19200300.100.1.3",
            Some("mail"),
            true,
        )];
        let out = policy
            .filter(vec![], "https://sp.example.com", &[], &required, &[])
            .unwrap();
        assert!(out.is_empty());
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
            )
            .unwrap();
        // CoCo + only_required: eppn (not required by the SP) is withheld
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].friendly_name.as_deref(), Some("mail"));
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
