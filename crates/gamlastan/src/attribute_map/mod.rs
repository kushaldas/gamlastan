// Attribute name conversion between local (friendly) names and on-the-wire
// SAML attribute names (pysaml2 `AttributeConverter` equivalent).
//
// A converter is keyed by the attribute NameFormat it understands and holds
// case-insensitive bidirectional maps:
// - `fro`: wire name (e.g. `urn:oid:0.9.2342.19200300.100.1.3`) -> local name (`mail`)
// - `to`:  local name -> wire name
//
// The shipped maps (eduPerson, SCHAC, eIDAS, X.500, ADFS, ...) live in
// [`maps`] and are generated from pysaml2's curated attribute maps.

pub mod maps;

use std::collections::HashMap;

use crate::core::assertion::attribute::{Attribute, AttributeValue};
use crate::core::assertion::name_id::NameId;
use crate::core::constants;

/// A static, shipped attribute map (see [`maps`]).
#[derive(Debug, Clone, Copy)]
pub struct StaticAttributeMap {
    /// The attribute NameFormat this map applies to.
    pub identifier: &'static str,
    /// (wire name, local name) pairs.
    pub fro: &'static [(&'static str, &'static str)],
    /// (local name, wire name) pairs.
    pub to: &'static [(&'static str, &'static str)],
}

/// Standard SAML URI map (eduPerson, SCHAC, eduOrg, eIDAS, X.500, ...).
pub static SAML_URI: StaticAttributeMap = StaticAttributeMap {
    identifier: maps::saml_uri::IDENTIFIER,
    fro: maps::saml_uri::FRO,
    to: maps::saml_uri::TO,
};

/// Basic name-format map (`urn:mace:dir:attribute-def:` names).
pub static BASIC: StaticAttributeMap = StaticAttributeMap {
    identifier: maps::basic::IDENTIFIER,
    fro: maps::basic::FRO,
    to: maps::basic::TO,
};

/// Shibboleth 1.0 attribute namespace map.
pub static SHIBBOLETH_URI: StaticAttributeMap = StaticAttributeMap {
    identifier: maps::shibboleth_uri::IDENTIFIER,
    fro: maps::shibboleth_uri::FRO,
    to: maps::shibboleth_uri::TO,
};

/// ADFS 1.x claim map.
pub static ADFS_V1X: StaticAttributeMap = StaticAttributeMap {
    identifier: maps::adfs_v1x::IDENTIFIER,
    fro: maps::adfs_v1x::FRO,
    to: maps::adfs_v1x::TO,
};

/// ADFS 2.0 claim map.
pub static ADFS_V20: StaticAttributeMap = StaticAttributeMap {
    identifier: maps::adfs_v20::IDENTIFIER,
    fro: maps::adfs_v20::FRO,
    to: maps::adfs_v20::TO,
};

/// All shipped maps, in lookup order.
///
/// Note that `ADFS_V1X` and `ADFS_V20` share the `unspecified` NameFormat;
/// `ADFS_V20` is listed first and wins on conflicting wire names.
pub static DEFAULT_MAPS: &[&StaticAttributeMap] =
    &[&SAML_URI, &BASIC, &SHIBBOLETH_URI, &ADFS_V20, &ADFS_V1X];

/// Bidirectional attribute name converter for one NameFormat.
///
/// Lookups are case-insensitive on both wire and local names, matching
/// pysaml2 behavior.
#[derive(Debug, Clone, Default)]
pub struct AttributeConverter {
    name_format: String,
    /// wire name (lowercased) -> local name
    fro: HashMap<String, String>,
    /// local name (lowercased) -> wire name
    to: HashMap<String, String>,
}

impl AttributeConverter {
    /// Create an empty converter for the given NameFormat.
    pub fn new(name_format: impl Into<String>) -> Self {
        AttributeConverter {
            name_format: name_format.into(),
            fro: HashMap::new(),
            to: HashMap::new(),
        }
    }

    /// Build a converter from a shipped static map.
    pub fn from_static(map: &StaticAttributeMap) -> Self {
        let mut conv = AttributeConverter::new(map.identifier);
        for (wire, local) in map.fro {
            conv.fro.insert(wire.to_lowercase(), (*local).to_string());
        }
        for (local, wire) in map.to {
            conv.to.insert(local.to_lowercase(), (*wire).to_string());
        }
        conv
    }

    /// Build a converter from (wire name, local name) pairs, mirroring the
    /// entries in both directions.
    pub fn from_entries(name_format: impl Into<String>, entries: &[(&str, &str)]) -> Self {
        let mut conv = AttributeConverter::new(name_format);
        for (wire, local) in entries {
            conv.add_mapping(wire, local);
        }
        conv
    }

    /// Add a single wire <-> local mapping (both directions).
    pub fn add_mapping(&mut self, wire: &str, local: &str) {
        self.fro.insert(wire.to_lowercase(), local.to_string());
        self.to.insert(local.to_lowercase(), wire.to_string());
    }

    /// The attribute NameFormat this converter applies to.
    pub fn name_format(&self) -> &str {
        &self.name_format
    }

    /// Wire name -> local name.
    pub fn to_local_name(&self, wire_name: &str) -> Option<&str> {
        self.fro.get(&wire_name.to_lowercase()).map(String::as_str)
    }

    /// Local name -> wire name.
    pub fn to_wire_name(&self, local_name: &str) -> Option<&str> {
        self.to.get(&local_name.to_lowercase()).map(String::as_str)
    }
}

/// An attribute expressed under its local (friendly) name.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAttribute {
    /// The local attribute name (e.g. `mail`, `eduPersonPrincipalName`).
    pub name: String,
    /// The attribute values.
    pub values: Vec<AttributeValue>,
}

impl LocalAttribute {
    /// Convenience constructor from string values.
    pub fn from_strings(name: impl Into<String>, values: &[&str]) -> Self {
        LocalAttribute {
            name: name.into(),
            values: values
                .iter()
                .map(|v| AttributeValue::String((*v).to_string()))
                .collect(),
        }
    }
}

/// A set of converters covering multiple NameFormats — the unit the SP/IdP
/// actually uses (pysaml2 `ac_factory()` result).
#[derive(Debug, Clone)]
pub struct AttributeConverterSet {
    converters: Vec<AttributeConverter>,
    allow_unknown_attributes: bool,
}

impl Default for AttributeConverterSet {
    fn default() -> Self {
        Self::with_default_maps()
    }
}

impl AttributeConverterSet {
    /// A set loaded with all shipped maps ([`DEFAULT_MAPS`]).
    pub fn with_default_maps() -> Self {
        AttributeConverterSet {
            converters: DEFAULT_MAPS
                .iter()
                .map(|m| AttributeConverter::from_static(m))
                .collect(),
            allow_unknown_attributes: false,
        }
    }

    /// A set from custom converters (e.g. loaded map directories).
    pub fn new(converters: Vec<AttributeConverter>) -> Self {
        AttributeConverterSet {
            converters,
            allow_unknown_attributes: false,
        }
    }

    /// Whether attributes missing from every map are passed through
    /// (`true`) or dropped (`false`, the default) during conversion —
    /// pysaml2's `allow_unknown_attributes`.
    pub fn allow_unknown_attributes(mut self, allow: bool) -> Self {
        self.allow_unknown_attributes = allow;
        self
    }

    /// The converter registered for the given NameFormat, if any.
    pub fn converter_for(&self, name_format: &str) -> Option<&AttributeConverter> {
        self.converters
            .iter()
            .find(|c| c.name_format == name_format)
    }

    /// Resolve the local name of a wire attribute.
    ///
    /// Resolution order: the map matching the attribute's NameFormat, then
    /// (for attributes without a NameFormat) every map in order, then the
    /// FriendlyName carried in the attribute itself.
    pub fn local_name(&self, attribute: &Attribute) -> Option<String> {
        if let Some(nf) = &attribute.name_format {
            if let Some(conv) = self.converter_for(nf) {
                if let Some(local) = conv.to_local_name(&attribute.name) {
                    return Some(local.to_string());
                }
            }
        } else {
            for conv in &self.converters {
                if let Some(local) = conv.to_local_name(&attribute.name) {
                    return Some(local.to_string());
                }
            }
        }
        attribute.friendly_name.clone()
    }

    /// Resolve the local name of a wire attribute using **only** the registered
    /// NameFormat converters — never the attribute's own `FriendlyName`.
    ///
    /// [`local_name`](Self::local_name) additionally falls back to the
    /// `FriendlyName` carried on the attribute. That fallback is convenient when
    /// turning *received* attributes into local form, but it must not drive
    /// attribute *release* decisions: a `FriendlyName` is non-unique and, in an
    /// SP's `RequestedAttribute`, attacker-controllable. Using it as a match key
    /// would let SP metadata request a locally-mapped attribute by putting its
    /// local name in the `FriendlyName` without naming it by the correct wire
    /// `Name` (Finding #7, CWE-345). Release matching therefore resolves the
    /// requested attribute through this method and falls back only to the exact
    /// wire `Name`.
    pub fn local_name_via_converters(&self, attribute: &Attribute) -> Option<String> {
        if let Some(nf) = &attribute.name_format {
            // A declared NameFormat selects its converter; an unknown format has
            // no trusted mapping (mirrors `local_name`, minus the FriendlyName).
            return self
                .converter_for(nf)
                .and_then(|conv| conv.to_local_name(&attribute.name))
                .map(str::to_string);
        }
        for conv in &self.converters {
            if let Some(local) = conv.to_local_name(&attribute.name) {
                return Some(local.to_string());
            }
        }
        None
    }

    /// Convert wire attributes to local attributes (pysaml2 `to_local`).
    ///
    /// Unknown attributes (no map entry and no FriendlyName) are dropped
    /// unless `allow_unknown_attributes` is set, in which case the wire name
    /// is used as the local name. Values for the same local name are merged.
    pub fn to_local(&self, attributes: &[Attribute]) -> Vec<LocalAttribute> {
        let mut out: Vec<LocalAttribute> = Vec::new();
        for attr in attributes {
            // Resolve each wire attribute to its local name; unknown ones
            // are dropped or passed through depending on the policy flag.
            let name = match self.local_name(attr) {
                Some(name) => name,
                None if self.allow_unknown_attributes => attr.name.clone(),
                None => continue,
            };
            match out.iter_mut().find(|la| la.name == name) {
                Some(existing) => existing.values.extend(attr.values.iter().cloned()),
                None => out.push(LocalAttribute {
                    name,
                    values: attr.values.clone(),
                }),
            }
        }
        out
    }

    /// Convert local attributes to wire attributes under the given
    /// NameFormat (pysaml2 `from_local`).
    ///
    /// Local names with no map entry are passed through verbatim (with no
    /// NameFormat) when `allow_unknown_attributes` is set, dropped otherwise.
    pub fn from_local(&self, ava: &[LocalAttribute], name_format: &str) -> Vec<Attribute> {
        let Some(conv) = self.converter_for(name_format) else {
            return if self.allow_unknown_attributes {
                ava.iter()
                    .map(|la| Attribute {
                        name: la.name.clone(),
                        name_format: None,
                        friendly_name: None,
                        values: la.values.clone(),
                    })
                    .collect()
            } else {
                vec![]
            };
        };

        let mut out = Vec::new();
        for la in ava {
            match conv.to_wire_name(&la.name) {
                Some(wire) => out.push(Attribute {
                    name: wire.to_string(),
                    name_format: Some(name_format.to_string()),
                    friendly_name: Some(la.name.clone()),
                    values: la.values.clone(),
                }),
                None if self.allow_unknown_attributes => out.push(Attribute {
                    name: la.name.clone(),
                    name_format: None,
                    friendly_name: None,
                    values: la.values.clone(),
                }),
                None => {}
            }
        }
        out
    }
}

// ── eduPersonTargetedID (NameID-valued attribute) ──────────────────────────

/// The eduPersonTargetedID wire name.
pub const EPTID_OID: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10";

/// Build an eduPersonTargetedID attribute carrying `<saml:NameID>` values
/// (pysaml2 `to_eptid_value` equivalent).
///
/// Per the eduPerson specification the value is a persistent NameID with
/// NameQualifier = IdP entity ID and SPNameQualifier = SP entity ID; use
/// [`crate::idp::eptid::Eptid`] to generate the identifier value itself.
pub fn eptid_attribute(name_ids: Vec<NameId>) -> Attribute {
    Attribute {
        name: EPTID_OID.to_string(),
        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
        friendly_name: Some("eduPersonTargetedID".to_string()),
        values: name_ids.into_iter().map(AttributeValue::NameId).collect(),
    }
}

/// Extract the NameID values from an eduPersonTargetedID attribute.
pub fn eptid_name_ids(attribute: &Attribute) -> Vec<&NameId> {
    attribute
        .values
        .iter()
        .filter_map(|v| match v {
            AttributeValue::NameId(n) => Some(n),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_maps_loaded() {
        assert_eq!(SAML_URI.identifier, constants::ATTRNAME_FORMAT_URI);
        assert!(SAML_URI.fro.len() > 200);
        assert!(BASIC.fro.len() > 150);
        assert!(SHIBBOLETH_URI.fro.len() > 80);
        assert_eq!(ADFS_V1X.fro.len(), 4);
        assert_eq!(ADFS_V20.fro.len(), 18);
    }

    #[test]
    fn test_converter_bidirectional() {
        let conv = AttributeConverter::from_static(&SAML_URI);
        assert_eq!(
            conv.to_local_name("urn:oid:0.9.2342.19200300.100.1.3"),
            Some("mail")
        );
        assert_eq!(
            conv.to_wire_name("mail"),
            Some("urn:oid:0.9.2342.19200300.100.1.3")
        );
        // Case-insensitive lookups
        assert_eq!(
            conv.to_wire_name("MAIL"),
            Some("urn:oid:0.9.2342.19200300.100.1.3")
        );
        assert_eq!(
            conv.to_local_name("URN:OID:0.9.2342.19200300.100.1.3"),
            Some("mail")
        );
    }

    #[test]
    fn test_edu_person_and_eidas_entries_present() {
        let conv = AttributeConverter::from_static(&SAML_URI);
        assert_eq!(
            conv.to_local_name("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
            Some("eduPersonPrincipalName")
        );
        assert_eq!(
            conv.to_local_name("urn:oid:1.3.6.1.4.1.25178.1.2.9"),
            Some("schacHomeOrganization")
        );
        assert_eq!(
            conv.to_local_name("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier"),
            Some("PersonIdentifier")
        );
    }

    fn wire_mail() -> Attribute {
        Attribute {
            name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
            name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            friendly_name: None,
            values: vec![AttributeValue::String("a@example.com".to_string())],
        }
    }

    #[test]
    fn test_to_local_known() {
        let set = AttributeConverterSet::with_default_maps();
        let local = set.to_local(&[wire_mail()]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "mail");
        assert_eq!(local[0].values[0].as_str(), Some("a@example.com"));
    }

    #[test]
    fn test_to_local_unknown_dropped_by_default() {
        let set = AttributeConverterSet::with_default_maps();
        let attr = Attribute {
            name: "urn:example:custom".to_string(),
            name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            friendly_name: None,
            values: vec![AttributeValue::String("x".to_string())],
        };
        assert!(set.to_local(std::slice::from_ref(&attr)).is_empty());

        let permissive = AttributeConverterSet::with_default_maps().allow_unknown_attributes(true);
        let local = permissive.to_local(&[attr]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "urn:example:custom");
    }

    #[test]
    fn test_to_local_falls_back_to_friendly_name() {
        let set = AttributeConverterSet::with_default_maps();
        let attr = Attribute {
            name: "urn:example:custom".to_string(),
            name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            friendly_name: Some("customAttr".to_string()),
            values: vec![],
        };
        let local = set.to_local(&[attr]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "customAttr");
    }

    #[test]
    fn test_to_local_merges_same_local_name() {
        let set = AttributeConverterSet::with_default_maps();
        // mail via OID and via basic name both map to "mail"
        let basic_mail = Attribute {
            name: "urn:mace:dir:attribute-def:mail".to_string(),
            name_format: Some(maps::basic::IDENTIFIER.to_string()),
            friendly_name: None,
            values: vec![AttributeValue::String("b@example.com".to_string())],
        };
        let local = set.to_local(&[wire_mail(), basic_mail]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].values.len(), 2);
    }

    #[test]
    fn test_from_local_roundtrip() {
        let set = AttributeConverterSet::with_default_maps();
        let ava = vec![
            LocalAttribute::from_strings("mail", &["a@example.com"]),
            LocalAttribute::from_strings("eduPersonPrincipalName", &["a@example.org"]),
        ];
        let wire = set.from_local(&ava, constants::ATTRNAME_FORMAT_URI);
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0].name, "urn:oid:0.9.2342.19200300.100.1.3");
        assert_eq!(wire[0].friendly_name.as_deref(), Some("mail"));
        assert_eq!(
            wire[1].name_format.as_deref(),
            Some(constants::ATTRNAME_FORMAT_URI)
        );

        let back = set.to_local(&wire);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "mail");
    }

    #[test]
    fn test_from_local_unknown() {
        let set = AttributeConverterSet::with_default_maps();
        let ava = vec![LocalAttribute::from_strings("notMapped", &["v"])];
        assert!(set
            .from_local(&ava, constants::ATTRNAME_FORMAT_URI)
            .is_empty());

        let permissive = AttributeConverterSet::with_default_maps().allow_unknown_attributes(true);
        let wire = permissive.from_local(&ava, constants::ATTRNAME_FORMAT_URI);
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].name, "notMapped");
        assert!(wire[0].name_format.is_none());
    }

    #[test]
    fn test_eptid_attribute() {
        let nid = NameId {
            value: "abc123".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some("https://idp.example.com".to_string()),
            sp_name_qualifier: Some("https://sp.example.com".to_string()),
            sp_provided_id: None,
        };
        let attr = eptid_attribute(vec![nid.clone()]);
        assert_eq!(attr.name, EPTID_OID);
        assert_eq!(attr.friendly_name.as_deref(), Some("eduPersonTargetedID"));
        let extracted = eptid_name_ids(&attr);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].value, "abc123");
    }

    #[test]
    fn test_adfs_maps() {
        let conv = AttributeConverter::from_static(&ADFS_V20);
        assert_eq!(
            conv.to_local_name("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"),
            Some("role")
        );
    }
}
