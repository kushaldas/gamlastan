// Structured accessors over the raw XML gamlastan stores in metadata
// `Extensions`. Two extensions drive attribute-release decisions:
//
// - `mdrpi:RegistrationInfo` (SAML V2.0 Metadata RPI) carries the SP's
//   `registrationAuthority`, used to select a release policy by federation
//   operator (pysaml2 `Policy.get` precedence: SP > registration authority >
//   default).
// - `mdattr:EntityAttributes` (SAML V2.0 Metadata Extensions for Entity
//   Attributes) carries entity-category URIs (`http://macedir.org/entity-
//   category`) and the `subject-id:req` requirement, both consumed by the
//   entity-category / subject-id release logic in `idp::entity_category`.
//
// gamlastan keeps `Extensions` as opaque raw XML, so these are parsed on demand
// (mirroring `spid.rs`): wrap the fragment in a namespaced root and parse it
// through `parse_secure`, which rejects DTDs and bounds resource use.

use super::extensions::Extensions;

/// SAML V2.0 Metadata RPI namespace.
pub const MDRPI_NS: &str = "urn:oasis:names:tc:SAML:metadata:rpi";
/// SAML V2.0 Metadata Extensions for Entity Attributes namespace.
pub const MDATTR_NS: &str = "urn:oasis:names:tc:SAML:metadata:attribute";
/// SAML 2.0 assertion namespace (for `saml:Attribute` / `saml:AttributeValue`).
pub const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// The entity-attribute `Name` that carries entity-category URIs.
pub const ENTITY_CATEGORY_ATTR: &str = "http://macedir.org/entity-category";

/// Parsed view of the attribute-release-relevant metadata extensions of one
/// entity. Cheap to ignore (empty when the entity has no such extensions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdExtensions {
    /// `mdrpi:RegistrationInfo/@registrationAuthority`, if present.
    pub registration_authority: Option<String>,
    /// `mdattr:EntityAttributes` as `(Name, values)` pairs, in document order.
    pub entity_attributes: Vec<(String, Vec<String>)>,
}

impl MdExtensions {
    /// Parse the relevant extensions out of an [`Extensions`] container.
    pub fn from_extensions(ext: &Extensions) -> Self {
        Self::parse(&ext.raw_xml)
    }

    /// Parse from the raw `Extensions` child XML. Returns an empty value on any
    /// parse error or when nothing relevant is present (fail-soft: missing or
    /// malformed metadata extensions simply yield "no signal", never an error).
    pub fn parse(raw_xml: &str) -> Self {
        let mut out = MdExtensions::default();
        let trimmed = raw_xml.trim();
        if trimmed.is_empty() {
            return out;
        }

        // Wrap the fragment so its namespace prefixes resolve, mirroring
        // `spid.rs`. The declarations on our synthetic root are only used if the
        // fragment itself does not redeclare them.
        let inner = if trimmed.contains("<md:Extensions") || trimmed.contains("<Extensions") {
            trimmed.to_string()
        } else {
            format!(
                "<md:Extensions xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{trimmed}</md:Extensions>"
            )
        };
        let full = format!(
            r#"<gamlastan-md-root xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="{MDRPI_NS}" xmlns:mdattr="{MDATTR_NS}" xmlns:saml="{SAML_ASSERTION_NS}">{inner}</gamlastan-md-root>"#
        );

        let Ok(doc) = crate::xml::parse_secure(&full) else {
            return out;
        };
        let Some(root) = doc.document_element() else {
            return out;
        };
        walk(&doc, root, false, &mut out);
        out
    }

    /// All values of the entity attribute named `name` (across every matching
    /// `saml:Attribute`).
    pub fn entity_attribute_values(&self, name: &str) -> Vec<String> {
        self.entity_attributes
            .iter()
            .filter(|(n, _)| n == name)
            .flat_map(|(_, values)| values.iter().cloned())
            .collect()
    }

    /// The SP's published entity-category URIs
    /// (`http://macedir.org/entity-category`).
    pub fn entity_categories(&self) -> Vec<String> {
        self.entity_attribute_values(ENTITY_CATEGORY_ATTR)
    }
}

/// Recursively collect the registration authority and entity attributes.
///
/// `in_entity_attributes` tracks whether the current node is a descendant of an
/// `mdattr:EntityAttributes` element. Only `saml:Attribute` elements inside one
/// are treated as entity attributes; a `saml:Attribute` that appears in some
/// other extension fragment is ignored.
fn walk(
    doc: &crate::xml::Document<'_>,
    node: crate::xml::NodeId,
    in_entity_attributes: bool,
    out: &mut MdExtensions,
) {
    for child in doc.children_iter(node) {
        let Some(elem) = doc.element(child) else {
            continue;
        };
        let ns = elem.name.namespace_uri.as_deref();
        let local: &str = &elem.name.local_name;

        let mut child_in_entity_attributes = in_entity_attributes;
        if ns == Some(MDRPI_NS) && local == "RegistrationInfo" {
            if out.registration_authority.is_none() {
                if let Some(ra) = elem.get_attribute("registrationAuthority") {
                    out.registration_authority = Some(ra.to_string());
                }
            }
        } else if ns == Some(MDATTR_NS) && local == "EntityAttributes" {
            child_in_entity_attributes = true;
        } else if in_entity_attributes && ns == Some(SAML_ASSERTION_NS) && local == "Attribute" {
            if let Some(name) = elem.get_attribute("Name") {
                let values = attribute_values(doc, child);
                out.entity_attributes.push((name.to_string(), values));
            }
        }

        walk(doc, child, child_in_entity_attributes, out);
    }
}

/// Collect the text of the `saml:AttributeValue` children of an
/// `saml:Attribute` element.
fn attribute_values(doc: &crate::xml::Document<'_>, attr_node: crate::xml::NodeId) -> Vec<String> {
    let mut values = Vec::new();
    for child in doc.children_iter(attr_node) {
        let Some(elem) = doc.element(child) else {
            continue;
        };
        if elem.name.namespace_uri.as_deref() == Some(SAML_ASSERTION_NS)
            && *elem.name.local_name == *"AttributeValue"
        {
            let text = match doc.text_content(child) {
                Some(t) => t.trim().to_string(),
                None => doc.text_content_deep(child).trim().to_string(),
            };
            if !text.is_empty() {
                values.push(text);
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWAMID_SP_EXT: &str = r#"
        <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
            registrationAuthority="http://www.swamid.se/" registrationInstant="2020-01-01T00:00:00Z">
          <mdrpi:RegistrationPolicy xml:lang="en">https://www.swamid.se/</mdrpi:RegistrationPolicy>
        </mdrpi:RegistrationInfo>
        <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
          <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
              Name="http://macedir.org/entity-category">
            <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
            <saml:AttributeValue>https://refeds.org/category/code-of-conduct/v2</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req">
            <saml:AttributeValue>any</saml:AttributeValue>
          </saml:Attribute>
        </mdattr:EntityAttributes>
    "#;

    #[test]
    fn test_registration_authority() {
        let ext = MdExtensions::parse(SWAMID_SP_EXT);
        assert_eq!(
            ext.registration_authority.as_deref(),
            Some("http://www.swamid.se/")
        );
    }

    #[test]
    fn test_entity_categories_and_subject_id_req() {
        let ext = MdExtensions::parse(SWAMID_SP_EXT);
        let cats = ext.entity_categories();
        assert!(cats.contains(&"http://refeds.org/category/research-and-scholarship".to_string()));
        assert!(cats.contains(&"https://refeds.org/category/code-of-conduct/v2".to_string()));
        assert_eq!(
            ext.entity_attribute_values("urn:oasis:names:tc:SAML:profiles:subject-id:req"),
            vec!["any".to_string()]
        );
    }

    #[test]
    fn test_empty_and_irrelevant_extensions() {
        assert_eq!(MdExtensions::parse(""), MdExtensions::default());
        assert_eq!(MdExtensions::parse("   "), MdExtensions::default());
        // An unrelated extension yields no signal, not an error.
        let ext = MdExtensions::parse(
            r#"<alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>"#,
        );
        assert!(ext.registration_authority.is_none());
        assert!(ext.entity_categories().is_empty());
    }

    #[test]
    fn test_stray_saml_attribute_outside_entity_attributes_is_ignored() {
        // A saml:Attribute that is NOT inside mdattr:EntityAttributes (here in
        // an unrelated requested-attributes fragment) must not be picked up as
        // an entity attribute.
        let ext = MdExtensions::parse(
            r#"
            <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute Name="http://macedir.org/entity-category">
                <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>
            <somens:Other xmlns:somens="urn:example:other"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute Name="urn:example:should-be-ignored">
                <saml:AttributeValue>nope</saml:AttributeValue>
              </saml:Attribute>
            </somens:Other>
            "#,
        );
        assert_eq!(ext.entity_attributes.len(), 1);
        assert_eq!(
            ext.entity_attributes[0].0,
            "http://macedir.org/entity-category"
        );
        assert!(ext
            .entity_attribute_values("urn:example:should-be-ignored")
            .is_empty());
    }

    #[test]
    fn test_malformed_extension_is_fail_soft() {
        // Not well-formed: returns the empty default rather than panicking.
        assert_eq!(
            MdExtensions::parse("<mdrpi:RegistrationInfo registrationAuthority=unquoted>"),
            MdExtensions::default()
        );
    }
}
