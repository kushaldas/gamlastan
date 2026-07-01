// Metadata extension builders and readers (section 2).
//
// The Sweden Connect profile layers a number of metadata extensions on top of
// SAML 2.0 metadata:
//
// - `<mdattr:EntityAttributes>` carrying entity categories [EntCat] and an
//   assurance-certification attribute [SAML2IAP] (sections 2.1.2, 2.1.3, 2.1.4).
// - `<mdui:UIInfo>` display information (section 2.1.1.1).
// - `<shibmd:Scope>` authorised scopes for IdPs (section 2.1.3.1).
// - `<idpdisc:DiscoveryResponse>` for SPs using a central discovery service
//   (section 2.1.2).
//
// Builders return namespace-qualified element fragments; combine them with
// [`extensions`] to produce an `<md:Extensions>` container (an [`Extensions`]
// value) that can be attached to an `EntityDescriptor` or role descriptor.

use crate::metadata::types::extensions::Extensions;
use crate::xml::uppsala;
use crate::xml::XmlWriter;

use super::constants;

/// A logotype reference for `<mdui:Logo>` (section 2.1.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logo {
    /// The logo URL (may be a `data:` URI for in-line images).
    pub url: String,
    /// Logo height in pixels.
    pub height: u32,
    /// Logo width in pixels.
    pub width: u32,
    /// Optional `xml:lang`.
    pub lang: Option<String>,
}

/// `<mdui:UIInfo>` display information for an SP or IdP role descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UiInfo {
    /// `<mdui:DisplayName>` entries as `(lang, value)`. At least one with
    /// `lang = "sv"` is required by section 2.1.1.1.
    pub display_names: Vec<(String, String)>,
    /// `<mdui:Description>` entries as `(lang, value)`.
    pub descriptions: Vec<(String, String)>,
    /// `<mdui:Logo>` entries (at least one is required).
    pub logos: Vec<Logo>,
}

impl UiInfo {
    /// Serialize the `<mdui:UIInfo>` element (namespace-qualified).
    pub fn to_xml_string(&self) -> String {
        let mut w = XmlWriter::new();
        w.start_element("mdui:UIInfo", &[("xmlns:mdui", constants::NS_MDUI)]);
        for (lang, val) in &self.display_names {
            write_localized(&mut w, "mdui:DisplayName", lang, val);
        }
        for (lang, val) in &self.descriptions {
            write_localized(&mut w, "mdui:Description", lang, val);
        }
        for logo in &self.logos {
            let height = logo.height.to_string();
            let width = logo.width.to_string();
            let mut attrs: Vec<(&str, &str)> =
                vec![("height", height.as_str()), ("width", width.as_str())];
            if let Some(lang) = &logo.lang {
                attrs.push(("xml:lang", lang.as_str()));
            }
            w.start_element("mdui:Logo", &attrs);
            w.text(&logo.url);
            w.end_element("mdui:Logo");
        }
        w.end_element("mdui:UIInfo");
        w.into_string()
    }
}

fn write_localized(w: &mut XmlWriter, elem: &str, lang: &str, value: &str) {
    w.start_element(elem, &[("xml:lang", lang)]);
    w.text(value);
    w.end_element(elem);
}

/// Build an `<mdattr:EntityAttributes>` fragment declaring the given entity
/// categories and assurance-certification values.
///
/// Entity categories are emitted as values of a single
/// `http://macedir.org/entity-category` attribute; assurance certifications as
/// values of the `urn:oasis:names:tc:SAML:attribute:assurance-certification`
/// attribute (only emitted when non-empty — typically only on IdPs).
pub fn entity_attributes_xml(
    entity_categories: &[&str],
    assurance_certifications: &[&str],
) -> String {
    let mut w = XmlWriter::new();
    w.start_element(
        "mdattr:EntityAttributes",
        &[
            ("xmlns:mdattr", constants::NS_MDATTR),
            ("xmlns:saml2", constants::NS_SAML_ASSERTION),
        ],
    );
    if !entity_categories.is_empty() {
        write_uri_attribute(&mut w, constants::ENTITY_CATEGORY_ATTR, entity_categories);
    }
    if !assurance_certifications.is_empty() {
        write_uri_attribute(
            &mut w,
            constants::ASSURANCE_CERTIFICATION_ATTR,
            assurance_certifications,
        );
    }
    w.end_element("mdattr:EntityAttributes");
    w.into_string()
}

fn write_uri_attribute(w: &mut XmlWriter, name: &str, values: &[&str]) {
    w.start_element(
        "saml2:Attribute",
        &[
            ("Name", name),
            ("NameFormat", constants::ATTRNAME_FORMAT_URI),
        ],
    );
    for v in values {
        w.start_element("saml2:AttributeValue", &[]);
        w.text(v);
        w.end_element("saml2:AttributeValue");
    }
    w.end_element("saml2:Attribute");
}

/// Build a `<shibmd:Scope>` fragment (section 2.1.3.1).
pub fn scope_xml(value: &str, regexp: bool) -> String {
    let mut w = XmlWriter::new();
    w.start_element(
        "shibmd:Scope",
        &[
            ("xmlns:shibmd", constants::NS_SHIBMD),
            ("regexp", if regexp { "true" } else { "false" }),
        ],
    );
    w.text(value);
    w.end_element("shibmd:Scope");
    w.into_string()
}

/// Build an `<idpdisc:DiscoveryResponse>` fragment (section 2.1.2).
pub fn discovery_response_xml(index: u16, location: &str) -> String {
    let index = index.to_string();
    let mut w = XmlWriter::new();
    w.empty_element(
        "idpdisc:DiscoveryResponse",
        &[
            ("xmlns:idpdisc", constants::NS_IDPDISCO),
            (
                "Binding",
                "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol",
            ),
            ("index", index.as_str()),
            ("Location", location),
        ],
    );
    w.into_string()
}

/// Wrap one or more element fragments in an `<md:Extensions>` container.
pub fn extensions(fragments: &[String]) -> Extensions {
    let mut w = XmlWriter::new();
    w.start_element("md:Extensions", &[("xmlns:md", constants::NS_MD)]);
    for f in fragments {
        // Fragments are already-serialized, trusted XML element snippets.
        w.raw(f);
    }
    w.end_element("md:Extensions");
    Extensions::new(w.into_string())
}

// ── Readers ─────────────────────────────────────────────────────────────────

/// Extract all values of the named `<saml2:Attribute>` from an
/// `<mdattr:EntityAttributes>` carried in the given metadata extensions.
///
/// Returns an empty vector if the extensions do not contain the attribute (or
/// cannot be parsed).
pub fn entity_attribute_values(ext: &Extensions, attribute_name: &str) -> Vec<String> {
    let full_xml = format!(
        r#"<root xmlns:md="{}" xmlns:mdattr="{}" xmlns:saml2="{}" xmlns:saml="{}">{}</root>"#,
        constants::NS_MD,
        constants::NS_MDATTR,
        constants::NS_SAML_ASSERTION,
        constants::NS_SAML_ASSERTION,
        ext.raw_xml
    );

    let doc = match crate::xml::parse_secure(&full_xml) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let root = match doc.document_element() {
        Some(r) => r,
        None => return Vec::new(),
    };

    let mut values = Vec::new();
    collect_attribute_values(&doc, root, attribute_name, &mut values);
    values
}

fn collect_attribute_values<'a>(
    doc: &'a uppsala::Document<'a>,
    node: uppsala::NodeId,
    attribute_name: &str,
    out: &mut Vec<String>,
) {
    for child in doc.children_iter(node) {
        if let Some(elem) = doc.element(child) {
            let is_attribute = elem.name.local_name.as_ref() == "Attribute"
                && elem.name.namespace_uri.as_deref() == Some(constants::NS_SAML_ASSERTION);
            if is_attribute && doc.get_attribute(child, "Name") == Some(attribute_name) {
                for value_node in doc.children_iter(child) {
                    if let Some(value_elem) = doc.element(value_node) {
                        if value_elem.name.local_name.as_ref() == "AttributeValue" {
                            let text = doc
                                .text_content(value_node)
                                .map(|t| t.to_string())
                                .unwrap_or_else(|| doc.text_content_deep(value_node));
                            let trimmed = text.trim();
                            if !trimmed.is_empty() {
                                out.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
            // Recurse to reach the Attribute elements nested in EntityAttributes.
            collect_attribute_values(doc, child, attribute_name, out);
        }
    }
}

/// The entity categories declared in the given metadata extensions.
pub fn entity_categories(ext: &Extensions) -> Vec<String> {
    entity_attribute_values(ext, constants::ENTITY_CATEGORY_ATTR)
}

/// The assurance-certification (Level of Assurance) values declared by an IdP.
pub fn assurance_certifications(ext: &Extensions) -> Vec<String> {
    entity_attribute_values(ext, constants::ASSURANCE_CERTIFICATION_ATTR)
}

/// Whether the entity is a Signature Service (declares the `sigservice` service
/// type entity category, section 2.1.4).
pub fn is_signature_service(ext: &Extensions) -> bool {
    entity_categories(ext)
        .iter()
        .any(|c| c == constants::ST_SIGSERVICE)
}

/// Whether the IdP advertises SCAL2 / SAP support (section 2.1.3).
pub fn supports_scal2(ext: &Extensions) -> bool {
    entity_categories(ext)
        .iter()
        .any(|c| c == constants::SPROP_SCAL2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_attributes_roundtrip() {
        let xml = entity_attributes_xml(
            &[constants::EC_LOA3_PNR, constants::ST_SIGSERVICE],
            &[constants::LOA3],
        );
        let ext = extensions(&[xml]);

        let cats = entity_categories(&ext);
        assert!(cats.iter().any(|c| c == constants::EC_LOA3_PNR));
        assert!(cats.iter().any(|c| c == constants::ST_SIGSERVICE));
        assert!(is_signature_service(&ext));

        let loas = assurance_certifications(&ext);
        assert_eq!(loas, vec![constants::LOA3.to_string()]);
    }

    #[test]
    fn test_no_assurance_for_sp() {
        let xml = entity_attributes_xml(&[constants::EC_LOA3_PNR], &[]);
        assert!(!xml.contains("assurance-certification"));
        let ext = extensions(&[xml]);
        assert!(assurance_certifications(&ext).is_empty());
        assert!(!is_signature_service(&ext));
    }

    #[test]
    fn test_ui_info_xml() {
        let ui = UiInfo {
            display_names: vec![("sv".into(), "Min tjänst".into())],
            descriptions: vec![("sv".into(), "Beskrivning".into())],
            logos: vec![Logo {
                url: "https://sp.example.se/logo.svg".into(),
                height: 64,
                width: 64,
                lang: None,
            }],
        };
        let xml = ui.to_xml_string();
        assert!(xml.contains("mdui:UIInfo"));
        assert!(xml.contains("xml:lang=\"sv\""));
        assert!(xml.contains("Min tjänst"));
        assert!(xml.contains("mdui:Logo"));
        assert!(xml.contains("height=\"64\""));
    }

    #[test]
    fn test_scope_and_discovery() {
        assert!(scope_xml("2021006883", false).contains("regexp=\"false\""));
        assert!(scope_xml("2021006883", false).contains(">2021006883<"));
        let dr = discovery_response_xml(0, "https://sp.example.se/disco");
        assert!(dr.contains("idpdisc:DiscoveryResponse"));
        assert!(dr.contains("index=\"0\""));
        assert!(dr.contains("Location=\"https://sp.example.se/disco\""));
    }

    #[test]
    fn test_supports_scal2() {
        let ext = extensions(&[entity_attributes_xml(&[constants::SPROP_SCAL2], &[])]);
        assert!(supports_scal2(&ext));
    }
}
