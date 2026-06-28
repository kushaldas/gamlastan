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
/// SAML V2.0 Metadata Extensions for Login and Discovery UI (MDUI) namespace.
pub const MDUI_NS: &str = "urn:oasis:names:tc:SAML:metadata:ui";
/// SAML V2.0 Metadata Extensions for Algorithm Support namespace.
pub const ALGSUPPORT_NS: &str = "urn:oasis:names:tc:SAML:metadata:algsupport";
/// XML namespace, for the `xml:lang` attribute.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A localized string (`xml:lang` plus value) from an MDUI element.
///
/// `value` is **attacker-controlled** (see [`UiInfo`]); output-encode it before
/// rendering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalizedText {
    /// The `xml:lang` tag, if present.
    pub lang: Option<String>,
    /// The element text. Attacker-controlled; output-encode before display.
    pub value: String,
}

/// An `mdui:Logo` (a URL with optional dimensions and language).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiLogo {
    /// The `xml:lang` tag, if present.
    pub lang: Option<String>,
    /// Logo width in pixels, if a valid integer was given.
    pub width: Option<u32>,
    /// Logo height in pixels, if a valid integer was given.
    pub height: Option<u32>,
    /// The logo URL (or `data:` URI). **Attacker-controlled and unvalidated**
    /// (see [`UiInfo`]): the scheme is not restricted, so before using it as an
    /// `<img src>`/link target a consumer MUST reject anything outside an
    /// expected allowlist (typically `https:`, plus `data:` only if images are
    /// intentionally inlined).
    pub url: String,
}

/// Parsed `mdui:UIInfo` (SP/IdP display metadata for consent and discovery UIs).
///
/// # Security
///
/// Every field here is copied **verbatim from attacker-controllable metadata**
/// (federation aggregates / MDQ) and is parsed for display, not validated for
/// safety. Treat all strings and URLs as untrusted:
///
/// - HTML-rendering consumers (e.g. an IdP consent screen) MUST output-encode
///   `display_names` / `descriptions` / `keywords` values, or they risk stored
///   XSS.
/// - URL-bearing fields (`information_urls`, `privacy_statement_urls`, and
///   [`UiLogo::url`]) are NOT scheme-checked; a value may be `javascript:` or a
///   hostile `data:` URI. Restrict to an expected scheme allowlist (e.g.
///   `https:`) before emitting them as `href`/`src`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiInfo {
    /// `mdui:DisplayName` entries. Attacker-controlled; output-encode.
    pub display_names: Vec<LocalizedText>,
    /// `mdui:Description` entries. Attacker-controlled; output-encode.
    pub descriptions: Vec<LocalizedText>,
    /// `mdui:InformationURL` entries. Attacker-controlled and not scheme-checked;
    /// validate the scheme before use as a link.
    pub information_urls: Vec<LocalizedText>,
    /// `mdui:PrivacyStatementURL` entries. Attacker-controlled and not
    /// scheme-checked; validate the scheme before use as a link.
    pub privacy_statement_urls: Vec<LocalizedText>,
    /// `mdui:Keywords` entries (each value is the raw space-separated string).
    /// Attacker-controlled; output-encode.
    pub keywords: Vec<LocalizedText>,
    /// `mdui:Logo` entries. See [`UiLogo::url`] for the URL trust caveat.
    pub logos: Vec<UiLogo>,
}

impl UiInfo {
    /// Whether this UIInfo carries no entries at all.
    pub fn is_empty(&self) -> bool {
        self.display_names.is_empty()
            && self.descriptions.is_empty()
            && self.information_urls.is_empty()
            && self.privacy_statement_urls.is_empty()
            && self.keywords.is_empty()
            && self.logos.is_empty()
    }
}

/// Parsed view of the attribute-release-relevant metadata extensions of one
/// entity. Cheap to ignore (empty when the entity has no such extensions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdExtensions {
    /// `mdrpi:RegistrationInfo/@registrationAuthority`, if present.
    pub registration_authority: Option<String>,
    /// `mdattr:EntityAttributes` as `(Name, values)` pairs, in document order.
    pub entity_attributes: Vec<(String, Vec<String>)>,
    /// The first `mdui:UIInfo` found, if any.
    pub ui_info: Option<UiInfo>,
    /// `alg:SigningMethod/@Algorithm` URIs, in document order.
    pub signing_methods: Vec<String>,
    /// `alg:DigestMethod/@Algorithm` URIs, in document order.
    pub digest_methods: Vec<String>,
}

impl MdExtensions {
    /// Parse the relevant extensions out of an [`Extensions`] container.
    pub fn from_extensions(ext: &Extensions) -> Self {
        Self::parse(&ext.raw_xml)
    }

    /// Parse from raw `Extensions` XML (either the full `<md:Extensions>` element or just
    /// its child elements). Returns an empty value on any parse error or when nothing relevant
    /// is present (fail-soft: missing or malformed metadata extensions simply yield "no
    /// signal", never an error).
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
        // Declare every prefix these accessors care about on the synthetic root,
        // so a fragment that used a prefix declared on an ancestor we did not
        // capture (the common case for role-level Extensions, where xmlns:mdui /
        // xmlns:alg sit on the EntityDescriptor) still resolves.
        let full = format!(
            r#"<gamlastan-md-root xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="{MDRPI_NS}" xmlns:mdattr="{MDATTR_NS}" xmlns:saml="{SAML_ASSERTION_NS}" xmlns:mdui="{MDUI_NS}" xmlns:alg="{ALGSUPPORT_NS}">{inner}</gamlastan-md-root>"#
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

    /// All advertised algorithm URIs: every `alg:SigningMethod` first, then
    /// every `alg:DigestMethod`. Each group preserves its own document order,
    /// but the two groups are concatenated rather than merged, so a
    /// `alg:DigestMethod` that appears before a `alg:SigningMethod` in the XML
    /// still sorts after it. Callers must not treat the combined order as the
    /// original document order.
    pub fn supported_algorithms(&self) -> Vec<String> {
        let mut out = self.signing_methods.clone();
        out.extend(self.digest_methods.iter().cloned());
        out
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
        } else if ns == Some(MDUI_NS) && local == "UIInfo" {
            // Keep the first UIInfo; its children are parsed here, so don't
            // recurse into them.
            if out.ui_info.is_none() {
                out.ui_info = Some(parse_ui_info(doc, child));
            }
            continue;
        } else if ns == Some(ALGSUPPORT_NS) && local == "SigningMethod" {
            if let Some(alg) = elem.get_attribute("Algorithm") {
                out.signing_methods.push(alg.to_string());
            }
        } else if ns == Some(ALGSUPPORT_NS) && local == "DigestMethod" {
            if let Some(alg) = elem.get_attribute("Algorithm") {
                out.digest_methods.push(alg.to_string());
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
            && elem.name.local_name == "AttributeValue"
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

/// The trimmed text content of an element (direct text, falling back to a deep
/// gather), or the empty string.
fn element_text(doc: &crate::xml::Document<'_>, node: crate::xml::NodeId) -> String {
    match doc.text_content(node) {
        Some(t) => t.trim().to_string(),
        None => doc.text_content_deep(node).trim().to_string(),
    }
}

/// The `xml:lang` of an element, if present.
fn element_lang(elem: &crate::xml::uppsala::Element<'_>) -> Option<String> {
    elem.get_attribute_ns(XML_NS, "lang")
        .or_else(|| elem.get_attribute("xml:lang"))
        .map(str::to_string)
}

/// Parse the children of an `mdui:UIInfo` element.
fn parse_ui_info(doc: &crate::xml::Document<'_>, node: crate::xml::NodeId) -> UiInfo {
    let mut info = UiInfo::default();
    for child in doc.children_iter(node) {
        let Some(elem) = doc.element(child) else {
            continue;
        };
        if elem.name.namespace_uri.as_deref() != Some(MDUI_NS) {
            continue;
        }
        let lang = element_lang(elem);
        match elem.name.local_name.as_ref() {
            "DisplayName" => info.display_names.push(LocalizedText {
                lang,
                value: element_text(doc, child),
            }),
            "Description" => info.descriptions.push(LocalizedText {
                lang,
                value: element_text(doc, child),
            }),
            "InformationURL" => info.information_urls.push(LocalizedText {
                lang,
                value: element_text(doc, child),
            }),
            "PrivacyStatementURL" => info.privacy_statement_urls.push(LocalizedText {
                lang,
                value: element_text(doc, child),
            }),
            "Keywords" => info.keywords.push(LocalizedText {
                lang,
                value: element_text(doc, child),
            }),
            "Logo" => info.logos.push(UiLogo {
                lang,
                width: elem.get_attribute("width").and_then(|s| s.parse().ok()),
                height: elem.get_attribute("height").and_then(|s| s.parse().ok()),
                url: element_text(doc, child),
            }),
            _ => {}
        }
    }
    info
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
    fn test_ui_info_parsing() {
        let ext = MdExtensions::parse(
            r#"
            <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
              <mdui:DisplayName xml:lang="en">Example Service</mdui:DisplayName>
              <mdui:DisplayName xml:lang="sv">Exempeltjänst</mdui:DisplayName>
              <mdui:Description xml:lang="en">An example.</mdui:Description>
              <mdui:InformationURL xml:lang="en">https://example.org/about</mdui:InformationURL>
              <mdui:PrivacyStatementURL xml:lang="en">https://example.org/privacy</mdui:PrivacyStatementURL>
              <mdui:Keywords xml:lang="en">login example</mdui:Keywords>
              <mdui:Logo width="80" height="60" xml:lang="en">https://example.org/logo.png</mdui:Logo>
            </mdui:UIInfo>
            "#,
        );
        let ui = ext.ui_info.expect("UIInfo present");
        assert_eq!(ui.display_names.len(), 2);
        assert_eq!(ui.display_names[0].lang.as_deref(), Some("en"));
        assert_eq!(ui.display_names[0].value, "Example Service");
        assert_eq!(ui.display_names[1].value, "Exempeltjänst");
        assert_eq!(ui.descriptions[0].value, "An example.");
        assert_eq!(ui.information_urls[0].value, "https://example.org/about");
        assert_eq!(
            ui.privacy_statement_urls[0].value,
            "https://example.org/privacy"
        );
        assert_eq!(ui.keywords[0].value, "login example");
        assert_eq!(ui.logos.len(), 1);
        assert_eq!(ui.logos[0].url, "https://example.org/logo.png");
        assert_eq!(ui.logos[0].width, Some(80));
        assert_eq!(ui.logos[0].height, Some(60));
        assert_eq!(ui.logos[0].lang.as_deref(), Some("en"));
    }

    #[test]
    fn test_algorithm_support_parsing() {
        let ext = MdExtensions::parse(
            r#"
            <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"/>
            <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            "#,
        );
        assert_eq!(
            ext.signing_methods,
            vec![
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512".to_string(),
            ]
        );
        assert_eq!(
            ext.digest_methods,
            vec!["http://www.w3.org/2001/04/xmlenc#sha256".to_string()]
        );
        // supported_algorithms lists signing methods first, then digests.
        let all = ext.supported_algorithms();
        assert_eq!(all.len(), 3);
        assert!(all[0].contains("rsa-sha256"));
        assert!(all[2].contains("xmlenc#sha256"));
    }

    #[test]
    fn test_ui_info_with_ancestor_declared_namespace() {
        // Role-level Extensions are captured as a raw fragment that uses the
        // mdui/alg prefixes declared on an ancestor (the EntityDescriptor) we did
        // not capture. The synthetic root must still resolve them.
        let ext = MdExtensions::parse(
            r#"
            <mdui:UIInfo>
              <mdui:DisplayName xml:lang="en">Example SP</mdui:DisplayName>
            </mdui:UIInfo>
            <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            "#,
        );
        let ui = ext.ui_info.expect("UIInfo resolves without a local xmlns");
        assert_eq!(ui.display_names[0].value, "Example SP");
        assert_eq!(
            ext.signing_methods,
            vec!["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string()]
        );
    }

    #[test]
    fn test_ui_info_absent_yields_none() {
        assert!(MdExtensions::parse(SWAMID_SP_EXT).ui_info.is_none());
        assert!(MdExtensions::default().ui_info.is_none());
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
