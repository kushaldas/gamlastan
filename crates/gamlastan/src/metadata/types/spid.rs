// SPID SAML Extensions
//
// Typed representations of SPID-specific extension elements defined in
// the namespace `https://spid.gov.it/saml-extensions`.
//
// These extensions appear inside `<md:Extensions>` within
// `<ContactPerson contactType="other">` in SPID SP metadata.
//
// References:
// - SPID Regole Tecniche (Technical Rules)
// - https://docs.italia.it/italia/spid/spid-regole-tecniche-oidc/

use super::extensions::Extensions;
use crate::xml::XmlWriter;

/// SPID extensions namespace URI.
pub const SPID_EXTENSIONS_NS: &str = "https://spid.gov.it/saml-extensions";

/// XML namespace prefix used for SPID extensions.
const SPID_PREFIX: &str = "spid";

// ── SP Type ────────────────────────────────────────────────────────────────

/// SPID Service Provider type.
///
/// Determines the profile the SPID validator applies to the SP metadata.
/// These are mutually exclusive — exactly one must be present in the
/// `ContactPerson[@contactType='other']` extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpidSpType {
    /// Public administration SP (`<spid:Public/>`).
    Public,
    /// Private SP (`<spid:Private/>`).
    Private,
    /// Public services full aggregator (`<spid:PublicServicesFullAggregator/>`).
    PublicServicesFullAggregator,
    /// Public services light aggregator (`<spid:PublicServicesLightAggregator/>`).
    PublicServicesLightAggregator,
    /// Private services full aggregator (`<spid:PrivateServicesFullAggregator/>`).
    PrivateServicesFullAggregator,
    /// Private services light aggregator (`<spid:PrivateServicesLightAggregator/>`).
    PrivateServicesLightAggregator,
    /// Public services full operator (`<spid:PublicServicesFullOperator/>`).
    PublicServicesFullOperator,
    /// Public services light operator (`<spid:PublicServicesLightOperator/>`).
    PublicServicesLightOperator,
    /// Public operator (`<spid:PublicOperator/>`).
    PublicOperator,
}

impl SpidSpType {
    /// Return the XML local element name (without namespace prefix).
    pub fn element_name(&self) -> &'static str {
        match self {
            SpidSpType::Public => "Public",
            SpidSpType::Private => "Private",
            SpidSpType::PublicServicesFullAggregator => "PublicServicesFullAggregator",
            SpidSpType::PublicServicesLightAggregator => "PublicServicesLightAggregator",
            SpidSpType::PrivateServicesFullAggregator => "PrivateServicesFullAggregator",
            SpidSpType::PrivateServicesLightAggregator => "PrivateServicesLightAggregator",
            SpidSpType::PublicServicesFullOperator => "PublicServicesFullOperator",
            SpidSpType::PublicServicesLightOperator => "PublicServicesLightOperator",
            SpidSpType::PublicOperator => "PublicOperator",
        }
    }

    /// Parse from an XML local element name.
    pub fn from_element_name(name: &str) -> Option<Self> {
        match name {
            "Public" => Some(SpidSpType::Public),
            "Private" => Some(SpidSpType::Private),
            "PublicServicesFullAggregator" => Some(SpidSpType::PublicServicesFullAggregator),
            "PublicServicesLightAggregator" => Some(SpidSpType::PublicServicesLightAggregator),
            "PrivateServicesFullAggregator" => Some(SpidSpType::PrivateServicesFullAggregator),
            "PrivateServicesLightAggregator" => Some(SpidSpType::PrivateServicesLightAggregator),
            "PublicServicesFullOperator" => Some(SpidSpType::PublicServicesFullOperator),
            "PublicServicesLightOperator" => Some(SpidSpType::PublicServicesLightOperator),
            "PublicOperator" => Some(SpidSpType::PublicOperator),
            _ => None,
        }
    }
}

// ── SPID Contact Extensions ───────────────────────────────────────────────

/// SPID-specific extensions for `ContactPerson[@contactType='other']`.
///
/// These typed fields are serialized into (and can be parsed from) an
/// `<md:Extensions>` element containing SPID namespace-qualified children.
///
/// # Example
///
/// ```
/// use gamlastan::metadata::types::spid::{SpidContactExtensions, SpidSpType};
///
/// let ext = SpidContactExtensions {
///     sp_type: SpidSpType::Public,
///     vat_number: Some("VATIT-12345678901".into()),
///     fiscal_code: Some("XYZABC80A01H501T".into()),
///     ipa_code: None,
///     municipality: None,
///     province: None,
///     country: None,
/// };
///
/// let extensions = ext.to_extensions();
/// assert!(!extensions.raw_xml.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SpidContactExtensions {
    /// SP type marker (required, exactly one).
    pub sp_type: SpidSpType,
    /// VAT number (e.g., "VATIT-12345678901"). Required for private SPs.
    pub vat_number: Option<String>,
    /// Fiscal code (e.g., "XYZABC80A01H501T").
    pub fiscal_code: Option<String>,
    /// IPA code. Required for public administration SPs.
    pub ipa_code: Option<String>,
    /// Municipality name.
    pub municipality: Option<String>,
    /// Province code (2-letter).
    pub province: Option<String>,
    /// Country code (ISO 3166, e.g., "IT").
    pub country: Option<String>,
}

impl SpidContactExtensions {
    /// Create extensions for a public administration SP.
    pub fn public_sp(ipa_code: &str) -> Self {
        SpidContactExtensions {
            sp_type: SpidSpType::Public,
            vat_number: None,
            fiscal_code: None,
            ipa_code: Some(ipa_code.to_string()),
            municipality: None,
            province: None,
            country: None,
        }
    }

    /// Create extensions for a private SP.
    pub fn private_sp(vat_number: &str, fiscal_code: &str) -> Self {
        SpidContactExtensions {
            sp_type: SpidSpType::Private,
            vat_number: Some(vat_number.to_string()),
            fiscal_code: Some(fiscal_code.to_string()),
            ipa_code: None,
            municipality: None,
            province: None,
            country: None,
        }
    }

    /// Serialize into an `Extensions` value suitable for use in a
    /// `ContactPerson`.
    ///
    /// The resulting XML contains the `<md:Extensions>` wrapper with
    /// SPID namespace-qualified child elements.
    pub fn to_extensions(&self) -> Extensions {
        let mut w = XmlWriter::new();
        let ns_attr = &format!("xmlns:{SPID_PREFIX}");

        w.start_element("md:Extensions", &[]);

        // Identity elements first (order: VATNumber, FiscalCode, IPACode)
        if let Some(ref vat) = self.vat_number {
            w.start_element(
                &format!("{SPID_PREFIX}:VATNumber"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(vat);
            w.end_element(&format!("{SPID_PREFIX}:VATNumber"));
        }

        if let Some(ref fc) = self.fiscal_code {
            w.start_element(
                &format!("{SPID_PREFIX}:FiscalCode"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(fc);
            w.end_element(&format!("{SPID_PREFIX}:FiscalCode"));
        }

        if let Some(ref ipa) = self.ipa_code {
            w.start_element(
                &format!("{SPID_PREFIX}:IPACode"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(ipa);
            w.end_element(&format!("{SPID_PREFIX}:IPACode"));
        }

        // Location elements
        if let Some(ref mun) = self.municipality {
            w.start_element(
                &format!("{SPID_PREFIX}:Municipality"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(mun);
            w.end_element(&format!("{SPID_PREFIX}:Municipality"));
        }

        if let Some(ref prov) = self.province {
            w.start_element(
                &format!("{SPID_PREFIX}:Province"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(prov);
            w.end_element(&format!("{SPID_PREFIX}:Province"));
        }

        if let Some(ref country) = self.country {
            w.start_element(
                &format!("{SPID_PREFIX}:Country"),
                &[(ns_attr, SPID_EXTENSIONS_NS)],
            );
            w.text(country);
            w.end_element(&format!("{SPID_PREFIX}:Country"));
        }

        // SP type marker (empty element, last)
        let type_name = format!("{SPID_PREFIX}:{}", self.sp_type.element_name());
        w.empty_element(&type_name, &[(ns_attr, SPID_EXTENSIONS_NS)]);

        w.end_element("md:Extensions");

        Extensions::new(w.into_string())
    }

    /// Try to parse SPID contact extensions from an `Extensions` value.
    ///
    /// Returns `None` if the extensions don't contain recognizable SPID
    /// elements, or `Err` if parsing fails (e.g., no SP type marker found).
    pub fn from_extensions(ext: &Extensions) -> Result<Option<Self>, SpidExtensionError> {
        Self::parse_raw_xml(&ext.raw_xml)
    }

    /// Parse from raw XML string (the `Extensions` content).
    fn parse_raw_xml(raw_xml: &str) -> Result<Option<Self>, SpidExtensionError> {
        // Quick check: does this look like it contains SPID extension elements?
        if !raw_xml.contains(SPID_EXTENSIONS_NS)
            && !raw_xml.contains("spid:")
            && !raw_xml.contains("VATNumber")
            && !raw_xml.contains("FiscalCode")
            && !raw_xml.contains("IPACode")
            && !raw_xml.contains("Public")
            && !raw_xml.contains("Private")
        {
            return Ok(None);
        }

        // Parse the XML fragment to extract elements
        // Wrap in a root element if needed for parsing
        let xml_to_parse = if raw_xml.contains("<md:Extensions") || raw_xml.contains("<Extensions")
        {
            raw_xml.to_string()
        } else {
            format!("<md:Extensions xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{raw_xml}</md:Extensions>")
        };

        // Wrap in a document root for full namespace resolution
        let full_xml = format!(
            r#"<root xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="{SPID_EXTENSIONS_NS}">{xml_to_parse}</root>"#
        );

        let doc = crate::xml::uppsala::parse(&full_xml)
            .map_err(|e| SpidExtensionError::ParseError(e.to_string()))?;

        let mut sp_type: Option<SpidSpType> = None;
        let mut vat_number: Option<String> = None;
        let mut fiscal_code: Option<String> = None;
        let mut ipa_code: Option<String> = None;
        let mut municipality: Option<String> = None;
        let mut province: Option<String> = None;
        let mut country: Option<String> = None;
        let mut found_any = false;

        // Walk all elements looking for SPID namespace children
        let root = doc
            .document_element()
            .ok_or_else(|| SpidExtensionError::ParseError("Empty document".to_string()))?;

        visit_elements(&doc, root, &mut |local_name, ns, text| {
            let is_spid = ns == Some(SPID_EXTENSIONS_NS);
            if !is_spid {
                return;
            }
            found_any = true;
            match local_name {
                "VATNumber" => vat_number = text,
                "FiscalCode" => fiscal_code = text,
                "IPACode" => ipa_code = text,
                "Municipality" => municipality = text,
                "Province" => province = text,
                "Country" => country = text,
                other => {
                    if let Some(t) = SpidSpType::from_element_name(other) {
                        sp_type = Some(t);
                    }
                }
            }
        });

        if !found_any {
            return Ok(None);
        }

        let sp_type = sp_type.ok_or(SpidExtensionError::MissingSpType)?;

        Ok(Some(SpidContactExtensions {
            sp_type,
            vat_number,
            fiscal_code,
            ipa_code,
            municipality,
            province,
            country,
        }))
    }
}

/// Walk all descendant elements, calling `f` with (local_name, namespace_uri, text_content).
fn visit_elements<'a>(
    doc: &'a crate::xml::Document<'a>,
    node: crate::xml::NodeId,
    f: &mut impl FnMut(&str, Option<&str>, Option<String>),
) {
    for child in doc.children_iter(node) {
        if let Some(elem) = doc.element(child) {
            let local: &str = &elem.name.local_name;
            let ns: Option<&str> = elem.name.namespace_uri.as_deref();
            // Try zero-copy text_content first, fall back to deep concatenation
            let text = match doc.text_content(child) {
                Some(t) => Some(t.to_string()),
                None => {
                    let deep = doc.text_content_deep(child);
                    if deep.is_empty() {
                        None
                    } else {
                        Some(deep)
                    }
                }
            };
            f(local, ns, text);
            visit_elements(doc, child, f);
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Error type for SPID extension parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum SpidExtensionError {
    /// Failed to parse the XML content.
    ParseError(String),
    /// No SP type marker element found (Public, Private, etc.).
    MissingSpType,
}

impl std::fmt::Display for SpidExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpidExtensionError::ParseError(msg) => {
                write!(f, "SPID extension parse error: {msg}")
            }
            SpidExtensionError::MissingSpType => {
                write!(
                    f,
                    "SPID extension missing SP type marker (Public/Private/...)"
                )
            }
        }
    }
}

impl std::error::Error for SpidExtensionError {}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp_type_element_name_roundtrip() {
        let types = [
            SpidSpType::Public,
            SpidSpType::Private,
            SpidSpType::PublicServicesFullAggregator,
            SpidSpType::PublicServicesLightAggregator,
            SpidSpType::PrivateServicesFullAggregator,
            SpidSpType::PrivateServicesLightAggregator,
            SpidSpType::PublicServicesFullOperator,
            SpidSpType::PublicServicesLightOperator,
            SpidSpType::PublicOperator,
        ];
        for t in types {
            let name = t.element_name();
            let parsed = SpidSpType::from_element_name(name).unwrap();
            assert_eq!(t, parsed, "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_sp_type_from_unknown() {
        assert_eq!(SpidSpType::from_element_name("Unknown"), None);
        assert_eq!(SpidSpType::from_element_name(""), None);
    }

    #[test]
    fn test_public_sp_constructor() {
        let ext = SpidContactExtensions::public_sp("ABC123");
        assert_eq!(ext.sp_type, SpidSpType::Public);
        assert_eq!(ext.ipa_code.as_deref(), Some("ABC123"));
        assert!(ext.vat_number.is_none());
        assert!(ext.fiscal_code.is_none());
    }

    #[test]
    fn test_private_sp_constructor() {
        let ext = SpidContactExtensions::private_sp("VATIT-12345", "ABCDEF80A01H501T");
        assert_eq!(ext.sp_type, SpidSpType::Private);
        assert_eq!(ext.vat_number.as_deref(), Some("VATIT-12345"));
        assert_eq!(ext.fiscal_code.as_deref(), Some("ABCDEF80A01H501T"));
        assert!(ext.ipa_code.is_none());
    }

    #[test]
    fn test_to_extensions_public() {
        let ext = SpidContactExtensions {
            sp_type: SpidSpType::Public,
            vat_number: Some("VATIT-12345678901".into()),
            fiscal_code: Some("XYZABC80A01H501T".into()),
            ipa_code: None,
            municipality: None,
            province: None,
            country: None,
        };

        let extensions = ext.to_extensions();
        let xml = &extensions.raw_xml;

        assert!(xml.contains("<md:Extensions>"));
        assert!(xml.contains("</md:Extensions>"));
        assert!(xml.contains("spid:VATNumber"));
        assert!(xml.contains("VATIT-12345678901"));
        assert!(xml.contains("spid:FiscalCode"));
        assert!(xml.contains("XYZABC80A01H501T"));
        assert!(xml.contains("spid:Public"));
        assert!(xml.contains(SPID_EXTENSIONS_NS));
        // Public marker should be an empty element
        assert!(!xml.contains("spid:Private"));
    }

    #[test]
    fn test_to_extensions_private() {
        let ext = SpidContactExtensions::private_sp("VATIT-99999999999", "RSSMRA80A01H501Z");
        let extensions = ext.to_extensions();
        let xml = &extensions.raw_xml;

        assert!(xml.contains("spid:Private"));
        assert!(!xml.contains("spid:Public"));
        assert!(xml.contains("VATIT-99999999999"));
        assert!(xml.contains("RSSMRA80A01H501Z"));
    }

    #[test]
    fn test_to_extensions_with_location() {
        let ext = SpidContactExtensions {
            sp_type: SpidSpType::Public,
            vat_number: None,
            fiscal_code: None,
            ipa_code: Some("IPA001".into()),
            municipality: Some("Roma".into()),
            province: Some("RM".into()),
            country: Some("IT".into()),
        };

        let extensions = ext.to_extensions();
        let xml = &extensions.raw_xml;

        assert!(xml.contains("spid:IPACode"));
        assert!(xml.contains("IPA001"));
        assert!(xml.contains("spid:Municipality"));
        assert!(xml.contains("Roma"));
        assert!(xml.contains("spid:Province"));
        assert!(xml.contains("RM"));
        assert!(xml.contains("spid:Country"));
        assert!(xml.contains("IT"));
    }

    #[test]
    fn test_roundtrip_public_sp() {
        let original = SpidContactExtensions {
            sp_type: SpidSpType::Public,
            vat_number: Some("VATIT-12345678901".into()),
            fiscal_code: Some("XYZABC80A01H501T".into()),
            ipa_code: None,
            municipality: None,
            province: None,
            country: None,
        };

        let extensions = original.to_extensions();
        let parsed = SpidContactExtensions::from_extensions(&extensions)
            .expect("parse should succeed")
            .expect("should contain SPID extensions");

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_roundtrip_private_sp() {
        let original = SpidContactExtensions::private_sp("VATIT-99999999999", "RSSMRA80A01H501Z");

        let extensions = original.to_extensions();
        let parsed = SpidContactExtensions::from_extensions(&extensions)
            .expect("parse should succeed")
            .expect("should contain SPID extensions");

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_roundtrip_all_fields() {
        let original = SpidContactExtensions {
            sp_type: SpidSpType::PublicServicesFullAggregator,
            vat_number: Some("VATIT-11111111111".into()),
            fiscal_code: Some("ABCDEF01A01H501Z".into()),
            ipa_code: Some("IPA999".into()),
            municipality: Some("Milano".into()),
            province: Some("MI".into()),
            country: Some("IT".into()),
        };

        let extensions = original.to_extensions();
        let parsed = SpidContactExtensions::from_extensions(&extensions)
            .expect("parse should succeed")
            .expect("should contain SPID extensions");

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_non_spid_extensions() {
        let ext = Extensions::new("<SomeOtherExtension>value</SomeOtherExtension>");
        let result = SpidContactExtensions::from_extensions(&ext).unwrap();
        assert!(result.is_none(), "non-SPID extensions should return None");
    }

    #[test]
    fn test_from_spid_without_sp_type() {
        let ext = Extensions::new(format!(
            r#"<md:Extensions><spid:VATNumber xmlns:spid="{SPID_EXTENSIONS_NS}">VAT123</spid:VATNumber></md:Extensions>"#
        ));
        let result = SpidContactExtensions::from_extensions(&ext);
        assert!(
            matches!(result, Err(SpidExtensionError::MissingSpType)),
            "should fail without SP type marker"
        );
    }

    #[test]
    fn test_error_display() {
        let e = SpidExtensionError::MissingSpType;
        let s = e.to_string();
        assert!(s.contains("missing SP type"));

        let e = SpidExtensionError::ParseError("bad xml".into());
        let s = e.to_string();
        assert!(s.contains("bad xml"));
    }
}
