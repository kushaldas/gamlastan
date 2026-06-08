// PrincipalSelection / RequestedPrincipalSelection extensions [SC.Principal],
// sections 5.3.3 and 2.1.3.

use crate::metadata::types::extensions::Extensions;

use super::constants;
use super::xmlutil::{escape_attr, escape_text};

/// A single `<psc:MatchValue>` carrying a known attribute value for the
/// principal that is about to be authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchValue {
    /// The attribute `Name` (e.g. the personal identity number OID).
    pub name: String,
    /// The attribute `NameFormat` (defaults to the URI format when omitted).
    pub name_format: Option<String>,
    /// The known attribute value.
    pub value: String,
}

impl MatchValue {
    /// Convenience constructor for a URI-format match value.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        MatchValue {
            name: name.into(),
            name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            value: value.into(),
        }
    }

    /// A match value for the Swedish personal identity number.
    pub fn personal_identity_number(value: impl Into<String>) -> Self {
        MatchValue::new(constants::ATTR_PERSONAL_IDENTITY_NUMBER, value)
    }

    /// A match value for the country code (used to bypass the eIDAS country
    /// selection dialogue, section 5.3.2 note).
    pub fn country(code: impl Into<String>) -> Self {
        MatchValue::new(constants::ATTR_C, code)
    }

    fn write(&self, out: &mut String) {
        out.push_str("<psc:MatchValue");
        out.push_str(" Name=\"");
        out.push_str(&escape_attr(&self.name));
        out.push('"');
        if let Some(nf) = &self.name_format {
            out.push_str(" NameFormat=\"");
            out.push_str(&escape_attr(nf));
            out.push('"');
        }
        out.push('>');
        out.push_str(&escape_text(&self.value));
        out.push_str("</psc:MatchValue>");
    }
}

/// The `<psc:PrincipalSelection>` `<saml2p:AuthnRequest>` extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalSelection {
    /// The known attribute values for the principal.
    pub match_values: Vec<MatchValue>,
}

impl PrincipalSelection {
    /// Create a principal selection from a set of match values.
    pub fn new(match_values: Vec<MatchValue>) -> Self {
        PrincipalSelection { match_values }
    }

    /// Serialize the `<psc:PrincipalSelection>` element (namespace-qualified).
    ///
    /// The result is intended to be placed inside a `<saml2p:Extensions>`
    /// element of an `AuthnRequest` (see [`super::request::request_extensions_xml`]).
    pub fn to_xml_string(&self) -> String {
        let mut out = String::new();
        out.push_str("<psc:PrincipalSelection xmlns:psc=\"");
        out.push_str(constants::NS_PSC);
        out.push_str("\">");
        for mv in &self.match_values {
            mv.write(&mut out);
        }
        out.push_str("</psc:PrincipalSelection>");
        out
    }
}

/// The `<psc:RequestedPrincipalSelection>` metadata extension, declared by an
/// IdP under its `<md:IDPSSODescriptor>` to advertise which attributes it wants
/// to receive in a `PrincipalSelection` (section 2.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestedPrincipalSelection {
    /// The attributes the IdP wants the requester to supply, as
    /// `(Name, NameFormat)` pairs.
    pub match_attributes: Vec<(String, Option<String>)>,
}

impl RequestedPrincipalSelection {
    /// Serialize the `<psc:RequestedPrincipalSelection>` element.
    pub fn to_xml_string(&self) -> String {
        let mut out = String::new();
        out.push_str("<psc:RequestedPrincipalSelection xmlns:psc=\"");
        out.push_str(constants::NS_PSC);
        out.push_str("\">");
        for (name, name_format) in &self.match_attributes {
            out.push_str("<psc:MatchValue Name=\"");
            out.push_str(&escape_attr(name));
            out.push('"');
            if let Some(nf) = name_format {
                out.push_str(" NameFormat=\"");
                out.push_str(&escape_attr(nf));
                out.push('"');
            }
            out.push_str("/>");
        }
        out.push_str("</psc:RequestedPrincipalSelection>");
        out
    }

    /// Wrap this extension in an `<md:Extensions>` container for placement under
    /// an `<md:IDPSSODescriptor>`.
    pub fn to_extensions(&self) -> Extensions {
        Extensions::new(format!(
            "<md:Extensions>{}</md:Extensions>",
            self.to_xml_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_selection_xml() {
        let ps =
            PrincipalSelection::new(vec![MatchValue::personal_identity_number("197001012380")]);
        let xml = ps.to_xml_string();
        assert!(xml.contains("psc:PrincipalSelection"));
        assert!(xml.contains(constants::NS_PSC));
        assert!(xml.contains(constants::ATTR_PERSONAL_IDENTITY_NUMBER));
        assert!(xml.contains("197001012380"));
        assert!(xml.contains("psc:MatchValue"));
    }

    #[test]
    fn test_match_value_escaping() {
        // The Name lives in an attribute (quotes escaped); the value is element
        // text (quotes left intact, but `&`/`<`/`>` escaped).
        let mv = MatchValue::new("a\"b", "x&y<z");
        let mut s = String::new();
        mv.write(&mut s);
        assert!(s.contains("Name=\"a&quot;b\""));
        assert!(s.contains(">x&amp;y&lt;z<"));
    }

    #[test]
    fn test_requested_principal_selection_extensions() {
        let rps = RequestedPrincipalSelection {
            match_attributes: vec![(
                constants::ATTR_PERSONAL_IDENTITY_NUMBER.to_string(),
                Some(constants::ATTRNAME_FORMAT_URI.to_string()),
            )],
        };
        let ext = rps.to_extensions();
        assert!(ext.raw_xml.contains("md:Extensions"));
        assert!(ext.raw_xml.contains("RequestedPrincipalSelection"));
    }
}
