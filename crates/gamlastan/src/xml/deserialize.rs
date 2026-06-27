// gamlastan xml deserialization trait and support.
//
// The SamlDeserialize trait provides zero-copy deserialization from an
// uppsala Document into borrowed SAML types (FooRef<'a>).

use uppsala::{Document, NodeId};

use crate::xml::error::XmlError;

/// Zero-copy deserialization from an uppsala Document.
///
/// Implementors produce borrowed SAML types whose string fields
/// reference data directly in the XML document buffer, avoiding allocations.
///
/// # Lifetime
///
/// The lifetime `'a` ties the deserialized type to the Document and the
/// original XML string it was parsed from.
pub trait SamlDeserialize<'a>: Sized {
    /// Deserialize from a document node.
    ///
    /// All string fields in the returned type borrow from the document's
    /// underlying buffer (via `Cow<'a, str>` in the Element attributes).
    ///
    /// # Arguments
    ///
    /// * `doc` - The parsed XML document.
    /// * `node` - The node ID of the element to deserialize from.
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError>;
}

/// Convenience function to parse a complete SAML XML document.
///
/// Parses the XML string and deserializes the root element into the
/// specified SAML type.
pub fn parse_saml<'a, T: SamlDeserialize<'a>>(doc: &'a Document<'a>) -> Result<T, XmlError> {
    let root = doc.document_element().ok_or(XmlError::EmptyDocument)?;
    T::from_xml(doc, root)
}

/// Parse untrusted SAML XML with SAML-specific input hardening.
///
/// This is the parse entry point for any attacker-controlled XML (inbound
/// protocol messages, SOAP/PAOS envelopes, remote metadata, KeyInfo fragments,
/// decrypted assertions). It is a drop-in replacement for [`uppsala::parse`]
/// (same return type) and layers two defenses:
///
/// 1. **uppsala 0.5 resource limits** — inherited automatically from
///    [`uppsala::parse`]: element-nesting depth cap
///    ([`uppsala::parser::DEFAULT_MAX_DEPTH`], 128), entity-expansion byte
///    budget ([`uppsala::parser::DEFAULT_MAX_ENTITY_EXPANSION`], 1 MiB), and
///    entity-nesting depth cap ([`uppsala::parser::DEFAULT_MAX_ENTITY_DEPTH`],
///    256). These bound classic billion-laughs / quadratic-blowup
///    amplification and deep-nesting stack exhaustion.
///
/// 2. **DTD rejection** — any document carrying a `<!DOCTYPE …>` is refused.
///    Legitimate SAML messages never contain a DTD; refusing them closes the
///    internal-entity-expansion attack surface entirely (defense in depth over
///    uppsala's expansion byte budget) and removes the XXE entry point.
///
/// Trusted XML the library produces itself (serialize-then-reparse round trips,
/// unit-test fixtures) may continue to call [`uppsala::parse`] directly.
pub fn parse_secure(xml: &str) -> Result<Document<'_>, uppsala::XmlError> {
    let doc = uppsala::parse(xml)?;
    if doc.doctype.is_some() {
        return Err(uppsala::XmlError::well_formedness(
            "DOCTYPE/DTD declarations are forbidden in SAML messages",
            1,
            1,
        ));
    }
    Ok(doc)
}

#[cfg(test)]
mod parse_secure_tests {
    use super::parse_secure;

    #[test]
    fn rejects_doctype_declaration() {
        // A SAML-shaped payload that smuggles in a DTD must be refused even
        // though uppsala bounds the expansion: SAML forbids DTDs outright.
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE Response [ <!ENTITY x "expanded"> ]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>"#;
        assert!(parse_secure(xml).is_err());
    }

    #[test]
    fn rejects_internal_subset_without_entities() {
        let xml = r#"<!DOCTYPE Response><Response/>"#;
        assert!(parse_secure(xml).is_err());
    }

    #[test]
    fn accepts_well_formed_saml_without_dtd() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"/>"#;
        let doc = parse_secure(xml).expect("DTD-free SAML must parse");
        assert!(doc.document_element().is_some());
    }
}
