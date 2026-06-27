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
///    Legitimate SAML messages never contain a DTD, so no DTD-bearing document
///    is ever accepted past this parse boundary, removing the XXE / entity-
///    smuggling entry point from all downstream SAML handling.
///
/// Note on ordering: uppsala parses the document (including any internal DTD
/// subset, expanding internal entities within the byte/depth budgets above)
/// *before* this function inspects [`Document::doctype`] and rejects it. The
/// guarantee is therefore "nothing with a DTD is handed to SAML code", not
/// "no DTD parsing work occurs" — the bounded parse work that happens before
/// rejection is capped by uppsala's resource limits, never unbounded.
///
/// Trusted XML the library produces itself (serialize-then-reparse round trips,
/// unit-test fixtures) may continue to call [`uppsala::parse`] directly.
pub fn parse_secure(xml: &str) -> Result<Document<'_>, uppsala::XmlError> {
    let doc = uppsala::parse(xml)?;
    if doc.doctype.is_some() {
        let (line, column) = locate_doctype(xml).unwrap_or((1, 1));
        return Err(uppsala::XmlError::well_formedness(
            "DOCTYPE/DTD declarations are forbidden in SAML messages",
            line,
            column,
        ));
    }
    Ok(doc)
}

/// Locate the `<!DOCTYPE` token and return its 1-based `(line, column)`.
///
/// Reports the actual position of the offending declaration so error logs point
/// at it rather than at a misleading `1:1`. Returns `None` when the literal
/// cannot be found (e.g. an exotic-but-valid spelling uppsala accepted that this
/// byte search misses), so callers fall back to `1:1`.
fn locate_doctype(xml: &str) -> Option<(usize, usize)> {
    let offset = xml.find("<!DOCTYPE")?;
    let mut line = 1usize;
    let mut line_start = 0usize;
    for (i, b) in xml.as_bytes()[..offset].iter().enumerate() {
        if *b == b'\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    // Column counts UTF-8 characters from the line start, not raw bytes.
    let column = xml[line_start..offset].chars().count() + 1;
    Some((line, column))
}

#[cfg(test)]
mod parse_secure_tests {
    use super::{locate_doctype, parse_secure};

    #[test]
    fn reports_doctype_position() {
        // DOCTYPE on its own line: line 2, column 1.
        assert_eq!(
            locate_doctype("<?xml version=\"1.0\"?>\n<!DOCTYPE x [ ]>\n<x/>"),
            Some((2, 1))
        );
        // Indented DOCTYPE on the first line: column is 1-based from line start.
        assert_eq!(locate_doctype("   <!DOCTYPE x><x/>"), Some((1, 4)));
        // Column counts characters, not bytes (the leading text is multi-byte).
        assert_eq!(
            locate_doctype("<!-- café -->\n<!DOCTYPE x><x/>"),
            Some((2, 1))
        );
        // No DOCTYPE present.
        assert_eq!(locate_doctype("<x/>"), None);
    }

    #[test]
    fn rejects_doctype_declaration() {
        // Well-formed XML whose only disqualifying feature is the DTD: the
        // DOCTYPE name (`samlp:Response`) matches the root element, and the
        // entity reference resolves, so `uppsala::parse` accepts it. That
        // isolates the rejection to `parse_secure`'s DOCTYPE check rather than
        // a generic parse error, which would let the test pass for the wrong
        // reason.
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE samlp:Response [ <!ENTITY x "expanded"> ]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&x;</samlp:Response>"#;
        assert!(
            uppsala::parse(xml).is_ok(),
            "precondition: the DTD-bearing document is itself well-formed"
        );
        assert!(
            parse_secure(xml).is_err(),
            "parse_secure must reject the document solely because of the DTD"
        );
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
