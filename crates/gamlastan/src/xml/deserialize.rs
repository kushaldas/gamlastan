// gamlastan xml deserialization trait and support.
//
// The SamlDeserialize trait provides zero-copy deserialization from an
// uppsala Document into borrowed SAML types (FooRef<'a>).

use uppsala::{Document, NodeId, NodeKind};

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

/// Parser policy for [`parse_secure_with_config`].
///
/// The default is the SAML-safe policy used by [`parse_secure`]: keep uppsala's
/// default resource caps, reject `<!DOCTYPE>` at parse time, and reject entity
/// declarations if a caller deliberately allows a DTD for a non-SAML use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureParseConfig {
    /// Maximum element nesting depth accepted by the parser.
    pub max_depth: u32,
    /// Maximum total bytes of entity expansion accepted during one parse.
    pub max_entity_expansion: usize,
    /// Reject any `<!DOCTYPE>` declaration before parsing its internal subset.
    pub forbid_dtd: bool,
    /// Reject `<!ENTITY>` declarations inside a DTD.
    pub forbid_entities: bool,
    /// Reject any XML comment (`<!-- … -->`) anywhere in the document.
    pub forbid_comments: bool,
    /// Reject any processing instruction (`<?target … ?>`) anywhere in the
    /// document. The XML declaration (`<?xml … ?>`) is not a processing
    /// instruction and is unaffected.
    pub forbid_pis: bool,
}

impl Default for SecureParseConfig {
    fn default() -> Self {
        Self {
            max_depth: uppsala::parser::DEFAULT_MAX_DEPTH,
            max_entity_expansion: uppsala::parser::DEFAULT_MAX_ENTITY_EXPANSION,
            forbid_dtd: true,
            forbid_entities: true,
            forbid_comments: true,
            forbid_pis: true,
        }
    }
}

impl SecureParseConfig {
    /// Create the default SAML-safe parse policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the maximum element nesting depth.
    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Override the maximum total bytes of entity expansion per parse.
    pub fn with_max_entity_expansion(mut self, max_bytes: usize) -> Self {
        self.max_entity_expansion = max_bytes;
        self
    }

    /// Configure whether `<!DOCTYPE>` is rejected at parse time.
    ///
    /// Leave this enabled for SAML. Disabling it is intended only for callers
    /// reusing gamlastan's XML helpers on trusted, non-SAML XML.
    pub fn with_forbid_dtd(mut self, forbid: bool) -> Self {
        self.forbid_dtd = forbid;
        self
    }

    /// Configure whether `<!ENTITY>` declarations are rejected inside a DTD.
    ///
    /// This matters only when [`with_forbid_dtd`](Self::with_forbid_dtd) is set
    /// to `false`; rejecting the whole DTD is stricter and remains the default.
    pub fn with_forbid_entities(mut self, forbid: bool) -> Self {
        self.forbid_entities = forbid;
        self
    }

    /// Configure whether XML comments are rejected after parsing.
    ///
    /// Leave this enabled for SAML. Rejecting comments closes the
    /// comment-truncation signature-bypass class (CVE-2017-11427): a comment
    /// splits an element's text into multiple nodes, so a reader that returns
    /// only the first text node sees a different value than the one the
    /// signature was computed over.
    pub fn with_forbid_comments(mut self, forbid: bool) -> Self {
        self.forbid_comments = forbid;
        self
    }

    /// Configure whether processing instructions are rejected after parsing.
    ///
    /// Leave this enabled for SAML. The XML declaration (`<?xml … ?>`) is not a
    /// processing instruction and is never affected by this policy.
    pub fn with_forbid_pis(mut self, forbid: bool) -> Self {
        self.forbid_pis = forbid;
        self
    }

    fn parser(self) -> uppsala::Parser {
        uppsala::Parser::new()
            .with_max_depth(self.max_depth)
            .with_max_entity_expansion(self.max_entity_expansion)
            .with_forbid_dtd(self.forbid_dtd)
            .with_forbid_entities(self.forbid_entities)
    }
}

/// Parse untrusted SAML XML with SAML-specific input hardening.
///
/// This is the parse entry point for any attacker-controlled XML (inbound
/// protocol messages, SOAP/PAOS envelopes, remote metadata, KeyInfo fragments,
/// decrypted assertions). It is a drop-in replacement for [`uppsala::parse`]
/// (same return type) and applies [`SecureParseConfig::default`]:
///
/// 1. **uppsala resource limits** — element-nesting depth cap
///    ([`uppsala::parser::DEFAULT_MAX_DEPTH`], 128), entity-expansion byte
///    budget ([`uppsala::parser::DEFAULT_MAX_ENTITY_EXPANSION`], 1 MiB), and
///    entity-nesting depth cap ([`uppsala::parser::DEFAULT_MAX_ENTITY_DEPTH`],
///    256). These bound classic billion-laughs / quadratic-blowup
///    amplification and deep-nesting stack exhaustion.
///
/// 2. **parse-time DTD/entity rejection** — any document carrying a
///    `<!DOCTYPE …>` is refused before the DTD internal subset is parsed.
///    Legitimate SAML messages never contain a DTD, so no DTD-bearing document
///    is ever accepted past this parse boundary, removing the XXE / entity-
///    smuggling entry point from all downstream SAML handling.
///
/// Trusted XML the library produces itself (serialize-then-reparse round trips,
/// unit-test fixtures) may continue to call [`uppsala::parse`] directly.
pub fn parse_secure(xml: &str) -> Result<Document<'_>, uppsala::XmlError> {
    parse_secure_with_config(xml, &SecureParseConfig::default())
}

/// Parse XML with an explicit secure parse policy.
///
/// `parse_secure` is the recommended SAML entry point. This variant exists for
/// callers that need to tune uppsala's parser caps while keeping the same
/// fail-closed parser surface.
pub fn parse_secure_with_config<'a>(
    xml: &'a str,
    config: &SecureParseConfig,
) -> Result<Document<'a>, uppsala::XmlError> {
    let doc = config.parser().parse(xml)?;
    if config.forbid_comments || config.forbid_pis {
        reject_forbidden_nodes(&doc, config)?;
    }
    Ok(doc)
}

/// Post-parse rejection of comment and processing-instruction nodes.
///
/// uppsala has no parser-level flag for these, so we walk the built DOM once and
/// fail closed if a disallowed node is present anywhere (prolog, element
/// content, or epilog). This is the choke point that closes the
/// comment-truncation bypass: a document carrying a comment is refused before
/// any field text is extracted.
fn reject_forbidden_nodes(
    doc: &Document<'_>,
    config: &SecureParseConfig,
) -> Result<(), uppsala::XmlError> {
    for id in doc.descendants(doc.root()) {
        match doc.node_kind(id) {
            Some(NodeKind::Comment(_)) if config.forbid_comments => {
                return Err(uppsala::XmlError::well_formedness(
                    "response contained illegal XML comments",
                    0,
                    0,
                ));
            }
            Some(NodeKind::ProcessingInstruction(_)) if config.forbid_pis => {
                return Err(uppsala::XmlError::well_formedness(
                    "response contained illegal processing instructions",
                    0,
                    0,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod parse_secure_tests {
    use super::{parse_secure, parse_secure_with_config, SecureParseConfig};

    #[test]
    fn secure_config_defaults_to_saml_safe_policy() {
        let config = SecureParseConfig::default();
        assert_eq!(config.max_depth, uppsala::parser::DEFAULT_MAX_DEPTH);
        assert_eq!(
            config.max_entity_expansion,
            uppsala::parser::DEFAULT_MAX_ENTITY_EXPANSION
        );
        assert!(config.forbid_dtd);
        assert!(config.forbid_entities);
        assert!(config.forbid_comments);
        assert!(config.forbid_pis);
    }

    #[test]
    fn rejects_xml_comment() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><!-- x --></samlp:Response>"#;
        let err = parse_secure(xml).expect_err("comment-bearing document must be rejected");
        assert!(
            err.to_string().contains("illegal XML comments"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_processing_instruction() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><?php evil ?></samlp:Response>"#;
        let err = parse_secure(xml).expect_err("PI-bearing document must be rejected");
        assert!(
            err.to_string().contains("illegal processing instructions"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_embedded_comment_in_nameid() {
        // The comment-truncation bypass: a comment splits the NameID text so a
        // first-text-node reader would see "victim@example.com" while the
        // signature covers the comment-stripped "victim@example.com.evil.com".
        // parse_secure must refuse the document before any text extraction.
        let xml = r#"<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">victim@example.com<!---->.evil.com</saml:NameID>"#;
        let err = parse_secure(xml).expect_err("comment in NameID must be rejected");
        assert!(
            err.to_string().contains("illegal XML comments"),
            "got: {err}"
        );
    }

    #[test]
    fn accepts_xml_declaration_which_is_not_a_pi() {
        // The XML declaration must not be mistaken for a processing instruction.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"/>"#;
        assert!(parse_secure(xml).is_ok());
    }

    #[test]
    fn explicit_policy_can_allow_comments_and_pis() {
        let xml = r#"<Response><!-- ok --><?pi ok ?></Response>"#;
        assert!(parse_secure(xml).is_err());

        let config = SecureParseConfig::new()
            .with_forbid_comments(false)
            .with_forbid_pis(false);
        assert!(parse_secure_with_config(xml, &config).is_ok());
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
    fn reports_doctype_position_from_parser() {
        // DOCTYPE on its own line: uppsala rejects at its opening token and
        // reports that position (line 2), not a generic 1:1.
        let err = parse_secure("<?xml version=\"1.0\"?>\n<!DOCTYPE x [ ]>\n<x/>")
            .expect_err("DTD-bearing document must be rejected");
        assert!(
            err.to_string().contains("at 2:1"),
            "error should point at the DOCTYPE declaration, got: {err}"
        );
    }

    #[test]
    fn accepts_well_formed_saml_without_dtd() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"/>"#;
        let doc = parse_secure(xml).expect("DTD-free SAML must parse");
        assert!(doc.document_element().is_some());
    }

    #[test]
    fn explicit_policy_can_tighten_depth_limit() {
        let xml = "<a><b/></a>";
        assert!(parse_secure(xml).is_ok());

        let config = SecureParseConfig::new().with_max_depth(1);
        assert!(parse_secure_with_config(xml, &config).is_err());
    }

    #[test]
    fn explicit_policy_can_allow_dtd_but_reject_entities() {
        let xml = r#"<!DOCTYPE Response [ <!ENTITY x "expanded"> ]><Response/>"#;
        let config = SecureParseConfig::new()
            .with_forbid_dtd(false)
            .with_forbid_entities(true);
        assert!(parse_secure_with_config(xml, &config).is_err());
    }
}
