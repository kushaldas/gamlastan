// SAML 2.0 Metadata - KeyDescriptor
//
// Per saml-metadata-2.0-os Section 2.4.1.1
// Errata: E62 (TLS/signing), E68 (multiple keys), E69 (KeyInfo semantics)

use std::str::FromStr;

/// Key usage enumeration.
///
/// Per E62:
/// - `Signing` means applicable to signing AND TLS/SSL operations.
/// - `Encryption` means suitable for wrapping encryption keys.
/// - If omitted (`None`), applicable to both uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// Key is for signing (and TLS/SSL per E62).
    Signing,
    /// Key is for encryption (key wrapping).
    Encryption,
}

impl KeyUse {
    /// Convert to the XML attribute value.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyUse::Signing => "signing",
            KeyUse::Encryption => "encryption",
        }
    }
}

impl FromStr for KeyUse {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "signing" => Ok(KeyUse::Signing),
            "encryption" => Ok(KeyUse::Encryption),
            _ => Err(()),
        }
    }
}

/// Borrowed encryption method.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptionMethodRef<'a> {
    /// Algorithm URI (required).
    pub algorithm: &'a str,
    /// Optional key size.
    pub key_size: Option<u32>,
    /// Optional OAEPparams (base64).
    pub oaep_params: Option<&'a str>,
}

impl<'a> EncryptionMethodRef<'a> {
    /// Convert to owned EncryptionMethod.
    pub fn to_owned(&self) -> EncryptionMethod {
        EncryptionMethod {
            algorithm: self.algorithm.to_string(),
            key_size: self.key_size,
            oaep_params: self.oaep_params.map(|s| s.to_string()),
        }
    }
}

/// Owned encryption method.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptionMethod {
    /// Algorithm URI (required).
    pub algorithm: String,
    /// Optional key size.
    pub key_size: Option<u32>,
    /// Optional OAEPparams (base64).
    pub oaep_params: Option<String>,
}

/// Borrowed key descriptor - references parsed XML.
///
/// Per E68: multiple KeyDescriptors with the same `use` = any included key may be used.
/// Per E69: KeyInfo content has no implied semantics about cert validity, etc.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyDescriptorRef<'a> {
    /// Key use (optional; None = both signing and encryption per E62).
    pub use_: Option<KeyUse>,
    /// Raw ds:KeyInfo XML (opaque).
    pub key_info_xml: &'a str,
    /// Encryption methods (0..n).
    pub encryption_methods: Vec<EncryptionMethodRef<'a>>,
}

impl<'a> KeyDescriptorRef<'a> {
    /// Convert to owned KeyDescriptor.
    pub fn to_owned(&self) -> KeyDescriptor {
        KeyDescriptor {
            use_: self.use_,
            key_info_xml: self.key_info_xml.to_string(),
            encryption_methods: self
                .encryption_methods
                .iter()
                .map(|em| em.to_owned())
                .collect(),
        }
    }
}

/// Owned key descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyDescriptor {
    /// Key use (optional; None = both signing and encryption per E62).
    pub use_: Option<KeyUse>,
    /// Raw ds:KeyInfo XML (opaque).
    pub key_info_xml: String,
    /// Encryption methods (0..n).
    pub encryption_methods: Vec<EncryptionMethod>,
}

impl KeyDescriptor {
    /// Create a signing key descriptor with the given KeyInfo XML.
    pub fn signing(key_info_xml: impl Into<String>) -> Self {
        KeyDescriptor {
            use_: Some(KeyUse::Signing),
            key_info_xml: key_info_xml.into(),
            encryption_methods: vec![],
        }
    }

    /// Create an encryption key descriptor with the given KeyInfo XML.
    pub fn encryption(key_info_xml: impl Into<String>) -> Self {
        KeyDescriptor {
            use_: Some(KeyUse::Encryption),
            key_info_xml: key_info_xml.into(),
            encryption_methods: vec![],
        }
    }

    /// Create a key descriptor for both signing and encryption (use omitted).
    pub fn both(key_info_xml: impl Into<String>) -> Self {
        KeyDescriptor {
            use_: None,
            key_info_xml: key_info_xml.into(),
            encryption_methods: vec![],
        }
    }

    /// Check if this key can be used for signing (per E62).
    pub fn can_sign(&self) -> bool {
        matches!(self.use_, None | Some(KeyUse::Signing))
    }

    /// Check if this key can be used for encryption.
    pub fn can_encrypt(&self) -> bool {
        matches!(self.use_, None | Some(KeyUse::Encryption))
    }

    /// Extract the DER-encoded X.509 certificates carried in this descriptor's
    /// `<ds:KeyInfo>` (the `<ds:X509Data><ds:X509Certificate>` elements).
    ///
    /// The `key_info_xml` is opaque XML (per E69), so it is parsed here on
    /// demand. Returns one entry per `X509Certificate` element, in document
    /// order, with surrounding whitespace stripped and the base64 decoded
    /// (padded or unpadded, standard alphabet).
    ///
    /// # Empty result is *not* "no verification required"
    ///
    /// An empty vec is returned when there is no X.509 data **and** when the
    /// KeyInfo cannot be parsed or a certificate cannot be base64-decoded —
    /// these conditions are deliberately indistinguishable, because a
    /// descriptor with no usable cert is treated the same way regardless of
    /// *why* it has none. Callers using these certificates as verification
    /// keys MUST therefore treat an empty result as "this descriptor yields no
    /// trust anchor" and fail closed (reject the signature), never as
    /// "verification is optional." Do not branch on `is_empty()` to skip
    /// signature checking.
    pub fn x509_certificates_der(&self) -> Vec<Vec<u8>> {
        x509_certificates_der_from_key_info(&self.key_info_xml)
    }
}

/// Standard base64 alphabet, but tolerant of missing `=` padding on decode.
///
/// XML-DSig `<X509Certificate>` content is conformantly padded, but some
/// producers omit padding; without this an otherwise-valid signing cert would
/// be silently dropped from the candidate set. The alphabet stays strict
/// (no URL-safe `-`/`_`).
const X509_BASE64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// The XML Signature namespace. Trusted `<X509Certificate>` nodes must live here
/// (or be namespace-unqualified, which non-conformant-but-common producers emit);
/// an element explicitly bound to a *different* namespace is a lookalike and must
/// not become a trust anchor.
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// True for the XML Signature namespace or no namespace at all. Used to accept
/// legacy unqualified `<X509Certificate>`/`<X509Data>` while rejecting elements
/// deliberately bound to a foreign namespace (e.g. `evil:X509Certificate`).
fn is_xmldsig_or_unqualified(ns: Option<&str>) -> bool {
    ns.is_none() || ns == Some(XMLDSIG_NS)
}

/// Pull every XML-DSig `<X509Certificate>` out of a `KeyInfo` fragment and
/// base64-decode it to DER.
///
/// Two trust constraints (Finding #2, CWE-347/CWE-345): a certificate is only a
/// candidate signing key if its element is (a) in the XML Signature namespace
/// (or unqualified), not a foreign-namespace lookalike, and (b) nested under an
/// `<X509Data>` parent — matching the XMLDSig schema. Without (a) a metadata
/// author could smuggle attacker DER through an `<evil:X509Certificate>` tag;
/// without (b) any `X509Certificate`-named element anywhere would be trusted.
fn x509_certificates_der_from_key_info(key_info_xml: &str) -> Vec<Vec<u8>> {
    use base64::Engine;

    let doc = match crate::xml::parse_secure(key_info_xml) {
        Ok(doc) => doc,
        // KeyInfo captured from a larger metadata document often borrows
        // ancestor namespace declarations and is not valid standalone XML.
        // Fall back to a prefix-tolerant fragment scan for X509Certificate.
        Err(_) => return x509_certificates_der_from_fragment(key_info_xml),
    };
    let mut out = Vec::new();
    for node in doc.descendants(doc.root()) {
        let Some(elem) = doc.element(node) else {
            continue;
        };
        if &*elem.name.local_name != "X509Certificate" {
            continue;
        }
        // (a) Reject explicit foreign-namespace lookalikes.
        if !is_xmldsig_or_unqualified(elem.name.namespace_uri.as_deref()) {
            continue;
        }
        // (b) Require an <X509Data> ancestor (XMLDSig structure).
        if !has_x509data_ancestor(&doc, node) {
            continue;
        }
        // Certificate base64 is often pretty-printed across lines; strip all
        // ASCII whitespace before decoding.
        let b64: String = doc.text_content_deep(node).split_whitespace().collect();
        if b64.is_empty() {
            continue;
        }
        if let Ok(der) = X509_BASE64.decode(&b64) {
            out.push(der);
        }
    }
    out
}

/// True if `node` has an `<X509Data>` ancestor in the XMLDSig (or unqualified)
/// namespace.
fn has_x509data_ancestor(doc: &uppsala::Document<'_>, node: uppsala::NodeId) -> bool {
    let mut current = doc.parent(node);
    while let Some(parent) = current {
        if let Some(elem) = doc.element(parent) {
            if &*elem.name.local_name == "X509Data"
                && is_xmldsig_or_unqualified(elem.name.namespace_uri.as_deref())
            {
                return true;
            }
        }
        current = doc.parent(parent);
    }
    false
}

/// Fallback extractor for `KeyInfo` fragments that cannot be parsed standalone
/// because they inherit namespace declarations from the (now absent) metadata
/// ancestors.
///
/// Without those ancestor declarations we cannot resolve prefixes to namespaces,
/// so trust is anchored to the fragment's root element: the deserializer only
/// ever feeds this function a genuine XMLDSig `<KeyInfo>`, so the root's prefix
/// *is* the prefix bound to the XML Signature namespace. A certificate is
/// honoured only when all of these hold (Finding #2, CWE-347/CWE-345):
///
/// 1. the `<X509Certificate>` uses the **same prefix** as the `<KeyInfo>` root —
///    a different prefix must resolve to a different (foreign) namespace via an
///    ancestor declaration, i.e. an inherited-prefix lookalike such as
///    `<evil:X509Certificate>`;
/// 2. it is enclosed in an `<X509Data>` element that *also* uses that prefix; and
/// 3. neither the `<X509Certificate>` nor the enclosing `<X509Data>` start tag
///    rebinds its prefix (or the default namespace) to a non-XMLDSig namespace
///    inline.
///
/// This deliberately fails closed on the pathological case of two distinct
/// prefixes both bound to the XMLDSig namespace; a conformant producer uses one.
fn x509_certificates_der_from_fragment(key_info_xml: &str) -> Vec<Vec<u8>> {
    use base64::Engine;

    let mut out = Vec::new();

    // Anchor trust to the KeyInfo root's prefix; if we cannot identify it, trust
    // nothing from this fragment.
    let Some(expected_prefix) = fragment_root_prefix(key_info_xml) else {
        return out;
    };

    let mut cursor = 0;
    while let Some((tag_start, start_tag_end, qualified_name)) =
        find_next_x509_start_tag(key_info_xml, cursor)
    {
        let close_tag = format!("</{qualified_name}>");
        let Some(rel_close) = key_info_xml[start_tag_end + 1..].find(&close_tag) else {
            break;
        };

        let content_end = start_tag_end + 1 + rel_close;
        let cert_tag_body = &key_info_xml[tag_start + 1..start_tag_end];

        // (1) the cert prefix must match the KeyInfo root, (2) it must be
        // enclosed in an <X509Data> under that same prefix, and (3) neither tag
        // may rebind that prefix (or the default namespace) to a foreign URI.
        if qualified_prefix(qualified_name) == expected_prefix {
            if let Some(data_tag_body) =
                enclosing_x509data_tag(key_info_xml, tag_start, expected_prefix)
            {
                if !declares_foreign_namespace(cert_tag_body)
                    && !declares_foreign_namespace(data_tag_body)
                {
                    let b64: String = key_info_xml[start_tag_end + 1..content_end]
                        .split_whitespace()
                        .collect();
                    if !b64.is_empty() {
                        if let Ok(der) = X509_BASE64.decode(&b64) {
                            out.push(der);
                        }
                    }
                }
            }
        }

        cursor = content_end + close_tag.len();
    }

    out
}

/// The prefix (with trailing colon, e.g. `"ds:"`, or `""` for the default
/// namespace) of the fragment's root `<KeyInfo>` element. The deserializer only
/// produces genuine XMLDSig `<KeyInfo>` fragments here, so this prefix is the one
/// the original document binds to the XML Signature namespace. Returns `None`
/// when the root tag is missing or is not a `KeyInfo` element.
fn fragment_root_prefix(key_info_xml: &str) -> Option<&str> {
    let lt = key_info_xml.find('<')?;
    let rest = &key_info_xml[lt + 1..];
    let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/')?;
    let qname = &rest[..end];
    match qname.split_once(':') {
        Some((prefix, "KeyInfo")) => Some(&qname[..prefix.len() + 1]),
        Some(_) => None,
        None if qname == "KeyInfo" => Some(""),
        None => None,
    }
}

/// The namespace prefix of `qualified_name`, including the trailing colon (e.g.
/// `"ds:"`), or `""` when the name is unprefixed.
fn qualified_prefix(qualified_name: &str) -> &str {
    match qualified_name.find(':') {
        Some(i) => &qualified_name[..i + 1],
        None => "",
    }
}

/// If byte position `pos` (the `<` of an X509Certificate start tag) sits inside a
/// `<{prefix}X509Data ...>` element, return that start tag's attribute body
/// (between the qualified name and `>`); otherwise `None`. Prefix-exact: an
/// `<X509Data>` under a *different* prefix does not enclose the certificate.
fn enclosing_x509data_tag<'a>(xml: &'a str, pos: usize, prefix: &str) -> Option<&'a str> {
    let before = &xml[..pos];
    let open_needle = format!("<{prefix}X509Data");
    let close_needle = format!("</{prefix}X509Data");
    let open = last_tag(before, &open_needle)?;
    // A later close before `pos` means we are no longer inside the element.
    if let Some(close) = last_tag(before, &close_needle) {
        if close > open {
            return None;
        }
    }
    let after_name = open + open_needle.len();
    let tag_end = find_tag_end(xml, after_name)?;
    let attrs = &xml[after_name..tag_end];
    // A self-closing `<X509Data .../>` ends at its own start tag, so it does not
    // enclose a certificate that appears later. There is no matching close tag to
    // trip the guard above, so detect the trailing `/` (after any whitespace; the
    // `>` was located quote-aware, so a `/` here is the self-close marker, not
    // part of an attribute value) and treat the certificate as not enclosed.
    if attrs.trim_end().ends_with('/') {
        return None;
    }
    Some(attrs)
}

/// Byte index of the last occurrence of `needle` (e.g. `"<ds:X509Data"`) in
/// `haystack` whose following character terminates the element name (whitespace,
/// `>`, `/`, or end of input), so `"<ds:X509DataFoo"` does not match.
fn last_tag(haystack: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    let mut found = None;
    while let Some(rel) = haystack[from..].find(needle) {
        let at = from + rel;
        let after = haystack[at + needle.len()..].chars().next();
        if after.map_or(true, |c| c.is_whitespace() || c == '>' || c == '/') {
            found = Some(at);
        }
        from = at + needle.len();
    }
    found
}

/// True if a start-tag body declares a default or prefixed `xmlns` bound to a
/// namespace other than XMLDSig. Used to reject inline foreign-namespace
/// rebinding in the fragment fallback.
///
/// XML permits arbitrary whitespace around the `=` of an attribute
/// (`xmlns:ds = "urn:evil"`), so this parses `name = "value"` pairs with a small
/// scanner rather than whitespace tokenization — a token-splitting check would
/// miss the spaced form and let a rebinding slip through.
///
/// A prefixed declaration (`xmlns:ds`) bound to anything other than XMLDSig is
/// foreign, including an empty URI (`xmlns:ds=""`): an empty value undeclares or
/// rebinds the prefix and must be rejected so it cannot masquerade as a trusted
/// XMLDSig prefix. The default-namespace undeclaration `xmlns=""` is legal and
/// benign (it binds the default to "no namespace"), so it is not treated as
/// foreign; only a non-empty default rebinding to a non-XMLDSig URI is.
fn declares_foreign_namespace(tag_body: &str) -> bool {
    tag_attributes(tag_body).into_iter().any(|(name, value)| {
        if name.starts_with("xmlns:") {
            value != XMLDSIG_NS
        } else if name == "xmlns" {
            !value.is_empty() && value != XMLDSIG_NS
        } else {
            false
        }
    })
}

/// Scan a start-tag body into `(name, value)` attribute pairs, tolerating
/// arbitrary whitespace around `=` and both quote styles. Values are returned
/// without their surrounding quotes; the leading element name (which has no
/// `=value`) and any malformed remnants are skipped. This is a minimal scanner
/// sufficient for namespace-declaration detection in the KeyInfo fragment
/// fallback, not a general XML attribute parser.
fn tag_attributes(tag_body: &str) -> Vec<(&str, &str)> {
    let bytes = tag_body.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < n && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        let name = &tag_body[name_start..i];
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < n && bytes[i] == b'=' {
            i += 1; // consume '='
            while i < n && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < n && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let value_start = i;
                while i < n && bytes[i] != quote {
                    i += 1;
                }
                let value = &tag_body[value_start..i];
                if i < n {
                    i += 1; // consume closing quote
                }
                if !name.is_empty() {
                    out.push((name, value));
                }
            }
        } else if i == name_start {
            // No progress (e.g. a stray '='): advance to avoid an infinite loop.
            i += 1;
        }
    }
    out
}

fn find_next_x509_start_tag(xml: &str, mut cursor: usize) -> Option<(usize, usize, &str)> {
    while let Some(rel_lt) = xml[cursor..].find('<') {
        let tag_start = cursor + rel_lt;
        let tag_end = find_tag_end(xml, tag_start + 1)?;
        if let Some(qualified_name) = parse_x509_start_tag_name(&xml[tag_start + 1..tag_end]) {
            return Some((tag_start, tag_end, qualified_name));
        }
        cursor = tag_end + 1;
    }

    None
}

fn parse_x509_start_tag_name(tag_body: &str) -> Option<&str> {
    let trimmed = tag_body.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.starts_with('!')
        || trimmed.starts_with('?')
        || trimmed.ends_with('/')
    {
        return None;
    }

    let qualified_name = trimmed.split_whitespace().next()?;
    (qualified_name.rsplit(':').next() == Some("X509Certificate")).then_some(qualified_name)
}

fn find_tag_end(xml: &str, from: usize) -> Option<usize> {
    let bytes = xml.as_bytes();
    let mut quote = None;
    let mut index = from;

    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => match quote {
                Some(current) if current == bytes[index] => quote = None,
                None => quote = Some(bytes[index]),
                _ => {}
            },
            b'>' if quote.is_none() => return Some(index),
            _ => {}
        }
        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::types::entity_descriptor::{
        EntitiesDescriptorRef, EntityRolesRef, MetadataChildRef,
    };
    use crate::xml::parse_saml;

    fn first_idp_key_descriptor_without_inline_ds<'a>(
        entities: &'a EntitiesDescriptorRef<'a>,
    ) -> Option<KeyDescriptorRef<'a>> {
        find_idp_key_descriptor_without_inline_ds(&entities.children)
    }

    fn find_idp_key_descriptor_without_inline_ds<'a>(
        children: &'a [MetadataChildRef<'a>],
    ) -> Option<KeyDescriptorRef<'a>> {
        for child in children {
            match child {
                MetadataChildRef::Entity(entity) => {
                    let EntityRolesRef::Roles { idp_sso, .. } = &entity.roles else {
                        continue;
                    };
                    for idp in idp_sso {
                        for key_descriptor in &idp.sso_base.base.key_descriptors {
                            if key_descriptor.key_info_xml.contains("<ds:KeyInfo")
                                && key_descriptor.key_info_xml.contains("X509Certificate")
                                && !key_descriptor.key_info_xml.contains("xmlns:ds=")
                            {
                                return Some(key_descriptor.clone());
                            }
                        }
                    }
                }
                MetadataChildRef::Entities(entities) => {
                    if let Some(key_descriptor) =
                        first_idp_key_descriptor_without_inline_ds(entities)
                    {
                        return Some(key_descriptor);
                    }
                }
            }
        }

        None
    }

    #[test]
    fn test_key_use_roundtrip() {
        assert_eq!("signing".parse::<KeyUse>().unwrap(), KeyUse::Signing);
        assert_eq!("encryption".parse::<KeyUse>().unwrap(), KeyUse::Encryption);
        assert!("other".parse::<KeyUse>().is_err());
    }

    #[test]
    fn test_key_descriptor_signing() {
        let kd = KeyDescriptor::signing("<ds:KeyInfo/>");
        assert!(kd.can_sign());
        assert!(!kd.can_encrypt());
    }

    #[test]
    fn test_key_descriptor_encryption() {
        let kd = KeyDescriptor::encryption("<ds:KeyInfo/>");
        assert!(!kd.can_sign());
        assert!(kd.can_encrypt());
    }

    #[test]
    fn test_key_descriptor_both() {
        let kd = KeyDescriptor::both("<ds:KeyInfo/>");
        assert!(kd.can_sign());
        assert!(kd.can_encrypt());
        assert!(kd.use_.is_none());
    }

    #[test]
    fn test_x509_certificates_der_extraction() {
        // base64("hello") = "aGVsbG8="
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>",
        );
        assert_eq!(kd.x509_certificates_der(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_x509_certificates_der_multiline_default_ns_and_empty() {
        // Pretty-printed base64, default (prefix-less) namespace.
        let kd = KeyDescriptor::signing(
            "<KeyInfo><X509Data><X509Certificate>\n  aGVs\n  bG8=\n  </X509Certificate>\
             </X509Data></KeyInfo>",
        );
        assert_eq!(kd.x509_certificates_der(), vec![b"hello".to_vec()]);

        // KeyInfo without any X509 data yields nothing.
        let none = KeyDescriptor::signing("<ds:KeyInfo><ds:KeyName>k</ds:KeyName></ds:KeyInfo>");
        assert!(none.x509_certificates_der().is_empty());
    }

    #[test]
    fn test_x509_certificates_der_multiple_in_document_order() {
        // base64("one") = "b25l", base64("two") = "dHdv".
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>b25l</ds:X509Certificate>\
             <ds:X509Certificate>dHdv</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>",
        );
        // Both certs, in document order.
        assert_eq!(
            kd.x509_certificates_der(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn test_x509_certificates_der_accepts_unpadded_base64() {
        // base64("hello") padded is "aGVsbG8="; some producers emit it without
        // the trailing pad. Both must decode (F-2).
        let unpadded = KeyDescriptor::signing(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>aGVsbG8</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo>",
        );
        assert_eq!(unpadded.x509_certificates_der(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_x509_certificates_der_handles_deserialized_fragment_without_namespace() {
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert_eq!(kd.x509_certificates_der(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_x509_certificates_der_rejects_foreign_namespace_lookalike() {
        // Finding #2 regression: an <evil:X509Certificate> bound to a non-XMLDSig
        // namespace must NOT be promoted to a trusted certificate. This fragment
        // parses cleanly (all namespaces inline), so it goes through the
        // namespace-aware path, which rejects the foreign namespace.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
             xmlns:evil=\"urn:evil\">\
             <evil:X509Data><evil:X509Certificate>aGVsbG8=</evil:X509Certificate>\
             </evil:X509Data></ds:KeyInfo>",
        );
        assert!(
            kd.x509_certificates_der().is_empty(),
            "foreign-namespace X509Certificate must not be trusted"
        );
    }

    #[test]
    fn test_x509_certificates_der_requires_x509data_ancestor() {
        // Finding #2 regression: an X509Certificate that is not inside an
        // X509Data element is not a conformant trust anchor and must be ignored.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:KeyInfo>",
        );
        assert!(
            kd.x509_certificates_der().is_empty(),
            "X509Certificate without X509Data ancestor must not be trusted"
        );
    }

    #[test]
    fn test_x509_certificates_der_fragment_requires_x509data() {
        // Finding #2 regression (fragment path): a loose X509Certificate in an
        // unparseable fragment (inherited prefix) without X509Data is ignored.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo><ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(kd.x509_certificates_der().is_empty());
    }

    #[test]
    fn test_x509_certificates_der_fragment_rejects_self_closing_x509data() {
        // PR #20 review: a self-closing <ds:X509Data/> ends immediately, so a
        // later loose <ds:X509Certificate> is NOT enclosed by it. The structural
        // guard must not treat the self-closing element as an open enclosure (it
        // has no close tag to trip the existing check), otherwise a loose cert
        // would be trusted in the fragment fallback (Finding #2).
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <ds:X509Data/>\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(
            kd.x509_certificates_der().is_empty(),
            "a cert after a self-closing X509Data must not be treated as enclosed"
        );

        // Same for the self-closing tag written with a space before the slash.
        let kd_spaced = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <ds:X509Data />\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd_spaced.key_info_xml).is_err());
        assert!(kd_spaced.x509_certificates_der().is_empty());
    }

    #[test]
    fn test_x509_certificates_der_fragment_rejects_inherited_foreign_prefix() {
        // Finding #2 / R1 regression (fragment path): when the cert's prefix is
        // declared on a (now-absent) ancestor — so the fragment does not parse
        // standalone — a *different* prefix from the KeyInfo root must resolve to
        // a different namespace and is rejected as an inherited-prefix lookalike.
        // Here KeyInfo uses `ds:` while the X509Data/X509Certificate use `evil:`;
        // both prefixes are undeclared in the fragment, so it hits the fallback.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <evil:X509Data><evil:X509Certificate>aGVsbG8=</evil:X509Certificate>\
             </evil:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(
            kd.x509_certificates_der().is_empty(),
            "a foreign inherited-prefix X509Certificate must not be trusted in the fragment path"
        );
    }

    #[test]
    fn test_x509_certificates_der_fragment_rejects_inline_rebound_prefix() {
        // Finding #2 / R1 regression (fragment path): even when the prefix
        // *matches* the KeyInfo root, an inline xmlns that rebinds it to a
        // foreign namespace on the X509Data (or cert) tag must be rejected. The
        // fragment still fails standalone parse because `ds:` is undeclared on
        // the root KeyInfo, so it reaches the fallback.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <ds:X509Data xmlns:ds=\"urn:evil\">\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(
            kd.x509_certificates_der().is_empty(),
            "an inline-rebound foreign namespace must not be trusted in the fragment path"
        );
    }

    #[test]
    fn test_x509_certificates_der_fragment_rejects_rebind_with_spaced_equals() {
        // PR #20 review: XML allows whitespace around '=' in attributes, so an
        // inline rebinding written as `xmlns:ds = "urn:evil"` must still be
        // rejected by the fragment fallback — a whitespace-tokenizing check
        // would miss it and re-open the rebinding evasion.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <ds:X509Data xmlns:ds = \"urn:evil\">\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(
            kd.x509_certificates_der().is_empty(),
            "a spaced-equals inline foreign-namespace rebinding must not be trusted"
        );

        // The same evasion on the default namespace.
        let kd_default = KeyDescriptor::signing(
            "<KeyInfo>\
             <X509Data xmlns = 'urn:evil'>\
             <X509Certificate>aGVsbG8=</X509Certificate></X509Data></KeyInfo>",
        );
        // (Parses standalone, but the namespace-aware path also rejects urn:evil.)
        assert!(kd_default.x509_certificates_der().is_empty());
    }

    #[test]
    fn test_x509_certificates_der_fragment_rejects_empty_prefixed_namespace() {
        // PR #20 review: an empty namespace URI on a prefixed declaration
        // (`xmlns:ds=""`) undeclares/rebinds the prefix and must be treated as
        // foreign — otherwise an attacker could rebind the KeyInfo-root prefix
        // away from XMLDSig in the fragment fallback without detection.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo>\
             <ds:X509Data xmlns:ds=\"\">\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert!(
            kd.x509_certificates_der().is_empty(),
            "an empty-URI prefixed namespace rebinding must not be trusted"
        );

        // The benign counterpart: a default-namespace undeclaration `xmlns=""`
        // is legal and must NOT, on its own, mark the tag foreign.
        assert!(!declares_foreign_namespace("X509Data xmlns=\"\""));
        assert!(declares_foreign_namespace("X509Data xmlns:ds=\"\""));
    }

    #[test]
    fn test_x509_certificates_der_fragment_accepts_matching_prefix() {
        // The legitimate fragment case still works: KeyInfo, X509Data and
        // X509Certificate share the `ds:` prefix (bound to XMLDSig on an absent
        // ancestor), so the fragment fails standalone parse but is trusted.
        let kd = KeyDescriptor::signing(
            "<ds:KeyInfo><ds:X509Data>\
             <ds:X509Certificate>aGVsbG8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        );
        assert!(uppsala::parse(&kd.key_info_xml).is_err());
        assert_eq!(kd.x509_certificates_der(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_x509_certificates_der_unparseable_keyinfo_is_empty() {
        // Malformed XML must yield an empty vec, not panic.
        let kd = KeyDescriptor::signing("<ds:KeyInfo><ds:X509Data>not closed");
        assert!(kd.x509_certificates_der().is_empty());
    }

    #[test]
    fn test_x509_certificates_der_edugain_fragment_without_inline_namespace() {
        let xml = include_str!("../../../../../edugain-v2.xml");
        let doc = uppsala::parse(xml).unwrap();
        let entities: EntitiesDescriptorRef<'_> = parse_saml(&doc).unwrap();
        let key_descriptor = first_idp_key_descriptor_without_inline_ds(&entities)
            .expect("expected eduGAIN IdP KeyInfo without inline ds namespace");

        assert!(uppsala::parse(key_descriptor.key_info_xml).is_err());
        assert!(!key_descriptor.to_owned().x509_certificates_der().is_empty());
    }

    #[test]
    fn test_key_descriptor_ref_to_owned() {
        let r = KeyDescriptorRef {
            use_: Some(KeyUse::Signing),
            key_info_xml: "<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>",
            encryption_methods: vec![EncryptionMethodRef {
                algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                key_size: Some(128),
                oaep_params: None,
            }],
        };
        let o = r.to_owned();
        assert_eq!(o.use_, Some(KeyUse::Signing));
        assert_eq!(o.encryption_methods.len(), 1);
        assert_eq!(o.encryption_methods[0].key_size, Some(128));
    }
}
