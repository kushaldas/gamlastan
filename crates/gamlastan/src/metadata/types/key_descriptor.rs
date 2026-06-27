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

/// Pull every `<X509Certificate>` (any namespace prefix) out of a `KeyInfo`
/// fragment and base64-decode it to DER.
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

fn x509_certificates_der_from_fragment(key_info_xml: &str) -> Vec<Vec<u8>> {
    use base64::Engine;

    let mut out = Vec::new();
    let mut cursor = 0;

    while let Some((start_tag_end, qualified_name)) = find_next_x509_start_tag(key_info_xml, cursor)
    {
        let close_tag = format!("</{qualified_name}>");
        let Some(rel_close) = key_info_xml[start_tag_end + 1..].find(&close_tag) else {
            break;
        };

        let content_end = start_tag_end + 1 + rel_close;
        let b64: String = key_info_xml[start_tag_end + 1..content_end]
            .split_whitespace()
            .collect();
        if !b64.is_empty() {
            if let Ok(der) = X509_BASE64.decode(&b64) {
                out.push(der);
            }
        }

        cursor = content_end + close_tag.len();
    }

    out
}

fn find_next_x509_start_tag(xml: &str, mut cursor: usize) -> Option<(usize, &str)> {
    while let Some(rel_lt) = xml[cursor..].find('<') {
        let tag_start = cursor + rel_lt;
        let tag_end = find_tag_end(xml, tag_start + 1)?;
        if let Some(qualified_name) = parse_x509_start_tag_name(&xml[tag_start + 1..tag_end]) {
            return Some((tag_end, qualified_name));
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
