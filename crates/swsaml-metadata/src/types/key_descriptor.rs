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
}

#[cfg(test)]
mod tests {
    use super::*;

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
