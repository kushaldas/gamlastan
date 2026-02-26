// SAML 2.0 Metadata - Localized types
//
// LocalizedNameType and LocalizedURIType per saml-metadata-2.0-os Section 2.2.4-2.2.5

/// Borrowed localized name - references parsed XML.
///
/// A name string with an xml:lang attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedNameRef<'a> {
    /// The language tag (xml:lang, required).
    pub lang: &'a str,
    /// The name value.
    pub value: &'a str,
}

impl<'a> LocalizedNameRef<'a> {
    /// Convert to owned LocalizedName.
    pub fn to_owned(&self) -> LocalizedName {
        LocalizedName {
            lang: self.lang.to_string(),
            value: self.value.to_string(),
        }
    }
}

/// Owned localized name - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedName {
    /// The language tag (xml:lang, required).
    pub lang: String,
    /// The name value.
    pub value: String,
}

impl LocalizedName {
    /// Create a new localized name.
    pub fn new(lang: impl Into<String>, value: impl Into<String>) -> Self {
        LocalizedName {
            lang: lang.into(),
            value: value.into(),
        }
    }
}

/// Borrowed localized URI - references parsed XML.
///
/// A URI string with an xml:lang attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedUriRef<'a> {
    /// The language tag (xml:lang, required).
    pub lang: &'a str,
    /// The URI value.
    pub value: &'a str,
}

impl<'a> LocalizedUriRef<'a> {
    /// Convert to owned LocalizedUri.
    pub fn to_owned(&self) -> LocalizedUri {
        LocalizedUri {
            lang: self.lang.to_string(),
            value: self.value.to_string(),
        }
    }
}

/// Owned localized URI - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedUri {
    /// The language tag (xml:lang, required).
    pub lang: String,
    /// The URI value.
    pub value: String,
}

impl LocalizedUri {
    /// Create a new localized URI.
    pub fn new(lang: impl Into<String>, value: impl Into<String>) -> Self {
        LocalizedUri {
            lang: lang.into(),
            value: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localized_name_ref_to_owned() {
        let r = LocalizedNameRef {
            lang: "en",
            value: "Example Organization",
        };
        let o = r.to_owned();
        assert_eq!(o.lang, "en");
        assert_eq!(o.value, "Example Organization");
    }

    #[test]
    fn test_localized_uri_ref_to_owned() {
        let r = LocalizedUriRef {
            lang: "en",
            value: "https://example.com",
        };
        let o = r.to_owned();
        assert_eq!(o.lang, "en");
        assert_eq!(o.value, "https://example.com");
    }

    #[test]
    fn test_localized_name_new() {
        let n = LocalizedName::new("sv", "Exempelorganisation");
        assert_eq!(n.lang, "sv");
        assert_eq!(n.value, "Exempelorganisation");
    }
}
