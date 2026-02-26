// SAML 2.0 Metadata - Extensions container
//
// Per saml-metadata-2.0-os Section 2.2.1, Extensions is a generic container
// for namespace-qualified extension elements.

/// Borrowed extensions container - references parsed XML.
///
/// Contains the raw XML of extension elements. We store the raw XML string
/// since extensions are opaque to the SAML metadata processor.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionsRef<'a> {
    /// Raw XML content of the Extensions element (children only).
    pub raw_xml: &'a str,
}

impl<'a> ExtensionsRef<'a> {
    /// Convert to owned Extensions.
    pub fn to_owned(&self) -> Extensions {
        Extensions {
            raw_xml: self.raw_xml.to_string(),
        }
    }
}

/// Owned extensions container.
#[derive(Debug, Clone, PartialEq)]
pub struct Extensions {
    /// Raw XML content of the Extensions element (children only).
    pub raw_xml: String,
}

impl Extensions {
    /// Create new extensions from raw XML.
    pub fn new(raw_xml: impl Into<String>) -> Self {
        Extensions {
            raw_xml: raw_xml.into(),
        }
    }

    /// Check if extensions are empty.
    pub fn is_empty(&self) -> bool {
        self.raw_xml.trim().is_empty()
    }
}
