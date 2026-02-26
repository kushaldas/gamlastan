// SAML 2.0 Metadata - AdditionalMetadataLocation
//
// Per saml-metadata-2.0-os Section 2.3.2.3

/// Borrowed additional metadata location - references parsed XML.
#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalMetadataLocationRef<'a> {
    /// The namespace URI of the metadata profile (required).
    pub namespace: &'a str,
    /// The URL where additional metadata can be found.
    pub location: &'a str,
}

impl<'a> AdditionalMetadataLocationRef<'a> {
    /// Convert to owned AdditionalMetadataLocation.
    pub fn to_owned(&self) -> AdditionalMetadataLocation {
        AdditionalMetadataLocation {
            namespace: self.namespace.to_string(),
            location: self.location.to_string(),
        }
    }
}

/// Owned additional metadata location.
#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalMetadataLocation {
    /// The namespace URI of the metadata profile (required).
    pub namespace: String,
    /// The URL where additional metadata can be found.
    pub location: String,
}
