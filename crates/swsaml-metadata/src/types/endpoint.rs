// SAML 2.0 Metadata - Endpoint types
//
// EndpointType and IndexedEndpointType per saml-metadata-2.0-os Section 2.2.2-2.2.3

/// Borrowed endpoint type - references parsed XML.
///
/// Represents a SAML protocol binding endpoint.
/// Schema: Binding (required), Location (required), ResponseLocation (optional).
#[derive(Debug, Clone, PartialEq)]
pub struct EndpointRef<'a> {
    /// The SAML binding URI (required).
    pub binding: &'a str,
    /// The endpoint location URI (required).
    pub location: &'a str,
    /// Optional response location URI.
    pub response_location: Option<&'a str>,
}

impl<'a> EndpointRef<'a> {
    /// Convert to owned Endpoint.
    pub fn to_owned(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.to_string(),
            location: self.location.to_string(),
            response_location: self.response_location.map(|s| s.to_string()),
        }
    }
}

/// Owned endpoint type - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    /// The SAML binding URI (required).
    pub binding: String,
    /// The endpoint location URI (required).
    pub location: String,
    /// Optional response location URI.
    pub response_location: Option<String>,
}

impl Endpoint {
    /// Create a new endpoint with binding and location.
    pub fn new(binding: impl Into<String>, location: impl Into<String>) -> Self {
        Endpoint {
            binding: binding.into(),
            location: location.into(),
            response_location: None,
        }
    }

    /// Create a new endpoint with response location.
    pub fn with_response_location(
        binding: impl Into<String>,
        location: impl Into<String>,
        response_location: impl Into<String>,
    ) -> Self {
        Endpoint {
            binding: binding.into(),
            location: location.into(),
            response_location: Some(response_location.into()),
        }
    }
}

/// Borrowed indexed endpoint type - references parsed XML.
///
/// Extends EndpointType with index and isDefault attributes.
/// Schema: index (required xs:unsignedShort), isDefault (optional xs:boolean).
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedEndpointRef<'a> {
    /// The base endpoint.
    pub endpoint: EndpointRef<'a>,
    /// The index of this endpoint (required).
    pub index: u16,
    /// Whether this is the default endpoint (optional).
    pub is_default: Option<bool>,
}

impl<'a> IndexedEndpointRef<'a> {
    /// Convert to owned IndexedEndpoint.
    pub fn to_owned(&self) -> IndexedEndpoint {
        IndexedEndpoint {
            endpoint: self.endpoint.to_owned(),
            index: self.index,
            is_default: self.is_default,
        }
    }
}

/// Owned indexed endpoint type - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedEndpoint {
    /// The base endpoint.
    pub endpoint: Endpoint,
    /// The index of this endpoint (required).
    pub index: u16,
    /// Whether this is the default endpoint (optional).
    pub is_default: Option<bool>,
}

impl IndexedEndpoint {
    /// Create a new indexed endpoint.
    pub fn new(endpoint: Endpoint, index: u16) -> Self {
        IndexedEndpoint {
            endpoint,
            index,
            is_default: None,
        }
    }

    /// Create a new indexed endpoint marked as default.
    pub fn new_default(endpoint: Endpoint, index: u16) -> Self {
        IndexedEndpoint {
            endpoint,
            index,
            is_default: Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_new() {
        let ep = Endpoint::new(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "https://sp.example.com/acs",
        );
        assert_eq!(ep.binding, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assert_eq!(ep.location, "https://sp.example.com/acs");
        assert!(ep.response_location.is_none());
    }

    #[test]
    fn test_endpoint_with_response_location() {
        let ep = Endpoint::with_response_location(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "https://sp.example.com/slo",
            "https://sp.example.com/slo-response",
        );
        assert_eq!(
            ep.response_location.as_deref(),
            Some("https://sp.example.com/slo-response")
        );
    }

    #[test]
    fn test_endpoint_ref_to_owned() {
        let ep_ref = EndpointRef {
            binding: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
            location: "https://idp.example.com/sso",
            response_location: None,
        };
        let ep = ep_ref.to_owned();
        assert_eq!(ep.binding, "urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
        assert_eq!(ep.location, "https://idp.example.com/sso");
    }

    #[test]
    fn test_indexed_endpoint_new() {
        let ep = Endpoint::new(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "https://sp.example.com/acs",
        );
        let indexed = IndexedEndpoint::new(ep, 0);
        assert_eq!(indexed.index, 0);
        assert!(indexed.is_default.is_none());
    }

    #[test]
    fn test_indexed_endpoint_default() {
        let ep = Endpoint::new(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "https://sp.example.com/acs",
        );
        let indexed = IndexedEndpoint::new_default(ep, 0);
        assert_eq!(indexed.is_default, Some(true));
    }

    #[test]
    fn test_indexed_endpoint_ref_to_owned() {
        let ref_ = IndexedEndpointRef {
            endpoint: EndpointRef {
                binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                location: "https://sp.example.com/artifact",
                response_location: None,
            },
            index: 1,
            is_default: Some(false),
        };
        let owned = ref_.to_owned();
        assert_eq!(owned.index, 1);
        assert_eq!(owned.is_default, Some(false));
    }
}
