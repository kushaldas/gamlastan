// SAML 2.0 Namespace URI constants
//
// References:
// - saml-core-2.0-os Section 1.3 (Common Attributes)
// - saml-metadata-2.0-os Section 2.1
// - saml-bindings-2.0-os Section 3 (various)

/// SAML 2.0 Assertion namespace
pub const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// SAML 2.0 Protocol namespace
pub const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// SAML 2.0 Metadata namespace
pub const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// W3C XML Digital Signature namespace
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// W3C XML Encryption namespace
pub const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

/// SOAP 1.1 Envelope namespace
pub const SOAP11_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// Liberty Alliance PAOS namespace
pub const PAOS_NS: &str = "urn:liberty:paos:2003-08";

/// SAML 2.0 ECP namespace
pub const ECP_NS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";

/// X.500 attribute namespace
pub const X500_NS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500";

/// DCE PAC attribute namespace
pub const DCE_NS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE";

/// XML Schema Instance namespace
pub const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// XML Schema namespace
pub const XS_NS: &str = "http://www.w3.org/2001/XMLSchema";

/// Common namespace prefixes used in SAML messages
pub mod prefix {
    /// SAML assertion prefix
    pub const SAML: &str = "saml";
    /// SAML protocol prefix
    pub const SAMLP: &str = "samlp";
    /// SAML metadata prefix
    pub const MD: &str = "md";
    /// XML Digital Signature prefix
    pub const DS: &str = "ds";
    /// XML Encryption prefix
    pub const XENC: &str = "xenc";
    /// SOAP 1.1 prefix
    pub const SOAP: &str = "S";
    /// XML Schema Instance prefix
    pub const XSI: &str = "xsi";
    /// XML Schema prefix
    pub const XS: &str = "xs";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_constants_not_empty() {
        assert!(!SAML_ASSERTION_NS.is_empty());
        assert!(!SAML_PROTOCOL_NS.is_empty());
        assert!(!SAML_METADATA_NS.is_empty());
        assert!(!XMLDSIG_NS.is_empty());
        assert!(!XMLENC_NS.is_empty());
        assert!(!SOAP11_NS.is_empty());
    }

    #[test]
    fn test_saml_namespaces_are_urns() {
        assert!(SAML_ASSERTION_NS.starts_with("urn:"));
        assert!(SAML_PROTOCOL_NS.starts_with("urn:"));
        assert!(SAML_METADATA_NS.starts_with("urn:"));
    }

    #[test]
    fn test_w3c_namespaces_are_urls() {
        assert!(XMLDSIG_NS.starts_with("http://www.w3.org/"));
        assert!(XMLENC_NS.starts_with("http://www.w3.org/"));
    }
}
