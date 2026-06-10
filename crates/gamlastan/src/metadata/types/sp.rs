// SAML 2.0 Metadata - SPSSODescriptor
//
// Per saml-metadata-2.0-os Section 2.4.4

use super::endpoint::{IndexedEndpoint, IndexedEndpointRef};
use super::localized::{LocalizedName, LocalizedNameRef};
use super::role_descriptor::{SsoDescriptorBase, SsoDescriptorBaseRef};
use crate::core::assertion::attribute::{Attribute, AttributeRef};

/// Borrowed requested attribute - references parsed XML.
///
/// Per saml-metadata-2.0-os Section 2.4.4.1.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestedAttributeRef<'a> {
    /// The attribute base fields.
    pub attribute: AttributeRef<'a>,
    /// Whether this attribute is required (optional, default false).
    pub is_required: Option<bool>,
}

impl<'a> RequestedAttributeRef<'a> {
    /// Convert to owned RequestedAttribute.
    pub fn to_owned(&self) -> RequestedAttribute {
        RequestedAttribute {
            attribute: self.attribute.to_owned(),
            is_required: self.is_required,
        }
    }
}

/// Owned requested attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestedAttribute {
    /// The attribute base fields.
    pub attribute: Attribute,
    /// Whether this attribute is required (optional, default false).
    pub is_required: Option<bool>,
}

/// Borrowed attribute consuming service - references parsed XML.
///
/// Per saml-metadata-2.0-os Section 2.4.4.1.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeConsumingServiceRef<'a> {
    /// The index of this service (required).
    pub index: u16,
    /// Whether this is the default service (optional).
    pub is_default: Option<bool>,
    /// Service names (1..n, required).
    pub service_names: Vec<LocalizedNameRef<'a>>,
    /// Service descriptions (0..n).
    pub service_descriptions: Vec<LocalizedNameRef<'a>>,
    /// Requested attributes (1..n, required).
    pub requested_attributes: Vec<RequestedAttributeRef<'a>>,
}

impl<'a> AttributeConsumingServiceRef<'a> {
    /// Convert to owned AttributeConsumingService.
    pub fn to_owned(&self) -> AttributeConsumingService {
        AttributeConsumingService {
            index: self.index,
            is_default: self.is_default,
            service_names: self.service_names.iter().map(|n| n.to_owned()).collect(),
            service_descriptions: self
                .service_descriptions
                .iter()
                .map(|n| n.to_owned())
                .collect(),
            requested_attributes: self
                .requested_attributes
                .iter()
                .map(|r| r.to_owned())
                .collect(),
        }
    }
}

/// Owned attribute consuming service.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeConsumingService {
    /// The index of this service (required).
    pub index: u16,
    /// Whether this is the default service (optional).
    pub is_default: Option<bool>,
    /// Service names (1..n, required).
    pub service_names: Vec<LocalizedName>,
    /// Service descriptions (0..n).
    pub service_descriptions: Vec<LocalizedName>,
    /// Requested attributes (1..n, required).
    pub requested_attributes: Vec<RequestedAttribute>,
}

/// Borrowed SP SSO Descriptor - references parsed XML.
///
/// Per saml-metadata-2.0-os Section 2.4.4.
#[derive(Debug, Clone, PartialEq)]
pub struct SpSsoDescriptorRef<'a> {
    /// SSO descriptor base fields.
    pub sso_base: SsoDescriptorBaseRef<'a>,
    /// Whether the SP signs AuthnRequests (optional, default false).
    pub authn_requests_signed: Option<bool>,
    /// Whether the SP wants assertions signed (optional, default false).
    pub want_assertions_signed: Option<bool>,
    /// Assertion consumer service endpoints (1..n, required, indexed).
    pub assertion_consumer_services: Vec<IndexedEndpointRef<'a>>,
    /// Attribute consuming services (0..n).
    pub attribute_consuming_services: Vec<AttributeConsumingServiceRef<'a>>,
}

impl<'a> SpSsoDescriptorRef<'a> {
    /// Convert to owned SpSsoDescriptor.
    pub fn to_owned(&self) -> SpSsoDescriptor {
        SpSsoDescriptor {
            sso_base: self.sso_base.to_owned(),
            authn_requests_signed: self.authn_requests_signed,
            want_assertions_signed: self.want_assertions_signed,
            assertion_consumer_services: self
                .assertion_consumer_services
                .iter()
                .map(|a| a.to_owned())
                .collect(),
            attribute_consuming_services: self
                .attribute_consuming_services
                .iter()
                .map(|a| a.to_owned())
                .collect(),
        }
    }
}

/// Owned SP SSO Descriptor - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct SpSsoDescriptor {
    /// SSO descriptor base fields.
    pub sso_base: SsoDescriptorBase,
    /// Whether the SP signs AuthnRequests (optional, default false).
    pub authn_requests_signed: Option<bool>,
    /// Whether the SP wants assertions signed (optional, default false).
    pub want_assertions_signed: Option<bool>,
    /// Assertion consumer service endpoints (1..n, required, indexed).
    pub assertion_consumer_services: Vec<IndexedEndpoint>,
    /// Attribute consuming services (0..n).
    pub attribute_consuming_services: Vec<AttributeConsumingService>,
}

impl SpSsoDescriptor {
    /// DER-encoded signing certificates drawn from this descriptor's key
    /// descriptors.
    ///
    /// Includes descriptors marked `use="signing"` and those with no `use`
    /// (valid for signing per metadata erratum E62); descriptors marked
    /// `use="encryption"` are skipped. Certificates are returned in document
    /// order across all matching key descriptors.
    ///
    /// As with [`KeyDescriptor::x509_certificates_der`], an empty result means
    /// "no signing trust anchor could be extracted" — whether the SP
    /// advertises none or the KeyInfo was unparseable is deliberately
    /// indistinguishable. Callers MUST fail closed on an empty result and
    /// never treat it as permission to skip signature verification.
    ///
    /// [`KeyDescriptor::x509_certificates_der`]: crate::metadata::types::key_descriptor::KeyDescriptor::x509_certificates_der
    pub fn signing_certificates_der(&self) -> Vec<Vec<u8>> {
        self.sso_base
            .base
            .key_descriptors
            .iter()
            .filter(|kd| kd.can_sign())
            .flat_map(|kd| kd.x509_certificates_der())
            .collect()
    }

    /// DER-encoded encryption certificates drawn from this descriptor's key
    /// descriptors.
    ///
    /// Includes descriptors marked `use="encryption"` and those with no `use`
    /// (valid for encryption per metadata erratum E62); descriptors marked
    /// `use="signing"` are skipped. Certificates are returned in document
    /// order across all matching key descriptors.
    pub fn encryption_certificates_der(&self) -> Vec<Vec<u8>> {
        self.sso_base
            .base
            .key_descriptors
            .iter()
            .filter(|kd| kd.can_encrypt())
            .flat_map(|kd| kd.x509_certificates_der())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use crate::metadata::types::key_descriptor::KeyDescriptor;
    use crate::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    fn sp_with_keys(key_descriptors: Vec<KeyDescriptor>) -> SpSsoDescriptor {
        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
        base.key_descriptors = key_descriptors;
        SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            authn_requests_signed: Some(true),
            want_assertions_signed: Some(true),
            assertion_consumer_services: vec![IndexedEndpoint::new_default(
                Endpoint::new(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "https://sp.example.com/acs",
                ),
                0,
            )],
            attribute_consuming_services: vec![],
        }
    }

    /// A KeyInfo carrying a single X509Certificate whose DER is the base64
    /// payload — tiny payloads let the tests assert exact bytes.
    fn key_info_with(b64: &str) -> String {
        format!(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>"
        )
    }

    #[test]
    fn test_sp_sso_descriptor_basic() {
        let sp = sp_with_keys(vec![]);
        assert_eq!(sp.authn_requests_signed, Some(true));
        assert_eq!(sp.assertion_consumer_services.len(), 1);
        assert_eq!(sp.assertion_consumer_services[0].is_default, Some(true));
    }

    #[test]
    fn test_signing_certificates_der_excludes_encryption_key() {
        // base64("sign") = "c2lnbg==", base64("encr") = "ZW5jcg==".
        let sp = sp_with_keys(vec![
            KeyDescriptor::signing(key_info_with("c2lnbg==")),
            KeyDescriptor::encryption(key_info_with("ZW5jcg==")),
        ]);
        assert_eq!(sp.signing_certificates_der(), vec![b"sign".to_vec()]);
    }

    #[test]
    fn test_encryption_certificates_der_excludes_signing_key() {
        let sp = sp_with_keys(vec![
            KeyDescriptor::signing(key_info_with("c2lnbg==")),
            KeyDescriptor::encryption(key_info_with("ZW5jcg==")),
        ]);
        assert_eq!(sp.encryption_certificates_der(), vec![b"encr".to_vec()]);
    }

    #[test]
    fn test_use_omitted_key_serves_both_roles() {
        // A descriptor with no `use` is valid for both roles per E62.
        // base64("both") = "Ym90aA==".
        let sp = sp_with_keys(vec![KeyDescriptor::both(key_info_with("Ym90aA=="))]);
        assert_eq!(sp.signing_certificates_der(), vec![b"both".to_vec()]);
        assert_eq!(sp.encryption_certificates_der(), vec![b"both".to_vec()]);
    }
}
