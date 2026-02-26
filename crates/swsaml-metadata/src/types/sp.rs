// SAML 2.0 Metadata - SPSSODescriptor
//
// Per saml-metadata-2.0-os Section 2.4.4

use super::endpoint::{IndexedEndpoint, IndexedEndpointRef};
use super::localized::{LocalizedName, LocalizedNameRef};
use super::role_descriptor::{SsoDescriptorBase, SsoDescriptorBaseRef};
use swsaml_core::assertion::attribute::{Attribute, AttributeRef};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::endpoint::{Endpoint, IndexedEndpoint};
    use crate::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    #[test]
    fn test_sp_sso_descriptor_basic() {
        let sp = SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base: RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ]),
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
        };
        assert_eq!(sp.authn_requests_signed, Some(true));
        assert_eq!(sp.assertion_consumer_services.len(), 1);
        assert_eq!(sp.assertion_consumer_services[0].is_default, Some(true));
    }
}
