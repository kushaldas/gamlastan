// SAML 2.0 Metadata - AttributeAuthorityDescriptor
//
// Per saml-metadata-2.0-os Section 2.4.7

use super::endpoint::{Endpoint, EndpointRef};
use super::role_descriptor::{RoleDescriptorBase, RoleDescriptorBaseRef};
use crate::core::assertion::attribute::{Attribute, AttributeRef};

/// Borrowed AttributeAuthority Descriptor - references parsed XML.
///
/// Describes an attribute authority.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeAuthorityDescriptorRef<'a> {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBaseRef<'a>,
    /// Attribute service endpoints (1..n, required).
    pub attribute_services: Vec<EndpointRef<'a>>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<EndpointRef<'a>>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<&'a str>,
    /// Attribute profiles (0..n).
    pub attribute_profiles: Vec<&'a str>,
    /// Attributes (0..n).
    pub attributes: Vec<AttributeRef<'a>>,
}

impl<'a> AttributeAuthorityDescriptorRef<'a> {
    /// Convert to owned AttributeAuthorityDescriptor.
    pub fn to_owned(&self) -> AttributeAuthorityDescriptor {
        AttributeAuthorityDescriptor {
            base: self.base.to_owned(),
            attribute_services: self
                .attribute_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            assertion_id_request_services: self
                .assertion_id_request_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            name_id_formats: self.name_id_formats.iter().map(|s| s.to_string()).collect(),
            attribute_profiles: self
                .attribute_profiles
                .iter()
                .map(|s| s.to_string())
                .collect(),
            attributes: self.attributes.iter().map(|a| a.to_owned()).collect(),
        }
    }
}

/// Owned AttributeAuthority Descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeAuthorityDescriptor {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBase,
    /// Attribute service endpoints (1..n, required).
    pub attribute_services: Vec<Endpoint>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<Endpoint>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<String>,
    /// Attribute profiles (0..n).
    pub attribute_profiles: Vec<String>,
    /// Attributes (0..n).
    pub attributes: Vec<Attribute>,
}
