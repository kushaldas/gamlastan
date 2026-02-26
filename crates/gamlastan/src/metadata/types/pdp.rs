// SAML 2.0 Metadata - PDPDescriptor
//
// Per saml-metadata-2.0-os Section 2.4.6

use super::endpoint::{Endpoint, EndpointRef};
use super::role_descriptor::{RoleDescriptorBase, RoleDescriptorBaseRef};

/// Borrowed PDP Descriptor - references parsed XML.
///
/// Describes a policy decision point.
#[derive(Debug, Clone, PartialEq)]
pub struct PdpDescriptorRef<'a> {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBaseRef<'a>,
    /// AuthzService endpoints (1..n, required).
    pub authz_services: Vec<EndpointRef<'a>>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<EndpointRef<'a>>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<&'a str>,
}

impl<'a> PdpDescriptorRef<'a> {
    /// Convert to owned PdpDescriptor.
    pub fn to_owned(&self) -> PdpDescriptor {
        PdpDescriptor {
            base: self.base.to_owned(),
            authz_services: self.authz_services.iter().map(|s| s.to_owned()).collect(),
            assertion_id_request_services: self
                .assertion_id_request_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            name_id_formats: self.name_id_formats.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Owned PDP Descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct PdpDescriptor {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBase,
    /// AuthzService endpoints (1..n, required).
    pub authz_services: Vec<Endpoint>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<Endpoint>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<String>,
}
