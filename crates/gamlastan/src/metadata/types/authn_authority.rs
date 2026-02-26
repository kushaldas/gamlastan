// SAML 2.0 Metadata - AuthnAuthorityDescriptor
//
// Per saml-metadata-2.0-os Section 2.4.5

use super::endpoint::{Endpoint, EndpointRef};
use super::role_descriptor::{RoleDescriptorBase, RoleDescriptorBaseRef};

/// Borrowed AuthnAuthority Descriptor - references parsed XML.
///
/// Describes an authentication authority.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnAuthorityDescriptorRef<'a> {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBaseRef<'a>,
    /// AuthnQuery service endpoints (1..n, required).
    pub authn_query_services: Vec<EndpointRef<'a>>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<EndpointRef<'a>>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<&'a str>,
}

impl<'a> AuthnAuthorityDescriptorRef<'a> {
    /// Convert to owned AuthnAuthorityDescriptor.
    pub fn to_owned(&self) -> AuthnAuthorityDescriptor {
        AuthnAuthorityDescriptor {
            base: self.base.to_owned(),
            authn_query_services: self
                .authn_query_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            assertion_id_request_services: self
                .assertion_id_request_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            name_id_formats: self.name_id_formats.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Owned AuthnAuthority Descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthnAuthorityDescriptor {
    /// Role descriptor base fields.
    pub base: RoleDescriptorBase,
    /// AuthnQuery service endpoints (1..n, required).
    pub authn_query_services: Vec<Endpoint>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<Endpoint>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<String>,
}
