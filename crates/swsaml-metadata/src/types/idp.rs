// SAML 2.0 Metadata - IDPSSODescriptor
//
// Per saml-metadata-2.0-os Section 2.4.3

use super::endpoint::{Endpoint, EndpointRef};
use super::role_descriptor::{SsoDescriptorBase, SsoDescriptorBaseRef};
use swsaml_core::assertion::attribute::{Attribute, AttributeRef};

/// Borrowed IDP SSO Descriptor - references parsed XML.
///
/// Describes an identity provider's SSO capabilities.
#[derive(Debug, Clone, PartialEq)]
pub struct IdpSsoDescriptorRef<'a> {
    /// SSO descriptor base fields.
    pub sso_base: SsoDescriptorBaseRef<'a>,
    /// Whether the IdP wants AuthnRequests signed (optional, default false).
    pub want_authn_requests_signed: Option<bool>,
    /// Single sign-on service endpoints (1..n, required).
    /// ResponseLocation MUST be omitted per spec.
    pub single_sign_on_services: Vec<EndpointRef<'a>>,
    /// Name ID mapping service endpoints (0..n).
    /// ResponseLocation MUST be omitted per spec.
    pub name_id_mapping_services: Vec<EndpointRef<'a>>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<EndpointRef<'a>>,
    /// Attribute profiles (0..n).
    pub attribute_profiles: Vec<&'a str>,
    /// Attributes (0..n).
    pub attributes: Vec<AttributeRef<'a>>,
}

impl<'a> IdpSsoDescriptorRef<'a> {
    /// Convert to owned IdpSsoDescriptor.
    pub fn to_owned(&self) -> IdpSsoDescriptor {
        IdpSsoDescriptor {
            sso_base: self.sso_base.to_owned(),
            want_authn_requests_signed: self.want_authn_requests_signed,
            single_sign_on_services: self
                .single_sign_on_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            name_id_mapping_services: self
                .name_id_mapping_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            assertion_id_request_services: self
                .assertion_id_request_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            attribute_profiles: self
                .attribute_profiles
                .iter()
                .map(|s| s.to_string())
                .collect(),
            attributes: self.attributes.iter().map(|a| a.to_owned()).collect(),
        }
    }
}

/// Owned IDP SSO Descriptor - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct IdpSsoDescriptor {
    /// SSO descriptor base fields.
    pub sso_base: SsoDescriptorBase,
    /// Whether the IdP wants AuthnRequests signed (optional, default false).
    pub want_authn_requests_signed: Option<bool>,
    /// Single sign-on service endpoints (1..n, required).
    /// ResponseLocation MUST be omitted per spec.
    pub single_sign_on_services: Vec<Endpoint>,
    /// Name ID mapping service endpoints (0..n).
    /// ResponseLocation MUST be omitted per spec.
    pub name_id_mapping_services: Vec<Endpoint>,
    /// Assertion ID request service endpoints (0..n).
    pub assertion_id_request_services: Vec<Endpoint>,
    /// Attribute profiles (0..n).
    pub attribute_profiles: Vec<String>,
    /// Attributes (0..n).
    pub attributes: Vec<Attribute>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::endpoint::Endpoint;
    use crate::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    #[test]
    fn test_idp_sso_descriptor_basic() {
        let idp = IdpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base: RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ]),
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            want_authn_requests_signed: Some(true),
            single_sign_on_services: vec![Endpoint::new(
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                "https://idp.example.com/sso",
            )],
            name_id_mapping_services: vec![],
            assertion_id_request_services: vec![],
            attribute_profiles: vec![],
            attributes: vec![],
        };
        assert_eq!(idp.want_authn_requests_signed, Some(true));
        assert_eq!(idp.single_sign_on_services.len(), 1);
    }
}
