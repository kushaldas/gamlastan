// SAML 2.0 Metadata - Role Descriptor types
//
// Per saml-metadata-2.0-os Sections 2.4.1, 2.4.2
//
// RoleDescriptorBase is the abstract base for all role descriptors.
// SsoDescriptorBase extends it with SSO-specific elements.

use chrono::{DateTime, Utc};

use super::contact::{ContactPerson, ContactPersonRef};
use super::endpoint::{Endpoint, EndpointRef, IndexedEndpoint, IndexedEndpointRef};
use super::extensions::{Extensions, ExtensionsRef};
use super::key_descriptor::{KeyDescriptor, KeyDescriptorRef};
use super::organization::{Organization, OrganizationRef};

/// Borrowed role descriptor base fields - references parsed XML.
///
/// Abstract type containing common fields for all role descriptors.
/// Per saml-metadata-2.0-os Section 2.4.1.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleDescriptorBaseRef<'a> {
    /// Optional ID.
    pub id: Option<&'a str>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<&'a str>,
    /// Supported protocol URIs (space-separated in XML, required).
    pub protocol_support_enumeration: Vec<&'a str>,
    /// Optional error URL.
    pub error_url: Option<&'a str>,
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// Key descriptors (0..n).
    pub key_descriptors: Vec<KeyDescriptorRef<'a>>,
    /// Optional organization.
    pub organization: Option<OrganizationRef<'a>>,
    /// Contact persons (0..n).
    pub contact_persons: Vec<ContactPersonRef<'a>>,
}

impl<'a> RoleDescriptorBaseRef<'a> {
    /// Convert to owned RoleDescriptorBase.
    pub fn to_owned(&self) -> RoleDescriptorBase {
        RoleDescriptorBase {
            id: self.id.map(|s| s.to_string()),
            valid_until: self.valid_until,
            cache_duration: self.cache_duration.map(|s| s.to_string()),
            protocol_support_enumeration: self
                .protocol_support_enumeration
                .iter()
                .map(|s| s.to_string())
                .collect(),
            error_url: self.error_url.map(|s| s.to_string()),
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            key_descriptors: self.key_descriptors.iter().map(|k| k.to_owned()).collect(),
            organization: self.organization.as_ref().map(|o| o.to_owned()),
            contact_persons: self.contact_persons.iter().map(|c| c.to_owned()).collect(),
        }
    }
}

/// Owned role descriptor base fields.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleDescriptorBase {
    /// Optional ID.
    pub id: Option<String>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<String>,
    /// Supported protocol URIs (required, at least one).
    pub protocol_support_enumeration: Vec<String>,
    /// Optional error URL.
    pub error_url: Option<String>,
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// Key descriptors (0..n).
    pub key_descriptors: Vec<KeyDescriptor>,
    /// Optional organization.
    pub organization: Option<Organization>,
    /// Contact persons (0..n).
    pub contact_persons: Vec<ContactPerson>,
}

impl RoleDescriptorBase {
    /// Create a new role descriptor base with the given protocols.
    pub fn new(protocols: Vec<String>) -> Self {
        RoleDescriptorBase {
            id: None,
            valid_until: None,
            cache_duration: None,
            protocol_support_enumeration: protocols,
            error_url: None,
            extensions: None,
            key_descriptors: vec![],
            organization: None,
            contact_persons: vec![],
        }
    }

    /// Check if a specific protocol is supported.
    pub fn supports_protocol(&self, protocol_uri: &str) -> bool {
        self.protocol_support_enumeration
            .iter()
            .any(|p| p == protocol_uri)
    }
}

/// Borrowed SSO descriptor base fields - references parsed XML.
///
/// Extends RoleDescriptorBase with SSO-specific endpoints.
/// Per saml-metadata-2.0-os Section 2.4.2.
#[derive(Debug, Clone, PartialEq)]
pub struct SsoDescriptorBaseRef<'a> {
    /// The role descriptor base fields.
    pub base: RoleDescriptorBaseRef<'a>,
    /// Artifact resolution services (0..n, indexed).
    pub artifact_resolution_services: Vec<IndexedEndpointRef<'a>>,
    /// Single logout services (0..n).
    pub single_logout_services: Vec<EndpointRef<'a>>,
    /// Manage name ID services (0..n).
    pub manage_name_id_services: Vec<EndpointRef<'a>>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<&'a str>,
}

impl<'a> SsoDescriptorBaseRef<'a> {
    /// Convert to owned SsoDescriptorBase.
    pub fn to_owned(&self) -> SsoDescriptorBase {
        SsoDescriptorBase {
            base: self.base.to_owned(),
            artifact_resolution_services: self
                .artifact_resolution_services
                .iter()
                .map(|a| a.to_owned())
                .collect(),
            single_logout_services: self
                .single_logout_services
                .iter()
                .map(|s| s.to_owned())
                .collect(),
            manage_name_id_services: self
                .manage_name_id_services
                .iter()
                .map(|m| m.to_owned())
                .collect(),
            name_id_formats: self.name_id_formats.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Owned SSO descriptor base fields.
#[derive(Debug, Clone, PartialEq)]
pub struct SsoDescriptorBase {
    /// The role descriptor base fields.
    pub base: RoleDescriptorBase,
    /// Artifact resolution services (0..n, indexed).
    /// ResponseLocation MUST be omitted per spec.
    pub artifact_resolution_services: Vec<IndexedEndpoint>,
    /// Single logout services (0..n). Can have ResponseLocation.
    pub single_logout_services: Vec<Endpoint>,
    /// Manage name ID services (0..n). Can have ResponseLocation.
    pub manage_name_id_services: Vec<Endpoint>,
    /// Supported NameID formats (0..n).
    pub name_id_formats: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_descriptor_supports_protocol() {
        let rd = RoleDescriptorBase::new(vec![
            "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            "urn:oasis:names:tc:SAML:1.1:protocol".to_string(),
        ]);
        assert!(rd.supports_protocol("urn:oasis:names:tc:SAML:2.0:protocol"));
        assert!(!rd.supports_protocol("urn:unknown"));
    }

    #[test]
    fn test_role_descriptor_ref_to_owned() {
        let r = RoleDescriptorBaseRef {
            id: Some("_rd1"),
            valid_until: None,
            cache_duration: Some("PT1H"),
            protocol_support_enumeration: vec!["urn:oasis:names:tc:SAML:2.0:protocol"],
            error_url: None,
            extensions: None,
            key_descriptors: vec![],
            organization: None,
            contact_persons: vec![],
        };
        let o = r.to_owned();
        assert_eq!(o.id.as_deref(), Some("_rd1"));
        assert_eq!(o.cache_duration.as_deref(), Some("PT1H"));
        assert_eq!(o.protocol_support_enumeration.len(), 1);
    }
}
