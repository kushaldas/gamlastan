// SAML 2.0 Metadata - Validation
//
// Validates metadata structure and resolves endpoints.

use crate::error::MetadataError;
use crate::types::endpoint::{Endpoint, IndexedEndpoint};
use crate::types::entity_descriptor::EntityDescriptor;
use crate::types::idp::IdpSsoDescriptor;
use crate::types::sp::SpSsoDescriptor;

/// Metadata validator configuration.
pub struct MetadataValidator {
    /// Whether to require at least one SSO service for IdP descriptors.
    pub require_sso_service: bool,
    /// Whether to require at least one ACS for SP descriptors.
    pub require_acs: bool,
}

impl Default for MetadataValidator {
    fn default() -> Self {
        MetadataValidator {
            require_sso_service: true,
            require_acs: true,
        }
    }
}

impl MetadataValidator {
    /// Create a new validator with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate an EntityDescriptor.
    pub fn validate(&self, entity: &EntityDescriptor) -> Result<(), MetadataError> {
        // Check entity ID constraints
        if entity.entity_id.is_empty() {
            return Err(MetadataError::SchemaViolation(
                "EntityDescriptor entityID must not be empty".to_string(),
            ));
        }
        if entity.entity_id.len() > 1024 {
            return Err(MetadataError::SchemaViolation(format!(
                "EntityDescriptor entityID exceeds 1024 characters: {} chars",
                entity.entity_id.len()
            )));
        }

        // Validate IdP descriptors
        for idp in entity.idp_sso_descriptors() {
            self.validate_idp(idp)?;
        }

        // Validate SP descriptors
        for sp in entity.sp_sso_descriptors() {
            self.validate_sp(sp)?;
        }

        Ok(())
    }

    /// Validate an IDPSSODescriptor.
    fn validate_idp(&self, idp: &IdpSsoDescriptor) -> Result<(), MetadataError> {
        // SingleSignOnService is required (1..n)
        if self.require_sso_service && idp.single_sign_on_services.is_empty() {
            return Err(MetadataError::MissingRequiredEndpoint(
                "IDPSSODescriptor must have at least one SingleSignOnService".to_string(),
            ));
        }

        // SingleSignOnService MUST NOT have ResponseLocation
        for sso in &idp.single_sign_on_services {
            if sso.response_location.is_some() {
                return Err(MetadataError::SchemaViolation(
                    "SingleSignOnService MUST NOT have ResponseLocation".to_string(),
                ));
            }
        }

        // NameIDMappingService MUST NOT have ResponseLocation
        for nidms in &idp.name_id_mapping_services {
            if nidms.response_location.is_some() {
                return Err(MetadataError::SchemaViolation(
                    "NameIDMappingService MUST NOT have ResponseLocation".to_string(),
                ));
            }
        }

        // ArtifactResolutionService MUST NOT have ResponseLocation
        for ars in &idp.sso_base.artifact_resolution_services {
            if ars.endpoint.response_location.is_some() {
                return Err(MetadataError::SchemaViolation(
                    "ArtifactResolutionService MUST NOT have ResponseLocation".to_string(),
                ));
            }
        }

        // protocolSupportEnumeration is required
        if idp.sso_base.base.protocol_support_enumeration.is_empty() {
            return Err(MetadataError::SchemaViolation(
                "RoleDescriptor must specify at least one supported protocol".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate an SPSSODescriptor.
    fn validate_sp(&self, sp: &SpSsoDescriptor) -> Result<(), MetadataError> {
        // AssertionConsumerService is required (1..n)
        if self.require_acs && sp.assertion_consumer_services.is_empty() {
            return Err(MetadataError::MissingRequiredEndpoint(
                "SPSSODescriptor must have at least one AssertionConsumerService".to_string(),
            ));
        }

        // ArtifactResolutionService MUST NOT have ResponseLocation
        for ars in &sp.sso_base.artifact_resolution_services {
            if ars.endpoint.response_location.is_some() {
                return Err(MetadataError::SchemaViolation(
                    "ArtifactResolutionService MUST NOT have ResponseLocation".to_string(),
                ));
            }
        }

        // protocolSupportEnumeration is required
        if sp.sso_base.base.protocol_support_enumeration.is_empty() {
            return Err(MetadataError::SchemaViolation(
                "RoleDescriptor must specify at least one supported protocol".to_string(),
            ));
        }

        Ok(())
    }
}

/// Resolve the default endpoint from a list of indexed endpoints.
///
/// Per the SAML metadata spec:
/// 1. The endpoint with isDefault=true, if any
/// 2. The first endpoint with isDefault unset (not explicitly false)
/// 3. The endpoint with the lowest index
pub fn resolve_default_indexed_endpoint(endpoints: &[IndexedEndpoint]) -> Option<&IndexedEndpoint> {
    if endpoints.is_empty() {
        return None;
    }

    // 1. Look for isDefault=true
    if let Some(ep) = endpoints.iter().find(|e| e.is_default == Some(true)) {
        return Some(ep);
    }

    // 2. Look for isDefault unset (None, not Some(false))
    if let Some(ep) = endpoints.iter().find(|e| e.is_default.is_none()) {
        return Some(ep);
    }

    // 3. Lowest index
    endpoints.iter().min_by_key(|e| e.index)
}

/// Resolve an endpoint by binding URI from a list of endpoints.
pub fn resolve_endpoint_by_binding<'a>(
    endpoints: &'a [Endpoint],
    binding: &str,
) -> Option<&'a Endpoint> {
    endpoints.iter().find(|e| e.binding == binding)
}

/// Resolve an indexed endpoint by binding URI.
pub fn resolve_indexed_endpoint_by_binding<'a>(
    endpoints: &'a [IndexedEndpoint],
    binding: &str,
) -> Option<&'a IndexedEndpoint> {
    endpoints.iter().find(|e| e.endpoint.binding == binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::endpoint::{Endpoint, IndexedEndpoint};
    use crate::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use crate::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    fn make_sso_base() -> SsoDescriptorBase {
        SsoDescriptorBase {
            base: RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]),
            artifact_resolution_services: vec![],
            single_logout_services: vec![],
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        }
    }

    #[test]
    fn test_validate_empty_entity_id() {
        let entity = EntityDescriptor {
            entity_id: String::new(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };
        let v = MetadataValidator::new();
        assert!(v.validate(&entity).is_err());
    }

    #[test]
    fn test_validate_idp_missing_sso() {
        let entity = EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![IdpSsoDescriptor {
                    sso_base: make_sso_base(),
                    want_authn_requests_signed: None,
                    single_sign_on_services: vec![], // Missing!
                    name_id_mapping_services: vec![],
                    assertion_id_request_services: vec![],
                    attribute_profiles: vec![],
                    attributes: vec![],
                }],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };
        let v = MetadataValidator::new();
        let err = v.validate(&entity).unwrap_err();
        assert!(err.to_string().contains("SingleSignOnService"));
    }

    #[test]
    fn test_validate_idp_sso_response_location_rejected() {
        let entity = EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![IdpSsoDescriptor {
                    sso_base: make_sso_base(),
                    want_authn_requests_signed: None,
                    single_sign_on_services: vec![Endpoint::with_response_location(
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                        "https://idp.example.com/sso",
                        "https://idp.example.com/sso-response", // Not allowed!
                    )],
                    name_id_mapping_services: vec![],
                    assertion_id_request_services: vec![],
                    attribute_profiles: vec![],
                    attributes: vec![],
                }],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };
        let v = MetadataValidator::new();
        let err = v.validate(&entity).unwrap_err();
        assert!(err.to_string().contains("ResponseLocation"));
    }

    #[test]
    fn test_validate_sp_missing_acs() {
        let entity = EntityDescriptor {
            entity_id: "https://sp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![SpSsoDescriptor {
                    sso_base: make_sso_base(),
                    authn_requests_signed: None,
                    want_assertions_signed: None,
                    assertion_consumer_services: vec![], // Missing!
                    attribute_consuming_services: vec![],
                }],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };
        let v = MetadataValidator::new();
        let err = v.validate(&entity).unwrap_err();
        assert!(err.to_string().contains("AssertionConsumerService"));
    }

    #[test]
    fn test_resolve_default_indexed_endpoint() {
        let eps = vec![
            IndexedEndpoint::new(Endpoint::new("urn:binding:1", "https://example.com/1"), 0),
            IndexedEndpoint::new_default(
                Endpoint::new("urn:binding:2", "https://example.com/2"),
                1,
            ),
        ];
        let default = resolve_default_indexed_endpoint(&eps).unwrap();
        assert_eq!(default.index, 1); // isDefault=true wins
    }

    #[test]
    fn test_resolve_default_indexed_endpoint_none_set() {
        let eps = vec![
            IndexedEndpoint {
                endpoint: Endpoint::new("urn:binding:1", "https://example.com/1"),
                index: 2,
                is_default: None,
            },
            IndexedEndpoint {
                endpoint: Endpoint::new("urn:binding:2", "https://example.com/2"),
                index: 0,
                is_default: None,
            },
        ];
        // First with is_default=None wins (index 2 comes first in iteration)
        let default = resolve_default_indexed_endpoint(&eps).unwrap();
        assert_eq!(default.index, 2);
    }

    #[test]
    fn test_resolve_endpoint_by_binding() {
        let eps = vec![
            Endpoint::new(
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                "https://idp.example.com/sso/redirect",
            ),
            Endpoint::new(
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "https://idp.example.com/sso/post",
            ),
        ];
        let ep =
            resolve_endpoint_by_binding(&eps, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
                .unwrap();
        assert_eq!(ep.location, "https://idp.example.com/sso/post");
    }

    #[test]
    fn test_resolve_endpoint_by_binding_not_found() {
        let eps = vec![Endpoint::new(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "https://idp.example.com/sso",
        )];
        let ep = resolve_endpoint_by_binding(&eps, "urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
        assert!(ep.is_none());
    }
}
