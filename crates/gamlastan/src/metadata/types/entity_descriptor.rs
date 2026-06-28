// SAML 2.0 Metadata - EntityDescriptor and EntitiesDescriptor
//
// Per saml-metadata-2.0-os Sections 2.3.1, 2.3.2

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use super::additional::{AdditionalMetadataLocation, AdditionalMetadataLocationRef};
use super::affiliation::{AffiliationDescriptor, AffiliationDescriptorRef};
use super::attr_authority::{AttributeAuthorityDescriptor, AttributeAuthorityDescriptorRef};
use super::authn_authority::{AuthnAuthorityDescriptor, AuthnAuthorityDescriptorRef};
use super::contact::{ContactPerson, ContactPersonRef};
use super::extensions::{Extensions, ExtensionsRef};
use super::idp::{IdpSsoDescriptor, IdpSsoDescriptorRef};
use super::md_extensions::{MdExtensions, UiInfo as MdUiInfo};
use super::organization::{Organization, OrganizationRef};
use super::pdp::{PdpDescriptor, PdpDescriptorRef};
use super::sp::{SpSsoDescriptor, SpSsoDescriptorRef};

/// Borrowed entity roles - either role descriptors or an affiliation.
///
/// An EntityDescriptor contains either a set of role descriptors
/// or an AffiliationDescriptor, but not both.
#[derive(Debug, Clone, PartialEq)]
pub enum EntityRolesRef<'a> {
    /// Role descriptors (IDP, SP, AuthnAuthority, PDP, AA).
    Roles {
        /// IDP SSO descriptors (0..n).
        idp_sso: Vec<IdpSsoDescriptorRef<'a>>,
        /// SP SSO descriptors (0..n).
        sp_sso: Vec<SpSsoDescriptorRef<'a>>,
        /// AuthnAuthority descriptors (0..n).
        authn_authority: Vec<AuthnAuthorityDescriptorRef<'a>>,
        /// AttributeAuthority descriptors (0..n).
        attr_authority: Vec<AttributeAuthorityDescriptorRef<'a>>,
        /// PDP descriptors (0..n).
        pdp: Vec<PdpDescriptorRef<'a>>,
    },
    /// Affiliation descriptor.
    Affiliation(AffiliationDescriptorRef<'a>),
}

impl<'a> EntityRolesRef<'a> {
    /// Convert to owned EntityRoles.
    pub fn to_owned(&self) -> EntityRoles {
        match self {
            EntityRolesRef::Roles {
                idp_sso,
                sp_sso,
                authn_authority,
                attr_authority,
                pdp,
            } => EntityRoles::Roles {
                idp_sso: idp_sso.iter().map(|d| d.to_owned()).collect(),
                sp_sso: sp_sso.iter().map(|d| d.to_owned()).collect(),
                authn_authority: authn_authority.iter().map(|d| d.to_owned()).collect(),
                attr_authority: attr_authority.iter().map(|d| d.to_owned()).collect(),
                pdp: pdp.iter().map(|d| d.to_owned()).collect(),
            },
            EntityRolesRef::Affiliation(a) => EntityRoles::Affiliation(a.to_owned()),
        }
    }
}

/// Owned entity roles.
#[derive(Debug, Clone, PartialEq)]
pub enum EntityRoles {
    /// Role descriptors (IDP, SP, AuthnAuthority, PDP, AA).
    Roles {
        /// IDP SSO descriptors (0..n).
        idp_sso: Vec<IdpSsoDescriptor>,
        /// SP SSO descriptors (0..n).
        sp_sso: Vec<SpSsoDescriptor>,
        /// AuthnAuthority descriptors (0..n).
        authn_authority: Vec<AuthnAuthorityDescriptor>,
        /// AttributeAuthority descriptors (0..n).
        attr_authority: Vec<AttributeAuthorityDescriptor>,
        /// PDP descriptors (0..n).
        pdp: Vec<PdpDescriptor>,
    },
    /// Affiliation descriptor.
    Affiliation(AffiliationDescriptor),
}

impl EntityRoles {
    /// Get IdP SSO descriptors, if this entity has role descriptors.
    pub fn idp_sso_descriptors(&self) -> &[IdpSsoDescriptor] {
        match self {
            EntityRoles::Roles { idp_sso, .. } => idp_sso,
            EntityRoles::Affiliation(_) => &[],
        }
    }

    /// Get SP SSO descriptors, if this entity has role descriptors.
    pub fn sp_sso_descriptors(&self) -> &[SpSsoDescriptor] {
        match self {
            EntityRoles::Roles { sp_sso, .. } => sp_sso,
            EntityRoles::Affiliation(_) => &[],
        }
    }
}

/// Borrowed EntityDescriptor - references parsed XML.
///
/// The root element describing a single SAML entity.
/// Per saml-metadata-2.0-os Section 2.3.2.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityDescriptorRef<'a> {
    /// Entity ID (required, max 1024 chars).
    pub entity_id: &'a str,
    /// Optional ID attribute.
    pub id: Option<&'a str>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<&'a str>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// The entity's roles or affiliation.
    pub roles: EntityRolesRef<'a>,
    /// Optional organization.
    pub organization: Option<OrganizationRef<'a>>,
    /// Contact persons (0..n).
    pub contact_persons: Vec<ContactPersonRef<'a>>,
    /// Additional metadata locations (0..n).
    pub additional_metadata_locations: Vec<AdditionalMetadataLocationRef<'a>>,
}

impl<'a> EntityDescriptorRef<'a> {
    /// Convert to owned EntityDescriptor.
    pub fn to_owned(&self) -> EntityDescriptor {
        EntityDescriptor {
            entity_id: self.entity_id.to_string(),
            id: self.id.map(|s| s.to_string()),
            valid_until: self.valid_until,
            cache_duration: self.cache_duration.map(|s| s.to_string()),
            has_signature: self.has_signature,
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            roles: self.roles.to_owned(),
            organization: self.organization.as_ref().map(|o| o.to_owned()),
            contact_persons: self.contact_persons.iter().map(|c| c.to_owned()).collect(),
            additional_metadata_locations: self
                .additional_metadata_locations
                .iter()
                .map(|a| a.to_owned())
                .collect(),
        }
    }
}

/// Owned EntityDescriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityDescriptor {
    /// Entity ID (required, max 1024 chars).
    pub entity_id: String,
    /// Optional ID attribute.
    pub id: Option<String>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<String>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// The entity's roles or affiliation.
    pub roles: EntityRoles,
    /// Optional organization.
    pub organization: Option<Organization>,
    /// Contact persons (0..n).
    pub contact_persons: Vec<ContactPerson>,
    /// Additional metadata locations (0..n).
    pub additional_metadata_locations: Vec<AdditionalMetadataLocation>,
}

impl EntityDescriptor {
    /// Get IdP SSO descriptors.
    pub fn idp_sso_descriptors(&self) -> &[IdpSsoDescriptor] {
        self.roles.idp_sso_descriptors()
    }

    /// Get SP SSO descriptors.
    pub fn sp_sso_descriptors(&self) -> &[SpSsoDescriptor] {
        self.roles.sp_sso_descriptors()
    }

    /// Check if this entity is an IdP (has at least one IDPSSODescriptor).
    pub fn is_idp(&self) -> bool {
        !self.idp_sso_descriptors().is_empty()
    }

    /// Check if this entity is an SP (has at least one SPSSODescriptor).
    pub fn is_sp(&self) -> bool {
        !self.sp_sso_descriptors().is_empty()
    }

    /// Parse the attribute-release-relevant metadata extensions
    /// (`mdrpi:RegistrationInfo`, `mdattr:EntityAttributes`) out of this
    /// entity's `Extensions`. Returns an empty value when there are none.
    pub fn md_extensions(&self) -> MdExtensions {
        self.extensions
            .as_ref()
            .map(MdExtensions::from_extensions)
            .unwrap_or_default()
    }

    /// The entity's `mdrpi:RegistrationInfo/@registrationAuthority`, if present.
    /// Used to select an attribute-release policy by federation operator.
    pub fn registration_authority(&self) -> Option<String> {
        self.md_extensions().registration_authority
    }

    /// The entity's published entity-category URIs
    /// (`mdattr:EntityAttributes`, `http://macedir.org/entity-category`).
    pub fn entity_categories(&self) -> Vec<String> {
        self.md_extensions().entity_categories()
    }

    /// All values of the named entity attribute from `mdattr:EntityAttributes`
    /// (e.g. `urn:oasis:names:tc:SAML:profiles:subject-id:req`).
    pub fn entity_attribute_values(&self, name: &str) -> Vec<String> {
        self.md_extensions().entity_attribute_values(name)
    }

    /// The `mdui:UIInfo` published for the SP role (`SPSSODescriptor`), if any -
    /// the display name / logo / description an IdP shows for this SP. Falls back
    /// to entity-level `Extensions`.
    pub fn sp_ui_info(&self) -> Option<MdUiInfo> {
        self.role_ui_info(self.roles.sp_sso_descriptors().iter().map(|d| &d.sso_base))
    }

    /// The `mdui:UIInfo` published for the IdP role (`IDPSSODescriptor`), if any.
    /// Falls back to entity-level `Extensions`.
    pub fn idp_ui_info(&self) -> Option<MdUiInfo> {
        self.role_ui_info(self.roles.idp_sso_descriptors().iter().map(|d| &d.sso_base))
    }

    /// First non-empty UIInfo across the given role descriptors, then the
    /// entity-level Extensions.
    fn role_ui_info<'a>(
        &self,
        roles: impl Iterator<Item = &'a super::role_descriptor::SsoDescriptorBase>,
    ) -> Option<MdUiInfo> {
        for sso_base in roles {
            if let Some(ext) = &sso_base.base.extensions {
                if let Some(ui) = MdExtensions::from_extensions(ext).ui_info {
                    if !ui.is_empty() {
                        return Some(ui);
                    }
                }
            }
        }
        self.md_extensions().ui_info.filter(|ui| !ui.is_empty())
    }

    /// The algorithm URIs (`alg:SigningMethod` / `alg:DigestMethod`) advertised
    /// for algorithm support, with duplicates removed (first occurrence kept).
    ///
    /// Sources are aggregated in a fixed order: the entity-level `Extensions`
    /// first, then the IdP SSO role descriptors, then the SP SSO role
    /// descriptors; within each source, signing methods precede digest methods
    /// (see [`MdExtensions::supported_algorithms`]). Because IdP and SP
    /// descriptors are stored in separate collections, this is NOT the original
    /// XML role-descriptor order, so callers must not treat the order as
    /// meaningful.
    ///
    /// # Security
    ///
    /// This is an **untrusted advertisement** copied verbatim from the peer's
    /// metadata, not a security control. A peer that controls its own metadata
    /// can advertise only weak algorithms (or omit strong ones) to drive a
    /// downgrade. Consumers MUST intersect this list with a local
    /// minimum-strength allowlist (see `is_broken_algorithm`) and never simply
    /// adopt the peer's advertised choice. The list also aggregates the IdP and
    /// SP roles together; a caller needing a single role must filter itself.
    pub fn supported_algorithms(&self) -> Vec<String> {
        // First-seen de-duplication: `seen` gives O(1) membership instead of the
        // O(n^2) `Vec::contains` scan, while `out` keeps the fixed aggregation
        // order documented above.
        let mut out: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut push_from = |ext: &Extensions| {
            for alg in MdExtensions::from_extensions(ext).supported_algorithms() {
                if seen.insert(alg.clone()) {
                    out.push(alg);
                }
            }
        };
        if let Some(ext) = &self.extensions {
            push_from(ext);
        }
        let idp_bases = self.roles.idp_sso_descriptors().iter().map(|d| &d.sso_base);
        let sp_bases = self.roles.sp_sso_descriptors().iter().map(|d| &d.sso_base);
        for sso_base in idp_bases.chain(sp_bases) {
            if let Some(ext) = &sso_base.base.extensions {
                push_from(ext);
            }
        }
        out
    }
}

/// A child of EntitiesDescriptor: either an EntityDescriptor or nested EntitiesDescriptor.
#[derive(Debug, Clone, PartialEq)]
pub enum MetadataChildRef<'a> {
    /// An entity descriptor.
    Entity(Box<EntityDescriptorRef<'a>>),
    /// A nested entities descriptor.
    Entities(EntitiesDescriptorRef<'a>),
}

impl<'a> MetadataChildRef<'a> {
    /// Convert to owned MetadataChild.
    pub fn to_owned(&self) -> MetadataChild {
        match self {
            MetadataChildRef::Entity(e) => MetadataChild::Entity(Box::new((**e).to_owned())),
            MetadataChildRef::Entities(e) => MetadataChild::Entities(e.to_owned()),
        }
    }
}

/// Owned child of EntitiesDescriptor.
#[derive(Debug, Clone, PartialEq)]
pub enum MetadataChild {
    /// An entity descriptor.
    Entity(Box<EntityDescriptor>),
    /// A nested entities descriptor.
    Entities(EntitiesDescriptor),
}

/// Borrowed EntitiesDescriptor - references parsed XML.
///
/// A container for multiple EntityDescriptors and/or nested EntitiesDescriptors.
/// Per saml-metadata-2.0-os Section 2.3.1.
#[derive(Debug, Clone, PartialEq)]
pub struct EntitiesDescriptorRef<'a> {
    /// Optional ID attribute.
    pub id: Option<&'a str>,
    /// Optional valid-until datetime (E76: smaller of parent/child takes precedence).
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (E76: smaller of parent/child takes precedence).
    pub cache_duration: Option<&'a str>,
    /// Optional name.
    pub name: Option<&'a str>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// Children (1..n, at least one EntityDescriptor or EntitiesDescriptor).
    pub children: Vec<MetadataChildRef<'a>>,
}

impl<'a> EntitiesDescriptorRef<'a> {
    /// Convert to owned EntitiesDescriptor.
    pub fn to_owned(&self) -> EntitiesDescriptor {
        EntitiesDescriptor {
            id: self.id.map(|s| s.to_string()),
            valid_until: self.valid_until,
            cache_duration: self.cache_duration.map(|s| s.to_string()),
            name: self.name.map(|s| s.to_string()),
            has_signature: self.has_signature,
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            children: self.children.iter().map(|c| c.to_owned()).collect(),
        }
    }
}

/// Owned EntitiesDescriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct EntitiesDescriptor {
    /// Optional ID attribute.
    pub id: Option<String>,
    /// Optional valid-until datetime (E76: smaller of parent/child takes precedence).
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (E76: smaller of parent/child takes precedence).
    pub cache_duration: Option<String>,
    /// Optional name.
    pub name: Option<String>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// Children (1..n, at least one EntityDescriptor or EntitiesDescriptor).
    pub children: Vec<MetadataChild>,
}

impl EntitiesDescriptor {
    /// Iterate over all entity descriptors (recursively flattened).
    pub fn entity_descriptors(&self) -> Vec<&EntityDescriptor> {
        let mut result = vec![];
        for child in &self.children {
            match child {
                MetadataChild::Entity(e) => result.push(e.as_ref()),
                MetadataChild::Entities(es) => result.extend(es.entity_descriptors()),
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_sp_entity(entity_id: &str) -> EntityDescriptor {
        EntityDescriptor {
            entity_id: entity_id.to_string(),
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
        }
    }

    #[test]
    fn test_entity_descriptor_metadata_extension_accessors() {
        use super::super::extensions::Extensions;

        // No Extensions: every accessor yields an empty value, never panics.
        let bare = simple_sp_entity("https://sp.example.com");
        assert_eq!(bare.registration_authority(), None);
        assert!(bare.entity_categories().is_empty());
        assert!(bare
            .entity_attribute_values("urn:oasis:names:tc:SAML:profiles:subject-id:req")
            .is_empty());
        assert_eq!(bare.md_extensions(), MdExtensions::default());

        // With RegistrationInfo + EntityAttributes, the accessors round-trip
        // through MdExtensions.
        let mut ed = simple_sp_entity("https://sp.swamid.example");
        ed.extensions = Some(Extensions::new(
            r#"
            <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
                registrationAuthority="http://www.swamid.se/"/>
            <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute Name="http://macedir.org/entity-category">
                <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req">
                <saml:AttributeValue>any</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>
            "#
            .to_string(),
        ));
        assert_eq!(
            ed.registration_authority().as_deref(),
            Some("http://www.swamid.se/")
        );
        assert_eq!(
            ed.entity_categories(),
            vec!["http://refeds.org/category/research-and-scholarship".to_string()]
        );
        assert_eq!(
            ed.entity_attribute_values("urn:oasis:names:tc:SAML:profiles:subject-id:req"),
            vec!["any".to_string()]
        );
    }

    #[test]
    fn test_entity_descriptor_ui_info_and_algorithms_from_role() {
        use super::super::extensions::Extensions;
        use super::super::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

        // An SP whose SPSSODescriptor carries mdui:UIInfo and algsupport.
        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
        base.extensions = Some(Extensions::new(
            r#"
            <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
              <mdui:DisplayName xml:lang="en">Example SP</mdui:DisplayName>
            </mdui:UIInfo>
            <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            "#
            .to_string(),
        ));
        let sp = SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            authn_requests_signed: None,
            want_assertions_signed: None,
            assertion_consumer_services: vec![],
            attribute_consuming_services: vec![],
        };
        let mut ed = simple_sp_entity("https://sp.example.com");
        ed.roles = EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![sp],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        };

        let ui = ed.sp_ui_info().expect("SP UIInfo");
        assert_eq!(ui.display_names[0].value, "Example SP");
        assert!(ed.idp_ui_info().is_none());
        assert_eq!(
            ed.supported_algorithms(),
            vec!["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string()]
        );
    }

    #[test]
    fn test_entity_descriptor_is_idp_sp() {
        let ed = simple_sp_entity("https://example.com");
        assert!(!ed.is_idp());
        assert!(!ed.is_sp());
    }

    #[test]
    fn test_entities_descriptor_flatten() {
        let entities = EntitiesDescriptor {
            id: None,
            valid_until: None,
            cache_duration: None,
            name: Some("Test Federation".to_string()),
            has_signature: false,
            extensions: None,
            children: vec![
                MetadataChild::Entity(Box::new(simple_sp_entity("https://sp1.example.com"))),
                MetadataChild::Entities(EntitiesDescriptor {
                    id: None,
                    valid_until: None,
                    cache_duration: None,
                    name: None,
                    has_signature: false,
                    extensions: None,
                    children: vec![
                        MetadataChild::Entity(Box::new(simple_sp_entity(
                            "https://sp2.example.com",
                        ))),
                        MetadataChild::Entity(Box::new(simple_sp_entity(
                            "https://sp3.example.com",
                        ))),
                    ],
                }),
            ],
        };
        let all = entities.entity_descriptors();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].entity_id, "https://sp1.example.com");
        assert_eq!(all[1].entity_id, "https://sp2.example.com");
        assert_eq!(all[2].entity_id, "https://sp3.example.com");
    }

    #[test]
    fn test_entity_roles_accessors() {
        let roles = EntityRoles::Affiliation(AffiliationDescriptor {
            affiliation_owner_id: "https://federation.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            affiliate_members: vec!["https://sp.example.com".to_string()],
            key_descriptors: vec![],
        });
        // Affiliation variant returns empty slices for SSO descriptors
        assert!(roles.idp_sso_descriptors().is_empty());
        assert!(roles.sp_sso_descriptors().is_empty());
    }
}
