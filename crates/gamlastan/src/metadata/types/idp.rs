// SAML 2.0 Metadata - IDPSSODescriptor
//
// Per saml-metadata-2.0-os Section 2.4.3

use super::endpoint::{Endpoint, EndpointRef};
use super::role_descriptor::{SsoDescriptorBase, SsoDescriptorBaseRef};
use crate::core::assertion::attribute::{Attribute, AttributeRef};

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

impl IdpSsoDescriptor {
    /// The first `SingleSignOnService` endpoint advertised for `binding`
    /// (e.g. [`BINDING_HTTP_REDIRECT`](crate::core::constants::BINDING_HTTP_REDIRECT)),
    /// if any.
    pub fn single_sign_on_service(&self, binding: &str) -> Option<&Endpoint> {
        self.single_sign_on_services
            .iter()
            .find(|e| e.binding == binding)
    }

    /// DER-encoded signing certificates drawn from this descriptor's key
    /// descriptors.
    ///
    /// Includes descriptors marked `use="signing"` and those with no `use`
    /// (valid for signing per metadata erratum E62); descriptors marked
    /// `use="encryption"` are skipped. Certificates are returned in document
    /// order across all matching key descriptors.
    ///
    /// As with [`KeyDescriptor::x509_certificates_der`], an empty result means
    /// "no signing trust anchor could be extracted" — whether the IdP
    /// advertises none or the KeyInfo was unparseable is deliberately
    /// indistinguishable. Callers MUST fail closed on an empty result and
    /// never treat it as permission to skip signature verification.
    pub fn signing_certificates_der(&self) -> Vec<Vec<u8>> {
        self.sso_base
            .base
            .key_descriptors
            .iter()
            .filter(|kd| kd.can_sign())
            .flat_map(|kd| kd.x509_certificates_der())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::types::entity_descriptor::{EntitiesDescriptorRef, EntityRolesRef, MetadataChildRef};
    use crate::metadata::types::endpoint::Endpoint;
    use crate::metadata::types::key_descriptor::{KeyDescriptor, KeyUse};
    use crate::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
    use crate::xml::parse_saml;

    const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    /// Build an IdpSsoDescriptor with the given key descriptors and SSO endpoints.
    fn idp(key_descriptors: Vec<KeyDescriptor>, sso: Vec<Endpoint>) -> IdpSsoDescriptor {
        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
        base.key_descriptors = key_descriptors;
        IdpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            want_authn_requests_signed: Some(true),
            single_sign_on_services: sso,
            name_id_mapping_services: vec![],
            assertion_id_request_services: vec![],
            attribute_profiles: vec![],
            attributes: vec![],
        }
    }

    /// A KeyInfo carrying a single X509Certificate whose DER is `der_bytes`
    /// (base64-encoded). Uses a tiny payload so we can assert exact bytes.
    fn key_info_with(b64: &str) -> String {
        format!(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>"
        )
    }

    fn first_real_idp_from_children<'a>(
        children: &'a [MetadataChildRef<'a>],
    ) -> Option<IdpSsoDescriptorRef<'a>> {
        for child in children {
            match child {
                MetadataChildRef::Entity(entity) => {
                    let EntityRolesRef::Roles { idp_sso, .. } = &entity.roles else {
                        continue;
                    };
                    for idp in idp_sso {
                        if idp.sso_base.base.key_descriptors.iter().any(|kd| {
                            matches!(kd.use_, None | Some(KeyUse::Signing))
                                && kd.key_info_xml.contains("X509Certificate")
                                && !kd.key_info_xml.contains("xmlns:ds=")
                        }) {
                            return Some(idp.clone());
                        }
                    }
                }
                MetadataChildRef::Entities(entities) => {
                    if let Some(idp) = first_real_idp_from_children(&entities.children) {
                        return Some(idp);
                    }
                }
            }
        }

        None
    }

    #[test]
    fn test_idp_sso_descriptor_basic() {
        let descriptor = idp(
            vec![],
            vec![Endpoint::new(REDIRECT, "https://idp.example.com/sso")],
        );
        assert_eq!(descriptor.want_authn_requests_signed, Some(true));
        assert_eq!(descriptor.single_sign_on_services.len(), 1);
    }

    #[test]
    fn test_single_sign_on_service_selection() {
        let descriptor = idp(
            vec![],
            vec![
                Endpoint::new(POST, "https://idp.example.com/sso/post"),
                Endpoint::new(REDIRECT, "https://idp.example.com/sso/redirect"),
            ],
        );

        // Returns the endpoint for the requested binding...
        assert_eq!(
            descriptor
                .single_sign_on_service(REDIRECT)
                .unwrap()
                .location,
            "https://idp.example.com/sso/redirect"
        );
        // ...and None for a binding that is not advertised.
        assert!(descriptor
            .single_sign_on_service("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact")
            .is_none());
    }

    #[test]
    fn test_single_sign_on_service_first_wins() {
        let descriptor = idp(
            vec![],
            vec![
                Endpoint::new(REDIRECT, "https://idp.example.com/first"),
                Endpoint::new(REDIRECT, "https://idp.example.com/second"),
            ],
        );
        assert_eq!(
            descriptor
                .single_sign_on_service(REDIRECT)
                .unwrap()
                .location,
            "https://idp.example.com/first"
        );
    }

    #[test]
    fn test_signing_certificates_der_excludes_encryption_key() {
        // base64("sign") = "c2lnbg==", base64("encr") = "ZW5jcg==".
        let descriptor = idp(
            vec![
                KeyDescriptor::signing(key_info_with("c2lnbg==")),
                KeyDescriptor::encryption(key_info_with("ZW5jcg==")),
            ],
            vec![],
        );
        // Only the signing descriptor's cert is returned; encryption is skipped.
        assert_eq!(
            descriptor.signing_certificates_der(),
            vec![b"sign".to_vec()]
        );
    }

    #[test]
    fn test_signing_certificates_der_includes_use_omitted() {
        // A descriptor with no `use` is signing-capable per E62.
        // base64("both") = "Ym90aA==".
        let descriptor = idp(vec![KeyDescriptor::both(key_info_with("Ym90aA=="))], vec![]);
        assert_eq!(
            descriptor.signing_certificates_der(),
            vec![b"both".to_vec()]
        );
    }

    #[test]
    fn test_signing_certificates_der_aggregates_in_document_order() {
        // base64("aaa") = "YWFh", base64("bbb") = "YmJi".
        let descriptor = idp(
            vec![
                KeyDescriptor::signing(key_info_with("YWFh")),
                KeyDescriptor::signing(key_info_with("YmJi")),
            ],
            vec![],
        );
        assert_eq!(
            descriptor.signing_certificates_der(),
            vec![b"aaa".to_vec(), b"bbb".to_vec()]
        );
    }

    #[test]
    fn test_signing_certificates_der_from_real_edugain_metadata() {
        let xml = include_str!("../../../../../edugain-v2.xml");
        let doc = uppsala::parse(xml).unwrap();
        let entities: EntitiesDescriptorRef<'_> = parse_saml(&doc).unwrap();
        let idp = first_real_idp_from_children(&entities.children)
            .expect("expected eduGAIN IdP with signing KeyInfo fragment");
        let descriptor = idp.to_owned();

        assert!(descriptor
            .sso_base
            .base
            .key_descriptors
            .iter()
            .any(|kd| kd.can_sign() && kd.key_info_xml.contains("X509Certificate")));
        assert!(!descriptor.signing_certificates_der().is_empty());
    }
}
