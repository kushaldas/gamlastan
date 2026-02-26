// SamlDeserialize implementations for metadata Ref types.
//
// Each impl deserializes from an uppsala Document node into the zero-copy
// borrowed SAML metadata type, with all &str fields borrowing from the
// document buffer.
//
// References:
// - saml-metadata-2.0-os Sections 2.2-2.5
// - Errata: E62, E68, E69, E76, E91

use uppsala::{Document, NodeId};

use crate::core::assertion::attribute::AttributeRef;
use crate::core::namespace::{SAML_ASSERTION_NS, SAML_METADATA_NS, XMLDSIG_NS};

use crate::xml::deserialize::SamlDeserialize;
use crate::xml::error::XmlError;
use crate::xml::helpers::{
    find_child_element, find_child_elements, optional_attribute, parse_optional_bool_attr,
    parse_optional_datetime_attr, parse_optional_u16_attr, required_attribute, verify_element,
};

use crate::metadata::types::additional::AdditionalMetadataLocationRef;
use crate::metadata::types::affiliation::AffiliationDescriptorRef;
use crate::metadata::types::attr_authority::AttributeAuthorityDescriptorRef;
use crate::metadata::types::authn_authority::AuthnAuthorityDescriptorRef;
use crate::metadata::types::contact::{ContactPersonRef, ContactType};
use crate::metadata::types::endpoint::{EndpointRef, IndexedEndpointRef};
use crate::metadata::types::entity_descriptor::{
    EntitiesDescriptorRef, EntityDescriptorRef, EntityRolesRef, MetadataChildRef,
};
use crate::metadata::types::extensions::ExtensionsRef;
use crate::metadata::types::idp::IdpSsoDescriptorRef;
use crate::metadata::types::key_descriptor::{EncryptionMethodRef, KeyDescriptorRef, KeyUse};
use crate::metadata::types::localized::{LocalizedNameRef, LocalizedUriRef};
use crate::metadata::types::organization::OrganizationRef;
use crate::metadata::types::pdp::PdpDescriptorRef;
use crate::metadata::types::role_descriptor::{RoleDescriptorBaseRef, SsoDescriptorBaseRef};
use crate::metadata::types::sp::{
    AttributeConsumingServiceRef, RequestedAttributeRef, SpSsoDescriptorRef,
};

/// XML namespace for xml:lang attribute.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

// ── Endpoint ───────────────────────────────────────────────────────────────

/// Deserialize an EndpointRef from any element with EndpointType attributes.
/// Does NOT verify the element name since it's used for various endpoint elements.
fn deserialize_endpoint_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<EndpointRef<'a>, XmlError> {
    let binding = required_attribute(doc, node, "Binding")?;
    let location = required_attribute(doc, node, "Location")?;
    let response_location = optional_attribute(doc, node, "ResponseLocation");
    Ok(EndpointRef {
        binding,
        location,
        response_location,
    })
}

/// Deserialize an IndexedEndpointRef from any element with IndexedEndpointType attributes.
fn deserialize_indexed_endpoint_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<IndexedEndpointRef<'a>, XmlError> {
    let endpoint = deserialize_endpoint_ref(doc, node)?;
    let index =
        parse_optional_u16_attr(doc, node, "index")?.ok_or_else(|| XmlError::MissingAttribute {
            element: doc
                .element(node)
                .map(|e| e.name.local_name.to_string())
                .unwrap_or_default(),
            attribute: "index".to_string(),
        })?;
    let is_default = parse_optional_bool_attr(doc, node, "isDefault")?;
    Ok(IndexedEndpointRef {
        endpoint,
        index,
        is_default,
    })
}

// ── Localized types ────────────────────────────────────────────────────────

fn deserialize_localized_name_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<LocalizedNameRef<'a>, XmlError> {
    let lang = doc
        .element(node)
        .and_then(|e| e.get_attribute_ns(XML_NS, "lang"))
        .or_else(|| optional_attribute(doc, node, "xml:lang"))
        .unwrap_or("en");
    let value = doc.element_text(node).unwrap_or("");
    Ok(LocalizedNameRef { lang, value })
}

fn deserialize_localized_uri_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<LocalizedUriRef<'a>, XmlError> {
    let lang = doc
        .element(node)
        .and_then(|e| e.get_attribute_ns(XML_NS, "lang"))
        .or_else(|| optional_attribute(doc, node, "xml:lang"))
        .unwrap_or("en");
    let value = doc.element_text(node).unwrap_or("");
    Ok(LocalizedUriRef { lang, value })
}

// ── Extensions ─────────────────────────────────────────────────────────────

fn deserialize_extensions_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<ExtensionsRef<'a>, XmlError> {
    // Store the raw XML source of the Extensions element's children.
    // We use node_source for the whole element.
    let raw_xml = doc.node_source(node).unwrap_or("");
    Ok(ExtensionsRef { raw_xml })
}

// ── EncryptionMethod ───────────────────────────────────────────────────────

fn deserialize_encryption_method_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<EncryptionMethodRef<'a>, XmlError> {
    let algorithm = required_attribute(doc, node, "Algorithm")?;
    // KeySize child element (optional)
    let key_size = find_child_element(doc, node, SAML_METADATA_NS, "KeySize")
        .or_else(|| {
            // KeySize may be in xenc namespace
            find_child_element(doc, node, "http://www.w3.org/2001/04/xmlenc#", "KeySize")
        })
        .map(|n| {
            let text = doc.element_text(n).unwrap_or("");
            text.parse::<u32>()
                .map_err(|_| XmlError::InvalidInteger(text.to_string()))
        })
        .transpose()?;
    // OAEPparams child element (optional)
    let oaep_params = find_child_element(doc, node, SAML_METADATA_NS, "OAEPparams")
        .or_else(|| {
            find_child_element(doc, node, "http://www.w3.org/2001/04/xmlenc#", "OAEPparams")
        })
        .map(|n| doc.element_text(n).unwrap_or(""));
    Ok(EncryptionMethodRef {
        algorithm,
        key_size,
        oaep_params,
    })
}

// ── KeyDescriptor ──────────────────────────────────────────────────────────

fn deserialize_key_descriptor_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<KeyDescriptorRef<'a>, XmlError> {
    let use_ = optional_attribute(doc, node, "use")
        .map(|s| {
            s.parse::<KeyUse>()
                .map_err(|_| XmlError::InvalidAttributeValue {
                    element: "KeyDescriptor".to_string(),
                    attribute: "use".to_string(),
                    value: s.to_string(),
                })
        })
        .transpose()?;

    // ds:KeyInfo - store raw XML
    let key_info_xml = find_child_element(doc, node, XMLDSIG_NS, "KeyInfo")
        .map(|n| doc.node_source(n).unwrap_or(""))
        .unwrap_or("");

    // EncryptionMethod elements (in md namespace)
    let em_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "EncryptionMethod");
    // Also check xenc namespace
    let mut encryption_methods = Vec::new();
    for em_node in &em_nodes {
        encryption_methods.push(deserialize_encryption_method_ref(doc, *em_node)?);
    }
    let xenc_em_nodes = find_child_elements(
        doc,
        node,
        "http://www.w3.org/2001/04/xmlenc#",
        "EncryptionMethod",
    );
    for em_node in &xenc_em_nodes {
        encryption_methods.push(deserialize_encryption_method_ref(doc, *em_node)?);
    }

    Ok(KeyDescriptorRef {
        use_,
        key_info_xml,
        encryption_methods,
    })
}

// ── Organization ───────────────────────────────────────────────────────────

fn deserialize_organization_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<OrganizationRef<'a>, XmlError> {
    let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
        .map(|n| deserialize_extensions_ref(doc, n))
        .transpose()?;

    let name_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "OrganizationName");
    let mut organization_names = Vec::with_capacity(name_nodes.len());
    for n in name_nodes {
        organization_names.push(deserialize_localized_name_ref(doc, n)?);
    }

    let display_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "OrganizationDisplayName");
    let mut organization_display_names = Vec::with_capacity(display_nodes.len());
    for n in display_nodes {
        organization_display_names.push(deserialize_localized_name_ref(doc, n)?);
    }

    let url_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "OrganizationURL");
    let mut organization_urls = Vec::with_capacity(url_nodes.len());
    for n in url_nodes {
        organization_urls.push(deserialize_localized_uri_ref(doc, n)?);
    }

    Ok(OrganizationRef {
        extensions,
        organization_names,
        organization_display_names,
        organization_urls,
    })
}

// ── ContactPerson ──────────────────────────────────────────────────────────

fn deserialize_contact_person_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<ContactPersonRef<'a>, XmlError> {
    let contact_type_str = required_attribute(doc, node, "contactType")?;
    let contact_type: ContactType =
        contact_type_str
            .parse()
            .map_err(|_| XmlError::InvalidAttributeValue {
                element: "ContactPerson".to_string(),
                attribute: "contactType".to_string(),
                value: contact_type_str.to_string(),
            })?;

    let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
        .map(|n| deserialize_extensions_ref(doc, n))
        .transpose()?;

    let company = find_child_element(doc, node, SAML_METADATA_NS, "Company")
        .map(|n| doc.element_text(n).unwrap_or(""));

    let given_name = find_child_element(doc, node, SAML_METADATA_NS, "GivenName")
        .map(|n| doc.element_text(n).unwrap_or(""));

    let sur_name = find_child_element(doc, node, SAML_METADATA_NS, "SurName")
        .map(|n| doc.element_text(n).unwrap_or(""));

    let email_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "EmailAddress");
    let mut email_addresses = Vec::with_capacity(email_nodes.len());
    for n in email_nodes {
        email_addresses.push(doc.element_text(n).unwrap_or(""));
    }

    let phone_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "TelephoneNumber");
    let mut telephone_numbers = Vec::with_capacity(phone_nodes.len());
    for n in phone_nodes {
        telephone_numbers.push(doc.element_text(n).unwrap_or(""));
    }

    Ok(ContactPersonRef {
        contact_type,
        extensions,
        company,
        given_name,
        sur_name,
        email_addresses,
        telephone_numbers,
    })
}

// ── AdditionalMetadataLocation ─────────────────────────────────────────────

fn deserialize_additional_metadata_location_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<AdditionalMetadataLocationRef<'a>, XmlError> {
    let namespace = required_attribute(doc, node, "namespace")?;
    let location = doc.element_text(node).unwrap_or("");
    Ok(AdditionalMetadataLocationRef {
        namespace,
        location,
    })
}

// ── RoleDescriptorBase ─────────────────────────────────────────────────────

fn deserialize_role_descriptor_base_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<RoleDescriptorBaseRef<'a>, XmlError> {
    let id = optional_attribute(doc, node, "ID");
    let valid_until = parse_optional_datetime_attr(doc, node, "validUntil")?;
    let cache_duration = optional_attribute(doc, node, "cacheDuration");
    let error_url = optional_attribute(doc, node, "errorURL");

    // protocolSupportEnumeration is required, space-separated
    let pse_str = required_attribute(doc, node, "protocolSupportEnumeration")?;
    let protocol_support_enumeration: Vec<&str> = pse_str.split_whitespace().collect();

    let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
        .map(|n| deserialize_extensions_ref(doc, n))
        .transpose()?;

    let kd_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "KeyDescriptor");
    let mut key_descriptors = Vec::with_capacity(kd_nodes.len());
    for n in kd_nodes {
        key_descriptors.push(deserialize_key_descriptor_ref(doc, n)?);
    }

    let organization = find_child_element(doc, node, SAML_METADATA_NS, "Organization")
        .map(|n| deserialize_organization_ref(doc, n))
        .transpose()?;

    let cp_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ContactPerson");
    let mut contact_persons = Vec::with_capacity(cp_nodes.len());
    for n in cp_nodes {
        contact_persons.push(deserialize_contact_person_ref(doc, n)?);
    }

    Ok(RoleDescriptorBaseRef {
        id,
        valid_until,
        cache_duration,
        protocol_support_enumeration,
        error_url,
        extensions,
        key_descriptors,
        organization,
        contact_persons,
    })
}

// ── SsoDescriptorBase ──────────────────────────────────────────────────────

fn deserialize_sso_descriptor_base_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<SsoDescriptorBaseRef<'a>, XmlError> {
    let base = deserialize_role_descriptor_base_ref(doc, node)?;

    let ars_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ArtifactResolutionService");
    let mut artifact_resolution_services = Vec::with_capacity(ars_nodes.len());
    for n in ars_nodes {
        artifact_resolution_services.push(deserialize_indexed_endpoint_ref(doc, n)?);
    }

    let slo_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "SingleLogoutService");
    let mut single_logout_services = Vec::with_capacity(slo_nodes.len());
    for n in slo_nodes {
        single_logout_services.push(deserialize_endpoint_ref(doc, n)?);
    }

    let mnid_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ManageNameIDService");
    let mut manage_name_id_services = Vec::with_capacity(mnid_nodes.len());
    for n in mnid_nodes {
        manage_name_id_services.push(deserialize_endpoint_ref(doc, n)?);
    }

    let nid_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "NameIDFormat");
    let mut name_id_formats = Vec::with_capacity(nid_nodes.len());
    for n in nid_nodes {
        name_id_formats.push(doc.element_text(n).unwrap_or(""));
    }

    Ok(SsoDescriptorBaseRef {
        base,
        artifact_resolution_services,
        single_logout_services,
        manage_name_id_services,
        name_id_formats,
    })
}

// ── IdpSsoDescriptor ───────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for IdpSsoDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "IDPSSODescriptor")?;
        let sso_base = deserialize_sso_descriptor_base_ref(doc, node)?;
        let want_authn_requests_signed =
            parse_optional_bool_attr(doc, node, "WantAuthnRequestsSigned")?;

        let sso_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "SingleSignOnService");
        let mut single_sign_on_services = Vec::with_capacity(sso_nodes.len());
        for n in sso_nodes {
            single_sign_on_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let nidm_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "NameIDMappingService");
        let mut name_id_mapping_services = Vec::with_capacity(nidm_nodes.len());
        for n in nidm_nodes {
            name_id_mapping_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let aidrs_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AssertionIDRequestService");
        let mut assertion_id_request_services = Vec::with_capacity(aidrs_nodes.len());
        for n in aidrs_nodes {
            assertion_id_request_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let ap_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AttributeProfile");
        let mut attribute_profiles = Vec::with_capacity(ap_nodes.len());
        for n in ap_nodes {
            attribute_profiles.push(doc.element_text(n).unwrap_or(""));
        }

        let attr_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Attribute");
        let mut attributes = Vec::with_capacity(attr_nodes.len());
        for n in attr_nodes {
            attributes.push(AttributeRef::from_xml(doc, n)?);
        }

        Ok(IdpSsoDescriptorRef {
            sso_base,
            want_authn_requests_signed,
            single_sign_on_services,
            name_id_mapping_services,
            assertion_id_request_services,
            attribute_profiles,
            attributes,
        })
    }
}

// ── RequestedAttribute ─────────────────────────────────────────────────────

fn deserialize_requested_attribute_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<RequestedAttributeRef<'a>, XmlError> {
    // RequestedAttribute has the same attrs as Attribute plus isRequired.
    // We reuse the Attribute deserialization pattern but on a different element name.
    let name = required_attribute(doc, node, "Name")?;
    let name_format = optional_attribute(doc, node, "NameFormat");
    let friendly_name = optional_attribute(doc, node, "FriendlyName");
    let is_required = parse_optional_bool_attr(doc, node, "isRequired")?;

    let value_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AttributeValue");
    let mut values = Vec::with_capacity(value_nodes.len());
    for val_node in value_nodes {
        use crate::core::assertion::attribute::AttributeValueRef;
        values.push(AttributeValueRef::from_xml(doc, val_node)?);
    }

    Ok(RequestedAttributeRef {
        attribute: AttributeRef {
            name,
            name_format,
            friendly_name,
            values,
        },
        is_required,
    })
}

// ── AttributeConsumingService ──────────────────────────────────────────────

fn deserialize_attribute_consuming_service_ref<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<AttributeConsumingServiceRef<'a>, XmlError> {
    let index =
        parse_optional_u16_attr(doc, node, "index")?.ok_or_else(|| XmlError::MissingAttribute {
            element: "AttributeConsumingService".to_string(),
            attribute: "index".to_string(),
        })?;
    let is_default = parse_optional_bool_attr(doc, node, "isDefault")?;

    let sn_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ServiceName");
    let mut service_names = Vec::with_capacity(sn_nodes.len());
    for n in sn_nodes {
        service_names.push(deserialize_localized_name_ref(doc, n)?);
    }

    let sd_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ServiceDescription");
    let mut service_descriptions = Vec::with_capacity(sd_nodes.len());
    for n in sd_nodes {
        service_descriptions.push(deserialize_localized_name_ref(doc, n)?);
    }

    let ra_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "RequestedAttribute");
    let mut requested_attributes = Vec::with_capacity(ra_nodes.len());
    for n in ra_nodes {
        requested_attributes.push(deserialize_requested_attribute_ref(doc, n)?);
    }

    Ok(AttributeConsumingServiceRef {
        index,
        is_default,
        service_names,
        service_descriptions,
        requested_attributes,
    })
}

// ── SpSsoDescriptor ────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for SpSsoDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "SPSSODescriptor")?;
        let sso_base = deserialize_sso_descriptor_base_ref(doc, node)?;
        let authn_requests_signed = parse_optional_bool_attr(doc, node, "AuthnRequestsSigned")?;
        let want_assertions_signed = parse_optional_bool_attr(doc, node, "WantAssertionsSigned")?;

        let acs_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AssertionConsumerService");
        let mut assertion_consumer_services = Vec::with_capacity(acs_nodes.len());
        for n in acs_nodes {
            assertion_consumer_services.push(deserialize_indexed_endpoint_ref(doc, n)?);
        }

        let acser_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AttributeConsumingService");
        let mut attribute_consuming_services = Vec::with_capacity(acser_nodes.len());
        for n in acser_nodes {
            attribute_consuming_services.push(deserialize_attribute_consuming_service_ref(doc, n)?);
        }

        Ok(SpSsoDescriptorRef {
            sso_base,
            authn_requests_signed,
            want_assertions_signed,
            assertion_consumer_services,
            attribute_consuming_services,
        })
    }
}

// ── AuthnAuthorityDescriptor ───────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthnAuthorityDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "AuthnAuthorityDescriptor")?;
        let base = deserialize_role_descriptor_base_ref(doc, node)?;

        let aqs_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AuthnQueryService");
        let mut authn_query_services = Vec::with_capacity(aqs_nodes.len());
        for n in aqs_nodes {
            authn_query_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let aidrs_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AssertionIDRequestService");
        let mut assertion_id_request_services = Vec::with_capacity(aidrs_nodes.len());
        for n in aidrs_nodes {
            assertion_id_request_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let nid_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "NameIDFormat");
        let mut name_id_formats = Vec::with_capacity(nid_nodes.len());
        for n in nid_nodes {
            name_id_formats.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(AuthnAuthorityDescriptorRef {
            base,
            authn_query_services,
            assertion_id_request_services,
            name_id_formats,
        })
    }
}

// ── PdpDescriptor ──────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for PdpDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "PDPDescriptor")?;
        let base = deserialize_role_descriptor_base_ref(doc, node)?;

        let az_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AuthzService");
        let mut authz_services = Vec::with_capacity(az_nodes.len());
        for n in az_nodes {
            authz_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let aidrs_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AssertionIDRequestService");
        let mut assertion_id_request_services = Vec::with_capacity(aidrs_nodes.len());
        for n in aidrs_nodes {
            assertion_id_request_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let nid_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "NameIDFormat");
        let mut name_id_formats = Vec::with_capacity(nid_nodes.len());
        for n in nid_nodes {
            name_id_formats.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(PdpDescriptorRef {
            base,
            authz_services,
            assertion_id_request_services,
            name_id_formats,
        })
    }
}

// ── AttributeAuthorityDescriptor ───────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AttributeAuthorityDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "AttributeAuthorityDescriptor")?;
        let base = deserialize_role_descriptor_base_ref(doc, node)?;

        let as_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AttributeService");
        let mut attribute_services = Vec::with_capacity(as_nodes.len());
        for n in as_nodes {
            attribute_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let aidrs_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AssertionIDRequestService");
        let mut assertion_id_request_services = Vec::with_capacity(aidrs_nodes.len());
        for n in aidrs_nodes {
            assertion_id_request_services.push(deserialize_endpoint_ref(doc, n)?);
        }

        let nid_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "NameIDFormat");
        let mut name_id_formats = Vec::with_capacity(nid_nodes.len());
        for n in nid_nodes {
            name_id_formats.push(doc.element_text(n).unwrap_or(""));
        }

        let ap_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AttributeProfile");
        let mut attribute_profiles = Vec::with_capacity(ap_nodes.len());
        for n in ap_nodes {
            attribute_profiles.push(doc.element_text(n).unwrap_or(""));
        }

        let attr_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Attribute");
        let mut attributes = Vec::with_capacity(attr_nodes.len());
        for n in attr_nodes {
            attributes.push(AttributeRef::from_xml(doc, n)?);
        }

        Ok(AttributeAuthorityDescriptorRef {
            base,
            attribute_services,
            assertion_id_request_services,
            name_id_formats,
            attribute_profiles,
            attributes,
        })
    }
}

// ── AffiliationDescriptor ──────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AffiliationDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "AffiliationDescriptor")?;
        let affiliation_owner_id = required_attribute(doc, node, "affiliationOwnerID")?;
        let id = optional_attribute(doc, node, "ID");
        let valid_until = parse_optional_datetime_attr(doc, node, "validUntil")?;
        let cache_duration = optional_attribute(doc, node, "cacheDuration");
        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
            .map(|n| deserialize_extensions_ref(doc, n))
            .transpose()?;

        let member_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "AffiliateMember");
        let mut affiliate_members = Vec::with_capacity(member_nodes.len());
        for n in member_nodes {
            affiliate_members.push(doc.element_text(n).unwrap_or(""));
        }

        let kd_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "KeyDescriptor");
        let mut key_descriptors = Vec::with_capacity(kd_nodes.len());
        for n in kd_nodes {
            key_descriptors.push(deserialize_key_descriptor_ref(doc, n)?);
        }

        Ok(AffiliationDescriptorRef {
            affiliation_owner_id,
            id,
            valid_until,
            cache_duration,
            has_signature,
            extensions,
            affiliate_members,
            key_descriptors,
        })
    }
}

// ── EntityDescriptor ───────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for EntityDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "EntityDescriptor")?;
        let entity_id = required_attribute(doc, node, "entityID")?;
        let id = optional_attribute(doc, node, "ID");
        let valid_until = parse_optional_datetime_attr(doc, node, "validUntil")?;
        let cache_duration = optional_attribute(doc, node, "cacheDuration");
        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
            .map(|n| deserialize_extensions_ref(doc, n))
            .transpose()?;

        // Determine: roles or affiliation?
        let affiliation_node =
            find_child_element(doc, node, SAML_METADATA_NS, "AffiliationDescriptor");

        let roles = if let Some(aff_node) = affiliation_node {
            EntityRolesRef::Affiliation(AffiliationDescriptorRef::from_xml(doc, aff_node)?)
        } else {
            // Collect role descriptors
            let idp_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "IDPSSODescriptor");
            let mut idp_sso = Vec::with_capacity(idp_nodes.len());
            for n in idp_nodes {
                idp_sso.push(IdpSsoDescriptorRef::from_xml(doc, n)?);
            }

            let sp_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "SPSSODescriptor");
            let mut sp_sso = Vec::with_capacity(sp_nodes.len());
            for n in sp_nodes {
                sp_sso.push(SpSsoDescriptorRef::from_xml(doc, n)?);
            }

            let aa_nodes =
                find_child_elements(doc, node, SAML_METADATA_NS, "AuthnAuthorityDescriptor");
            let mut authn_authority = Vec::with_capacity(aa_nodes.len());
            for n in aa_nodes {
                authn_authority.push(AuthnAuthorityDescriptorRef::from_xml(doc, n)?);
            }

            let attr_auth_nodes =
                find_child_elements(doc, node, SAML_METADATA_NS, "AttributeAuthorityDescriptor");
            let mut attr_authority = Vec::with_capacity(attr_auth_nodes.len());
            for n in attr_auth_nodes {
                attr_authority.push(AttributeAuthorityDescriptorRef::from_xml(doc, n)?);
            }

            let pdp_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "PDPDescriptor");
            let mut pdp = Vec::with_capacity(pdp_nodes.len());
            for n in pdp_nodes {
                pdp.push(PdpDescriptorRef::from_xml(doc, n)?);
            }

            EntityRolesRef::Roles {
                idp_sso,
                sp_sso,
                authn_authority,
                attr_authority,
                pdp,
            }
        };

        let organization = find_child_element(doc, node, SAML_METADATA_NS, "Organization")
            .map(|n| deserialize_organization_ref(doc, n))
            .transpose()?;

        let cp_nodes = find_child_elements(doc, node, SAML_METADATA_NS, "ContactPerson");
        let mut contact_persons = Vec::with_capacity(cp_nodes.len());
        for n in cp_nodes {
            contact_persons.push(deserialize_contact_person_ref(doc, n)?);
        }

        let aml_nodes =
            find_child_elements(doc, node, SAML_METADATA_NS, "AdditionalMetadataLocation");
        let mut additional_metadata_locations = Vec::with_capacity(aml_nodes.len());
        for n in aml_nodes {
            additional_metadata_locations
                .push(deserialize_additional_metadata_location_ref(doc, n)?);
        }

        Ok(EntityDescriptorRef {
            entity_id,
            id,
            valid_until,
            cache_duration,
            has_signature,
            extensions,
            roles,
            organization,
            contact_persons,
            additional_metadata_locations,
        })
    }
}

// ── EntitiesDescriptor ─────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for EntitiesDescriptorRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_METADATA_NS, "EntitiesDescriptor")?;
        let id = optional_attribute(doc, node, "ID");
        let valid_until = parse_optional_datetime_attr(doc, node, "validUntil")?;
        let cache_duration = optional_attribute(doc, node, "cacheDuration");
        let name = optional_attribute(doc, node, "Name");
        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        let extensions = find_child_element(doc, node, SAML_METADATA_NS, "Extensions")
            .map(|n| deserialize_extensions_ref(doc, n))
            .transpose()?;

        // Children: EntityDescriptor or EntitiesDescriptor
        let mut children = Vec::new();
        for child in doc.children_iter(node) {
            if let Some(elem) = doc.element(child) {
                if !elem.matches_name_ns(SAML_METADATA_NS, "EntityDescriptor")
                    && !elem.matches_name_ns(SAML_METADATA_NS, "EntitiesDescriptor")
                {
                    continue;
                }
                let local = elem.name.local_name.as_ref();
                match local {
                    "EntityDescriptor" => {
                        let ed = EntityDescriptorRef::from_xml(doc, child)?;
                        children.push(MetadataChildRef::Entity(Box::new(ed)));
                    }
                    "EntitiesDescriptor" => {
                        let es = EntitiesDescriptorRef::from_xml(doc, child)?;
                        children.push(MetadataChildRef::Entities(es));
                    }
                    _ => {}
                }
            }
        }

        Ok(EntitiesDescriptorRef {
            id,
            valid_until,
            cache_duration,
            name,
            has_signature,
            extensions,
            children,
        })
    }
}
