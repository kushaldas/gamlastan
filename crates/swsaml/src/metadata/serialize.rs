// SamlSerialize implementations for owned metadata types.
//
// Each impl serializes the owned SAML metadata type to XML using the
// uppsala XmlWriter.
//
// References:
// - saml-metadata-2.0-os Sections 2.2-2.5

use uppsala::XmlWriter;

use crate::core::namespace::{SAML_ASSERTION_NS, SAML_METADATA_NS, XMLDSIG_NS, XMLENC_NS};

use crate::xml::error::XmlError;
use crate::xml::helpers::format_datetime;
use crate::xml::serialize::SamlSerialize;

use crate::metadata::types::affiliation::AffiliationDescriptor;
use crate::metadata::types::attr_authority::AttributeAuthorityDescriptor;
use crate::metadata::types::authn_authority::AuthnAuthorityDescriptor;
use crate::metadata::types::contact::ContactPerson;
use crate::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
use crate::metadata::types::entity_descriptor::{
    EntitiesDescriptor, EntityDescriptor, EntityRoles, MetadataChild,
};
use crate::metadata::types::extensions::Extensions;
use crate::metadata::types::idp::IdpSsoDescriptor;
use crate::metadata::types::key_descriptor::{EncryptionMethod, KeyDescriptor};
use crate::metadata::types::localized::{LocalizedName, LocalizedUri};
use crate::metadata::types::organization::Organization;
use crate::metadata::types::pdp::PdpDescriptor;
use crate::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use crate::metadata::types::sp::{AttributeConsumingService, RequestedAttribute, SpSsoDescriptor};

// ── Helper: write endpoint ─────────────────────────────────────────────────

fn write_endpoint(w: &mut XmlWriter, tag: &str, ep: &Endpoint) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = vec![("Binding", &ep.binding), ("Location", &ep.location)];
    if let Some(ref rl) = ep.response_location {
        attrs.push(("ResponseLocation", rl));
    }
    w.empty_element(tag, &attrs);
    Ok(())
}

fn write_indexed_endpoint(
    w: &mut XmlWriter,
    tag: &str,
    ep: &IndexedEndpoint,
) -> Result<(), XmlError> {
    let index_str = ep.index.to_string();
    let mut attrs: Vec<(&str, &str)> = vec![
        ("Binding", &ep.endpoint.binding),
        ("Location", &ep.endpoint.location),
        ("index", &index_str),
    ];
    if let Some(ref rl) = ep.endpoint.response_location {
        attrs.push(("ResponseLocation", rl));
    }
    let is_default_str;
    if let Some(is_default) = ep.is_default {
        is_default_str = if is_default { "true" } else { "false" };
        attrs.push(("isDefault", is_default_str));
    }
    w.empty_element(tag, &attrs);
    Ok(())
}

// ── Helper: write localized ────────────────────────────────────────────────

fn write_localized_name(w: &mut XmlWriter, tag: &str, name: &LocalizedName) {
    w.start_element(tag, &[("xml:lang", &name.lang)]);
    w.text(&name.value);
    w.end_element(tag);
}

fn write_localized_uri(w: &mut XmlWriter, tag: &str, uri: &LocalizedUri) {
    w.start_element(tag, &[("xml:lang", &uri.lang)]);
    w.text(&uri.value);
    w.end_element(tag);
}

// ── Helper: write text element ─────────────────────────────────────────────

fn write_text_element(w: &mut XmlWriter, tag: &str, text: &str) {
    w.start_element(tag, &[]);
    w.text(text);
    w.end_element(tag);
}

// ── Extensions ─────────────────────────────────────────────────────────────

fn write_extensions(w: &mut XmlWriter, ext: &Extensions) {
    // Write the raw XML stored in extensions. If it already contains the
    // <md:Extensions> wrapper, write it raw; otherwise wrap it.
    if ext.raw_xml.contains("<md:Extensions") || ext.raw_xml.contains("<Extensions") {
        w.raw(&ext.raw_xml);
    } else {
        w.start_element("md:Extensions", &[]);
        w.raw(&ext.raw_xml);
        w.end_element("md:Extensions");
    }
}

// ── EncryptionMethod ───────────────────────────────────────────────────────

fn write_encryption_method(w: &mut XmlWriter, em: &EncryptionMethod) -> Result<(), XmlError> {
    if em.key_size.is_some() || em.oaep_params.is_some() {
        w.start_element("md:EncryptionMethod", &[("Algorithm", &em.algorithm)]);
        if let Some(ks) = em.key_size {
            let ks_str = ks.to_string();
            write_text_element(w, "xenc:KeySize", &ks_str);
        }
        if let Some(ref oaep) = em.oaep_params {
            write_text_element(w, "xenc:OAEPparams", oaep);
        }
        w.end_element("md:EncryptionMethod");
    } else {
        w.empty_element("md:EncryptionMethod", &[("Algorithm", &em.algorithm)]);
    }
    Ok(())
}

// ── KeyDescriptor ──────────────────────────────────────────────────────────

fn write_key_descriptor(w: &mut XmlWriter, kd: &KeyDescriptor) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = Vec::new();
    if let Some(ref use_) = kd.use_ {
        attrs.push(("use", use_.as_str()));
    }
    w.start_element("md:KeyDescriptor", &attrs);
    // Write KeyInfo raw XML
    if !kd.key_info_xml.is_empty() {
        w.raw(&kd.key_info_xml);
    }
    for em in &kd.encryption_methods {
        write_encryption_method(w, em)?;
    }
    w.end_element("md:KeyDescriptor");
    Ok(())
}

// ── Organization ───────────────────────────────────────────────────────────

fn write_organization(w: &mut XmlWriter, org: &Organization) -> Result<(), XmlError> {
    w.start_element("md:Organization", &[]);
    if let Some(ref ext) = org.extensions {
        write_extensions(w, ext);
    }
    for name in &org.organization_names {
        write_localized_name(w, "md:OrganizationName", name);
    }
    for display in &org.organization_display_names {
        write_localized_name(w, "md:OrganizationDisplayName", display);
    }
    for url in &org.organization_urls {
        write_localized_uri(w, "md:OrganizationURL", url);
    }
    w.end_element("md:Organization");
    Ok(())
}

// ── ContactPerson ──────────────────────────────────────────────────────────

fn write_contact_person(w: &mut XmlWriter, cp: &ContactPerson) -> Result<(), XmlError> {
    w.start_element(
        "md:ContactPerson",
        &[("contactType", cp.contact_type.as_str())],
    );
    if let Some(ref ext) = cp.extensions {
        write_extensions(w, ext);
    }
    if let Some(ref company) = cp.company {
        write_text_element(w, "md:Company", company);
    }
    if let Some(ref given) = cp.given_name {
        write_text_element(w, "md:GivenName", given);
    }
    if let Some(ref sur) = cp.sur_name {
        write_text_element(w, "md:SurName", sur);
    }
    for email in &cp.email_addresses {
        write_text_element(w, "md:EmailAddress", email);
    }
    for phone in &cp.telephone_numbers {
        write_text_element(w, "md:TelephoneNumber", phone);
    }
    w.end_element("md:ContactPerson");
    Ok(())
}

// ── RoleDescriptorBase ─────────────────────────────────────────────────────

/// Build the attribute list for a role descriptor element, plus write common
/// child elements. Returns nothing; modifies writer in-place.
fn write_role_descriptor_base_attrs<'a>(
    base: &'a RoleDescriptorBase,
    attrs: &mut Vec<(&'a str, &'a str)>,
    valid_until_str: &'a mut String,
) {
    if let Some(ref id) = base.id {
        attrs.push(("ID", id));
    }
    if let Some(ref vu) = base.valid_until {
        *valid_until_str = format_datetime(vu);
        attrs.push(("validUntil", valid_until_str));
    }
    if let Some(ref cd) = base.cache_duration {
        attrs.push(("cacheDuration", cd));
    }
    if let Some(ref eu) = base.error_url {
        attrs.push(("errorURL", eu));
    }
}

fn write_role_descriptor_base_children(
    w: &mut XmlWriter,
    base: &RoleDescriptorBase,
) -> Result<(), XmlError> {
    if let Some(ref ext) = base.extensions {
        write_extensions(w, ext);
    }
    for kd in &base.key_descriptors {
        write_key_descriptor(w, kd)?;
    }
    if let Some(ref org) = base.organization {
        write_organization(w, org)?;
    }
    for cp in &base.contact_persons {
        write_contact_person(w, cp)?;
    }
    Ok(())
}

// ── SsoDescriptorBase children ─────────────────────────────────────────────

fn write_sso_descriptor_base_children(
    w: &mut XmlWriter,
    sso: &SsoDescriptorBase,
) -> Result<(), XmlError> {
    write_role_descriptor_base_children(w, &sso.base)?;
    for ars in &sso.artifact_resolution_services {
        write_indexed_endpoint(w, "md:ArtifactResolutionService", ars)?;
    }
    for slo in &sso.single_logout_services {
        write_endpoint(w, "md:SingleLogoutService", slo)?;
    }
    for mnid in &sso.manage_name_id_services {
        write_endpoint(w, "md:ManageNameIDService", mnid)?;
    }
    for nif in &sso.name_id_formats {
        write_text_element(w, "md:NameIDFormat", nif);
    }
    Ok(())
}

// ── IdpSsoDescriptor ───────────────────────────────────────────────────────

impl SamlSerialize for IdpSsoDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let pse = self.sso_base.base.protocol_support_enumeration.join(" ");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:saml", SAML_ASSERTION_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("protocolSupportEnumeration", &pse),
        ];
        let mut vu_str = String::new();
        write_role_descriptor_base_attrs(&self.sso_base.base, &mut attrs, &mut vu_str);
        let want_str;
        if let Some(want) = self.want_authn_requests_signed {
            want_str = if want { "true" } else { "false" };
            attrs.push(("WantAuthnRequestsSigned", want_str));
        }
        w.start_element("md:IDPSSODescriptor", &attrs);
        write_sso_descriptor_base_children(w, &self.sso_base)?;
        for sso in &self.single_sign_on_services {
            write_endpoint(w, "md:SingleSignOnService", sso)?;
        }
        for nidm in &self.name_id_mapping_services {
            write_endpoint(w, "md:NameIDMappingService", nidm)?;
        }
        for aidrs in &self.assertion_id_request_services {
            write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
        }
        for ap in &self.attribute_profiles {
            write_text_element(w, "md:AttributeProfile", ap);
        }
        for attr in &self.attributes {
            attr.to_xml(w)?;
        }
        w.end_element("md:IDPSSODescriptor");
        Ok(())
    }
}

// ── SpSsoDescriptor ────────────────────────────────────────────────────────

impl SamlSerialize for SpSsoDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let pse = self.sso_base.base.protocol_support_enumeration.join(" ");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:saml", SAML_ASSERTION_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("protocolSupportEnumeration", &pse),
        ];
        let mut vu_str = String::new();
        write_role_descriptor_base_attrs(&self.sso_base.base, &mut attrs, &mut vu_str);
        let authn_signed_str;
        if let Some(signed) = self.authn_requests_signed {
            authn_signed_str = if signed { "true" } else { "false" };
            attrs.push(("AuthnRequestsSigned", authn_signed_str));
        }
        let want_str;
        if let Some(want) = self.want_assertions_signed {
            want_str = if want { "true" } else { "false" };
            attrs.push(("WantAssertionsSigned", want_str));
        }
        w.start_element("md:SPSSODescriptor", &attrs);
        write_sso_descriptor_base_children(w, &self.sso_base)?;
        for acs in &self.assertion_consumer_services {
            write_indexed_endpoint(w, "md:AssertionConsumerService", acs)?;
        }
        for acser in &self.attribute_consuming_services {
            write_attribute_consuming_service(w, acser)?;
        }
        w.end_element("md:SPSSODescriptor");
        Ok(())
    }
}

// ── AttributeConsumingService ──────────────────────────────────────────────

fn write_attribute_consuming_service(
    w: &mut XmlWriter,
    acs: &AttributeConsumingService,
) -> Result<(), XmlError> {
    let index_str = acs.index.to_string();
    let mut attrs: Vec<(&str, &str)> = vec![("index", &index_str)];
    let is_default_str;
    if let Some(is_default) = acs.is_default {
        is_default_str = if is_default { "true" } else { "false" };
        attrs.push(("isDefault", is_default_str));
    }
    w.start_element("md:AttributeConsumingService", &attrs);
    for sn in &acs.service_names {
        write_localized_name(w, "md:ServiceName", sn);
    }
    for sd in &acs.service_descriptions {
        write_localized_name(w, "md:ServiceDescription", sd);
    }
    for ra in &acs.requested_attributes {
        write_requested_attribute(w, ra)?;
    }
    w.end_element("md:AttributeConsumingService");
    Ok(())
}

// ── RequestedAttribute ─────────────────────────────────────────────────────

fn write_requested_attribute(w: &mut XmlWriter, ra: &RequestedAttribute) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = vec![("Name", &ra.attribute.name)];
    if let Some(ref nf) = ra.attribute.name_format {
        attrs.push(("NameFormat", nf));
    }
    if let Some(ref fn_) = ra.attribute.friendly_name {
        attrs.push(("FriendlyName", fn_));
    }
    let is_required_str;
    if let Some(is_required) = ra.is_required {
        is_required_str = if is_required { "true" } else { "false" };
        attrs.push(("isRequired", is_required_str));
    }
    if ra.attribute.values.is_empty() {
        w.empty_element("md:RequestedAttribute", &attrs);
    } else {
        w.start_element("md:RequestedAttribute", &attrs);
        for value in &ra.attribute.values {
            value.to_xml(w)?;
        }
        w.end_element("md:RequestedAttribute");
    }
    Ok(())
}

// ── AuthnAuthorityDescriptor ───────────────────────────────────────────────

impl SamlSerialize for AuthnAuthorityDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let pse = self.base.protocol_support_enumeration.join(" ");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("protocolSupportEnumeration", &pse),
        ];
        let mut vu_str = String::new();
        write_role_descriptor_base_attrs(&self.base, &mut attrs, &mut vu_str);
        w.start_element("md:AuthnAuthorityDescriptor", &attrs);
        write_role_descriptor_base_children(w, &self.base)?;
        for aqs in &self.authn_query_services {
            write_endpoint(w, "md:AuthnQueryService", aqs)?;
        }
        for aidrs in &self.assertion_id_request_services {
            write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
        }
        for nif in &self.name_id_formats {
            write_text_element(w, "md:NameIDFormat", nif);
        }
        w.end_element("md:AuthnAuthorityDescriptor");
        Ok(())
    }
}

// ── PdpDescriptor ──────────────────────────────────────────────────────────

impl SamlSerialize for PdpDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let pse = self.base.protocol_support_enumeration.join(" ");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("protocolSupportEnumeration", &pse),
        ];
        let mut vu_str = String::new();
        write_role_descriptor_base_attrs(&self.base, &mut attrs, &mut vu_str);
        w.start_element("md:PDPDescriptor", &attrs);
        write_role_descriptor_base_children(w, &self.base)?;
        for az in &self.authz_services {
            write_endpoint(w, "md:AuthzService", az)?;
        }
        for aidrs in &self.assertion_id_request_services {
            write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
        }
        for nif in &self.name_id_formats {
            write_text_element(w, "md:NameIDFormat", nif);
        }
        w.end_element("md:PDPDescriptor");
        Ok(())
    }
}

// ── AttributeAuthorityDescriptor ───────────────────────────────────────────

impl SamlSerialize for AttributeAuthorityDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let pse = self.base.protocol_support_enumeration.join(" ");
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:saml", SAML_ASSERTION_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("protocolSupportEnumeration", &pse),
        ];
        let mut vu_str = String::new();
        write_role_descriptor_base_attrs(&self.base, &mut attrs, &mut vu_str);
        w.start_element("md:AttributeAuthorityDescriptor", &attrs);
        write_role_descriptor_base_children(w, &self.base)?;
        for asvc in &self.attribute_services {
            write_endpoint(w, "md:AttributeService", asvc)?;
        }
        for aidrs in &self.assertion_id_request_services {
            write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
        }
        for nif in &self.name_id_formats {
            write_text_element(w, "md:NameIDFormat", nif);
        }
        for ap in &self.attribute_profiles {
            write_text_element(w, "md:AttributeProfile", ap);
        }
        for attr in &self.attributes {
            attr.to_xml(w)?;
        }
        w.end_element("md:AttributeAuthorityDescriptor");
        Ok(())
    }
}

// ── AffiliationDescriptor ──────────────────────────────────────────────────

impl SamlSerialize for AffiliationDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("affiliationOwnerID", &self.affiliation_owner_id),
        ];
        if let Some(ref id) = self.id {
            attrs.push(("ID", id));
        }
        let vu_str;
        if let Some(ref vu) = self.valid_until {
            vu_str = format_datetime(vu);
            attrs.push(("validUntil", &vu_str));
        }
        if let Some(ref cd) = self.cache_duration {
            attrs.push(("cacheDuration", cd));
        }
        w.start_element("md:AffiliationDescriptor", &attrs);
        if let Some(ref ext) = self.extensions {
            write_extensions(w, ext);
        }
        for member in &self.affiliate_members {
            write_text_element(w, "md:AffiliateMember", member);
        }
        for kd in &self.key_descriptors {
            write_key_descriptor(w, kd)?;
        }
        w.end_element("md:AffiliationDescriptor");
        Ok(())
    }
}

// ── EntityDescriptor ───────────────────────────────────────────────────────

impl SamlSerialize for EntityDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:saml", SAML_ASSERTION_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
            ("entityID", &self.entity_id),
        ];
        if let Some(ref id) = self.id {
            attrs.push(("ID", id));
        }
        let vu_str;
        if let Some(ref vu) = self.valid_until {
            vu_str = format_datetime(vu);
            attrs.push(("validUntil", &vu_str));
        }
        if let Some(ref cd) = self.cache_duration {
            attrs.push(("cacheDuration", cd));
        }
        w.start_element("md:EntityDescriptor", &attrs);
        if let Some(ref ext) = self.extensions {
            write_extensions(w, ext);
        }

        // Roles or Affiliation
        match &self.roles {
            EntityRoles::Roles {
                idp_sso,
                sp_sso,
                authn_authority,
                attr_authority,
                pdp,
            } => {
                for idp in idp_sso {
                    idp.to_xml(w)?;
                }
                for sp in sp_sso {
                    sp.to_xml(w)?;
                }
                for aa in authn_authority {
                    aa.to_xml(w)?;
                }
                for attr_a in attr_authority {
                    attr_a.to_xml(w)?;
                }
                for p in pdp {
                    p.to_xml(w)?;
                }
            }
            EntityRoles::Affiliation(aff) => {
                aff.to_xml(w)?;
            }
        }

        if let Some(ref org) = self.organization {
            write_organization(w, org)?;
        }
        for cp in &self.contact_persons {
            write_contact_person(w, cp)?;
        }
        for aml in &self.additional_metadata_locations {
            w.start_element(
                "md:AdditionalMetadataLocation",
                &[("namespace", &aml.namespace)],
            );
            w.text(&aml.location);
            w.end_element("md:AdditionalMetadataLocation");
        }

        w.end_element("md:EntityDescriptor");
        Ok(())
    }
}

// ── EntitiesDescriptor ─────────────────────────────────────────────────────

impl SamlSerialize for EntitiesDescriptor {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = vec![
            ("xmlns:md", SAML_METADATA_NS),
            ("xmlns:saml", SAML_ASSERTION_NS),
            ("xmlns:ds", XMLDSIG_NS),
            ("xmlns:xenc", XMLENC_NS),
        ];
        if let Some(ref id) = self.id {
            attrs.push(("ID", id));
        }
        let vu_str;
        if let Some(ref vu) = self.valid_until {
            vu_str = format_datetime(vu);
            attrs.push(("validUntil", &vu_str));
        }
        if let Some(ref cd) = self.cache_duration {
            attrs.push(("cacheDuration", cd));
        }
        if let Some(ref name) = self.name {
            attrs.push(("Name", name));
        }
        w.start_element("md:EntitiesDescriptor", &attrs);
        if let Some(ref ext) = self.extensions {
            write_extensions(w, ext);
        }
        for child in &self.children {
            match child {
                MetadataChild::Entity(ed) => {
                    ed.to_xml(w)?;
                }
                MetadataChild::Entities(es) => {
                    // Nested EntitiesDescriptor - don't redeclare namespaces
                    write_entities_descriptor_nested(w, es)?;
                }
            }
        }
        w.end_element("md:EntitiesDescriptor");
        Ok(())
    }
}

/// Write a nested EntitiesDescriptor (without re-declaring xmlns).
fn write_entities_descriptor_nested(
    w: &mut XmlWriter,
    es: &EntitiesDescriptor,
) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = Vec::new();
    if let Some(ref id) = es.id {
        attrs.push(("ID", id));
    }
    let vu_str;
    if let Some(ref vu) = es.valid_until {
        vu_str = format_datetime(vu);
        attrs.push(("validUntil", &vu_str));
    }
    if let Some(ref cd) = es.cache_duration {
        attrs.push(("cacheDuration", cd));
    }
    if let Some(ref name) = es.name {
        attrs.push(("Name", name));
    }
    w.start_element("md:EntitiesDescriptor", &attrs);
    if let Some(ref ext) = es.extensions {
        write_extensions(w, ext);
    }
    for child in &es.children {
        match child {
            MetadataChild::Entity(ed) => {
                // Nested entity - write without xmlns redeclarations
                write_entity_descriptor_nested(w, ed)?;
            }
            MetadataChild::Entities(nested) => {
                write_entities_descriptor_nested(w, nested)?;
            }
        }
    }
    w.end_element("md:EntitiesDescriptor");
    Ok(())
}

/// Write an EntityDescriptor nested inside EntitiesDescriptor (no xmlns redecl).
fn write_entity_descriptor_nested(
    w: &mut XmlWriter,
    ed: &EntityDescriptor,
) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = vec![("entityID", &ed.entity_id)];
    if let Some(ref id) = ed.id {
        attrs.push(("ID", id));
    }
    let vu_str;
    if let Some(ref vu) = ed.valid_until {
        vu_str = format_datetime(vu);
        attrs.push(("validUntil", &vu_str));
    }
    if let Some(ref cd) = ed.cache_duration {
        attrs.push(("cacheDuration", cd));
    }
    w.start_element("md:EntityDescriptor", &attrs);
    if let Some(ref ext) = ed.extensions {
        write_extensions(w, ext);
    }
    match &ed.roles {
        EntityRoles::Roles {
            idp_sso,
            sp_sso,
            authn_authority,
            attr_authority,
            pdp,
        } => {
            for idp in idp_sso {
                write_idp_sso_nested(w, idp)?;
            }
            for sp in sp_sso {
                write_sp_sso_nested(w, sp)?;
            }
            for aa in authn_authority {
                write_authn_authority_nested(w, aa)?;
            }
            for attr_a in attr_authority {
                write_attr_authority_nested(w, attr_a)?;
            }
            for p in pdp {
                write_pdp_nested(w, p)?;
            }
        }
        EntityRoles::Affiliation(aff) => {
            write_affiliation_nested(w, aff)?;
        }
    }
    if let Some(ref org) = ed.organization {
        write_organization(w, org)?;
    }
    for cp in &ed.contact_persons {
        write_contact_person(w, cp)?;
    }
    for aml in &ed.additional_metadata_locations {
        w.start_element(
            "md:AdditionalMetadataLocation",
            &[("namespace", &aml.namespace)],
        );
        w.text(&aml.location);
        w.end_element("md:AdditionalMetadataLocation");
    }
    w.end_element("md:EntityDescriptor");
    Ok(())
}

// ── Nested role descriptor writers (no xmlns redecl) ───────────────────────

fn write_idp_sso_nested(w: &mut XmlWriter, idp: &IdpSsoDescriptor) -> Result<(), XmlError> {
    let pse = idp.sso_base.base.protocol_support_enumeration.join(" ");
    let mut attrs: Vec<(&str, &str)> = vec![("protocolSupportEnumeration", &pse)];
    let mut vu_str = String::new();
    write_role_descriptor_base_attrs(&idp.sso_base.base, &mut attrs, &mut vu_str);
    let want_str;
    if let Some(want) = idp.want_authn_requests_signed {
        want_str = if want { "true" } else { "false" };
        attrs.push(("WantAuthnRequestsSigned", want_str));
    }
    w.start_element("md:IDPSSODescriptor", &attrs);
    write_sso_descriptor_base_children(w, &idp.sso_base)?;
    for sso in &idp.single_sign_on_services {
        write_endpoint(w, "md:SingleSignOnService", sso)?;
    }
    for nidm in &idp.name_id_mapping_services {
        write_endpoint(w, "md:NameIDMappingService", nidm)?;
    }
    for aidrs in &idp.assertion_id_request_services {
        write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
    }
    for ap in &idp.attribute_profiles {
        write_text_element(w, "md:AttributeProfile", ap);
    }
    for attr in &idp.attributes {
        attr.to_xml(w)?;
    }
    w.end_element("md:IDPSSODescriptor");
    Ok(())
}

fn write_sp_sso_nested(w: &mut XmlWriter, sp: &SpSsoDescriptor) -> Result<(), XmlError> {
    let pse = sp.sso_base.base.protocol_support_enumeration.join(" ");
    let mut attrs: Vec<(&str, &str)> = vec![("protocolSupportEnumeration", &pse)];
    let mut vu_str = String::new();
    write_role_descriptor_base_attrs(&sp.sso_base.base, &mut attrs, &mut vu_str);
    let authn_signed_str;
    if let Some(signed) = sp.authn_requests_signed {
        authn_signed_str = if signed { "true" } else { "false" };
        attrs.push(("AuthnRequestsSigned", authn_signed_str));
    }
    let want_str;
    if let Some(want) = sp.want_assertions_signed {
        want_str = if want { "true" } else { "false" };
        attrs.push(("WantAssertionsSigned", want_str));
    }
    w.start_element("md:SPSSODescriptor", &attrs);
    write_sso_descriptor_base_children(w, &sp.sso_base)?;
    for acs in &sp.assertion_consumer_services {
        write_indexed_endpoint(w, "md:AssertionConsumerService", acs)?;
    }
    for acser in &sp.attribute_consuming_services {
        write_attribute_consuming_service(w, acser)?;
    }
    w.end_element("md:SPSSODescriptor");
    Ok(())
}

fn write_authn_authority_nested(
    w: &mut XmlWriter,
    aa: &AuthnAuthorityDescriptor,
) -> Result<(), XmlError> {
    let pse = aa.base.protocol_support_enumeration.join(" ");
    let mut attrs: Vec<(&str, &str)> = vec![("protocolSupportEnumeration", &pse)];
    let mut vu_str = String::new();
    write_role_descriptor_base_attrs(&aa.base, &mut attrs, &mut vu_str);
    w.start_element("md:AuthnAuthorityDescriptor", &attrs);
    write_role_descriptor_base_children(w, &aa.base)?;
    for aqs in &aa.authn_query_services {
        write_endpoint(w, "md:AuthnQueryService", aqs)?;
    }
    for aidrs in &aa.assertion_id_request_services {
        write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
    }
    for nif in &aa.name_id_formats {
        write_text_element(w, "md:NameIDFormat", nif);
    }
    w.end_element("md:AuthnAuthorityDescriptor");
    Ok(())
}

fn write_attr_authority_nested(
    w: &mut XmlWriter,
    aa: &AttributeAuthorityDescriptor,
) -> Result<(), XmlError> {
    let pse = aa.base.protocol_support_enumeration.join(" ");
    let mut attrs: Vec<(&str, &str)> = vec![("protocolSupportEnumeration", &pse)];
    let mut vu_str = String::new();
    write_role_descriptor_base_attrs(&aa.base, &mut attrs, &mut vu_str);
    w.start_element("md:AttributeAuthorityDescriptor", &attrs);
    write_role_descriptor_base_children(w, &aa.base)?;
    for asvc in &aa.attribute_services {
        write_endpoint(w, "md:AttributeService", asvc)?;
    }
    for aidrs in &aa.assertion_id_request_services {
        write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
    }
    for nif in &aa.name_id_formats {
        write_text_element(w, "md:NameIDFormat", nif);
    }
    for ap in &aa.attribute_profiles {
        write_text_element(w, "md:AttributeProfile", ap);
    }
    for attr in &aa.attributes {
        attr.to_xml(w)?;
    }
    w.end_element("md:AttributeAuthorityDescriptor");
    Ok(())
}

fn write_pdp_nested(w: &mut XmlWriter, pdp: &PdpDescriptor) -> Result<(), XmlError> {
    let pse = pdp.base.protocol_support_enumeration.join(" ");
    let mut attrs: Vec<(&str, &str)> = vec![("protocolSupportEnumeration", &pse)];
    let mut vu_str = String::new();
    write_role_descriptor_base_attrs(&pdp.base, &mut attrs, &mut vu_str);
    w.start_element("md:PDPDescriptor", &attrs);
    write_role_descriptor_base_children(w, &pdp.base)?;
    for az in &pdp.authz_services {
        write_endpoint(w, "md:AuthzService", az)?;
    }
    for aidrs in &pdp.assertion_id_request_services {
        write_endpoint(w, "md:AssertionIDRequestService", aidrs)?;
    }
    for nif in &pdp.name_id_formats {
        write_text_element(w, "md:NameIDFormat", nif);
    }
    w.end_element("md:PDPDescriptor");
    Ok(())
}

fn write_affiliation_nested(
    w: &mut XmlWriter,
    aff: &AffiliationDescriptor,
) -> Result<(), XmlError> {
    let mut attrs: Vec<(&str, &str)> = vec![("affiliationOwnerID", &aff.affiliation_owner_id)];
    if let Some(ref id) = aff.id {
        attrs.push(("ID", id));
    }
    let vu_str;
    if let Some(ref vu) = aff.valid_until {
        vu_str = format_datetime(vu);
        attrs.push(("validUntil", &vu_str));
    }
    if let Some(ref cd) = aff.cache_duration {
        attrs.push(("cacheDuration", cd));
    }
    w.start_element("md:AffiliationDescriptor", &attrs);
    if let Some(ref ext) = aff.extensions {
        write_extensions(w, ext);
    }
    for member in &aff.affiliate_members {
        write_text_element(w, "md:AffiliateMember", member);
    }
    for kd in &aff.key_descriptors {
        write_key_descriptor(w, kd)?;
    }
    w.end_element("md:AffiliationDescriptor");
    Ok(())
}
