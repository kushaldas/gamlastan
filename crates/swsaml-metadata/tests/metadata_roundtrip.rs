// Roundtrip tests for metadata types: serialize -> parse -> deserialize -> compare.
//
// Each test constructs an owned SAML metadata type, serializes it to XML, parses
// it back into a zero-copy Ref type, converts to owned, and asserts equality.

use swsaml_core::assertion::attribute::Attribute;
use swsaml_metadata::types::additional::AdditionalMetadataLocation;
use swsaml_metadata::types::affiliation::AffiliationDescriptor;
use swsaml_metadata::types::attr_authority::AttributeAuthorityDescriptor;
use swsaml_metadata::types::authn_authority::AuthnAuthorityDescriptor;
use swsaml_metadata::types::contact::{ContactPerson, ContactType};
use swsaml_metadata::types::endpoint::{Endpoint, IndexedEndpoint};
use swsaml_metadata::types::entity_descriptor::{
    EntitiesDescriptor, EntityDescriptor, EntityRoles, MetadataChild,
};
use swsaml_metadata::types::idp::IdpSsoDescriptor;
use swsaml_metadata::types::key_descriptor::{EncryptionMethod, KeyDescriptor, KeyUse};
use swsaml_metadata::types::localized::LocalizedName;
use swsaml_metadata::types::organization::Organization;
use swsaml_metadata::types::pdp::PdpDescriptor;
use swsaml_metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use swsaml_metadata::types::sp::{AttributeConsumingService, RequestedAttribute, SpSsoDescriptor};

use swsaml_xml::deserialize::{parse_saml, SamlDeserialize};
use swsaml_xml::serialize::SamlSerialize;

const SAML2_PROTO: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

fn make_role_base() -> RoleDescriptorBase {
    RoleDescriptorBase::new(vec![SAML2_PROTO.to_string()])
}

fn make_sso_base() -> SsoDescriptorBase {
    SsoDescriptorBase {
        base: make_role_base(),
        artifact_resolution_services: vec![],
        single_logout_services: vec![],
        manage_name_id_services: vec![],
        name_id_formats: vec![],
    }
}

// ── EntityDescriptor: IdP ──────────────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_idp_minimal() {
    let ed = EntityDescriptor {
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
                single_sign_on_services: vec![Endpoint::new(
                    HTTP_REDIRECT,
                    "https://idp.example.com/sso",
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
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.entity_id, ed.entity_id);
    assert!(!owned.has_signature);
    assert!(owned.is_idp());
    assert!(!owned.is_sp());
    match &owned.roles {
        EntityRoles::Roles { idp_sso, .. } => {
            assert_eq!(idp_sso.len(), 1);
            assert_eq!(idp_sso[0].single_sign_on_services[0].binding, HTTP_REDIRECT);
            assert_eq!(
                idp_sso[0].single_sign_on_services[0].location,
                "https://idp.example.com/sso"
            );
        }
        _ => panic!("expected Roles"),
    }
}

// ── EntityDescriptor: SP ───────────────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_sp_minimal() {
    let ed = EntityDescriptor {
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
                assertion_consumer_services: vec![IndexedEndpoint::new_default(
                    Endpoint::new(HTTP_POST, "https://sp.example.com/acs"),
                    0,
                )],
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
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.entity_id, ed.entity_id);
    assert!(owned.is_sp());
    match &owned.roles {
        EntityRoles::Roles { sp_sso, .. } => {
            assert_eq!(sp_sso.len(), 1);
            assert_eq!(sp_sso[0].assertion_consumer_services.len(), 1);
            assert_eq!(sp_sso[0].assertion_consumer_services[0].index, 0);
            assert_eq!(
                sp_sso[0].assertion_consumer_services[0].is_default,
                Some(true)
            );
        }
        _ => panic!("expected Roles"),
    }
}

// ── EntityDescriptor: Full IdP + SP ────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_full() {
    let ed = EntityDescriptor {
        entity_id: "https://dual.example.com".to_string(),
        id: Some("_ed_full_123".to_string()),
        valid_until: Some("2026-12-31T23:59:59Z".parse().unwrap()),
        cache_duration: Some("PT24H".to_string()),
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![IdpSsoDescriptor {
                sso_base: SsoDescriptorBase {
                    base: RoleDescriptorBase {
                        id: Some("_idp_rd".to_string()),
                        valid_until: None,
                        cache_duration: Some("PT12H".to_string()),
                        protocol_support_enumeration: vec![SAML2_PROTO.to_string()],
                        error_url: Some("https://dual.example.com/error".to_string()),
                        extensions: None,
                        key_descriptors: vec![KeyDescriptor {
                            use_: Some(KeyUse::Signing),
                            key_info_xml: "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBxxx</ds:X509Certificate></ds:X509Data></ds:KeyInfo>".to_string(),
                            encryption_methods: vec![],
                        }],
                        organization: None,
                        contact_persons: vec![],
                    },
                    artifact_resolution_services: vec![IndexedEndpoint::new(
                        Endpoint::new(SOAP, "https://dual.example.com/artifact"),
                        0,
                    )],
                    single_logout_services: vec![Endpoint::with_response_location(
                        HTTP_REDIRECT,
                        "https://dual.example.com/slo",
                        "https://dual.example.com/slo-response",
                    )],
                    manage_name_id_services: vec![],
                    name_id_formats: vec![
                        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
                    ],
                },
                want_authn_requests_signed: Some(true),
                single_sign_on_services: vec![
                    Endpoint::new(HTTP_REDIRECT, "https://dual.example.com/sso/redirect"),
                    Endpoint::new(HTTP_POST, "https://dual.example.com/sso/post"),
                ],
                name_id_mapping_services: vec![Endpoint::new(SOAP, "https://dual.example.com/nidm")],
                assertion_id_request_services: vec![],
                attribute_profiles: vec!["urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic".to_string()],
                attributes: vec![Attribute {
                    name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
                    name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    friendly_name: Some("eduPersonEntitlement".to_string()),
                    values: vec![],
                }],
            }],
            sp_sso: vec![SpSsoDescriptor {
                sso_base: SsoDescriptorBase {
                    base: RoleDescriptorBase {
                        id: None,
                        valid_until: None,
                        cache_duration: None,
                        protocol_support_enumeration: vec![SAML2_PROTO.to_string()],
                        error_url: None,
                        extensions: None,
                        key_descriptors: vec![
                            KeyDescriptor {
                                use_: Some(KeyUse::Signing),
                                key_info_xml: "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>SPSignCert</ds:X509Certificate></ds:X509Data></ds:KeyInfo>".to_string(),
                                encryption_methods: vec![],
                            },
                            KeyDescriptor {
                                use_: Some(KeyUse::Encryption),
                                key_info_xml: "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>SPEncCert</ds:X509Certificate></ds:X509Data></ds:KeyInfo>".to_string(),
                                encryption_methods: vec![EncryptionMethod {
                                    algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm".to_string(),
                                    key_size: Some(256),
                                    oaep_params: None,
                                }],
                            },
                        ],
                        organization: None,
                        contact_persons: vec![],
                    },
                    artifact_resolution_services: vec![],
                    single_logout_services: vec![],
                    manage_name_id_services: vec![],
                    name_id_formats: vec![
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string(),
                    ],
                },
                authn_requests_signed: Some(true),
                want_assertions_signed: Some(true),
                assertion_consumer_services: vec![
                    IndexedEndpoint::new_default(
                        Endpoint::new(HTTP_POST, "https://dual.example.com/acs/post"),
                        0,
                    ),
                    IndexedEndpoint::new(
                        Endpoint::new(HTTP_REDIRECT, "https://dual.example.com/acs/redirect"),
                        1,
                    ),
                ],
                attribute_consuming_services: vec![AttributeConsumingService {
                    index: 0,
                    is_default: Some(true),
                    service_names: vec![LocalizedName::new("en", "SP Service")],
                    service_descriptions: vec![LocalizedName::new("en", "A test SP service")],
                    requested_attributes: vec![RequestedAttribute {
                        attribute: Attribute {
                            name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
                            name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                            friendly_name: Some("mail".to_string()),
                            values: vec![],
                        },
                        is_required: Some(true),
                    }],
                }],
            }],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: Some(Organization::simple(
            "en",
            "Dual Example",
            "Dual Example Inc.",
            "https://dual.example.com",
        )),
        contact_persons: vec![
            ContactPerson {
                contact_type: ContactType::Technical,
                extensions: None,
                company: Some("Dual Corp".to_string()),
                given_name: Some("Jane".to_string()),
                sur_name: Some("Doe".to_string()),
                email_addresses: vec!["tech@dual.example.com".to_string()],
                telephone_numbers: vec!["+1-555-1234".to_string()],
            },
            ContactPerson {
                contact_type: ContactType::Support,
                extensions: None,
                company: None,
                given_name: None,
                sur_name: None,
                email_addresses: vec!["support@dual.example.com".to_string()],
                telephone_numbers: vec![],
            },
        ],
        additional_metadata_locations: vec![AdditionalMetadataLocation {
            namespace: "urn:x-custom:ns".to_string(),
            location: "https://dual.example.com/metadata/custom".to_string(),
        }],
    };

    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    // Top-level fields
    assert_eq!(owned.entity_id, ed.entity_id);
    assert_eq!(owned.id, ed.id);
    assert_eq!(owned.valid_until, ed.valid_until);
    assert_eq!(owned.cache_duration, ed.cache_duration);
    assert!(!owned.has_signature);

    // IdP
    match &owned.roles {
        EntityRoles::Roles {
            idp_sso, sp_sso, ..
        } => {
            assert_eq!(idp_sso.len(), 1);
            let idp = &idp_sso[0];
            assert_eq!(idp.want_authn_requests_signed, Some(true));
            assert_eq!(idp.single_sign_on_services.len(), 2);
            assert_eq!(idp.single_sign_on_services[0].binding, HTTP_REDIRECT);
            assert_eq!(idp.single_sign_on_services[1].binding, HTTP_POST);
            assert_eq!(idp.name_id_mapping_services.len(), 1);
            assert_eq!(idp.attribute_profiles.len(), 1);
            assert_eq!(idp.attributes.len(), 1);
            assert_eq!(
                idp.attributes[0].friendly_name.as_deref(),
                Some("eduPersonEntitlement")
            );

            // IdP SSO base
            assert_eq!(idp.sso_base.single_logout_services.len(), 1);
            assert_eq!(
                idp.sso_base.single_logout_services[0]
                    .response_location
                    .as_deref(),
                Some("https://dual.example.com/slo-response")
            );
            assert_eq!(idp.sso_base.artifact_resolution_services.len(), 1);
            assert_eq!(idp.sso_base.name_id_formats.len(), 2);

            // IdP role descriptor base
            assert_eq!(idp.sso_base.base.id.as_deref(), Some("_idp_rd"));
            assert_eq!(idp.sso_base.base.cache_duration.as_deref(), Some("PT12H"));
            assert_eq!(
                idp.sso_base.base.error_url.as_deref(),
                Some("https://dual.example.com/error")
            );
            assert_eq!(idp.sso_base.base.key_descriptors.len(), 1);
            assert_eq!(
                idp.sso_base.base.key_descriptors[0].use_,
                Some(KeyUse::Signing)
            );

            // SP
            assert_eq!(sp_sso.len(), 1);
            let sp = &sp_sso[0];
            assert_eq!(sp.authn_requests_signed, Some(true));
            assert_eq!(sp.want_assertions_signed, Some(true));
            assert_eq!(sp.assertion_consumer_services.len(), 2);
            assert_eq!(sp.assertion_consumer_services[0].index, 0);
            assert_eq!(sp.assertion_consumer_services[0].is_default, Some(true));
            assert_eq!(sp.assertion_consumer_services[1].index, 1);

            // SP key descriptors
            assert_eq!(sp.sso_base.base.key_descriptors.len(), 2);
            assert_eq!(
                sp.sso_base.base.key_descriptors[0].use_,
                Some(KeyUse::Signing)
            );
            assert_eq!(
                sp.sso_base.base.key_descriptors[1].use_,
                Some(KeyUse::Encryption)
            );
            assert_eq!(
                sp.sso_base.base.key_descriptors[1].encryption_methods.len(),
                1
            );
            assert_eq!(
                sp.sso_base.base.key_descriptors[1].encryption_methods[0].key_size,
                Some(256)
            );

            // SP AttributeConsumingService
            assert_eq!(sp.attribute_consuming_services.len(), 1);
            let acs = &sp.attribute_consuming_services[0];
            assert_eq!(acs.index, 0);
            assert_eq!(acs.is_default, Some(true));
            assert_eq!(acs.service_names.len(), 1);
            assert_eq!(acs.service_names[0].value, "SP Service");
            assert_eq!(acs.service_descriptions.len(), 1);
            assert_eq!(acs.requested_attributes.len(), 1);
            assert_eq!(acs.requested_attributes[0].is_required, Some(true));
        }
        _ => panic!("expected Roles"),
    }

    // Organization
    let org = owned.organization.as_ref().unwrap();
    assert_eq!(org.organization_names[0].value, "Dual Example");
    assert_eq!(org.organization_display_names[0].value, "Dual Example Inc.");
    assert_eq!(org.organization_urls[0].value, "https://dual.example.com");

    // Contact persons
    assert_eq!(owned.contact_persons.len(), 2);
    assert_eq!(
        owned.contact_persons[0].contact_type,
        ContactType::Technical
    );
    assert_eq!(
        owned.contact_persons[0].company.as_deref(),
        Some("Dual Corp")
    );
    assert_eq!(owned.contact_persons[0].given_name.as_deref(), Some("Jane"));
    assert_eq!(owned.contact_persons[0].sur_name.as_deref(), Some("Doe"));
    assert_eq!(owned.contact_persons[0].email_addresses.len(), 1);
    assert_eq!(owned.contact_persons[0].telephone_numbers.len(), 1);
    assert_eq!(owned.contact_persons[1].contact_type, ContactType::Support);

    // Additional metadata locations
    assert_eq!(owned.additional_metadata_locations.len(), 1);
    assert_eq!(
        owned.additional_metadata_locations[0].namespace,
        "urn:x-custom:ns"
    );
    assert_eq!(
        owned.additional_metadata_locations[0].location,
        "https://dual.example.com/metadata/custom"
    );
}

// ── AuthnAuthorityDescriptor ───────────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_authn_authority() {
    let ed = EntityDescriptor {
        entity_id: "https://aa.example.com".to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![],
            authn_authority: vec![AuthnAuthorityDescriptor {
                base: make_role_base(),
                authn_query_services: vec![Endpoint::new(
                    SOAP,
                    "https://aa.example.com/authnquery",
                )],
                assertion_id_request_services: vec![Endpoint::new(
                    SOAP,
                    "https://aa.example.com/assertionid",
                )],
                name_id_formats: vec![
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()
                ],
            }],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    match &owned.roles {
        EntityRoles::Roles {
            authn_authority, ..
        } => {
            assert_eq!(authn_authority.len(), 1);
            assert_eq!(authn_authority[0].authn_query_services.len(), 1);
            assert_eq!(authn_authority[0].assertion_id_request_services.len(), 1);
            assert_eq!(authn_authority[0].name_id_formats.len(), 1);
        }
        _ => panic!("expected Roles"),
    }
}

// ── AttributeAuthorityDescriptor ───────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_attr_authority() {
    let ed = EntityDescriptor {
        entity_id: "https://attrauth.example.com".to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![],
            authn_authority: vec![],
            attr_authority: vec![AttributeAuthorityDescriptor {
                base: make_role_base(),
                attribute_services: vec![Endpoint::new(SOAP, "https://attrauth.example.com/attrs")],
                assertion_id_request_services: vec![],
                name_id_formats: vec![],
                attribute_profiles: vec![
                    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic".to_string()
                ],
                attributes: vec![
                    Attribute {
                        name: "urn:oid:2.5.4.42".to_string(),
                        name_format: Some(
                            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string(),
                        ),
                        friendly_name: Some("givenName".to_string()),
                        values: vec![],
                    },
                    Attribute {
                        name: "urn:oid:2.5.4.4".to_string(),
                        name_format: Some(
                            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string(),
                        ),
                        friendly_name: Some("sn".to_string()),
                        values: vec![],
                    },
                ],
            }],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    match &owned.roles {
        EntityRoles::Roles { attr_authority, .. } => {
            assert_eq!(attr_authority.len(), 1);
            assert_eq!(attr_authority[0].attribute_services.len(), 1);
            assert_eq!(attr_authority[0].attribute_profiles.len(), 1);
            assert_eq!(attr_authority[0].attributes.len(), 2);
            assert_eq!(
                attr_authority[0].attributes[0].friendly_name.as_deref(),
                Some("givenName")
            );
            assert_eq!(
                attr_authority[0].attributes[1].friendly_name.as_deref(),
                Some("sn")
            );
        }
        _ => panic!("expected Roles"),
    }
}

// ── PdpDescriptor ──────────────────────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_pdp() {
    let ed = EntityDescriptor {
        entity_id: "https://pdp.example.com".to_string(),
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
            pdp: vec![PdpDescriptor {
                base: make_role_base(),
                authz_services: vec![Endpoint::new(SOAP, "https://pdp.example.com/authz")],
                assertion_id_request_services: vec![Endpoint::new(
                    SOAP,
                    "https://pdp.example.com/assertionid",
                )],
                name_id_formats: vec![
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()
                ],
            }],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    match &owned.roles {
        EntityRoles::Roles { pdp, .. } => {
            assert_eq!(pdp.len(), 1);
            assert_eq!(pdp[0].authz_services.len(), 1);
            assert_eq!(pdp[0].assertion_id_request_services.len(), 1);
            assert_eq!(pdp[0].name_id_formats.len(), 1);
        }
        _ => panic!("expected Roles"),
    }
}

// ── AffiliationDescriptor ──────────────────────────────────────────────────

#[test]
fn roundtrip_entity_descriptor_affiliation() {
    let ed = EntityDescriptor {
        entity_id: "https://federation.example.com".to_string(),
        id: Some("_aff_ed".to_string()),
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Affiliation(AffiliationDescriptor {
            affiliation_owner_id: "https://federation.example.com".to_string(),
            id: Some("_aff_1".to_string()),
            valid_until: Some("2027-01-01T00:00:00Z".parse().unwrap()),
            cache_duration: Some("PT48H".to_string()),
            has_signature: false,
            extensions: None,
            affiliate_members: vec![
                "https://sp1.example.com".to_string(),
                "https://sp2.example.com".to_string(),
                "https://idp.example.com".to_string(),
            ],
            key_descriptors: vec![],
        }),
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };
    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.entity_id, "https://federation.example.com");
    assert_eq!(owned.id.as_deref(), Some("_aff_ed"));
    match &owned.roles {
        EntityRoles::Affiliation(aff) => {
            assert_eq!(aff.affiliation_owner_id, "https://federation.example.com");
            assert_eq!(aff.id.as_deref(), Some("_aff_1"));
            assert_eq!(
                aff.valid_until,
                Some("2027-01-01T00:00:00Z".parse().unwrap())
            ); // Affiliation's own valid_until
            assert_eq!(aff.cache_duration.as_deref(), Some("PT48H"));
            assert_eq!(aff.affiliate_members.len(), 3);
            assert_eq!(aff.affiliate_members[0], "https://sp1.example.com");
        }
        _ => panic!("expected Affiliation"),
    }
}

// ── EntitiesDescriptor ─────────────────────────────────────────────────────

#[test]
fn roundtrip_entities_descriptor_simple() {
    let entities = EntitiesDescriptor {
        id: Some("_entities_1".to_string()),
        valid_until: Some("2026-06-30T00:00:00Z".parse().unwrap()),
        cache_duration: Some("PT6H".to_string()),
        name: Some("Test Federation".to_string()),
        has_signature: false,
        extensions: None,
        children: vec![
            MetadataChild::Entity(Box::new(EntityDescriptor {
                entity_id: "https://idp1.example.com".to_string(),
                id: None,
                valid_until: None,
                cache_duration: None,
                has_signature: false,
                extensions: None,
                roles: EntityRoles::Roles {
                    idp_sso: vec![IdpSsoDescriptor {
                        sso_base: make_sso_base(),
                        want_authn_requests_signed: Some(false),
                        single_sign_on_services: vec![Endpoint::new(
                            HTTP_POST,
                            "https://idp1.example.com/sso",
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
            })),
            MetadataChild::Entity(Box::new(EntityDescriptor {
                entity_id: "https://sp1.example.com".to_string(),
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
                        assertion_consumer_services: vec![IndexedEndpoint::new_default(
                            Endpoint::new(HTTP_POST, "https://sp1.example.com/acs"),
                            0,
                        )],
                        attribute_consuming_services: vec![],
                    }],
                    authn_authority: vec![],
                    attr_authority: vec![],
                    pdp: vec![],
                },
                organization: None,
                contact_persons: vec![],
                additional_metadata_locations: vec![],
            })),
        ],
    };

    let xml = entities.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntitiesDescriptorRef>(&doc)
            .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.id.as_deref(), Some("_entities_1"));
    assert_eq!(owned.name.as_deref(), Some("Test Federation"));
    assert_eq!(owned.cache_duration.as_deref(), Some("PT6H"));
    assert!(!owned.has_signature);
    assert_eq!(owned.children.len(), 2);

    // Flatten and check entity IDs
    let all_entities = owned.entity_descriptors();
    assert_eq!(all_entities.len(), 2);
    assert_eq!(all_entities[0].entity_id, "https://idp1.example.com");
    assert_eq!(all_entities[1].entity_id, "https://sp1.example.com");
}

// ── Nested EntitiesDescriptor ──────────────────────────────────────────────

#[test]
fn roundtrip_entities_descriptor_nested() {
    let entities = EntitiesDescriptor {
        id: None,
        valid_until: None,
        cache_duration: None,
        name: Some("Root Federation".to_string()),
        has_signature: false,
        extensions: None,
        children: vec![
            MetadataChild::Entities(EntitiesDescriptor {
                id: None,
                valid_until: None,
                cache_duration: None,
                name: Some("Sub Federation A".to_string()),
                has_signature: false,
                extensions: None,
                children: vec![MetadataChild::Entity(Box::new(EntityDescriptor {
                    entity_id: "https://sp-a.example.com".to_string(),
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
                            assertion_consumer_services: vec![IndexedEndpoint::new_default(
                                Endpoint::new(HTTP_POST, "https://sp-a.example.com/acs"),
                                0,
                            )],
                            attribute_consuming_services: vec![],
                        }],
                        authn_authority: vec![],
                        attr_authority: vec![],
                        pdp: vec![],
                    },
                    organization: None,
                    contact_persons: vec![],
                    additional_metadata_locations: vec![],
                }))],
            }),
            MetadataChild::Entity(Box::new(EntityDescriptor {
                entity_id: "https://idp-root.example.com".to_string(),
                id: None,
                valid_until: None,
                cache_duration: None,
                has_signature: false,
                extensions: None,
                roles: EntityRoles::Roles {
                    idp_sso: vec![IdpSsoDescriptor {
                        sso_base: make_sso_base(),
                        want_authn_requests_signed: None,
                        single_sign_on_services: vec![Endpoint::new(
                            HTTP_REDIRECT,
                            "https://idp-root.example.com/sso",
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
            })),
        ],
    };

    let xml = entities.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntitiesDescriptorRef>(&doc)
            .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.name.as_deref(), Some("Root Federation"));
    assert_eq!(owned.children.len(), 2);

    // Check nested structure
    match &owned.children[0] {
        MetadataChild::Entities(sub) => {
            assert_eq!(sub.name.as_deref(), Some("Sub Federation A"));
            assert_eq!(sub.children.len(), 1);
        }
        _ => panic!("expected nested EntitiesDescriptor"),
    }
    match &owned.children[1] {
        MetadataChild::Entity(ed) => {
            assert_eq!(ed.entity_id, "https://idp-root.example.com");
        }
        _ => panic!("expected EntityDescriptor"),
    }

    // Flatten
    let all = owned.entity_descriptors();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].entity_id, "https://sp-a.example.com");
    assert_eq!(all[1].entity_id, "https://idp-root.example.com");
}

// ── Standalone IdpSsoDescriptor ────────────────────────────────────────────

#[test]
fn roundtrip_idp_sso_descriptor_standalone() {
    // IdpSsoDescriptor serialized at top level (with xmlns declarations)
    let idp = IdpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase {
                id: Some("_idp_standalone".to_string()),
                valid_until: None,
                cache_duration: None,
                protocol_support_enumeration: vec![SAML2_PROTO.to_string()],
                error_url: None,
                extensions: None,
                key_descriptors: vec![],
                organization: None,
                contact_persons: vec![],
            },
            artifact_resolution_services: vec![],
            single_logout_services: vec![
                Endpoint::new(HTTP_REDIRECT, "https://idp.example.com/slo/redirect"),
                Endpoint::new(HTTP_POST, "https://idp.example.com/slo/post"),
            ],
            manage_name_id_services: vec![Endpoint::new(SOAP, "https://idp.example.com/mnid")],
            name_id_formats: vec![
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
            ],
        },
        want_authn_requests_signed: Some(true),
        single_sign_on_services: vec![Endpoint::new(HTTP_REDIRECT, "https://idp.example.com/sso")],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
    };

    let xml = idp.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed = swsaml_metadata::types::idp::IdpSsoDescriptorRef::from_xml(&doc, root).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.sso_base.base.id.as_deref(), Some("_idp_standalone"));
    assert_eq!(owned.want_authn_requests_signed, Some(true));
    assert_eq!(owned.single_sign_on_services.len(), 1);
    assert_eq!(owned.sso_base.single_logout_services.len(), 2);
    assert_eq!(owned.sso_base.manage_name_id_services.len(), 1);
    assert_eq!(owned.sso_base.name_id_formats.len(), 1);
}

// ── Standalone SpSsoDescriptor ─────────────────────────────────────────────

#[test]
fn roundtrip_sp_sso_descriptor_standalone() {
    let sp = SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: make_role_base(),
            artifact_resolution_services: vec![],
            single_logout_services: vec![],
            manage_name_id_services: vec![],
            name_id_formats: vec!["urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()],
        },
        authn_requests_signed: Some(false),
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![IndexedEndpoint::new_default(
            Endpoint::new(HTTP_POST, "https://sp.example.com/acs"),
            0,
        )],
        attribute_consuming_services: vec![],
    };

    let xml = sp.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed = swsaml_metadata::types::sp::SpSsoDescriptorRef::from_xml(&doc, root).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.authn_requests_signed, Some(false));
    assert_eq!(owned.want_assertions_signed, Some(true));
    assert_eq!(owned.assertion_consumer_services.len(), 1);
    assert_eq!(owned.assertion_consumer_services[0].is_default, Some(true));
    assert_eq!(owned.sso_base.name_id_formats.len(), 1);
}

// ── Standalone AuthnAuthorityDescriptor ────────────────────────────────────

#[test]
fn roundtrip_authn_authority_descriptor_standalone() {
    let aa = AuthnAuthorityDescriptor {
        base: make_role_base(),
        authn_query_services: vec![Endpoint::new(SOAP, "https://aa.example.com/authnquery")],
        assertion_id_request_services: vec![],
        name_id_formats: vec![],
    };

    let xml = aa.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed =
        swsaml_metadata::types::authn_authority::AuthnAuthorityDescriptorRef::from_xml(&doc, root)
            .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.authn_query_services.len(), 1);
    assert_eq!(
        owned.authn_query_services[0].location,
        "https://aa.example.com/authnquery"
    );
}

// ── Standalone PdpDescriptor ───────────────────────────────────────────────

#[test]
fn roundtrip_pdp_descriptor_standalone() {
    let pdp = PdpDescriptor {
        base: make_role_base(),
        authz_services: vec![Endpoint::new(SOAP, "https://pdp.example.com/authz")],
        assertion_id_request_services: vec![],
        name_id_formats: vec![],
    };

    let xml = pdp.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed = swsaml_metadata::types::pdp::PdpDescriptorRef::from_xml(&doc, root).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.authz_services.len(), 1);
}

// ── Standalone AttributeAuthorityDescriptor ────────────────────────────────

#[test]
fn roundtrip_attr_authority_descriptor_standalone() {
    let aa = AttributeAuthorityDescriptor {
        base: make_role_base(),
        attribute_services: vec![Endpoint::new(SOAP, "https://aa.example.com/attrs")],
        assertion_id_request_services: vec![],
        name_id_formats: vec![],
        attribute_profiles: vec![],
        attributes: vec![Attribute {
            name: "urn:oid:2.5.4.42".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![],
        }],
    };

    let xml = aa.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed = swsaml_metadata::types::attr_authority::AttributeAuthorityDescriptorRef::from_xml(
        &doc, root,
    )
    .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.attribute_services.len(), 1);
    assert_eq!(owned.attributes.len(), 1);
    assert_eq!(owned.attributes[0].name, "urn:oid:2.5.4.42");
}

// ── Standalone AffiliationDescriptor ───────────────────────────────────────

#[test]
fn roundtrip_affiliation_descriptor_standalone() {
    let aff = AffiliationDescriptor {
        affiliation_owner_id: "https://fed.example.com".to_string(),
        id: Some("_aff_standalone".to_string()),
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        affiliate_members: vec![
            "https://sp1.example.com".to_string(),
            "https://sp2.example.com".to_string(),
        ],
        key_descriptors: vec![KeyDescriptor {
            use_: None,
            key_info_xml: "<ds:KeyInfo><ds:KeyName>FedKey</ds:KeyName></ds:KeyInfo>".to_string(),
            encryption_methods: vec![],
        }],
    };

    let xml = aff.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let root = doc.document_element().unwrap();
    let parsed =
        swsaml_metadata::types::affiliation::AffiliationDescriptorRef::from_xml(&doc, root)
            .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.affiliation_owner_id, "https://fed.example.com");
    assert_eq!(owned.id.as_deref(), Some("_aff_standalone"));
    assert_eq!(owned.affiliate_members.len(), 2);
    assert_eq!(owned.key_descriptors.len(), 1);
    assert!(owned.key_descriptors[0].use_.is_none());
}

// ── Parse real-world-like SAML metadata XML ────────────────────────────────

#[test]
fn parse_handwritten_idp_metadata_xml() {
    let xml = r##"<md:EntityDescriptor
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        entityID="https://idp.university.edu/shibboleth"
        validUntil="2027-01-01T00:00:00Z">
      <md:IDPSSODescriptor
          protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
          WantAuthnRequestsSigned="true">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAX...</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://idp.university.edu/slo"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://idp.university.edu/sso/redirect"/>
        <md:SingleSignOnService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://idp.university.edu/sso/post"/>
      </md:IDPSSODescriptor>
      <md:Organization>
        <md:OrganizationName xml:lang="en">University</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="en">The University</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en">https://www.university.edu</md:OrganizationURL>
      </md:Organization>
      <md:ContactPerson contactType="technical">
        <md:GivenName>Admin</md:GivenName>
        <md:SurName>User</md:SurName>
        <md:EmailAddress>admin@university.edu</md:EmailAddress>
      </md:ContactPerson>
    </md:EntityDescriptor>"##;

    let doc = uppsala::parse(xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.entity_id, "https://idp.university.edu/shibboleth");
    assert!(owned.valid_until.is_some());
    assert!(owned.is_idp());
    assert!(!owned.is_sp());

    let idp = &owned.idp_sso_descriptors()[0];
    assert_eq!(idp.want_authn_requests_signed, Some(true));
    assert_eq!(idp.single_sign_on_services.len(), 2);
    assert_eq!(idp.sso_base.single_logout_services.len(), 1);
    assert_eq!(idp.sso_base.name_id_formats.len(), 1);
    assert_eq!(idp.sso_base.base.key_descriptors.len(), 1);
    assert_eq!(
        idp.sso_base.base.key_descriptors[0].use_,
        Some(KeyUse::Signing)
    );

    let org = owned.organization.as_ref().unwrap();
    assert_eq!(org.organization_names[0].lang, "en");
    assert_eq!(org.organization_names[0].value, "University");

    assert_eq!(owned.contact_persons.len(), 1);
    assert_eq!(
        owned.contact_persons[0].contact_type,
        ContactType::Technical
    );
    assert_eq!(
        owned.contact_persons[0].given_name.as_deref(),
        Some("Admin")
    );
    assert_eq!(
        owned.contact_persons[0].email_addresses[0],
        "admin@university.edu"
    );
}

#[test]
fn parse_handwritten_sp_metadata_xml() {
    let xml = r##"<md:EntityDescriptor
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        entityID="https://app.example.com/saml/metadata">
      <md:SPSSODescriptor
          protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
          AuthnRequestsSigned="true"
          WantAssertionsSigned="true">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIBxxx</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>MIIByyy</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
          <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm">
            <xenc:KeySize xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">256</xenc:KeySize>
          </md:EncryptionMethod>
        </md:KeyDescriptor>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://app.example.com/saml/slo"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://app.example.com/saml/acs"
            index="0"
            isDefault="true"/>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://app.example.com/saml/acs/redirect"
            index="1"/>
        <md:AttributeConsumingService index="0" isDefault="true">
          <md:ServiceName xml:lang="en">Example App</md:ServiceName>
          <md:ServiceDescription xml:lang="en">A sample application</md:ServiceDescription>
          <md:RequestedAttribute
              Name="urn:oid:0.9.2342.19200300.100.1.3"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
              FriendlyName="mail"
              isRequired="true"/>
          <md:RequestedAttribute
              Name="urn:oid:2.5.4.42"
              NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
              FriendlyName="givenName"/>
        </md:AttributeConsumingService>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>"##;

    let doc = uppsala::parse(xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.entity_id, "https://app.example.com/saml/metadata");
    assert!(owned.is_sp());

    let sp = &owned.sp_sso_descriptors()[0];
    assert_eq!(sp.authn_requests_signed, Some(true));
    assert_eq!(sp.want_assertions_signed, Some(true));
    assert_eq!(sp.assertion_consumer_services.len(), 2);
    assert_eq!(sp.assertion_consumer_services[0].index, 0);
    assert_eq!(sp.assertion_consumer_services[0].is_default, Some(true));
    assert_eq!(sp.assertion_consumer_services[1].index, 1);

    // Key descriptors
    assert_eq!(sp.sso_base.base.key_descriptors.len(), 2);
    assert_eq!(
        sp.sso_base.base.key_descriptors[0].use_,
        Some(KeyUse::Signing)
    );
    assert_eq!(
        sp.sso_base.base.key_descriptors[1].use_,
        Some(KeyUse::Encryption)
    );
    assert_eq!(
        sp.sso_base.base.key_descriptors[1].encryption_methods.len(),
        1
    );
    assert_eq!(
        sp.sso_base.base.key_descriptors[1].encryption_methods[0].algorithm,
        "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    );
    // KeySize may be in xenc namespace - check it parsed
    assert_eq!(
        sp.sso_base.base.key_descriptors[1].encryption_methods[0].key_size,
        Some(256)
    );

    // AttributeConsumingService
    assert_eq!(sp.attribute_consuming_services.len(), 1);
    let acs = &sp.attribute_consuming_services[0];
    assert_eq!(acs.index, 0);
    assert_eq!(acs.is_default, Some(true));
    assert_eq!(acs.service_names[0].value, "Example App");
    assert_eq!(acs.service_names[0].lang, "en");
    assert_eq!(acs.service_descriptions[0].value, "A sample application");
    assert_eq!(acs.requested_attributes.len(), 2);
    assert_eq!(acs.requested_attributes[0].is_required, Some(true));
    assert_eq!(
        acs.requested_attributes[0]
            .attribute
            .friendly_name
            .as_deref(),
        Some("mail")
    );
    assert_eq!(acs.requested_attributes[1].is_required, None);
    assert_eq!(
        acs.requested_attributes[1]
            .attribute
            .friendly_name
            .as_deref(),
        Some("givenName")
    );
}

#[test]
fn parse_handwritten_entities_descriptor_xml() {
    let xml = r##"<md:EntitiesDescriptor
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        Name="Example Federation"
        validUntil="2027-06-30T00:00:00Z">
      <md:EntitiesDescriptor Name="Sub Group">
        <md:EntityDescriptor entityID="https://sub-idp.example.com">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://sub-idp.example.com/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
      </md:EntitiesDescriptor>
      <md:EntityDescriptor entityID="https://root-sp.example.com">
        <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:AssertionConsumerService
              Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
              Location="https://root-sp.example.com/acs"
              index="0"/>
        </md:SPSSODescriptor>
      </md:EntityDescriptor>
    </md:EntitiesDescriptor>"##;

    let doc = uppsala::parse(xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntitiesDescriptorRef>(&doc)
            .unwrap();
    let owned = parsed.to_owned();

    assert_eq!(owned.name.as_deref(), Some("Example Federation"));
    assert!(owned.valid_until.is_some());
    assert_eq!(owned.children.len(), 2);

    // Nested EntitiesDescriptor
    match &owned.children[0] {
        MetadataChild::Entities(sub) => {
            assert_eq!(sub.name.as_deref(), Some("Sub Group"));
            assert_eq!(sub.children.len(), 1);
            match &sub.children[0] {
                MetadataChild::Entity(ed) => {
                    assert_eq!(ed.entity_id, "https://sub-idp.example.com");
                    assert!(ed.is_idp());
                }
                _ => panic!("expected Entity"),
            }
        }
        _ => panic!("expected Entities"),
    }

    // Direct EntityDescriptor
    match &owned.children[1] {
        MetadataChild::Entity(ed) => {
            assert_eq!(ed.entity_id, "https://root-sp.example.com");
            assert!(ed.is_sp());
        }
        _ => panic!("expected Entity"),
    }

    // Flatten
    let all = owned.entity_descriptors();
    assert_eq!(all.len(), 2);
}

// ── Key descriptor with no use attribute (both signing+encryption per E62) ──

#[test]
fn roundtrip_key_descriptor_no_use() {
    let ed = EntityDescriptor {
        entity_id: "https://dual-key.example.com".to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: None,
        roles: EntityRoles::Roles {
            idp_sso: vec![IdpSsoDescriptor {
                sso_base: SsoDescriptorBase {
                    base: RoleDescriptorBase {
                        id: None,
                        valid_until: None,
                        cache_duration: None,
                        protocol_support_enumeration: vec![SAML2_PROTO.to_string()],
                        error_url: None,
                        extensions: None,
                        key_descriptors: vec![KeyDescriptor {
                            use_: None, // Both signing and encryption per E62
                            key_info_xml:
                                "<ds:KeyInfo><ds:KeyName>DualKey</ds:KeyName></ds:KeyInfo>"
                                    .to_string(),
                            encryption_methods: vec![],
                        }],
                        organization: None,
                        contact_persons: vec![],
                    },
                    artifact_resolution_services: vec![],
                    single_logout_services: vec![],
                    manage_name_id_services: vec![],
                    name_id_formats: vec![],
                },
                want_authn_requests_signed: None,
                single_sign_on_services: vec![Endpoint::new(
                    HTTP_POST,
                    "https://dual-key.example.com/sso",
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

    let xml = ed.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed =
        parse_saml::<swsaml_metadata::types::entity_descriptor::EntityDescriptorRef>(&doc).unwrap();
    let owned = parsed.to_owned();

    let idp = &owned.idp_sso_descriptors()[0];
    // Per E62: omitted use means applicable to both uses
    assert!(idp.sso_base.base.key_descriptors[0].use_.is_none());
}
