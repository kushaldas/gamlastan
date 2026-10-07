//! Attribute release driven through the full orchestrator, not just
//! `ReleasePolicy::filter` in isolation.
//!
//! Reuses the ADR's own falsification framing: the release seam
//! (`idp::orchestrator::release`) must produce the same federation-policy
//! outcome (REFEDS R&S entity-category filtering) whether it is exercised
//! directly or through `create_authn_response`'s fixed assembly order. If the
//! two diverge, the seam is doing something the assembly order does not
//! account for.

use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::constants;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
use gamlastan::idp::authn_broker::AuthnBroker;
use gamlastan::idp::entity_category::REFEDS_RESEARCH_AND_SCHOLARSHIP;
use gamlastan::idp::ident::IdentDb;
use gamlastan::idp::orchestrator::{
    create_authn_response, AuthenticatedSubject, AuthnMethodRef, ResponseEngine, ResponseOutcome,
    ResponseParams,
};
use gamlastan::idp::policy::{PolicyEntry, ReleasePolicy};
use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
use gamlastan::metadata::types::extensions::Extensions;
use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
use gamlastan::metadata::types::sp::SpSsoDescriptor;
use gamlastan::profiles::sso::idp::ProcessedAuthnRequest;

const IDP: &str = "https://idp.example.org/metadata";
const SP: &str = "https://sp.example.org/metadata";
const ACS: &str = "https://sp.example.org/acs";

const CERT_PEM: &str = include_str!("fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("fixtures/enc-key.pem");

fn fixture_signer() -> (SamlSigner, String) {
    let mut key = loader::load_pem_auto(KEY_PEM.as_bytes(), None).expect("load private key");
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);
    let cert_b64: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    (signer, cert_b64)
}

fn mail_attribute() -> Attribute {
    Attribute {
        name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
        friendly_name: Some("mail".to_string()),
        values: vec![AttributeValue::String("alice@example.org".to_string())],
    }
}

fn cn_attribute() -> Attribute {
    Attribute {
        name: "urn:oid:2.5.4.3".to_string(),
        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
        friendly_name: Some("cn".to_string()),
        values: vec![AttributeValue::String("Alice Example".to_string())],
    }
}

/// A trusted SP entity descriptor publishing the REFEDS R&S entity category.
fn sp_entity_with_refeds() -> EntityDescriptor {
    EntityDescriptor {
        entity_id: SP.to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: Some(Extensions::new(
            r#"<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                  Name="http://macedir.org/entity-category">
                <saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>"#
                .to_string(),
        )),
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![sp_sso()],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    }
}

fn sp_sso() -> SpSsoDescriptor {
    SpSsoDescriptor {
        sso_base: SsoDescriptorBase {
            base: RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]),
            artifact_resolution_services: vec![],
            single_logout_services: vec![],
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        },
        authn_requests_signed: None,
        want_assertions_signed: Some(false),
        assertion_consumer_services: vec![],
        attribute_consuming_services: vec![],
    }
}

fn processed() -> ProcessedAuthnRequest {
    ProcessedAuthnRequest {
        request_id: "_req1".to_string(),
        sp_entity_id: SP.to_string(),
        acs_url: ACS.to_string(),
        acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
        force_authn: false,
        is_passive: false,
        requested_name_id_format: None,
        requested_sp_name_qualifier: None,
        allow_create: false,
        has_name_id_policy: false,
        requested_authn_context_class_refs: vec![],
        authn_context_comparison: None,
        requested_authn_context_decl_refs: vec![],
        attribute_consuming_service_index: None,
        extensions: None,
    }
}

/// The subject holds both `mail` (in R&S) and `cn` (not in R&S).
fn subject() -> AuthenticatedSubject {
    AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute(), cn_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: constants::AUTHN_CONTEXT_PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess1".to_string()),
    }
}

#[test]
fn refeds_entity_category_release_survives_full_assembly() {
    let decisions = ReleasePolicy::with_default(
        PolicyEntry::new().with_entity_categories(vec![&gamlastan::idp::entity_category::REFEDS]),
    );
    let idents = IdentDb::in_memory(IDP);
    let broker = AuthnBroker::new();
    let (signer, cert) = fixture_signer();

    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents,
        broker: &broker,
        assertions: None,
        signer: &signer,
        cert_der_b64: &cert,
    };

    let params = ResponseParams {
        processed: processed(),
        sp_sso: sp_sso(),
        sp_entity: Some(sp_entity_with_refeds()),
    };

    // Sanity check the fixture actually publishes the category the assembly
    // order is expected to read.
    assert_eq!(
        params.sp_entity_categories(),
        vec![REFEDS_RESEARCH_AND_SCHOLARSHIP.to_string()]
    );

    let outcome = create_authn_response(&engine, &params, &subject()).expect("no config fault");
    let issued = match outcome {
        ResponseOutcome::Issued(issued) => issued,
        other => panic!("expected Issued, got {other:?}"),
    };

    // `mail` is in R&S; `cn` is not, so it must not survive the full assembly
    // even though the subject held it.
    assert_eq!(
        issued.released_attribute_names,
        vec!["urn:oid:0.9.2342.19200300.100.1.3".to_string()]
    );

    // And the released set actually reached the signed XML (not just the
    // engine's own bookkeeping).
    assert!(issued.xml.contains("alice@example.org"));
    assert!(!issued.xml.contains("Alice Example"));
}
