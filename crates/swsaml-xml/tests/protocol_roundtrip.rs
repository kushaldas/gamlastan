// Roundtrip tests for protocol types: serialize -> parse -> deserialize -> compare.
//
// Each test constructs an owned SAML protocol type, serializes it to XML, parses
// it back into a zero-copy Ref type, converts to owned, and asserts equality.

use chrono::{DateTime, Utc};

use swsaml_core::assertion::attribute::{Attribute, AttributeStatement, AttributeValue};
use swsaml_core::assertion::authn::AuthnContext;
use swsaml_core::assertion::authn::AuthnStatement;
use swsaml_core::assertion::authz::{Action, Evidence};
use swsaml_core::assertion::conditions::{AudienceRestriction, Conditions};
use swsaml_core::assertion::issuer::Issuer;
use swsaml_core::assertion::name_id::{NameId, NameIdOrEncryptedId, NameIdPolicy};
use swsaml_core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use swsaml_core::assertion::types::Assertion;
use swsaml_core::constants::*;
use swsaml_core::identifiers::SamlVersion;
use swsaml_core::protocol::artifact::{ArtifactResolve, ArtifactResponse};
use swsaml_core::protocol::logout::{LogoutRequest, LogoutResponse};
use swsaml_core::protocol::name_id_mapping::{NameIdMappingRequest, NameIdMappingResponse};
use swsaml_core::protocol::name_id_mgmt::{
    ManageNameIdRequest, ManageNameIdResponse, NewIdOrTerminate,
};
use swsaml_core::protocol::query::{
    AssertionIdRequest, AttributeQuery, AuthnQuery, AuthzDecisionQuery,
};
use swsaml_core::protocol::request::{
    AuthnContextComparison, AuthnRequest, RequestBase, RequestedAuthnContext, Scoping,
};
use swsaml_core::protocol::response::{Response, ResponseBase};
use swsaml_core::protocol::status::{Status, StatusCode};

use swsaml_xml::serialize::SamlSerialize;

fn fixed_dt() -> DateTime<Utc> {
    "2025-06-15T12:30:00Z".parse::<DateTime<Utc>>().unwrap()
}

fn fixed_dt2() -> DateTime<Utc> {
    "2025-06-15T13:30:00Z".parse::<DateTime<Utc>>().unwrap()
}

fn success_status() -> Status {
    Status::success()
}

fn make_request_base(id: &str) -> RequestBase {
    RequestBase {
        id: id.to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/sso".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
    }
}

fn make_response_base(id: &str) -> ResponseBase {
    ResponseBase {
        id: id.to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://sp.example.com/acs".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://idp.example.com")),
        has_signature: false,
        in_response_to: Some("_req1".to_string()),
        status: success_status(),
    }
}

// ── AuthnRequest ────────────────────────────────────────────────────────────

#[test]
fn roundtrip_authn_request_minimal() {
    let original = AuthnRequest {
        base: make_request_base("_ar1"),
        subject: None,
        name_id_policy: None,
        conditions: None,
        requested_authn_context: None,
        scoping: None,
        force_authn: None,
        is_passive: None,
        assertion_consumer_service_index: None,
        assertion_consumer_service_url: None,
        protocol_binding: None,
        attribute_consuming_service_index: None,
        provider_name: None,
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::request::AuthnRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.id, "_ar1");
    assert_eq!(
        rt.base.destination.as_deref(),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        rt.base.issuer.as_ref().unwrap().value,
        "https://sp.example.com"
    );
    assert!(rt.name_id_policy.is_none());
    assert!(rt.requested_authn_context.is_none());
    assert!(rt.scoping.is_none());
}

#[test]
fn roundtrip_authn_request_full() {
    let original = AuthnRequest {
        base: make_request_base("_ar2"),
        subject: None,
        name_id_policy: Some(NameIdPolicy {
            format: Some(NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: Some("https://sp.example.com".to_string()),
            allow_create: true,
        }),
        conditions: Some(Conditions {
            not_before: Some(fixed_dt()),
            not_on_or_after: Some(fixed_dt2()),
            audience_restrictions: vec![AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            }],
            one_time_use: false,
            proxy_restriction: None,
        }),
        requested_authn_context: Some(RequestedAuthnContext {
            authn_context_class_refs: vec![AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string()],
            authn_context_decl_refs: vec![],
            comparison: AuthnContextComparison::Exact,
        }),
        scoping: Some(Scoping {
            proxy_count: Some(2),
            idp_list: vec!["https://other-idp.example.com".to_string()],
            requester_ids: vec!["https://requester.example.com".to_string()],
        }),
        force_authn: Some(true),
        is_passive: Some(false),
        assertion_consumer_service_index: None,
        assertion_consumer_service_url: Some("https://sp.example.com/acs".to_string()),
        protocol_binding: Some(BINDING_HTTP_POST.to_string()),
        attribute_consuming_service_index: Some(1),
        provider_name: Some("Example SP".to_string()),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::request::AuthnRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.id, "_ar2");
    assert_eq!(rt.force_authn, Some(true));
    assert_eq!(rt.is_passive, Some(false));
    assert_eq!(
        rt.assertion_consumer_service_url.as_deref(),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(rt.protocol_binding.as_deref(), Some(BINDING_HTTP_POST));
    assert_eq!(rt.attribute_consuming_service_index, Some(1));
    assert_eq!(rt.provider_name.as_deref(), Some("Example SP"));

    let nip = rt.name_id_policy.as_ref().unwrap();
    assert_eq!(nip.format.as_deref(), Some(NAMEID_PERSISTENT));
    assert_eq!(
        nip.sp_name_qualifier.as_deref(),
        Some("https://sp.example.com")
    );
    assert!(nip.allow_create);

    let rac = rt.requested_authn_context.as_ref().unwrap();
    assert_eq!(rac.comparison, AuthnContextComparison::Exact);
    assert_eq!(
        rac.authn_context_class_refs,
        vec![AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT]
    );

    let scoping = rt.scoping.as_ref().unwrap();
    assert_eq!(scoping.proxy_count, Some(2));
    assert_eq!(scoping.idp_list, vec!["https://other-idp.example.com"]);
    assert_eq!(scoping.requester_ids, vec!["https://requester.example.com"]);

    let conds = rt.conditions.as_ref().unwrap();
    assert_eq!(conds.not_before, Some(fixed_dt()));
    assert_eq!(conds.not_on_or_after, Some(fixed_dt2()));
}

// ── Response ────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_response_empty() {
    let original = Response {
        base: make_response_base("_r1"),
        assertions: vec![],
        encrypted_assertions: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::response::ResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.id, "_r1");
    assert_eq!(rt.base.in_response_to.as_deref(), Some("_req1"));
    assert!(rt.base.status.is_success());
    assert!(rt.assertions.is_empty());
    assert!(rt.encrypted_assertions.is_empty());
}

#[test]
fn roundtrip_response_with_assertion() {
    let assertion = Assertion {
        id: "_a1".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "user@example.com".to_string(),
                format: Some(NAMEID_EMAIL.to_string()),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![SubjectConfirmation {
                method: CM_BEARER.to_string(),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before: None,
                    not_on_or_after: Some(fixed_dt2()),
                    recipient: Some("https://sp.example.com/acs".to_string()),
                    in_response_to: Some("_req1".to_string()),
                    address: None,
                }),
            }],
        }),
        conditions: Some(Conditions {
            not_before: Some(fixed_dt()),
            not_on_or_after: Some(fixed_dt2()),
            audience_restrictions: vec![AudienceRestriction {
                audiences: vec!["https://sp.example.com".to_string()],
            }],
            one_time_use: false,
            proxy_restriction: None,
        }),
        authn_statements: vec![AuthnStatement {
            authn_instant: fixed_dt(),
            session_index: Some("_sess1".to_string()),
            session_not_on_or_after: None,
            subject_locality: None,
            authn_context: AuthnContext {
                authn_context_class_ref: Some(
                    AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string(),
                ),
                authn_context_decl_ref: None,
                authenticating_authorities: vec![],
            },
        }],
        authz_decision_statements: vec![],
        attribute_statements: vec![AttributeStatement {
            attributes: vec![Attribute {
                name: "email".to_string(),
                name_format: Some(ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("E-Mail".to_string()),
                values: vec![AttributeValue::String("user@example.com".to_string())],
            }],
        }],
    };

    let original = Response {
        base: make_response_base("_r2"),
        assertions: vec![assertion],
        encrypted_assertions: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::response::ResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.id, "_r2");
    assert_eq!(rt.assertions.len(), 1);
    let a = &rt.assertions[0];
    assert_eq!(a.id, "_a1");
    assert_eq!(a.issuer.value, "https://idp.example.com");
    assert!(a.subject.is_some());
    assert!(a.conditions.is_some());
    assert_eq!(a.authn_statements.len(), 1);
    assert_eq!(a.attribute_statements.len(), 1);
    assert_eq!(a.attribute_statements[0].attributes[0].name, "email");
}

#[test]
fn roundtrip_response_with_sub_status() {
    let original = Response {
        base: ResponseBase {
            id: "_r3".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: fixed_dt(),
            destination: None,
            consent: None,
            issuer: None,
            has_signature: false,
            in_response_to: None,
            status: Status {
                status_code: StatusCode {
                    value: STATUS_REQUESTER.to_string(),
                    sub_status: Some(Box::new(StatusCode {
                        value: STATUS_INVALID_NAMEID_POLICY.to_string(),
                        sub_status: None,
                    })),
                },
                status_message: Some("Invalid NameID policy".to_string()),
                status_detail: None,
            },
        },
        assertions: vec![],
        encrypted_assertions: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::response::ResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.status.status_code.value, STATUS_REQUESTER);
    let sub = rt.base.status.status_code.sub_status.as_ref().unwrap();
    assert_eq!(sub.value, STATUS_INVALID_NAMEID_POLICY);
    assert_eq!(
        rt.base.status.status_message.as_deref(),
        Some("Invalid NameID policy")
    );
}

// ── LogoutRequest ───────────────────────────────────────────────────────────

#[test]
fn roundtrip_logout_request() {
    let original = LogoutRequest {
        id: "_lr1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/slo".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        not_on_or_after: Some(fixed_dt2()),
        reason: Some(LOGOUT_REASON_USER.to_string()),
        name_id: NameIdOrEncryptedId::NameId(NameId {
            value: "user@example.com".to_string(),
            format: Some(NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }),
        session_indexes: vec!["_sess1".to_string(), "_sess2".to_string()],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::logout::LogoutRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_lr1");
    assert_eq!(rt.not_on_or_after, Some(fixed_dt2()));
    assert_eq!(rt.reason.as_deref(), Some(LOGOUT_REASON_USER));
    match &rt.name_id {
        NameIdOrEncryptedId::NameId(n) => {
            assert_eq!(n.value, "user@example.com");
            assert_eq!(n.format.as_deref(), Some(NAMEID_EMAIL));
        }
        _ => panic!("Expected NameId"),
    }
    assert_eq!(rt.session_indexes, vec!["_sess1", "_sess2"]);
}

// ── LogoutResponse ──────────────────────────────────────────────────────────

#[test]
fn roundtrip_logout_response() {
    let original = LogoutResponse {
        id: "_lresp1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://sp.example.com/slo".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://idp.example.com")),
        has_signature: false,
        in_response_to: Some("_lr1".to_string()),
        status: success_status(),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::logout::LogoutResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_lresp1");
    assert_eq!(rt.in_response_to.as_deref(), Some("_lr1"));
    assert!(rt.status.is_success());
}

// ── ArtifactResolve ─────────────────────────────────────────────────────────

#[test]
fn roundtrip_artifact_resolve() {
    let original = ArtifactResolve {
        id: "_arres1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/artifact".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        artifact: "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzUEolscKI".to_string(),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::artifact::ArtifactResolveRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_arres1");
    assert_eq!(
        rt.artifact,
        "AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6auzUEolscKI"
    );
}

// ── ArtifactResponse ────────────────────────────────────────────────────────

#[test]
fn roundtrip_artifact_response_no_message() {
    let original = ArtifactResponse {
        id: "_arresp1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity("https://idp.example.com")),
        has_signature: false,
        in_response_to: Some("_arres1".to_string()),
        status: success_status(),
        message: None,
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::artifact::ArtifactResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_arresp1");
    assert_eq!(rt.in_response_to.as_deref(), Some("_arres1"));
    assert!(rt.status.is_success());
    assert!(rt.message.is_none());
}

// ── ManageNameIdRequest ─────────────────────────────────────────────────────

#[test]
fn roundtrip_manage_name_id_request_new_id() {
    let original = ManageNameIdRequest {
        id: "_mn1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/manage".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(NameId {
            value: "old_user_id".to_string(),
            format: Some(NAMEID_PERSISTENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }),
        new_id_or_terminate: NewIdOrTerminate::NewId("new_user_id".to_string()),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::name_id_mgmt::ManageNameIdRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_mn1");
    match &rt.name_id {
        NameIdOrEncryptedId::NameId(n) => assert_eq!(n.value, "old_user_id"),
        _ => panic!("Expected NameId"),
    }
    match &rt.new_id_or_terminate {
        NewIdOrTerminate::NewId(s) => assert_eq!(s, "new_user_id"),
        _ => panic!("Expected NewId"),
    }
}

#[test]
fn roundtrip_manage_name_id_request_terminate() {
    let original = ManageNameIdRequest {
        id: "_mn2".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: None,
        consent: None,
        issuer: None,
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(NameId {
            value: "user_to_terminate".to_string(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }),
        new_id_or_terminate: NewIdOrTerminate::Terminate,
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::name_id_mgmt::ManageNameIdRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_mn2");
    assert!(matches!(
        rt.new_id_or_terminate,
        NewIdOrTerminate::Terminate
    ));
}

// ── ManageNameIdResponse ────────────────────────────────────────────────────

#[test]
fn roundtrip_manage_name_id_response() {
    let original = ManageNameIdResponse {
        id: "_mnr1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity("https://idp.example.com")),
        has_signature: false,
        in_response_to: Some("_mn1".to_string()),
        status: success_status(),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::name_id_mgmt::ManageNameIdResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_mnr1");
    assert_eq!(rt.in_response_to.as_deref(), Some("_mn1"));
    assert!(rt.status.is_success());
}

// ── NameIdMappingRequest ────────────────────────────────────────────────────

#[test]
fn roundtrip_name_id_mapping_request() {
    let original = NameIdMappingRequest {
        id: "_nmap1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/nameid-map".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        name_id: NameIdOrEncryptedId::NameId(NameId {
            value: "existing_name_id".to_string(),
            format: Some(NAMEID_PERSISTENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }),
        name_id_policy: NameIdPolicy {
            format: Some(NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        },
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::name_id_mapping::NameIdMappingRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_nmap1");
    match &rt.name_id {
        NameIdOrEncryptedId::NameId(n) => {
            assert_eq!(n.value, "existing_name_id");
            assert_eq!(n.format.as_deref(), Some(NAMEID_PERSISTENT));
        }
        _ => panic!("Expected NameId"),
    }
    assert_eq!(rt.name_id_policy.format.as_deref(), Some(NAMEID_TRANSIENT));
    assert!(rt.name_id_policy.allow_create);
}

// ── NameIdMappingResponse ───────────────────────────────────────────────────

#[test]
fn roundtrip_name_id_mapping_response() {
    let original = NameIdMappingResponse {
        id: "_nmapr1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: None,
        consent: None,
        issuer: Some(Issuer::entity("https://idp.example.com")),
        has_signature: false,
        in_response_to: Some("_nmap1".to_string()),
        status: success_status(),
        name_id: Some(NameIdOrEncryptedId::NameId(NameId {
            value: "mapped_name_id".to_string(),
            format: Some(NAMEID_TRANSIENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        })),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::name_id_mapping::NameIdMappingResponseRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_nmapr1");
    match rt.name_id.as_ref().unwrap() {
        NameIdOrEncryptedId::NameId(nid) => {
            assert_eq!(nid.value, "mapped_name_id");
            assert_eq!(nid.format.as_deref(), Some(NAMEID_TRANSIENT));
        }
        _ => panic!("Expected NameId variant"),
    }
}

// ── AssertionIdRequest ──────────────────────────────────────────────────────

#[test]
fn roundtrip_assertion_id_request() {
    let original = AssertionIdRequest {
        id: "_aidr1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/query".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        assertion_id_refs: vec!["_a1".to_string(), "_a2".to_string(), "_a3".to_string()],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::query::AssertionIdRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_aidr1");
    assert_eq!(rt.assertion_id_refs, vec!["_a1", "_a2", "_a3"]);
}

// ── AuthnQuery ──────────────────────────────────────────────────────────────

#[test]
fn roundtrip_authn_query() {
    let original = AuthnQuery {
        id: "_aq1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/authn-query".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "user@example.com".to_string(),
                format: Some(NAMEID_EMAIL.to_string()),
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![],
        },
        session_index: Some("_sess42".to_string()),
        requested_authn_context: Some(RequestedAuthnContext {
            authn_context_class_refs: vec![AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string()],
            authn_context_decl_refs: vec![],
            comparison: AuthnContextComparison::Minimum,
        }),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::query::AuthnQueryRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_aq1");
    assert_eq!(rt.session_index.as_deref(), Some("_sess42"));
    match rt.subject.name_id.as_ref().unwrap() {
        NameIdOrEncryptedId::NameId(n) => assert_eq!(n.value, "user@example.com"),
        _ => panic!("Expected NameId"),
    }
    let rac = rt.requested_authn_context.as_ref().unwrap();
    assert_eq!(rac.comparison, AuthnContextComparison::Minimum);
}

// ── AttributeQuery ──────────────────────────────────────────────────────────

#[test]
fn roundtrip_attribute_query() {
    let original = AttributeQuery {
        id: "_atq1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://idp.example.com/attr-query".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "user@example.com".to_string(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![],
        },
        attributes: vec![
            Attribute {
                name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
                name_format: Some(ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: Some("eduPersonEntitlement".to_string()),
                values: vec![],
            },
            Attribute {
                name: "email".to_string(),
                name_format: None,
                friendly_name: None,
                values: vec![],
            },
        ],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::query::AttributeQueryRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_atq1");
    assert_eq!(rt.attributes.len(), 2);
    assert_eq!(rt.attributes[0].name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.7");
    assert_eq!(
        rt.attributes[0].friendly_name.as_deref(),
        Some("eduPersonEntitlement")
    );
    assert_eq!(rt.attributes[1].name, "email");
}

// ── AuthzDecisionQuery ──────────────────────────────────────────────────────

#[test]
fn roundtrip_authz_decision_query() {
    let original = AuthzDecisionQuery {
        id: "_adq1".to_string(),
        version: SamlVersion::V2_0,
        issue_instant: fixed_dt(),
        destination: Some("https://pdp.example.com/authz".to_string()),
        consent: None,
        issuer: Some(Issuer::entity("https://sp.example.com")),
        has_signature: false,
        subject: Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "alice".to_string(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![],
        },
        resource: "https://app.example.com/secret".to_string(),
        actions: vec![
            Action {
                namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc".to_string(),
                value: "Read".to_string(),
            },
            Action {
                namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc".to_string(),
                value: "Write".to_string(),
            },
        ],
        evidence: Some(Evidence {
            assertion_id_refs: vec!["_evidence_a1".to_string()],
            assertion_uri_refs: vec![],
        }),
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::query::AuthzDecisionQueryRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_adq1");
    assert_eq!(rt.resource, "https://app.example.com/secret");
    assert_eq!(rt.actions.len(), 2);
    assert_eq!(rt.actions[0].value, "Read");
    assert_eq!(rt.actions[1].value, "Write");
    let evidence = rt.evidence.as_ref().unwrap();
    assert_eq!(evidence.assertion_id_refs, vec!["_evidence_a1"]);
}

// ── Consent roundtrip ───────────────────────────────────────────────────────

#[test]
fn roundtrip_authn_request_with_consent() {
    let original = AuthnRequest {
        base: RequestBase {
            id: "_consent1".to_string(),
            version: SamlVersion::V2_0,
            issue_instant: fixed_dt(),
            destination: None,
            consent: Some(CONSENT_UNSPECIFIED.to_string()),
            issuer: None,
            has_signature: false,
        },
        subject: None,
        name_id_policy: None,
        conditions: None,
        requested_authn_context: None,
        scoping: None,
        force_authn: None,
        is_passive: None,
        assertion_consumer_service_index: None,
        assertion_consumer_service_url: None,
        protocol_binding: None,
        attribute_consuming_service_index: None,
        provider_name: None,
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::protocol::request::AuthnRequestRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.base.consent.as_deref(), Some(CONSENT_UNSPECIFIED));
    assert!(rt.base.issuer.is_none());
    assert!(rt.base.destination.is_none());
}
