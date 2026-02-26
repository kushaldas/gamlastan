// Roundtrip tests for assertion types: serialize -> parse -> deserialize -> compare.
//
// Each test constructs an owned SAML type, serializes it to XML, parses it back
// into a zero-copy Ref type, converts to owned, and asserts equality.

use chrono::{DateTime, Utc};

use swsaml_core::assertion::attribute::{Attribute, AttributeStatement, AttributeValue};
use swsaml_core::assertion::authn::{AuthnContext, AuthnStatement, SubjectLocality};
use swsaml_core::assertion::authz::{Action, AuthzDecisionStatement, DecisionType, Evidence};
use swsaml_core::assertion::conditions::{AudienceRestriction, Conditions, ProxyRestriction};
use swsaml_core::assertion::issuer::Issuer;
use swsaml_core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use swsaml_core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use swsaml_core::assertion::types::Assertion;
use swsaml_core::constants::*;
use swsaml_core::identifiers::SamlVersion;

use swsaml_xml::serialize::SamlSerialize;

/// Fixed timestamp for deterministic tests.
fn fixed_dt() -> DateTime<Utc> {
    "2025-06-15T12:30:00Z".parse::<DateTime<Utc>>().unwrap()
}

fn fixed_dt2() -> DateTime<Utc> {
    "2025-06-15T13:30:00Z".parse::<DateTime<Utc>>().unwrap()
}

// ── Assertion roundtrip ─────────────────────────────────────────────────────

#[test]
fn roundtrip_assertion_minimal() {
    let original = Assertion {
        id: "_a1".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: None,
        conditions: None,
        authn_statements: vec![],
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();

    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let roundtripped = parsed.to_owned();

    assert_eq!(roundtripped.id, original.id);
    assert_eq!(roundtripped.issue_instant, original.issue_instant);
    assert_eq!(roundtripped.version, original.version);
    assert_eq!(roundtripped.issuer.value, original.issuer.value);
    assert_eq!(roundtripped.issuer.format, original.issuer.format);
    assert!(!roundtripped.has_signature);
    assert!(roundtripped.subject.is_none());
    assert!(roundtripped.conditions.is_none());
    assert!(roundtripped.authn_statements.is_empty());
    assert!(roundtripped.authz_decision_statements.is_empty());
    assert!(roundtripped.attribute_statements.is_empty());
}

#[test]
fn roundtrip_assertion_with_subject_conditions_authn() {
    let original = Assertion {
        id: "_a2".to_string(),
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
            session_not_on_or_after: Some(fixed_dt2()),
            subject_locality: Some(SubjectLocality {
                address: Some("10.0.0.1".to_string()),
                dns_name: Some("client.example.com".to_string()),
            }),
            authn_context: AuthnContext {
                authn_context_class_ref: Some(
                    AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string(),
                ),
                authn_context_decl_ref: None,
                authenticating_authorities: vec!["https://upstream.example.com".to_string()],
            },
        }],
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.id, "_a2");
    let subj = rt.subject.as_ref().unwrap();
    match subj.name_id.as_ref().unwrap() {
        NameIdOrEncryptedId::NameId(n) => {
            assert_eq!(n.value, "user@example.com");
            assert_eq!(n.format.as_deref(), Some(NAMEID_EMAIL));
        }
        _ => panic!("Expected NameId"),
    }
    assert_eq!(subj.subject_confirmations.len(), 1);
    let sc = &subj.subject_confirmations[0];
    assert_eq!(sc.method, CM_BEARER);
    let scd = sc.subject_confirmation_data.as_ref().unwrap();
    assert_eq!(scd.not_on_or_after, Some(fixed_dt2()));
    assert_eq!(scd.recipient.as_deref(), Some("https://sp.example.com/acs"));
    assert_eq!(scd.in_response_to.as_deref(), Some("_req1"));

    let conds = rt.conditions.as_ref().unwrap();
    assert_eq!(conds.not_before, Some(fixed_dt()));
    assert_eq!(conds.not_on_or_after, Some(fixed_dt2()));
    assert_eq!(conds.audience_restrictions.len(), 1);
    assert_eq!(
        conds.audience_restrictions[0].audiences,
        vec!["https://sp.example.com"]
    );
    assert!(!conds.one_time_use);
    assert!(conds.proxy_restriction.is_none());

    let authn = &rt.authn_statements[0];
    assert_eq!(authn.authn_instant, fixed_dt());
    assert_eq!(authn.session_index.as_deref(), Some("_sess1"));
    assert_eq!(authn.session_not_on_or_after, Some(fixed_dt2()));
    let loc = authn.subject_locality.as_ref().unwrap();
    assert_eq!(loc.address.as_deref(), Some("10.0.0.1"));
    assert_eq!(loc.dns_name.as_deref(), Some("client.example.com"));
    assert_eq!(
        authn.authn_context.authn_context_class_ref.as_deref(),
        Some(AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
    );
    assert_eq!(
        authn.authn_context.authenticating_authorities,
        vec!["https://upstream.example.com"]
    );
}

#[test]
fn roundtrip_assertion_with_authz_decision() {
    let original = Assertion {
        id: "_a3".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "alice".to_string(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None,
            })),
            subject_confirmations: vec![],
        }),
        conditions: None,
        authn_statements: vec![],
        authz_decision_statements: vec![AuthzDecisionStatement {
            resource: "https://app.example.com/resource".to_string(),
            decision: DecisionType::Permit,
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
                assertion_id_refs: vec!["_evidence_ref1".to_string()],
                assertion_uri_refs: vec!["https://idp.example.com/assertions/1".to_string()],
            }),
        }],
        attribute_statements: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.authz_decision_statements.len(), 1);
    let ads = &rt.authz_decision_statements[0];
    assert_eq!(ads.resource, "https://app.example.com/resource");
    assert_eq!(ads.decision, DecisionType::Permit);
    assert_eq!(ads.actions.len(), 2);
    assert_eq!(ads.actions[0].value, "Read");
    assert_eq!(ads.actions[1].value, "Write");
    let evidence = ads.evidence.as_ref().unwrap();
    assert_eq!(evidence.assertion_id_refs, vec!["_evidence_ref1"]);
    assert_eq!(
        evidence.assertion_uri_refs,
        vec!["https://idp.example.com/assertions/1"]
    );
}

#[test]
fn roundtrip_assertion_with_attributes() {
    let original = Assertion {
        id: "_a4".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: None,
        conditions: None,
        authn_statements: vec![],
        authz_decision_statements: vec![],
        attribute_statements: vec![AttributeStatement {
            attributes: vec![
                Attribute {
                    name: "email".to_string(),
                    name_format: Some(ATTRNAME_FORMAT_URI.to_string()),
                    friendly_name: Some("E-Mail".to_string()),
                    values: vec![AttributeValue::String("user@example.com".to_string())],
                },
                Attribute {
                    name: "age".to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::Integer(42)],
                },
                Attribute {
                    name: "active".to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::Boolean(true)],
                },
                Attribute {
                    name: "empty".to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::Null],
                },
            ],
        }],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    assert_eq!(rt.attribute_statements.len(), 1);
    let stmt = &rt.attribute_statements[0];
    assert_eq!(stmt.attributes.len(), 4);

    let email_attr = &stmt.attributes[0];
    assert_eq!(email_attr.name, "email");
    assert_eq!(email_attr.name_format.as_deref(), Some(ATTRNAME_FORMAT_URI));
    assert_eq!(email_attr.friendly_name.as_deref(), Some("E-Mail"));
    assert_eq!(email_attr.values.len(), 1);
    match &email_attr.values[0] {
        AttributeValue::String(s) => assert_eq!(s, "user@example.com"),
        other => panic!("Expected String, got {:?}", other),
    }

    let age_attr = &stmt.attributes[1];
    assert_eq!(age_attr.name, "age");
    match &age_attr.values[0] {
        AttributeValue::Integer(i) => assert_eq!(*i, 42),
        other => panic!("Expected Integer, got {:?}", other),
    }

    let active_attr = &stmt.attributes[2];
    match &active_attr.values[0] {
        AttributeValue::Boolean(b) => assert!(*b),
        other => panic!("Expected Boolean, got {:?}", other),
    }

    let empty_attr = &stmt.attributes[3];
    match &empty_attr.values[0] {
        AttributeValue::Null => {}
        other => panic!("Expected Null, got {:?}", other),
    }
}

#[test]
fn roundtrip_assertion_conditions_one_time_use_and_proxy() {
    let original = Assertion {
        id: "_a5".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: None,
        conditions: Some(Conditions {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions: vec![
                AudienceRestriction {
                    audiences: vec!["https://sp1.example.com".to_string()],
                },
                AudienceRestriction {
                    audiences: vec![
                        "https://sp2.example.com".to_string(),
                        "https://sp3.example.com".to_string(),
                    ],
                },
            ],
            one_time_use: true,
            proxy_restriction: Some(ProxyRestriction {
                count: Some(2),
                audiences: vec!["https://proxy.example.com".to_string()],
            }),
        }),
        authn_statements: vec![],
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    let conds = rt.conditions.as_ref().unwrap();
    assert!(conds.not_before.is_none());
    assert!(conds.not_on_or_after.is_none());

    // E46: OR within each AudienceRestriction, AND across
    assert_eq!(conds.audience_restrictions.len(), 2);
    assert_eq!(
        conds.audience_restrictions[0].audiences,
        vec!["https://sp1.example.com"]
    );
    assert_eq!(
        conds.audience_restrictions[1].audiences,
        vec!["https://sp2.example.com", "https://sp3.example.com"]
    );

    assert!(conds.one_time_use);

    let pr = conds.proxy_restriction.as_ref().unwrap();
    assert_eq!(pr.count, Some(2));
    assert_eq!(pr.audiences, vec!["https://proxy.example.com"]);
}

#[test]
fn roundtrip_assertion_subject_multiple_confirmations() {
    let original = Assertion {
        id: "_a6".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "persistent_id_abc".to_string(),
                format: Some(NAMEID_PERSISTENT.to_string()),
                name_qualifier: Some("https://idp.example.com".to_string()),
                sp_name_qualifier: Some("https://sp.example.com".to_string()),
                sp_provided_id: Some("sp_user_42".to_string()),
            })),
            subject_confirmations: vec![
                SubjectConfirmation {
                    method: CM_BEARER.to_string(),
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationData {
                        not_before: Some(fixed_dt()),
                        not_on_or_after: Some(fixed_dt2()),
                        recipient: Some("https://sp.example.com/acs".to_string()),
                        in_response_to: Some("_r1".to_string()),
                        address: Some("192.168.1.1".to_string()),
                    }),
                },
                SubjectConfirmation {
                    method: CM_HOLDER_OF_KEY.to_string(),
                    name_id: None,
                    subject_confirmation_data: None,
                },
            ],
        }),
        conditions: None,
        authn_statements: vec![],
        authz_decision_statements: vec![],
        attribute_statements: vec![],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    let subj = rt.subject.as_ref().unwrap();
    match subj.name_id.as_ref().unwrap() {
        NameIdOrEncryptedId::NameId(n) => {
            assert_eq!(n.value, "persistent_id_abc");
            assert_eq!(n.format.as_deref(), Some(NAMEID_PERSISTENT));
            assert_eq!(n.name_qualifier.as_deref(), Some("https://idp.example.com"));
            assert_eq!(
                n.sp_name_qualifier.as_deref(),
                Some("https://sp.example.com")
            );
            assert_eq!(n.sp_provided_id.as_deref(), Some("sp_user_42"));
        }
        _ => panic!("Expected NameId"),
    }
    assert_eq!(subj.subject_confirmations.len(), 2);

    let sc0 = &subj.subject_confirmations[0];
    assert_eq!(sc0.method, CM_BEARER);
    let scd0 = sc0.subject_confirmation_data.as_ref().unwrap();
    assert_eq!(scd0.not_before, Some(fixed_dt()));
    assert_eq!(scd0.not_on_or_after, Some(fixed_dt2()));
    assert_eq!(scd0.address.as_deref(), Some("192.168.1.1"));

    let sc1 = &subj.subject_confirmations[1];
    assert_eq!(sc1.method, CM_HOLDER_OF_KEY);
    assert!(sc1.subject_confirmation_data.is_none());
}

#[test]
fn roundtrip_assertion_full_kitchen_sink() {
    // Build the most comprehensive assertion possible
    let original = Assertion {
        id: "_full_assertion".to_string(),
        issue_instant: fixed_dt(),
        version: SamlVersion::V2_0,
        issuer: Issuer {
            value: "https://idp.example.com".to_string(),
            format: Some(NAMEID_ENTITY.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
        },
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                value: "john@example.com".to_string(),
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
                    in_response_to: Some("_req99".to_string()),
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
            one_time_use: true,
            proxy_restriction: Some(ProxyRestriction {
                count: Some(0),
                audiences: vec![],
            }),
        }),
        authn_statements: vec![AuthnStatement {
            authn_instant: fixed_dt(),
            session_index: Some("_s1".to_string()),
            session_not_on_or_after: Some(fixed_dt2()),
            subject_locality: None,
            authn_context: AuthnContext {
                authn_context_class_ref: Some(
                    AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT.to_string(),
                ),
                authn_context_decl_ref: None,
                authenticating_authorities: vec![],
            },
        }],
        authz_decision_statements: vec![AuthzDecisionStatement {
            resource: "urn:resource:1".to_string(),
            decision: DecisionType::Deny,
            actions: vec![Action {
                namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc".to_string(),
                value: "Execute".to_string(),
            }],
            evidence: None,
        }],
        attribute_statements: vec![AttributeStatement {
            attributes: vec![
                Attribute {
                    name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7".to_string(),
                    name_format: Some(ATTRNAME_FORMAT_URI.to_string()),
                    friendly_name: Some("eduPersonEntitlement".to_string()),
                    values: vec![
                        AttributeValue::String("entitlement1".to_string()),
                        AttributeValue::String("entitlement2".to_string()),
                    ],
                },
                Attribute {
                    name: "isAdmin".to_string(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::Boolean(false)],
                },
            ],
        }],
    };

    let xml = original.to_xml_string().unwrap();
    let doc = uppsala::parse(&xml).unwrap();
    let parsed: swsaml_core::assertion::types::AssertionRef<'_> =
        swsaml_xml::parse_saml(&doc).unwrap();
    let rt = parsed.to_owned();

    // Verify everything roundtripped
    assert_eq!(rt.id, "_full_assertion");
    assert_eq!(rt.issuer.value, "https://idp.example.com");
    assert_eq!(rt.issuer.format.as_deref(), Some(NAMEID_ENTITY));

    assert!(rt.subject.is_some());
    let conds = rt.conditions.as_ref().unwrap();
    assert!(conds.one_time_use);
    assert_eq!(conds.proxy_restriction.as_ref().unwrap().count, Some(0));

    assert_eq!(rt.authn_statements.len(), 1);
    assert_eq!(rt.authz_decision_statements.len(), 1);
    assert_eq!(rt.authz_decision_statements[0].decision, DecisionType::Deny);
    assert_eq!(rt.attribute_statements.len(), 1);
    assert_eq!(rt.attribute_statements[0].attributes.len(), 2);
    assert_eq!(rt.attribute_statements[0].attributes[0].values.len(), 2);

    match &rt.attribute_statements[0].attributes[1].values[0] {
        AttributeValue::Boolean(b) => assert!(!b),
        other => panic!("Expected Boolean(false), got {:?}", other),
    }
}
