// Roundtrip tests for per-request certificate encryption (PEFIM-style),
// encrypted Advice, and NameID-valued attribute values.
//
// Flow under test: build an assertion -> encrypt it toward a DER cert
// supplied at request time -> decrypt with the matching private key ->
// parse and compare.

use base64::Engine;
use chrono::Utc;

use gamlastan::attribute_map::eptid_attribute;
use gamlastan::core::assertion::attribute::{Attribute, AttributeStatement, AttributeValue};
use gamlastan::core::assertion::issuer::Issuer;
use gamlastan::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use gamlastan::core::assertion::subject::Subject;
use gamlastan::core::assertion::types::{Assertion, AssertionRef};
use gamlastan::core::constants;
use gamlastan::core::identifiers::{SamlId, SamlVersion};
use gamlastan::crypto::decryptor::SamlDecryptor;
use gamlastan::crypto::keys::bergshamra_keys::KeysManager;
use gamlastan::crypto::keys::loader;
use gamlastan::profiles::sso::idp::{
    add_encrypted_advice, assertion_to_self_contained_xml, encrypt_assertion_to_cert,
    encrypt_response_assertions_to_cert,
};
use gamlastan::xml::deserialize::SamlDeserialize;
use gamlastan::xml::serialize::SamlSerialize;

const CERT_PEM: &str = include_str!("fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("fixtures/enc-key.pem");

/// Strip the PEM armor and decode the body to DER.
fn cert_der() -> Vec<u8> {
    let body: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("valid PEM body")
}

/// A decryptor holding the private key matching the fixture cert.
fn decryptor() -> SamlDecryptor {
    let key = loader::load_pem_auto(KEY_PEM.as_bytes(), None).expect("load private key");
    let mut km = KeysManager::new();
    km.add_key(key);
    SamlDecryptor::new(km)
}

fn sample_assertion() -> Assertion {
    let name_id = NameId {
        value: "user-1234".to_string(),
        format: Some(constants::NAMEID_PERSISTENT.to_string()),
        name_qualifier: Some("https://idp.example.com".to_string()),
        sp_name_qualifier: Some("https://sp.example.com".to_string()),
        sp_provided_id: None,
    };
    Assertion {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: Utc::now(),
        issuer: Issuer::entity("https://idp.example.com"),
        has_signature: false,
        subject: Some(Subject {
            name_id: Some(NameIdOrEncryptedId::NameId(name_id.clone())),
            subject_confirmations: vec![],
        }),
        conditions: None,
        advice: None,
        authn_statements: vec![],
        authz_decision_statements: vec![],
        // Include an EPTID (NameID-valued) attribute to cover the
        // AttributeValue::NameId serialization path end to end.
        attribute_statements: vec![AttributeStatement {
            attributes: vec![
                Attribute {
                    name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
                    name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                    friendly_name: Some("mail".to_string()),
                    values: vec![AttributeValue::String("user@example.com".to_string())],
                },
                eptid_attribute(vec![name_id]),
            ],
        }],
    }
}

fn parse_assertion_xml(xml: &str) -> Assertion {
    let xml_owned = xml.to_string();
    let doc = gamlastan::xml::uppsala::parse(&xml_owned).expect("parse decrypted assertion");
    let root = doc.document_element().expect("root element");
    // Decryption leaves the <saml:EncryptedAssertion> wrapper in place;
    // descend to the inner <saml:Assertion> when needed.
    let assertion_node = if doc
        .element(root)
        .is_some_and(|e| e.name.local_name == "Assertion")
    {
        root
    } else {
        doc.children_iter(root)
            .find(|n| {
                doc.element(*n)
                    .is_some_and(|e| e.name.local_name == "Assertion")
            })
            .expect("Assertion element inside wrapper")
    };
    AssertionRef::from_xml(&doc, assertion_node)
        .expect("deserialize assertion")
        .to_owned()
}

#[test]
fn test_encrypt_to_cert_and_decrypt_roundtrip() {
    let assertion = sample_assertion();
    let encrypted = encrypt_assertion_to_cert(&assertion, &cert_der(), None).unwrap();

    let raw = String::from_utf8(encrypted.raw.clone()).unwrap();
    // The wrapper element and the GCM default must be on the wire.
    assert!(raw.starts_with("<saml:EncryptedAssertion"));
    assert!(raw.contains("aes256-gcm"));
    assert!(raw.contains("rsa-oaep-mgf1p"));
    // The recipient cert travels in the EncryptedKey's KeyInfo.
    assert!(raw.contains("X509Certificate"));
    // The plaintext must not leak.
    assert!(!raw.contains("user@example.com"));

    // Decrypt with the matching private key and compare the parsed result.
    let plaintext = decryptor().decrypt(&raw).unwrap();
    let decrypted = parse_assertion_xml(&plaintext);
    assert_eq!(decrypted.id, assertion.id);
    assert_eq!(decrypted.issuer.value, "https://idp.example.com");
    let attrs = &decrypted.attribute_statements[0].attributes;
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].values[0].as_str(), Some("user@example.com"));
    // The EPTID value survived as a structured NameID.
    match &attrs[1].values[0] {
        AttributeValue::NameId(nid) => {
            assert_eq!(nid.value, "user-1234");
            assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_PERSISTENT));
        }
        other => panic!("expected NameId value, got {other:?}"),
    }
}

#[test]
fn test_self_contained_assertion_parses_standalone() {
    let xml = assertion_to_self_contained_xml(&sample_assertion()).unwrap();
    // Namespace-complete: parses without any parent context.
    let parsed = parse_assertion_xml(&xml);
    assert_eq!(parsed.attribute_statements[0].attributes.len(), 2);
}

#[test]
fn test_encrypted_advice_roundtrip() {
    // The advice assertion carries the attributes; the main assertion
    // embeds it encrypted toward the request-supplied cert.
    let advice_assertion = sample_assertion();
    let mut main = sample_assertion();
    main.attribute_statements.clear();

    add_encrypted_advice(&mut main, &advice_assertion, &cert_der(), None).unwrap();

    // Serialize the main assertion and parse it back.
    let xml = main.to_xml_string().unwrap();
    assert!(xml.contains("<saml:Advice>"));
    assert!(xml.contains("<saml:EncryptedAssertion"));
    let parsed = parse_assertion_xml(&xml);

    let advice = parsed.advice.expect("advice present");
    assert_eq!(advice.encrypted_assertions.len(), 1);

    // Decrypt the embedded assertion and verify the attributes survived.
    let inner_raw = String::from_utf8(advice.encrypted_assertions[0].raw.clone()).unwrap();
    let plaintext = decryptor().decrypt(&inner_raw).unwrap();
    let inner = parse_assertion_xml(&plaintext);
    assert_eq!(inner.id, advice_assertion.id);
    assert_eq!(inner.attribute_statements[0].attributes.len(), 2);
}

#[test]
fn test_encrypt_response_assertions_drains_cleartext_and_preserves_existing() {
    use gamlastan::core::assertion::types::EncryptedAssertion;
    use gamlastan::core::protocol::response::{Response, ResponseBase};
    use gamlastan::core::protocol::status::Status;

    let preexisting = EncryptedAssertion {
        raw: b"<saml:EncryptedAssertion>pre</saml:EncryptedAssertion>".to_vec(),
    };
    let response = Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: Some(Issuer::entity("https://idp.example.com")),
            has_signature: false,
            in_response_to: None,
            status: Status::success(),
        },
        assertions: vec![sample_assertion()],
        encrypted_assertions: vec![preexisting.clone()],
    };

    let out = encrypt_response_assertions_to_cert(response, &cert_der(), None).unwrap();
    // Cleartext is drained; the pre-existing encrypted assertion is kept
    // first and the freshly encrypted one is appended after it.
    assert!(out.assertions.is_empty());
    assert_eq!(out.encrypted_assertions.len(), 2);
    assert_eq!(out.encrypted_assertions[0].raw, preexisting.raw);

    // Re-invoking must not accumulate further (nothing cleartext remains).
    let again = encrypt_response_assertions_to_cert(out, &cert_der(), None).unwrap();
    assert_eq!(again.encrypted_assertions.len(), 2);
}
