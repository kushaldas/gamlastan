//! A signature's `Reference` is limited to the SAML profile by default: the
//! `enveloped-signature` and exclusive-c14n transforms, and a same-document
//! reference (`""` or `#id`). Anything else is refused *before* the verifier
//! processes it. Today the verifier accepts any transform bergshamra implements
//! and reads a relative file named by a `Reference URI`; these tests pin the
//! behavior we want.

use super::*;
use crate::crypto::ReferenceUris;
use crate::crypto::{keys::loader, SamlSigner};
use crate::profiles::sso::idp::signature_template;

const CERT: &str = include_str!("../../tests/fixtures/enc-cert.pem");
const KEY: &str = include_str!("../../tests/fixtures/enc-key.pem");
const SIG_ALG: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ENVELOPED: &str =
    r##"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"##;
const ID: &str = "_req1";

fn signer() -> SamlSigner {
    let mut key = loader::load_pem_auto(KEY.as_bytes(), None).unwrap();
    key.usage = KeyUsage::Sign;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    SamlSigner::new(keys)
}

fn verifier() -> SamlVerifier {
    let mut key = loader::load_pem_auto(CERT.as_bytes(), None).unwrap();
    key.usage = KeyUsage::Verify;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    let mut verifier = SamlVerifier::new(keys);
    verifier.set_skip_time_checks(true);
    verifier
}

fn cert_b64() -> String {
    CERT.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect()
}

/// An `AuthnRequest` signed over `#_req1` with `transforms_xml` replacing the
/// template's enveloped-signature transform.
fn request_with_transforms(transforms_xml: &str) -> String {
    let signature = signature_template(ID, &cert_b64(), SIG_ALG).replace(ENVELOPED, transforms_xml);
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer>{signature}</samlp:AuthnRequest>"#
    );
    signer().sign_enveloped(&xml).unwrap()
}

/// A signature, not made with a real key, whose only Reference has `uri`. The
/// verifier must refuse it for the URI alone, before reading anything.
fn request_with_reference_uri(uri: &str) -> String {
    format!(
        r##"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{SIG_ALG}"/><ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></samlp:AuthnRequest>"##
    )
}

fn message(error: &CryptoError) -> String {
    error.to_string().to_lowercase()
}

/// The error a verification must fail with. If it returns a result instead,
/// say what the verifier decided without dumping key material.
fn refused(result: Result<Vec<VerifyResult>, CryptoError>, what: &str) -> CryptoError {
    match result {
        Err(error) => {
            // It must be this policy that refused it, not some later error
            // that happens to mention a reference.
            assert!(
                message(&error).contains("transform policy"),
                "{what}: refused, but not by the transform policy: {error}"
            );
            error
        }
        Ok(results) => {
            let summary: Vec<String> = results
                .iter()
                .map(|r| match r {
                    VerifyResult::Valid { references, .. } => format!(
                        "valid (references: {:?})",
                        references
                            .iter()
                            .map(|r| r.uri.as_str())
                            .collect::<Vec<_>>()
                    ),
                    VerifyResult::Invalid { reason } => format!("invalid: {reason}"),
                })
                .collect();
            panic!("{what}: the verifier did not refuse it, it returned {summary:?}");
        }
    }
}

// -- controls: the SAML profile keeps working ---------------------------------

#[test]
fn the_standard_saml_signature_is_accepted() {
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"##
    ));
    let results = verifier().verify_all_enveloped(&xml).unwrap();
    assert!(results.iter().all(|r| r.all_reference_digests_verified()));
}

#[test]
fn exclusive_c14n_with_comments_is_accepted() {
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>"##
    ));
    assert!(verifier().verify_all_enveloped(&xml).is_ok());
}

// -- transforms outside the profile are refused --------------------------------

#[test]
fn an_xpath_filter_transform_is_refused_by_default() {
    // Signs everything except the Issuer: a valid signature over a *narrowed*
    // request, so changing the Issuer afterwards would still verify.
    let xml = request_with_transforms(
        r##"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and not(ancestor-or-self::saml:Issuer)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"##,
    );
    let tampered = xml.replace("sp.example.test", "evil.example.test");
    let error = refused(
        verifier().verify_all_enveloped(&tampered),
        "a narrowing XPath transform",
    );
    assert!(message(&error).contains("transform"), "{error}");
}

// -- a Reference URI must be local ----------------------------------------------

#[test]
fn a_relative_file_reference_is_refused_before_any_file_is_read() {
    // `Cargo.toml` exists in the working directory of the test run. If the
    // verifier read it, the error would be a digest mismatch; it must instead
    // refuse the URI itself.
    let error = refused(
        verifier().verify_all_enveloped(&request_with_reference_uri("Cargo.toml")),
        "a file reference",
    );
    let text = message(&error);
    assert!(text.contains("uri"), "{error}");
    assert!(!text.contains("digest"), "the file was read: {error}");
}

#[test]
fn a_missing_file_reference_gets_the_same_refusal_as_an_existing_one() {
    // The error must not reveal whether a file exists.
    let existing = refused(
        verifier().verify_all_enveloped(&request_with_reference_uri("Cargo.toml")),
        "an existing file reference",
    );
    let missing = refused(
        verifier().verify_all_enveloped(&request_with_reference_uri("does-not-exist-xyz.txt")),
        "a missing file reference",
    );
    let strip = |e: &CryptoError, name: &str| message(e).replace(&name.to_lowercase(), "<uri>");
    assert_eq!(
        strip(&existing, "Cargo.toml"),
        strip(&missing, "does-not-exist-xyz.txt")
    );
}

// -- options ---------------------------------------------------------------------

const XPATH_NARROWING: &str = r##"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and not(ancestor-or-self::saml:Issuer)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"##;
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const INCLUSIVE_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const ENVELOPED_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

#[test]
fn the_permissive_policy_restores_the_old_behavior() {
    // Documented so the risk of opting out is visible: the narrowed signature
    // verifies even after the Issuer is changed.
    let xml = request_with_transforms(XPATH_NARROWING);
    let tampered = xml.replace("sp.example.test", "evil.example.test");
    let mut verifier = verifier();
    verifier.set_transform_policy(TransformPolicy::permissive());
    let results = verifier.verify_all_enveloped(&tampered).unwrap();
    assert!(results.iter().all(|r| r.is_valid()));
}

#[test]
fn a_transform_can_be_allowed_explicitly() {
    let xml = request_with_transforms(XPATH_NARROWING);
    let policy = TransformPolicy::saml().with_transforms([ENVELOPED_URI, EXC_C14N, XPATH]);
    let verifier = verifier().with_transform_policy(policy);
    assert!(verifier.verify_all_enveloped(&xml).unwrap()[0].is_valid());
}

#[test]
fn inclusive_c14n_is_refused_by_default_and_can_be_allowed() {
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{INCLUSIVE_C14N}"/>"##
    ));
    let error = refused(verifier().verify_all_enveloped(&xml), "inclusive c14n");
    assert!(message(&error).contains("transform"), "{error}");

    let policy = TransformPolicy::saml().with_transforms([ENVELOPED_URI, EXC_C14N, INCLUSIVE_C14N]);
    let verifier = verifier().with_transform_policy(policy);
    assert!(verifier.verify_all_enveloped(&xml).unwrap()[0].is_valid());
}

// -- reference URIs ---------------------------------------------------------------

#[test]
fn the_empty_uri_is_accepted() {
    let signature =
        signature_template(ID, &cert_b64(), SIG_ALG).replace(r##"URI="#_req1""##, r##"URI="""##);
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer>{signature}</samlp:AuthnRequest>"#
    );
    let xml = signer().sign_enveloped(&xml).unwrap();
    assert!(verifier().verify_all_enveloped(&xml).unwrap()[0].is_valid());
}

#[test]
fn other_uri_forms_are_refused() {
    for uri in [
        "#xpointer(id('_req1'))",
        "#xpointer(/)",
        "cid:attachment",
        "https://example.test/doc.xml#_req1",
        "../Cargo.toml",
        "/etc/hostname",
    ] {
        let error = refused(
            verifier().verify_all_enveloped(&request_with_reference_uri(uri)),
            uri,
        );
        assert!(message(&error).contains("reference uri"), "{uri}: {error}");
    }
}

#[test]
fn any_uri_policy_lets_the_verifier_resolve_the_reference_again() {
    // Only for explicit non-SAML interoperability: the file is read again.
    let policy = TransformPolicy::saml().with_reference_uris(ReferenceUris::Any);
    let verifier = verifier().with_transform_policy(policy);
    let results = verifier
        .verify_all_enveloped(&request_with_reference_uri("Cargo.toml"))
        .unwrap();
    assert!(matches!(&results[0], VerifyResult::Invalid { .. }));
}

#[test]
fn the_uri_in_an_error_is_escaped_and_cut_short() {
    let uri = format!("line1\nline2{}", "x".repeat(500));
    let error = refused(
        verifier().verify_all_enveloped(&request_with_reference_uri(&uri)),
        "a long uri",
    );
    let text = error.to_string();
    assert!(
        !text.contains('\n'),
        "a newline reached the message: {text:?}"
    );
    assert!(
        text.len() < 300,
        "the message is not bounded: {} bytes",
        text.len()
    );
}

// -- limits and the single-reference option -----------------------------------------

/// A signature that is not valid, with the given references. The transform
/// policy is checked before verification, so it needs no real signature.
fn signature_with_references(references: &str) -> String {
    format!(
        r##"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{SIG_ALG}"/>{references}</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></samlp:AuthnRequest>"##
    )
}

fn reference(transforms: usize) -> String {
    let transform = format!(r##"<ds:Transform Algorithm="{ENVELOPED_URI}"/>"##);
    format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms>{}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##,
        transform.repeat(transforms)
    )
}

#[test]
fn too_many_references_are_refused() {
    let xml = signature_with_references(&reference(1).repeat(9));
    let error = refused(verifier().verify_all_enveloped(&xml), "nine references");
    assert!(message(&error).contains("references"), "{error}");

    let widened =
        verifier().with_transform_policy(TransformPolicy::saml().with_max_references(Some(20)));
    // Past the policy the document is simply not validly signed.
    let outcome = widened.verify_all_enveloped(&xml);
    assert!(
        !matches!(&outcome, Err(e) if message(e).contains("policy")),
        "{outcome:?}"
    );
}

#[test]
fn too_many_transforms_are_refused() {
    let xml = signature_with_references(&reference(9));
    let error = refused(verifier().verify_all_enveloped(&xml), "nine transforms");
    assert!(message(&error).contains("transforms"), "{error}");
}

#[test]
fn a_single_reference_can_be_required() {
    let xml = signature_with_references(&format!("{}{}", reference(1), reference(1)));
    // Off by default: the policy lets two references through.
    let outcome = verifier().verify_all_enveloped(&xml);
    assert!(
        !matches!(&outcome, Err(e) if message(e).contains("policy")),
        "{outcome:?}"
    );

    let strict = verifier()
        .with_transform_policy(TransformPolicy::saml().with_require_single_reference(true));
    let error = refused(strict.verify_all_enveloped(&xml), "two references");
    assert!(message(&error).contains("exactly one"), "{error}");
}

#[test]
fn every_signature_in_the_message_is_checked() {
    // The second signature uses a transform outside the profile.
    let good = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    let bad_signature = signature_with_references(&format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform Algorithm="{XPATH}"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
    ));
    let nested = bad_signature
        .split_once("<ds:Signature")
        .map(|(_, rest)| {
            format!(
                "<ds:Signature{}",
                rest.trim_end_matches("</samlp:AuthnRequest>")
            )
        })
        .unwrap();
    let both = good.replace(
        "</samlp:AuthnRequest>",
        &format!("{nested}</samlp:AuthnRequest>"),
    );
    let error = refused(
        verifier().verify_all_enveloped(&both),
        "a second bad signature",
    );
    assert!(message(&error).contains("transform"), "{error}");
}
