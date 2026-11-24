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

/// An `AuthnRequest` signed over `#_req1` whose reference carries exactly the
/// transforms in `transforms_xml` (the content of `ds:Transforms`; the template's
/// own transforms are replaced, so none are left over).
fn request_with_transforms(transforms_xml: &str) -> String {
    let template = signature_template(ID, &cert_b64(), SIG_ALG);
    let start = template.find("<ds:Transforms>").unwrap() + "<ds:Transforms>".len();
    let end = template.find("</ds:Transforms>").unwrap();
    let signature = format!(
        "{}{}{}",
        &template[..start],
        transforms_xml,
        &template[end..]
    );
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
    // An XPath filter replaces the enveloped-signature transform, so allowing it
    // also means relaxing the profile structure.
    let policy = TransformPolicy::saml()
        .with_transforms([ENVELOPED_URI, EXC_C14N, XPATH])
        .with_require_profile_transforms(false);
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
    let policy = TransformPolicy::saml()
        .with_reference_uris(ReferenceUris::Any)
        .with_require_profile_transforms(false);
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

/// A reference with exactly the profile transforms (enveloped-signature, one c14n).
fn profile_reference() -> String {
    format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_URI}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
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
    let xml = signature_with_references(&profile_reference().repeat(9));
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
    let xml = signature_with_references(&format!("{}{}", profile_reference(), profile_reference()));
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

// -- elements the backend treats as transforms, whatever their namespace -----------

/// bergshamra executes any child of `ds:Transforms` whose *local name* is
/// `Transform`, in any namespace or none. The policy must see the same ones.
const UNQUALIFIED_XPATH: &str = r##"<Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and not(ancestor-or-self::saml:Issuer)</ds:XPath></Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"##;
const FOREIGN_XPATH: &str = r##"<x:Transform xmlns:x="urn:example:other" Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Signature) and not(ancestor-or-self::saml:Issuer)</ds:XPath></x:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"##;

#[test]
fn an_unqualified_xpath_transform_is_refused_like_a_qualified_one() {
    let xml = request_with_transforms(UNQUALIFIED_XPATH);
    let tampered = xml.replace("sp.example.test", "evil.example.test");
    let error = refused(
        verifier().verify_all_enveloped(&tampered),
        "an unqualified XPath transform",
    );
    assert!(message(&error).contains("transform"), "{error}");
}

#[test]
fn a_foreign_namespace_xpath_transform_is_refused_like_a_qualified_one() {
    let xml = request_with_transforms(FOREIGN_XPATH);
    let tampered = xml.replace("sp.example.test", "evil.example.test");
    let error = refused(
        verifier().verify_all_enveloped(&tampered),
        "a foreign-namespace XPath transform",
    );
    assert!(message(&error).contains("transform"), "{error}");
}

#[test]
fn many_unqualified_transforms_cannot_dodge_the_limit() {
    // Nine namespace-less transforms must not slip past the count limit; they
    // are refused at the first one, for being outside the XML-DSig namespace.
    let transform = format!(r##"<Transform Algorithm="{ENVELOPED_URI}"/>"##);
    let reference = format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms>{}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##,
        transform.repeat(9)
    );
    let xml = signature_with_references(&reference);
    let error = refused(
        verifier().verify_all_enveloped(&xml),
        "nine unqualified transforms",
    );
    assert!(message(&error).contains("namespace"), "{error}");
}

#[test]
fn an_unqualified_standard_transform_is_not_accepted_as_profile_compliant() {
    // Even a transform that would be allowed by its URI is refused when it is
    // not in the XML-DSig namespace: a SAML signature never has one.
    let xml = request_with_transforms(&format!(
        r##"<Transform Algorithm="{ENVELOPED_URI}"/><ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    let error = refused(
        verifier().verify_all_enveloped(&xml),
        "an unqualified transform",
    );
    assert!(message(&error).contains("namespace"), "{error}");
}

// -- the single-signature path (`verify_enveloped`), used by SLO and MDQ ----------------

#[test]
fn verify_enveloped_refuses_a_first_signature_with_an_xpath_transform() {
    let xml = request_with_transforms(XPATH_NARROWING);
    let tampered = xml.replace("sp.example.test", "evil.example.test");
    let error = verifier()
        .verify_enveloped(&tampered)
        .expect_err("the single-signature path must apply the transform policy");
    assert!(message(&error).contains("transform policy"), "{error}");
}

#[test]
fn verify_enveloped_accepts_the_standard_signature() {
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    let result = verifier().verify_enveloped(&xml).unwrap();
    assert!(result.is_valid() && result.all_reference_digests_verified());
}

#[test]
fn single_and_all_verification_inspect_the_same_signatures_as_the_backend() {
    // A clean first signature and a second one with an XPath transform. The
    // backend's single-signature path verifies only the first, so the policy
    // checks only the first there; the all-signatures path checks both. This
    // mirrors the algorithm-policy test of the same name and pins the symmetry.
    let clean = signature_template(ID, &cert_b64(), SIG_ALG);
    let narrowing = signature_template(ID, &cert_b64(), SIG_ALG).replace(
        ENVELOPED,
        r##"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"##,
    );
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer>{clean}{narrowing}</samlp:AuthnRequest>"#
    );
    let signed = signer().sign_enveloped(&xml).unwrap();

    assert!(
        verifier().verify_enveloped(&signed).unwrap().is_valid(),
        "the single-signature path consumes only the first signature"
    );
    let error = refused(
        verifier().verify_all_enveloped(&signed),
        "a second signature with an XPath transform",
    );
    assert!(message(&error).contains("transform"), "{error}");
}

// -- `with_transforms` replaces, `with_additional_transforms` extends -----------------

#[test]
fn with_transforms_replaces_the_allowlist_so_it_must_list_the_profile_too() {
    // Listing only the extra transform drops enveloped-signature and exclusive
    // c14n: every ordinary signature is then refused. This is the documented
    // behavior; `with_additional_transforms` is the safe way to add one.
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    let only_inclusive = TransformPolicy::saml().with_transforms([INCLUSIVE_C14N]);
    let error = refused(
        verifier()
            .with_transform_policy(only_inclusive)
            .verify_all_enveloped(&xml),
        "an allowlist without the profile",
    );
    assert!(message(&error).contains("transform"), "{error}");
}

#[test]
fn with_additional_transforms_keeps_the_profile_and_adds_the_extra_one() {
    let policy = TransformPolicy::saml().with_additional_transforms([INCLUSIVE_C14N]);
    assert!(policy.allows_transform(INCLUSIVE_C14N));
    assert!(policy.allows_transform(ENVELOPED_URI));
    assert!(policy.allows_transform(EXC_C14N));
    assert!(!policy.allows_transform(XPATH));

    let standard = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    let inclusive = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{INCLUSIVE_C14N}"/>"##
    ));
    let verifier = verifier().with_transform_policy(policy);
    assert!(verifier.verify_all_enveloped(&standard).unwrap()[0].is_valid());
    assert!(verifier.verify_all_enveloped(&inclusive).unwrap()[0].is_valid());
}

// -- structure the backend tolerates today, pinned ---------------------------------

#[test]
fn more_than_one_transforms_element_in_a_reference_is_refused() {
    let reference = format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_URI}"/></ds:Transforms><ds:Transforms><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
    );
    let error = verifier()
        .verify_all_enveloped(&signature_with_references(&reference))
        .expect_err("two ds:Transforms elements must be refused");
    assert!(message(&error).contains("more than one"), "{error}");
}

#[test]
fn a_transform_without_an_algorithm_is_refused() {
    let reference = format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
    );
    let error = verifier()
        .verify_all_enveloped(&signature_with_references(&reference))
        .expect_err("a transform with no Algorithm must be refused");
    assert!(message(&error).contains("algorithm"), "{error}");
}

// -- key retrieval inside a signature's KeyInfo --------------------------------------

/// A request signed by the fixture key whose `KeyInfo` is `key_info` instead of
/// the template's embedded certificate.
fn request_with_key_info(key_info: &str, trailer: &str) -> String {
    let template = signature_template(ID, &cert_b64(), SIG_ALG);
    let start = template
        .find("<ds:KeyInfo")
        .expect("template has a KeyInfo");
    let end = template
        .find("</ds:KeyInfo>")
        .expect("template has a KeyInfo")
        + "</ds:KeyInfo>".len();
    let signature = format!("{}{}{}", &template[..start], key_info, &template[end..]);
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer>{signature}{trailer}</samlp:AuthnRequest>"#
    );
    signer().sign_enveloped(&xml).unwrap()
}

/// The fixture certificate as a DER file the verifier could be told to read.
struct CertFile(std::path::PathBuf);

impl CertFile {
    fn new(tag: &str) -> Self {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64())
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "gamlastan-retrieval-{tag}-{}-{}.der",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, der).unwrap();
        Self(path)
    }

    fn retrieval_method(&self) -> String {
        format!(
            r##"<ds:KeyInfo><ds:RetrievalMethod URI="{}" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/></ds:KeyInfo>"##,
            self.0.display()
        )
    }
}

impl Drop for CertFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A verifier with **no keys at all** that has turned off `trusted_keys_only`,
/// the one setting under which a message can supply its own key.
fn keyless_verifier_trusting_the_message() -> SamlVerifier {
    let mut verifier = SamlVerifier::new(KeysManager::new());
    verifier.set_trusted_keys_only(false);
    verifier.set_skip_time_checks(true);
    verifier
}

#[test]
fn a_retrieval_method_in_key_info_is_refused_by_default() {
    // Without the policy this authenticates under a key read from a path named by
    // the message: the trust anchor came from the attacker.
    let file = CertFile::new("default");
    let xml = request_with_key_info(&file.retrieval_method(), "");
    let error = refused(
        keyless_verifier_trusting_the_message().verify_all_enveloped(&xml),
        "a RetrievalMethod",
    );
    assert!(message(&error).contains("retrievalmethod"), "{error}");
}

#[test]
fn an_unqualified_retrieval_method_is_refused_too() {
    // bergshamra accepts a RetrievalMethod in the XML-DSig namespace or in none.
    let file = CertFile::new("unqualified");
    let key_info = file
        .retrieval_method()
        .replace("ds:RetrievalMethod", "RetrievalMethod");
    let xml = request_with_key_info(&key_info, "");
    let error = refused(
        keyless_verifier_trusting_the_message().verify_all_enveloped(&xml),
        "an unqualified RetrievalMethod",
    );
    assert!(message(&error).contains("retrievalmethod"), "{error}");
}

#[test]
fn a_key_info_reference_is_refused_by_default() {
    // dsig11:KeyInfoReference makes the verifier use *any* element of the
    // document, found by ID, as the signature's KeyInfo, so a RetrievalMethod
    // could hide there from a scan of the signature's own KeyInfo.
    let file = CertFile::new("reference");
    let key_info = r##"<ds:KeyInfo><dsig11:KeyInfoReference xmlns:dsig11="http://www.w3.org/2009/xmldsig11#" URI="#hidden"/></ds:KeyInfo>"##;
    let hidden = file.retrieval_method().replace(
        "<ds:KeyInfo>",
        r##"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="hidden">"##,
    );
    let xml = request_with_key_info(key_info, &hidden);
    let error = refused(
        keyless_verifier_trusting_the_message().verify_all_enveloped(&xml),
        "a KeyInfoReference",
    );
    assert!(message(&error).contains("keyinforeference"), "{error}");
}

#[test]
fn key_retrieval_can_be_allowed_explicitly() {
    // Documents what the opt-in means: the verifier then reads the file.
    let file = CertFile::new("allowed");
    let xml = request_with_key_info(&file.retrieval_method(), "");
    let verifier = keyless_verifier_trusting_the_message()
        .with_transform_policy(TransformPolicy::saml().with_allow_key_retrieval(true));
    assert!(verifier.verify_all_enveloped(&xml).unwrap()[0].is_valid());
}

#[test]
fn the_embedded_certificate_key_info_is_unaffected() {
    let xml = request_with_transforms(&format!(
        r##"{ENVELOPED}<ds:Transform Algorithm="{EXC_C14N}"/>"##
    ));
    assert!(xml.contains("<ds:X509Certificate>"));
    assert!(verifier().verify_all_enveloped(&xml).unwrap()[0].is_valid());
}

// -- the profile transform structure: enveloped-signature and one c14n ----------------

/// A request signed by the fixture key whose reference uses exactly `transforms`
/// (the whole `ds:Transforms` element, or nothing).
fn request_with_transforms_element(transforms_element: &str) -> String {
    let template = signature_template(ID, &cert_b64(), SIG_ALG);
    let start = template.find("<ds:Transforms>").unwrap();
    let end = template.find("</ds:Transforms>").unwrap() + "</ds:Transforms>".len();
    let signature = format!(
        "{}{}{}",
        &template[..start],
        transforms_element,
        &template[end..]
    );
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.test</saml:Issuer>{signature}</samlp:AuthnRequest>"#
    );
    signer().sign_enveloped(&xml).unwrap()
}

#[test]
fn a_reference_with_no_transforms_is_refused_by_default() {
    // The backend would digest it under inclusive c14n, the thing the default
    // refuses: omitting the transforms must not be a way round the allowlist.
    let xml = request_with_transforms_element("");
    let error = refused(verifier().verify_all_enveloped(&xml), "no ds:Transforms");
    assert!(message(&error).contains("enveloped-signature"), "{error}");
}

#[test]
fn an_empty_transforms_element_is_refused_by_default() {
    let xml = request_with_transforms_element("<ds:Transforms/>");
    let error = refused(
        verifier().verify_all_enveloped(&xml),
        "an empty ds:Transforms",
    );
    assert!(message(&error).contains("enveloped-signature"), "{error}");
}

#[test]
fn enveloped_signature_without_a_c14n_transform_is_refused_by_default() {
    let xml = request_with_transforms_element(&format!(
        r##"<ds:Transforms>{ENVELOPED}</ds:Transforms>"##
    ));
    let error = refused(verifier().verify_all_enveloped(&xml), "no c14n transform");
    assert!(message(&error).contains("canonicalization"), "{error}");
}

#[test]
fn a_c14n_transform_without_enveloped_signature_is_refused_by_default() {
    // Not signed by us: such a signature would cover itself. The policy runs first.
    let reference = format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
    );
    let error = refused(
        verifier().verify_all_enveloped(&signature_with_references(&reference)),
        "c14n without enveloped-signature",
    );
    assert!(message(&error).contains("enveloped-signature"), "{error}");
}

#[test]
fn two_canonicalization_transforms_are_refused_by_default() {
    let reference = format!(
        r##"<ds:Reference URI="#{ID}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED_URI}"/><ds:Transform Algorithm="{EXC_C14N}"/><ds:Transform Algorithm="{EXC_C14N}WithComments"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"##
    );
    let error = refused(
        verifier().verify_all_enveloped(&signature_with_references(&reference)),
        "two c14n transforms",
    );
    assert!(message(&error).contains("canonicalization"), "{error}");
}

#[test]
fn the_profile_transform_requirement_can_be_turned_off() {
    // Enveloped-signature alone verifies; only the one-c14n requirement refuses it.
    let xml = request_with_transforms_element(&format!(
        r##"<ds:Transforms>{ENVELOPED}</ds:Transforms>"##
    ));
    let error = refused(verifier().verify_all_enveloped(&xml), "the default");
    assert!(message(&error).contains("canonicalization"), "{error}");
    let verifier = verifier()
        .with_transform_policy(TransformPolicy::saml().with_require_profile_transforms(false));
    assert!(verifier.verify_all_enveloped(&xml).unwrap()[0].is_valid());
}
