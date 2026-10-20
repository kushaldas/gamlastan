//! Dependency-free, process-oriented baseline; see docs/performance.md.
//! Fixture signing runs separately so it cannot inflate measurement-process RSS.

use std::error::Error;
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use base64::Engine;
use gamlastan::core::protocol::response::ResponseRef;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{digest, KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use gamlastan::profiles::sso::idp::sign_response_xml;
use gamlastan::xml::{parse_saml, parse_secure};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CERT: &str = include_str!("../tests/fixtures/enc-cert.pem");
const KEY: &str = include_str!("../tests/fixtures/enc-key.pem");
const WARMUP: usize = 10;
const CASES: &[(&str, usize, bool, bool)] = &[
    ("small-response", 4, false, true),
    ("medium-assertion", 32, true, false),
    ("large-both", 256, true, true),
];
const PHASES: &[&str] = &["parse", "extract", "verify", "verify-all", "pipeline"];

/// Certificate loading and verifier preparation are outside warm-operation timing.
fn verifier() -> Result<SamlVerifier> {
    let mut key = loader::load_pem_auto(CERT.as_bytes(), None)?;
    key.usage = KeyUsage::Verify;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    keys.add_trusted_cert(base64::engine::general_purpose::STANDARD.decode(cert_body())?);
    let mut verifier = SamlVerifier::new(keys);
    // Only certificate time checks are disabled, to keep this static test
    // certificate usable. All algorithm, trust and structural defaults remain.
    verifier.set_skip_time_checks(true);
    Ok(verifier)
}

fn cert_body() -> String {
    CERT.lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect()
}

/// Fixed IDs, timestamps, values and RSA-SHA256 signatures give repeatable bytes.
/// These are synthetic crypto/XML workloads, not live SSO credentials.
fn fixture(attributes: usize, assertion: bool, response: bool) -> Result<String> {
    let mut xml = String::from(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.test/acs" InResponseTo="_request"><saml:Issuer>https://idp.example.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.test</saml:Issuer><saml:Subject><saml:NameID>benchmark-user</saml:NameID></saml:Subject><saml:AttributeStatement>"#,
    );
    for index in 0..attributes {
        write!(
            xml,
            r#"<saml:Attribute Name="urn:example:attribute:{index}"><saml:AttributeValue>benchmark-value-{index:04}-abcdefghijklmnopqrstuvwxyz0123456789</saml:AttributeValue></saml:Attribute>"#
        )?;
    }
    xml.push_str("</saml:AttributeStatement></saml:Assertion></samlp:Response>");
    let mut key = loader::load_pem_auto(KEY.as_bytes(), None)?;
    key.usage = KeyUsage::Sign;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    Ok(sign_response_xml(
        &xml,
        &SamlSigner::new(keys),
        &cert_body(),
        "_response",
        Some("_assertion"),
        assertion,
        response,
    )?)
}

fn sha256(xml: &str) -> Result<String> {
    let mut hex = String::new();
    for byte in digest::sha256(xml.as_bytes())? {
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

/// Require a positive control before timing, even for parse-only measurements.
fn validate(xml: &str, verifier: &SamlVerifier) -> Result<(usize, usize)> {
    let doc = parse_secure(xml)?;
    let response: ResponseRef<'_> = parse_saml(&doc)?;
    if response.base.id != "_response"
        || response.assertions.len() != 1
        || response.assertions[0].id != "_assertion"
    {
        return Err("unexpected benchmark response shape".into());
    }
    let attributes = response.assertions[0]
        .attribute_statements
        .iter()
        .map(|statement| statement.attributes.len())
        .sum();
    let results = verifier.verify_all_enveloped(xml)?;
    if results.is_empty() || results.iter().any(|result| !result.is_valid()) {
        return Err("benchmark requires valid signatures".into());
    }
    Ok((attributes, results.len()))
}

/// Time the public API, including returned-value destruction. No I/O in the loop.
fn operation(phase: &str, xml: &str, verifier: &SamlVerifier) -> Result<()> {
    match phase {
        "parse" => {
            black_box(parse_secure(black_box(xml))?);
        }
        "extract" => {
            let doc = parse_secure(black_box(xml))?;
            black_box(parse_saml::<ResponseRef<'_>>(&doc)?);
        }
        "verify" => {
            let result = verifier.verify_enveloped(black_box(xml))?;
            if !result.is_valid() {
                return Err("signature did not validate".into());
            }
            black_box(result);
        }
        "verify-all" => {
            let results = verifier.verify_all_enveloped(black_box(xml))?;
            if results.is_empty() || results.iter().any(|result| !result.is_valid()) {
                return Err("signatures did not validate".into());
            }
            black_box(results);
        }
        "pipeline" => {
            operation("verify-all", xml, verifier)?;
            operation("extract", xml, verifier)?;
        }
        _ => {
            return Err("unknown phase; use parse, extract, verify, verify-all or pipeline".into())
        }
    }
    Ok(())
}

/// Generate artifacts once, in a different process from the measurement worker.
fn generate(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let verifier = verifier()?;
    for &(name, count, assertion, response) in CASES {
        let xml = fixture(count, assertion, response)?;
        assert_eq!(
            validate(&xml, &verifier)?,
            (count, usize::from(assertion) + usize::from(response))
        );
        // Never overwrite a previous corpus: keeping it is essential for A/B runs.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(format!("{name}.xml")))?;
        file.write_all(xml.as_bytes())?;
        println!("{name} bytes={} sha256={}", xml.len(), sha256(&xml)?);
    }
    Ok(())
}

/// Check determinism, all phases, signature cardinality and negative controls.
fn self_test() -> Result<()> {
    let verifier = verifier()?;
    for &(_, count, assertion, response) in CASES {
        let xml = fixture(count, assertion, response)?;
        assert_eq!(xml, fixture(count, assertion, response)?);
        assert_eq!(
            validate(&xml, &verifier)?,
            (count, usize::from(assertion) + usize::from(response))
        );
        for phase in PHASES {
            operation(phase, &xml, &verifier)?;
        }
        let tampered = xml.replace("benchmark-user", "tampered-user");
        assert!(validate(&tampered, &verifier).is_err());
        let malformed = &xml[..xml.len() / 2];
        assert!(validate(malformed, &verifier).is_err());
    }
    assert!(parse_secure("<!DOCTYPE root><root/>").is_err());
    println!("saml_pipeline smoke checks passed");
    Ok(())
}

/// One input/phase per process. Warmup and preflight are excluded from elapsed_ns
/// but included in the process peak RSS reported by an external time utility.
fn measure(phase: &str, path: &Path, iterations: usize) -> Result<()> {
    if !PHASES.contains(&phase) || iterations == 0 {
        return Err("expected a known phase and a positive iteration count".into());
    }
    let xml = std::fs::read_to_string(path)?;
    let verifier = verifier()?;
    let (attributes, signatures) = validate(&xml, &verifier)?;
    let hash = sha256(&xml)?;
    for _ in 0..WARMUP {
        operation(phase, &xml, &verifier)?;
    }
    let start = Instant::now();
    for _ in 0..iterations {
        operation(phase, &xml, &verifier)?;
    }
    let elapsed = start.elapsed();
    println!("phase,bytes,attributes,signatures,iterations,warmup,elapsed_ns,ns_per_op,sha256");
    println!(
        "{phase},{},{attributes},{signatures},{iterations},{WARMUP},{},{:.1},{hash}",
        xml.len(),
        elapsed.as_nanos(),
        elapsed.as_nanos() as f64 / iterations as f64
    );
    Ok(())
}

fn main() -> Result<()> {
    // Cargo adds --bench when launching a harness=false benchmark.
    let args: Vec<_> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--bench")
        .collect();
    match args.as_slice() {
        [] => self_test(),
        [flag] if flag == "--test" || flag == "--self-test" => self_test(),
        [flag, directory] if flag == "--generate" => generate(Path::new(directory)),
        [phase, file, iterations] => measure(phase, Path::new(file), iterations.parse()?),
        _ => Err(
            "usage: saml_pipeline [--self-test | --generate DIR | PHASE FILE ITERATIONS]".into(),
        ),
    }
}
