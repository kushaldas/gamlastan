//! End-to-end HSM (PKCS#11) signing test against a real token.
//!
//! This proves that [`SamlSigner::with_hsm_signer`] produces signatures — both
//! enveloped XML-DSig and detached HTTP-Redirect — that validate against the
//! token's certificate, with the private key never leaving the token.
//!
//! It is `#[ignore]`d and self-skips unless a provisioned token is described via
//! environment variables, so it never runs in normal CI. To run it locally with
//! SoftHSM2:
//!
//! ```sh
//! # 1. Create a token and an RSA key pair (label must match GAMLASTAN_PKCS11_LABEL)
//! softhsm2-util --init-token --slot 0 --label saml --so-pin 0000 --pin 1234
//! pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
//!     --keypairgen --key-type rsa:2048 --label saml-signing-key
//!
//! # 2. Export a self-signed cert for that key (via the pkcs11 engine / p11-kit),
//! #    PEM-encoded, to e.g. /tmp/saml-hsm.crt.pem
//!
//! # 3. Run the test
//! GAMLASTAN_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
//! GAMLASTAN_PKCS11_PIN=1234 \
//! GAMLASTAN_PKCS11_LABEL=saml-signing-key \
//! GAMLASTAN_PKCS11_CERT=/tmp/saml-hsm.crt.pem \
//!   cargo test -p gamlastan --test hsm_signing -- --ignored --nocapture
//! ```

use std::sync::Arc;

use gamlastan::crypto::kryptering::pkcs11::{Pkcs11Provider, Pkcs11Signer};
use gamlastan::crypto::kryptering::{HashAlgorithm, SignatureAlgorithm};
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};

const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// Read the four env vars describing a provisioned token, or `None` to skip.
fn token_config() -> Option<(String, String, String, String)> {
    Some((
        std::env::var("GAMLASTAN_PKCS11_MODULE").ok()?,
        std::env::var("GAMLASTAN_PKCS11_PIN").ok()?,
        std::env::var("GAMLASTAN_PKCS11_LABEL").ok()?,
        std::env::var("GAMLASTAN_PKCS11_CERT").ok()?,
    ))
}

/// Strip the PEM armor from a single CERTIFICATE block, returning the base64 body
/// (as it appears inside `<ds:X509Certificate>`) and the decoded DER bytes.
fn cert_b64_and_der(cert_pem: &str) -> (String, Vec<u8>) {
    use base64::Engine;
    let b64: String = cert_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("certificate body is valid base64");
    (b64, der)
}

#[test]
#[ignore = "requires a provisioned PKCS#11 token; set GAMLASTAN_PKCS11_* to run"]
fn hsm_signs_enveloped_and_redirect() {
    let Some((module, pin, label, cert_path)) = token_config() else {
        eprintln!("skipping: GAMLASTAN_PKCS11_* not set");
        return;
    };

    let cert_pem = std::fs::read_to_string(&cert_path).expect("read certificate PEM");
    let (cert_b64, cert_der) = cert_b64_and_der(&cert_pem);

    // --- Build the HSM-backed signer (private key stays on the token) ---------
    let provider = Pkcs11Provider::new(std::path::Path::new(&module)).expect("load PKCS#11 module");
    let session = provider.open_session(&pin).expect("open + login session");
    let pkcs11_signer = Pkcs11Signer::new(
        &session,
        &label,
        SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::Sha256),
    )
    .expect("bind Pkcs11Signer to private key");

    // Caveat 2: the KeysManager can be empty — the cert that lands in
    // <ds:KeyInfo> comes from the signature template, not from the manager.
    let signer = SamlSigner::with_hsm_signer(KeysManager::new(), Arc::new(pkcs11_signer));
    assert!(signer.is_hsm_backed());

    // A verifier that trusts only preconfigured key material. Keep
    // `trusted_keys_only` at its secure default so this exercises the stricter
    // trust model instead of accepting the inline certificate from KeyInfo.
    let mut verify_key = gamlastan::crypto::keys::loader::load_pem_auto(cert_pem.as_bytes(), None)
        .expect("load cert as verify key");
    verify_key.usage = KeyUsage::Verify;
    let mut verify_km = KeysManager::new();
    verify_km.add_key(verify_key);
    verify_km.add_trusted_cert(cert_der);
    let mut verifier = SamlVerifier::new(verify_km);
    verifier.set_skip_time_checks(true);

    // --- 1. Enveloped XML-DSig (assertion/response/metadata path) -------------
    let id = "_resp_hsm_1";
    let template = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
        id = id,
        cert = cert_b64,
    );
    let unsigned = format!(
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{id}" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">{template}<samlp:Status/></samlp:Response>"##,
        id = id,
        template = template,
    );

    let signed = signer
        .sign_enveloped(&unsigned)
        .expect("HSM enveloped signing");
    assert!(signed.contains("<ds:SignatureValue>") && !signed.contains("<ds:SignatureValue/>"));
    let result = verifier
        .verify_enveloped(&signed)
        .expect("verify HSM enveloped signature");
    assert!(
        result.is_valid(),
        "enveloped HSM signature did not validate"
    );

    // --- 2. Detached HTTP-Redirect signature (caveat 1) -----------------------
    let query = b"SAMLRequest=fakeRequest&RelayState=state&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256";
    let sig = signer
        .sign_redirect_query(query, RSA_SHA256_URI)
        .expect("HSM redirect signing");
    let valid = verifier
        .verify_redirect_query(query, &sig, RSA_SHA256_URI)
        .expect("verify HSM redirect signature");
    assert!(valid, "redirect HSM signature did not validate");

    // The algorithm cross-check must reject a mismatched SigAlg.
    let mismatch = signer.sign_redirect_query(query, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    assert!(mismatch.is_err(), "mismatched SigAlg should be rejected");

    eprintln!("HSM enveloped + redirect signatures both validated");
}
