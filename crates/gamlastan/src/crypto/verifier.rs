// gamlastan crypto verifier - SAML signature verification wrapping bergshamra::dsig.

use bergshamra_dsig::{
    verify::{verify, verify_all},
    DsigContext, VerifyResult,
};
use bergshamra_keys::{KeyUsage, KeysManager};

use crate::crypto::config::AlgorithmPolicy;
use crate::crypto::error::CryptoError;
use crate::xml::uppsala::{Document, NodeId};

const DEFAULT_HMAC_MIN_OUT_LEN_BITS: usize = 160;
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

#[derive(Clone, Copy)]
enum SignatureSelection {
    First,
    All,
}

fn is_dsig_element(doc: &Document<'_>, node: NodeId, local_name: &str) -> bool {
    doc.element(node).is_some_and(|element| {
        element.name.local_name == local_name
            && element.name.namespace_uri.as_deref() == Some(XMLDSIG_NS)
    })
}

fn exactly_one_direct_dsig_child(
    doc: &Document<'_>,
    parent: NodeId,
    local_name: &str,
) -> Result<NodeId, CryptoError> {
    let mut matches = doc
        .children_iter(parent)
        .filter(|child| is_dsig_element(doc, *child, local_name));
    let first = matches.next().ok_or_else(|| {
        CryptoError::VerificationFailed(format!(
            "algorithm policy check requires exactly one direct ds:{local_name} child; found none"
        ))
    })?;
    if matches.next().is_some() {
        return Err(CryptoError::VerificationFailed(format!(
            "algorithm policy check requires exactly one direct ds:{local_name} child; found multiple"
        )));
    }
    Ok(first)
}

fn algorithm_attribute<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
    element_name: &str,
) -> Result<&'a str, CryptoError> {
    doc.element(node)
        .and_then(|element| element.get_attribute("Algorithm"))
        .ok_or_else(|| {
            CryptoError::VerificationFailed(format!(
                "ds:{element_name} is missing its Algorithm attribute"
            ))
        })
}

fn validate_signature_algorithms(
    doc: &Document<'_>,
    signature: NodeId,
    policy: &AlgorithmPolicy,
    reject_hmac_signatures: bool,
) -> Result<(), CryptoError> {
    let signed_info = exactly_one_direct_dsig_child(doc, signature, "SignedInfo")?;
    let signature_method = exactly_one_direct_dsig_child(doc, signed_info, "SignatureMethod")?;
    let signature_algorithm = algorithm_attribute(doc, signature_method, "SignatureMethod")?;

    if reject_hmac_signatures && crate::security::signature::is_hmac_algorithm(signature_algorithm)
    {
        return Err(CryptoError::VerificationFailed(
            "HMAC-based SignatureMethod is not allowed for SAML signatures".to_string(),
        ));
    }
    if !policy.allows_signature_algorithm(signature_algorithm) {
        return Err(CryptoError::DisallowedSignatureAlgorithm(
            signature_algorithm.to_string(),
        ));
    }

    for reference in doc
        .children_iter(signed_info)
        .filter(|child| is_dsig_element(doc, *child, "Reference"))
    {
        let digest_method = exactly_one_direct_dsig_child(doc, reference, "DigestMethod")?;
        let digest_algorithm = algorithm_attribute(doc, digest_method, "DigestMethod")?;
        if !policy.allows_digest_algorithm(digest_algorithm) {
            return Err(CryptoError::DisallowedDigestAlgorithm(
                digest_algorithm.to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_enveloped_algorithm_policy(
    signed_xml: &str,
    policy: &AlgorithmPolicy,
    reject_hmac_signatures: bool,
    selection: SignatureSelection,
) -> Result<(), CryptoError> {
    if policy.is_permissive() && !reject_hmac_signatures {
        return Ok(());
    }

    let doc = crate::xml::parse_secure_metadata(signed_xml).map_err(|error| {
        CryptoError::VerificationFailed(format!(
            "could not parse XML for algorithm policy check: {error}"
        ))
    })?;
    let Some(root) = doc.document_element() else {
        return Ok(());
    };

    for signature in std::iter::once(root)
        .chain(doc.descendants(root))
        .filter(|node| is_dsig_element(&doc, *node, "Signature"))
    {
        validate_signature_algorithms(&doc, signature, policy, reject_hmac_signatures)?;
        if matches!(selection, SignatureSelection::First) {
            break;
        }
    }

    Ok(())
}

/// SAML-specific signature verifier that wraps bergshamra's XML-DSig verification.
///
/// Provides two verification modes:
/// - Enveloped signature: for verifying assertions, responses, and metadata
/// - Redirect query signature: detached signature for HTTP Redirect binding
///
/// Per E91: optionally rejects signatures containing `<ds:Object>` elements.
/// Before any cryptographic operation, [`AlgorithmPolicy`] restricts signature
/// and Reference-digest methods to modern SAML defaults. Applications that must
/// verify legacy XML security fixtures can opt into an exact custom policy or
/// [`AlgorithmPolicy::permissive`].
///
/// **Security**: By default, uses `trusted_keys_only` mode which only uses
/// pre-configured keys from the KeysManager for signature verification.
/// This prevents attackers from embedding their own X.509 certificates in the
/// XML's `<ds:KeyInfo>` and having them blindly trusted.
///
/// **XSW Protection**: By default, uses `strict_verification` mode which enforces
/// that each signed reference target is either the document root, an ancestor of the
/// `<Signature>`, or a sibling of the `<Signature>`. This prevents XML Signature
/// Wrapping attacks where signed content is moved to an unexpected position.
pub struct SamlVerifier {
    keys_manager: KeysManager,
    /// Signature and reference-digest algorithms accepted before crypto dispatch.
    algorithm_policy: AlgorithmPolicy,
    /// Per E91: reject signatures containing ds:Object elements.
    reject_ds_object: bool,
    /// When true (default), only use keys from the KeysManager, never inline.
    /// This prevents trusting attacker-embedded certificates in KeyInfo.
    trusted_keys_only: bool,
    /// When true (default), enforce positional constraints on reference targets
    /// to prevent XML Signature Wrapping (XSW) attacks.
    strict_verification: bool,
    /// Skip X.509 time checks (NotBefore/NotAfter) during verification.
    /// Useful when the IdP certificate has expired but is still functionally valid.
    skip_time_checks: bool,
    /// Minimum HMAC output length in bits to prevent HMAC truncation attacks
    /// (CVE-2009-0217). Default: 160 bits.
    hmac_min_out_len: usize,
    /// Require every signed reference digest to be verified locally.
    /// Default: true.
    require_reference_digests: bool,
    /// Allow raw inline KeyValue / DEREncodedKeyValue signatures even when
    /// trust anchors are configured. Default: false.
    allow_raw_inline_keyinfo_with_trust_anchors: bool,
    /// Reject HMAC-based `SignatureMethod` algorithms outright. Default: true.
    /// SAML IdPs sign with asymmetric keys, so a legitimate response is never
    /// HMAC-signed; rejecting HMAC closes a symmetric key-confusion class as
    /// defence in depth on top of `trusted_keys_only`.
    reject_hmac_signatures: bool,
}

impl SamlVerifier {
    /// Create a new SAML verifier with the given key manager.
    /// By default, ds:Object elements in signatures are rejected (per E91),
    /// and only pre-configured trusted keys are used for verification.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            algorithm_policy: AlgorithmPolicy::default(),
            reject_ds_object: true,
            trusted_keys_only: true,
            strict_verification: true,
            skip_time_checks: false,
            hmac_min_out_len: DEFAULT_HMAC_MIN_OUT_LEN_BITS,
            require_reference_digests: true,
            allow_raw_inline_keyinfo_with_trust_anchors: false,
            reject_hmac_signatures: true,
        }
    }

    /// Create a new SAML verifier with explicit ds:Object rejection setting.
    pub fn with_ds_object_rejection(keys_manager: KeysManager, reject_ds_object: bool) -> Self {
        Self {
            keys_manager,
            algorithm_policy: AlgorithmPolicy::default(),
            reject_ds_object,
            trusted_keys_only: true,
            strict_verification: true,
            skip_time_checks: false,
            hmac_min_out_len: DEFAULT_HMAC_MIN_OUT_LEN_BITS,
            require_reference_digests: true,
            allow_raw_inline_keyinfo_with_trust_anchors: false,
            reject_hmac_signatures: true,
        }
    }

    /// Set whether to skip X.509 time checks (NotBefore/NotAfter).
    pub fn set_skip_time_checks(&mut self, skip: bool) {
        self.skip_time_checks = skip;
    }

    /// Set the signature and reference-digest algorithm policy.
    pub fn set_algorithm_policy(&mut self, policy: AlgorithmPolicy) {
        self.algorithm_policy = policy;
    }

    /// Set the algorithm policy using builder style.
    pub fn with_algorithm_policy(mut self, policy: AlgorithmPolicy) -> Self {
        self.set_algorithm_policy(policy);
        self
    }

    /// Set whether to only use trusted keys from the KeysManager.
    ///
    /// When true (default), inline keys embedded in the XML's KeyInfo
    /// (KeyValue, X509Certificate, etc.) are ignored. Only pre-configured
    /// keys in the KeysManager are used for verification.
    ///
    /// When false, inline keys are tried first (standard XML-DSig behavior),
    /// which is less secure for SAML but may be needed for interop testing.
    pub fn set_trusted_keys_only(&mut self, trusted: bool) {
        self.trusted_keys_only = trusted;
    }

    /// Set whether to enforce strict reference position checks (XSW protection).
    ///
    /// When true (default), each signed reference target must be the document
    /// root, an ancestor of the `<Signature>`, or a sibling of the `<Signature>`.
    /// This prevents XML Signature Wrapping attacks where an attacker moves
    /// signed content to an unexpected position in the document tree.
    ///
    /// When false, any reference target position is accepted (standard XML-DSig
    /// behavior), which may be needed for non-SAML or interop use cases.
    pub fn set_strict_verification(&mut self, strict: bool) {
        self.strict_verification = strict;
    }

    /// Set the minimum HMAC output length in bits (CVE-2009-0217 protection).
    ///
    /// When a non-zero value is set, HMAC signatures with output length shorter
    /// than this value (in bits) will be rejected. This prevents HMAC truncation
    /// attacks where an attacker reduces the HMAC output to a trivially brute-
    /// forceable size.
    ///
    /// Default: 160 bits. Set to 0 to disable (not recommended).
    pub fn set_hmac_min_out_len(&mut self, bits: usize) {
        self.hmac_min_out_len = bits;
    }

    /// Set whether XML-DSig verification requires local digest coverage for
    /// all references.
    ///
    /// Keep this enabled for SAML. Disable only for profiles that verify
    /// detached content bytes out of band.
    pub fn set_require_reference_digests(&mut self, require: bool) {
        self.require_reference_digests = require;
    }

    /// Set whether raw inline `<KeyValue>` / `<DEREncodedKeyValue>` keys may
    /// satisfy verification when trust anchors are configured.
    ///
    /// Keep this disabled for SAML. It exists as a compatibility escape hatch
    /// for non-SAML interop suites that intentionally combine trust anchors
    /// with raw inline test keys.
    pub fn set_allow_raw_inline_keyinfo_with_trust_anchors(&mut self, allow: bool) {
        self.allow_raw_inline_keyinfo_with_trust_anchors = allow;
    }

    /// Set whether HMAC-based `SignatureMethod` algorithms are rejected.
    ///
    /// Keep this enabled for SAML: IdPs sign with asymmetric keys, so a
    /// legitimate response never uses HMAC. Disable only for non-SAML interop
    /// suites that deliberately exercise symmetric-key signatures. The
    /// configured [`AlgorithmPolicy`] must independently allow HMAC as well.
    pub fn set_reject_hmac_signatures(&mut self, reject: bool) {
        self.reject_hmac_signatures = reject;
    }

    /// Verify a signed SAML message (assertion, response, metadata).
    ///
    /// Per E91: checks for and rejects `<ds:Object>` elements in the signature
    /// if `reject_ds_object` is enabled.
    pub fn verify_enveloped(&self, signed_xml: &str) -> Result<VerifyResult, CryptoError> {
        // E91 check: reject XMLDSig Object elements before handing the
        // document to the verifier. The helper parses XML and compares
        // expanded names, so attackers cannot bypass it by changing prefixes.
        // Fail closed: if the document cannot be parsed for this check we must
        // not proceed as though it were clean (CWE-693).
        if self.reject_ds_object {
            match crate::security::signature::contains_ds_object(signed_xml) {
                Ok(true) => return Err(CryptoError::SignatureContainsDsObject),
                Ok(false) => {}
                Err(e) => {
                    return Err(CryptoError::VerificationFailed(format!(
                        "could not parse XML for E91 ds:Object check: {e}"
                    )))
                }
            }
        }

        validate_enveloped_algorithm_policy(
            signed_xml,
            &self.algorithm_policy,
            self.reject_hmac_signatures,
            SignatureSelection::First,
        )?;

        let ctx = self.dsig_context();
        let result = verify(&ctx, signed_xml)?;
        Ok(result)
    }

    /// Verify **every** `<Signature>` in a signed SAML message, returning one
    /// [`VerifyResult`] per signature in document order.
    ///
    /// [`verify_enveloped`](Self::verify_enveloped) only reports the *first*
    /// signature. That is insufficient for a document signed in more than one
    /// place — most importantly a SAML Response signed at both the Response and
    /// the Assertion level, where the Response signature comes first in document
    /// order. A caller that must bind a *specific* object (e.g. the consumed
    /// Assertion) to its own signature would otherwise never see the assertion's
    /// signature. This method verifies each signature independently so the caller
    /// can collect the references covered by all of them.
    ///
    /// The same E91 `<ds:Object>` guard as [`verify_enveloped`](Self::verify_enveloped)
    /// applies, and it fails closed if the document cannot be parsed for that
    /// check.
    pub fn verify_all_enveloped(&self, signed_xml: &str) -> Result<Vec<VerifyResult>, CryptoError> {
        if self.reject_ds_object {
            match crate::security::signature::contains_ds_object(signed_xml) {
                Ok(true) => return Err(CryptoError::SignatureContainsDsObject),
                Ok(false) => {}
                Err(e) => {
                    return Err(CryptoError::VerificationFailed(format!(
                        "could not parse XML for E91 ds:Object check: {e}"
                    )))
                }
            }
        }

        validate_enveloped_algorithm_policy(
            signed_xml,
            &self.algorithm_policy,
            self.reject_hmac_signatures,
            SignatureSelection::All,
        )?;

        let ctx = self.dsig_context();
        let results = verify_all(&ctx, signed_xml)?;
        Ok(results)
    }

    /// Build a [`DsigContext`] from this verifier's configured policy. Shared by
    /// the single-signature and all-signatures enveloped verification paths.
    fn dsig_context(&self) -> DsigContext {
        DsigContext::new(self.keys_manager.clone())
            .with_trusted_keys_only(self.trusted_keys_only)
            .with_strict_verification(self.strict_verification)
            .with_skip_time_checks(self.skip_time_checks)
            .with_hmac_min_out_len(self.hmac_min_out_len)
            .with_require_reference_digests(self.require_reference_digests)
            .with_allow_raw_inline_keyinfo_with_trust_anchors(
                self.allow_raw_inline_keyinfo_with_trust_anchors,
            )
    }

    /// Verify HTTP Redirect binding detached signature.
    ///
    /// Verifies the signature over the original URL-encoded query string bytes.
    ///
    /// CRITICAL: The query_string must be the original URL-encoded parameter values,
    /// NOT re-encoded values. Per SAML spec, the signature is computed over the
    /// exact URL-encoded form.
    ///
    /// HMAC algorithms are rejected by default because federation metadata
    /// distributes public verification keys, not shared secrets.
    ///
    /// # Errors
    ///
    /// Returns an error when the algorithm is prohibited or unsupported, no
    /// verification key is available, or signature verification fails.
    pub fn verify_redirect_query(
        &self,
        query_string: &[u8],
        signature: &[u8],
        algorithm_uri: &str,
    ) -> Result<bool, CryptoError> {
        if self.reject_hmac_signatures
            && crate::security::signature::is_hmac_algorithm(algorithm_uri)
        {
            return Err(CryptoError::VerificationFailed(
                "HMAC-based SignatureMethod is not allowed for SAML signatures".to_string(),
            ));
        }
        if !self
            .algorithm_policy
            .allows_signature_algorithm(algorithm_uri)
        {
            return Err(CryptoError::DisallowedSignatureAlgorithm(
                algorithm_uri.to_string(),
            ));
        }
        let sig_alg = bergshamra_crypto::sign::from_uri(algorithm_uri)
            .map_err(CryptoError::BergshamraError)?;
        let key = self
            .keys_manager
            .find_by_usage(KeyUsage::Verify)
            .ok_or_else(|| CryptoError::KeyNotFound("No verification key found".to_string()))?;
        let signing_key = key
            .to_signing_key()
            .map_err(CryptoError::BergshamraError)?
            .ok_or_else(|| {
                CryptoError::KeyNotFound("Key cannot be used for verification".to_string())
            })?;
        let valid = sig_alg
            .verify(&signing_key, query_string, signature)
            .map_err(CryptoError::BergshamraError)?;
        Ok(valid)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }

    /// Get the active signature and Reference-digest algorithm policy.
    pub fn algorithm_policy(&self) -> &AlgorithmPolicy {
        &self.algorithm_policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
    const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    fn signature(signature_algorithm: &str, digest_algorithm: &str) -> String {
        format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="{signature_algorithm}"/>
<ds:Reference URI="">
<ds:DigestMethod Algorithm="{digest_algorithm}"/>
<ds:DigestValue>AA==</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>"#
        )
    }

    fn validate(xml: &str, policy: &AlgorithmPolicy) -> Result<(), CryptoError> {
        validate_enveloped_algorithm_policy(xml, policy, true, SignatureSelection::All)
    }

    #[test]
    fn default_policy_accepts_sha2_and_rejects_sha1() {
        let policy = AlgorithmPolicy::default();
        validate(&signature(RSA_SHA256, SHA256), &policy).expect("SHA-256 is allowed");

        let signature_error =
            validate(&signature(RSA_SHA1, SHA256), &policy).expect_err("RSA-SHA1 must be rejected");
        assert!(
            matches!(&signature_error, CryptoError::DisallowedSignatureAlgorithm(uri) if uri == RSA_SHA1),
            "unexpected error: {signature_error}"
        );
        let digest_error =
            validate(&signature(RSA_SHA256, SHA1), &policy).expect_err("SHA-1 must be rejected");
        assert!(
            matches!(&digest_error, CryptoError::DisallowedDigestAlgorithm(uri) if uri == SHA1),
            "unexpected error: {digest_error}"
        );
    }

    #[test]
    fn custom_and_permissive_policies_support_explicit_legacy_interop() {
        let custom = AlgorithmPolicy::allow_only([RSA_SHA1], [SHA1]);
        validate_enveloped_algorithm_policy(
            &signature(RSA_SHA1, SHA1),
            &custom,
            false,
            SignatureSelection::All,
        )
        .expect("an explicitly allowlisted legacy pair is accepted");

        validate_enveloped_algorithm_policy(
            &signature(RSA_SHA1, SHA1),
            &AlgorithmPolicy::permissive(),
            false,
            SignatureSelection::All,
        )
        .expect("permissive policy preserves backend compatibility");
    }

    #[test]
    fn empty_allowlists_deny_all_algorithms() {
        let policy = AlgorithmPolicy::allow_only(Vec::<String>::new(), Vec::<String>::new());
        let error = validate(&signature(RSA_SHA256, SHA256), &policy)
            .expect_err("an empty allowlist must deny all signatures");
        assert!(
            matches!(&error, CryptoError::DisallowedSignatureAlgorithm(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn single_and_all_verification_inspect_the_same_signatures_as_backend() {
        let xml = format!(
            "<root>{}{}</root>",
            signature(RSA_SHA256, SHA256),
            signature(RSA_SHA1, SHA1)
        );
        validate_enveloped_algorithm_policy(
            &xml,
            &AlgorithmPolicy::default(),
            true,
            SignatureSelection::First,
        )
        .expect("single verification only selects the first signature");
        assert!(matches!(
            validate_enveloped_algorithm_policy(
                &xml,
                &AlgorithmPolicy::default(),
                true,
                SignatureSelection::All,
            ),
            Err(CryptoError::DisallowedSignatureAlgorithm(uri)) if uri == RSA_SHA1
        ));
    }

    #[test]
    fn policy_is_namespace_aware_and_ignores_non_reference_digests() {
        let prefixed = signature(RSA_SHA256, SHA256)
            .replace("ds:", "sig:")
            .replace("xmlns:ds", "xmlns:sig");
        validate(&prefixed, &AlgorithmPolicy::default())
            .expect("the XMLDSig prefix is not security-significant");

        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
<xenc:EncryptedKey><xenc:EncryptionMethod><ds:DigestMethod Algorithm="{SHA1}"/></xenc:EncryptionMethod></xenc:EncryptedKey>
{}
</root>"#,
            signature(RSA_SHA256, SHA256)
        );
        validate(&xml, &AlgorithmPolicy::default())
            .expect("an XML Encryption OAEP digest is not a Signature Reference digest");
    }

    #[test]
    fn malformed_algorithm_structure_fails_closed() {
        let missing_algorithm =
            signature(RSA_SHA256, SHA256).replace(&format!("Algorithm=\"{SHA256}\""), "");
        let error = validate(&missing_algorithm, &AlgorithmPolicy::default())
            .expect_err("missing Algorithm must fail closed");
        assert!(
            matches!(&error, CryptoError::VerificationFailed(reason) if reason.contains("missing its Algorithm")),
            "unexpected error: {error}"
        );

        let duplicate = signature(RSA_SHA256, SHA256).replace(
            &format!("<ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/>"),
            &format!(
                "<ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/>"
            ),
        );
        assert!(matches!(
            validate(&duplicate, &AlgorithmPolicy::default()),
            Err(CryptoError::VerificationFailed(reason)) if reason.contains("found multiple")
        ));
    }

    /// Verifies that HMAC Redirect signatures fail before verification-key lookup.
    #[test]
    fn redirect_verification_rejects_hmac_before_key_lookup() {
        let verifier = SamlVerifier::new(KeysManager::new());
        let err = verifier
            .verify_redirect_query(
                b"SAMLRequest=x&SigAlg=hmac",
                b"signature",
                "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
            )
            .expect_err("SAML redirect HMAC must be rejected by policy");
        assert!(err.to_string().contains("HMAC-based SignatureMethod"));
    }

    /// Reproduces issue #24: a backend-supported SHA-1 signature method must
    /// be rejected by the SAML policy before verification-key lookup.
    #[test]
    fn redirect_verification_rejects_sha1_before_key_lookup() {
        let verifier = SamlVerifier::new(KeysManager::new());
        let err = verifier
            .verify_redirect_query(
                b"SAMLRequest=x&SigAlg=rsa-sha1",
                b"signature",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            )
            .expect_err("SAML redirect RSA-SHA1 must be rejected by policy");
        assert!(
            err.to_string()
                .contains("not allowed by SAML algorithm policy"),
            "unexpected error: {err}"
        );
    }
}
