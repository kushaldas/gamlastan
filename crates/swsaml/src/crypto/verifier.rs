// swsaml-crypto verifier - SAML signature verification wrapping bergshamra::dsig.

use bergshamra_dsig::{verify::verify, DsigContext, VerifyResult};
use bergshamra_keys::{KeyUsage, KeysManager};

use crate::crypto::error::CryptoError;

/// SAML-specific signature verifier that wraps bergshamra's XML-DSig verification.
///
/// Provides two verification modes:
/// - Enveloped signature: for verifying assertions, responses, and metadata
/// - Redirect query signature: detached signature for HTTP Redirect binding
///
/// Per E91: optionally rejects signatures containing `<ds:Object>` elements.
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
}

impl SamlVerifier {
    /// Create a new SAML verifier with the given key manager.
    /// By default, ds:Object elements in signatures are rejected (per E91),
    /// and only pre-configured trusted keys are used for verification.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            reject_ds_object: true,
            trusted_keys_only: true,
            strict_verification: true,
            skip_time_checks: false,
        }
    }

    /// Create a new SAML verifier with explicit ds:Object rejection setting.
    pub fn with_ds_object_rejection(keys_manager: KeysManager, reject_ds_object: bool) -> Self {
        Self {
            keys_manager,
            reject_ds_object,
            trusted_keys_only: true,
            strict_verification: true,
            skip_time_checks: false,
        }
    }

    /// Set whether to skip X.509 time checks (NotBefore/NotAfter).
    pub fn set_skip_time_checks(&mut self, skip: bool) {
        self.skip_time_checks = skip;
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

    /// Verify a signed SAML message (assertion, response, metadata).
    ///
    /// Per E91: checks for and rejects `<ds:Object>` elements in the signature
    /// if `reject_ds_object` is enabled.
    pub fn verify_enveloped(&self, signed_xml: &str) -> Result<VerifyResult, CryptoError> {
        // E91 check: scan for ds:Object before verifying
        if self.reject_ds_object && signed_xml.contains("<ds:Object") {
            return Err(CryptoError::SignatureContainsDsObject);
        }

        let mut ctx = DsigContext::new(self.keys_manager.clone());
        ctx.trusted_keys_only = self.trusted_keys_only;
        ctx.strict_verification = self.strict_verification;
        ctx.skip_time_checks = self.skip_time_checks;
        let result = verify(&ctx, signed_xml)?;
        Ok(result)
    }

    /// Verify HTTP Redirect binding detached signature.
    ///
    /// Verifies the signature over the original URL-encoded query string bytes.
    ///
    /// CRITICAL: The query_string must be the original URL-encoded parameter values,
    /// NOT re-encoded values. Per SAML spec, the signature is computed over the
    /// exact URL-encoded form.
    pub fn verify_redirect_query(
        &self,
        query_string: &[u8],
        signature: &[u8],
        algorithm_uri: &str,
    ) -> Result<bool, CryptoError> {
        let sig_alg = bergshamra_crypto::sign::from_uri(algorithm_uri)
            .map_err(CryptoError::BergshamraError)?;
        let key = self
            .keys_manager
            .find_by_usage(KeyUsage::Verify)
            .ok_or_else(|| CryptoError::KeyNotFound("No verification key found".to_string()))?;
        let signing_key = key.to_signing_key().ok_or_else(|| {
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
}
