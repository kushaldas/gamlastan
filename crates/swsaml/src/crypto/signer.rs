// swsaml-crypto signer - SAML signing operations wrapping bergshamra::dsig.

use bergshamra_dsig::{sign::sign, DsigContext};
use bergshamra_keys::{KeyUsage, KeysManager};

use crate::crypto::error::CryptoError;

/// SAML-specific signer that wraps bergshamra's XML Digital Signature support.
///
/// Provides two signing modes:
/// - Enveloped signature: for signing assertions, responses, and metadata
/// - Redirect query signature: detached signature for HTTP Redirect binding
pub struct SamlSigner {
    keys_manager: KeysManager,
}

impl SamlSigner {
    /// Create a new SAML signer with the given key manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self { keys_manager }
    }

    /// Sign a SAML message with an enveloped signature.
    ///
    /// The input XML must contain an empty `<ds:Signature>` template element
    /// specifying the desired signature algorithm and canonicalization method.
    /// Returns the signed XML string with the populated signature.
    ///
    /// Used for: assertion signing, response signing, metadata signing.
    pub fn sign_enveloped(&self, xml_with_template: &str) -> Result<String, CryptoError> {
        let ctx = DsigContext::new(self.keys_manager.clone());
        let signed = sign(&ctx, xml_with_template)?;
        Ok(signed)
    }

    /// Sign bytes for HTTP Redirect binding (detached signature).
    ///
    /// This creates a signature over the query string bytes using the specified
    /// algorithm, as required by the SAML HTTP Redirect binding.
    ///
    /// The query string must be constructed as:
    /// `SAMLRequest=value&RelayState=value&SigAlg=value` (URL-encoded values).
    pub fn sign_redirect_query(
        &self,
        query_string: &[u8],
        algorithm_uri: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let sig_alg = bergshamra_crypto::sign::from_uri(algorithm_uri)
            .map_err(CryptoError::BergshamraError)?;
        let key = self
            .keys_manager
            .find_by_usage(KeyUsage::Sign)
            .ok_or_else(|| CryptoError::KeyNotFound("No signing key found".to_string()))?;
        let signing_key = key.to_signing_key().ok_or_else(|| {
            CryptoError::KeyNotFound("Key cannot be used for signing".to_string())
        })?;
        let signature = sig_alg
            .sign(&signing_key, query_string)
            .map_err(CryptoError::BergshamraError)?;
        Ok(signature)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }
}
