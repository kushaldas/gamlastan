// gamlastan crypto decryptor - SAML decryption wrapping bergshamra::enc.

use bergshamra_enc::{
    context::DEFAULT_MAX_PBKDF2_ITERATIONS, decrypt::decrypt, decrypt::decrypt_to_bytes, EncContext,
};
use bergshamra_keys::KeysManager;

use crate::crypto::error::CryptoError;

/// SAML decryption for EncryptedAssertion, EncryptedID, and EncryptedAttribute.
pub struct SamlDecryptor {
    keys_manager: KeysManager,
    max_pbkdf2_iterations: u32,
}

impl SamlDecryptor {
    /// Create a new SAML decryptor with the given key manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self {
            keys_manager,
            max_pbkdf2_iterations: DEFAULT_MAX_PBKDF2_ITERATIONS,
        }
    }

    /// Set the maximum XML-controlled PBKDF2 iteration count accepted during
    /// XML Encryption key derivation.
    ///
    /// The default comes from bergshamra. Set this lower for latency-sensitive
    /// services, or to `0` to reject PBKDF2-derived XML Encryption keys.
    pub fn set_max_pbkdf2_iterations(&mut self, max_iterations: u32) {
        self.max_pbkdf2_iterations = max_iterations;
    }

    /// Return the configured XML Encryption PBKDF2 iteration cap.
    pub fn max_pbkdf2_iterations(&self) -> u32 {
        self.max_pbkdf2_iterations
    }

    /// Decrypt a SAML EncryptedData element, returning the plaintext XML string.
    ///
    /// This is the typical path for decrypting EncryptedAssertion and EncryptedID
    /// elements, where the encrypted content is XML.
    pub fn decrypt(&self, encrypted_xml: &str) -> Result<String, CryptoError> {
        let ctx = self.enc_context();
        let plaintext = decrypt(&ctx, encrypted_xml)?;
        Ok(plaintext)
    }

    /// Decrypt to raw bytes (for non-XML encrypted content).
    ///
    /// Use this when the encrypted content may not be valid XML.
    pub fn decrypt_to_bytes(&self, encrypted_xml: &str) -> Result<Vec<u8>, CryptoError> {
        let ctx = self.enc_context();
        let bytes = decrypt_to_bytes(&ctx, encrypted_xml)?;
        Ok(bytes)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }

    fn enc_context(&self) -> EncContext {
        EncContext::new(self.keys_manager.clone())
            .with_max_pbkdf2_iterations(self.max_pbkdf2_iterations)
    }
}
