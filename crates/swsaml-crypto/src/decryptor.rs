// swsaml-crypto decryptor - SAML decryption wrapping bergshamra::enc.

use bergshamra_enc::{decrypt::decrypt, decrypt::decrypt_to_bytes, EncContext};
use bergshamra_keys::KeysManager;

use crate::error::CryptoError;

/// SAML decryption for EncryptedAssertion, EncryptedID, and EncryptedAttribute.
pub struct SamlDecryptor {
    keys_manager: KeysManager,
}

impl SamlDecryptor {
    /// Create a new SAML decryptor with the given key manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self { keys_manager }
    }

    /// Decrypt a SAML EncryptedData element, returning the plaintext XML string.
    ///
    /// This is the typical path for decrypting EncryptedAssertion and EncryptedID
    /// elements, where the encrypted content is XML.
    pub fn decrypt(&self, encrypted_xml: &str) -> Result<String, CryptoError> {
        let ctx = EncContext::new(self.keys_manager.clone());
        let plaintext = decrypt(&ctx, encrypted_xml)?;
        Ok(plaintext)
    }

    /// Decrypt to raw bytes (for non-XML encrypted content).
    ///
    /// Use this when the encrypted content may not be valid XML.
    pub fn decrypt_to_bytes(&self, encrypted_xml: &str) -> Result<Vec<u8>, CryptoError> {
        let ctx = EncContext::new(self.keys_manager.clone());
        let bytes = decrypt_to_bytes(&ctx, encrypted_xml)?;
        Ok(bytes)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }
}
