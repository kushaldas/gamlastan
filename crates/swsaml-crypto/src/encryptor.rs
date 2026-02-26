// swsaml-crypto encryptor - SAML encryption wrapping bergshamra::enc.

use bergshamra_enc::{encrypt::encrypt, EncContext};
use bergshamra_keys::KeysManager;

use crate::error::CryptoError;

/// SAML encryption for EncryptedAssertion, EncryptedID, and EncryptedAttribute.
///
/// Per E93: prefer GCM modes over CBC for built-in integrity protection.
pub struct SamlEncryptor {
    keys_manager: KeysManager,
}

impl SamlEncryptor {
    /// Create a new SAML encryptor with the given key manager.
    pub fn new(keys_manager: KeysManager) -> Self {
        Self { keys_manager }
    }

    /// Encrypt a SAML element.
    ///
    /// The template must contain `<xenc:EncryptedData>` with the desired
    /// algorithm specified in `<xenc:EncryptionMethod>`.
    ///
    /// Per E93: prefer GCM modes (AES-128-GCM, AES-256-GCM) over CBC
    /// for built-in integrity protection.
    pub fn encrypt(&self, template_xml: &str, plaintext: &[u8]) -> Result<String, CryptoError> {
        let ctx = EncContext::new(self.keys_manager.clone());
        let encrypted = encrypt(&ctx, template_xml, plaintext)?;
        Ok(encrypted)
    }

    /// Get a reference to the underlying keys manager.
    pub fn keys_manager(&self) -> &KeysManager {
        &self.keys_manager
    }
}
