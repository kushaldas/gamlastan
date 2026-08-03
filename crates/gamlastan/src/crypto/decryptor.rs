// gamlastan crypto decryptor - SAML decryption wrapping bergshamra::enc.

use bergshamra_enc::{
    context::DEFAULT_MAX_PBKDF2_ITERATIONS, decrypt::decrypt, decrypt::decrypt_to_bytes, EncContext,
};
use bergshamra_keys::KeysManager;

use crate::crypto::error::CryptoError;

const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

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
    ///
    /// # Errors
    ///
    /// Returns an error for malformed encrypted XML, prohibited RSA-PKCS#1
    /// v1.5 key transport, missing keys, or cryptographic decryption failure.
    pub fn decrypt(&self, encrypted_xml: &str) -> Result<String, CryptoError> {
        reject_rsa_1_5(encrypted_xml)?;
        let ctx = self.enc_context();
        let plaintext = decrypt(&ctx, encrypted_xml)?;
        Ok(plaintext)
    }

    /// Decrypt to raw bytes (for non-XML encrypted content).
    ///
    /// Use this when the encrypted content may not be valid XML.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed encrypted XML, prohibited RSA-PKCS#1
    /// v1.5 key transport, missing keys, or cryptographic decryption failure.
    pub fn decrypt_to_bytes(&self, encrypted_xml: &str) -> Result<Vec<u8>, CryptoError> {
        reject_rsa_1_5(encrypted_xml)?;
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

/// Reject XML Encryption documents that request RSA-PKCS#1 v1.5 key transport.
///
/// The document is parsed before key lookup so the prohibited algorithm fails
/// deterministically without exposing a padding-oracle-capable code path.
fn reject_rsa_1_5(encrypted_xml: &str) -> Result<(), CryptoError> {
    let doc = crate::xml::parse_secure(encrypted_xml)
        .map_err(|e| CryptoError::DecryptionError(format!("invalid encrypted XML: {e}")))?;
    for node in doc.descendants(doc.root()) {
        let Some(element) = doc.element(node) else {
            continue;
        };
        if element.matches_name_ns(crate::core::namespace::XMLENC_NS, "EncryptionMethod")
            && element.get_attribute("Algorithm") == Some(RSA_1_5)
        {
            return Err(CryptoError::UnsupportedAlgorithm(
                "RSA-PKCS#1 v1.5 key transport is prohibited; use RSA-OAEP".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that RSA-PKCS#1 v1.5 is rejected before any key lookup.
    #[test]
    fn rejects_rsa_1_5_before_key_lookup() {
        let xml = r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/></xenc:EncryptedKey></xenc:EncryptedData>"#;
        let decryptor = SamlDecryptor::new(KeysManager::new());
        assert!(matches!(
            decryptor.decrypt(xml),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            decryptor.decrypt_to_bytes(xml),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }
}
