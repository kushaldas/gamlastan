// gamlastan crypto encryptor - SAML encryption wrapping bergshamra::enc.

use base64::Engine;
use bergshamra_enc::{encrypt::encrypt, EncContext};
use bergshamra_keys::{loader, KeysManager};

use crate::crypto::error::CryptoError;

/// Default block-encryption algorithm (E93: GCM for built-in integrity).
pub const DEFAULT_DATA_ALGORITHM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

/// Default key-transport algorithm (RSA-OAEP-MGF1P).
pub const DEFAULT_KEY_TRANSPORT_ALGORITHM: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

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

    /// Build an encryptor whose only key is the recipient certificate's
    /// public key.
    ///
    /// This is the per-request (PEFIM-style) encryption path: the cert
    /// comes from the request (e.g. `profiles::pefim::first_encryption_cert_der`)
    /// instead of SP metadata. Pair with [`encrypted_data_template_for_cert`].
    pub fn for_certificate(cert_der: &[u8]) -> Result<Self, CryptoError> {
        // The cert's RSA public key becomes the session-key transport key;
        // bergshamra falls back to the first RSA key in the manager.
        let key = loader::load_x509_cert_der(cert_der).map_err(CryptoError::BergshamraError)?;
        let mut km = KeysManager::new();
        km.add_key(key);
        Ok(SamlEncryptor::new(km))
    }
}

/// Options for [`encrypted_data_template_for_cert`].
#[derive(Debug, Clone)]
pub struct CertEncryptionOptions {
    /// Block-encryption algorithm URI (default AES-256-GCM, per E93).
    pub data_algorithm: String,
    /// Key-transport algorithm URI (default RSA-OAEP-MGF1P).
    pub key_transport_algorithm: String,
    /// Embed the recipient certificate in the EncryptedKey's KeyInfo so
    /// the recipient can locate its decryption key (default true).
    pub include_certificate: bool,
}

impl Default for CertEncryptionOptions {
    fn default() -> Self {
        CertEncryptionOptions {
            data_algorithm: DEFAULT_DATA_ALGORITHM.to_string(),
            key_transport_algorithm: DEFAULT_KEY_TRANSPORT_ALGORITHM.to_string(),
            include_certificate: true,
        }
    }
}

/// Build the `<xenc:EncryptedData>` template encrypting toward the given
/// recipient certificate (DER).
///
/// The template carries an `<xenc:EncryptedKey>` with an empty CipherValue:
/// [`SamlEncryptor::encrypt`] generates a fresh session key, encrypts the
/// payload, and wraps the session key for the certificate's RSA key.
pub fn encrypted_data_template_for_cert(
    cert_der: &[u8],
    options: &CertEncryptionOptions,
) -> String {
    // KeyInfo block advertising the recipient cert (optional but
    // interoperable: lets the SP pick the right private key).
    let key_info = if options.include_certificate {
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        format!(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>\
             </ds:KeyInfo>"
        )
    } else {
        String::new()
    };

    format!(
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" \
         Type=\"http://www.w3.org/2001/04/xmlenc#Element\">\
         <xenc:EncryptionMethod Algorithm=\"{data_alg}\"/>\
         <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
         <xenc:EncryptedKey>\
         <xenc:EncryptionMethod Algorithm=\"{kt_alg}\"/>\
         {key_info}\
         <xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData>\
         </xenc:EncryptedKey>\
         </ds:KeyInfo>\
         <xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData>\
         </xenc:EncryptedData>",
        data_alg = options.data_algorithm,
        kt_alg = options.key_transport_algorithm,
        key_info = key_info,
    )
}
