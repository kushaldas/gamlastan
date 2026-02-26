// swsaml-crypto configuration types.
//
// Defines algorithm preferences and security policy for SAML crypto operations.

/// Algorithm preferences and security policy for SAML operations.
///
/// These defaults follow SAML errata recommendations:
/// - E81: any algorithm supported by bergshamra is allowed
/// - E91: reject signatures containing ds:Object elements
/// - E93: prefer GCM modes over CBC for built-in integrity protection
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Preferred signature algorithm URI for signing operations.
    /// Default: RSA-SHA256.
    pub preferred_signature_algorithm: String,

    /// Preferred digest algorithm URI.
    /// Default: SHA-256.
    pub preferred_digest_algorithm: String,

    /// Preferred encryption algorithm URI for data encryption.
    /// Default: AES-256-GCM (per E93: prefer GCM for integrity).
    pub preferred_encryption_algorithm: String,

    /// Preferred key wrap algorithm URI.
    /// Default: AES-256-KW.
    pub preferred_key_wrap_algorithm: String,

    /// Whether to reject signatures containing ds:Object elements (per E91).
    /// Default: true.
    pub reject_ds_object: bool,

    /// Minimum HMAC output length (in bits) to prevent truncation attacks.
    /// Default: 0 (use bergshamra default).
    pub hmac_min_output_length: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            preferred_signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                .to_string(),
            preferred_digest_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            preferred_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"
                .to_string(),
            preferred_key_wrap_algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes256".to_string(),
            reject_ds_object: true,
            hmac_min_output_length: 0,
        }
    }
}

impl CryptoConfig {
    /// Create a new CryptoConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration that prefers RSA-SHA256 signing.
    pub fn rsa_sha256() -> Self {
        Self::default()
    }

    /// Create a configuration that prefers ECDSA-P256-SHA256 signing.
    pub fn ecdsa_p256_sha256() -> Self {
        CryptoConfig {
            preferred_signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
                .to_string(),
            ..Self::default()
        }
    }
}
