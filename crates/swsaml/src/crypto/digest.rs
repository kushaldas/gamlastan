// swsaml-crypto digest - Digest computation wrapping bergshamra::crypto::digest.
//
// Used for: artifact SourceID (SHA-1 of entityID), reference digests, etc.

use crate::crypto::error::CryptoError;

/// Compute a digest using the specified algorithm URI.
///
/// Supports all digest algorithms provided by bergshamra:
/// SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3 variants.
pub fn digest(algorithm_uri: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(bergshamra_crypto::digest::digest(algorithm_uri, data)?)
}

/// Convenience: compute SHA-1 digest.
///
/// Used for SAML artifact SourceID computation (SHA-1 of entityID).
/// Note: SHA-1 is used here for interoperability, not security.
pub fn sha1(data: &[u8]) -> Vec<u8> {
    bergshamra_crypto::digest::digest("http://www.w3.org/2000/09/xmldsig#sha1", data)
        .expect("SHA-1 should always be available")
}

/// Convenience: compute SHA-256 digest.
pub fn sha256(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    digest("http://www.w3.org/2001/04/xmlenc#sha256", data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_digest() {
        let data = b"https://sp.example.com";
        let result = sha1(data);
        // SHA-1 produces 20 bytes
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_sha256_digest() {
        let data = b"test data";
        let result = sha256(data).unwrap();
        // SHA-256 produces 32 bytes
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_digest_unknown_algorithm() {
        let result = digest("http://example.com/unknown", b"data");
        assert!(result.is_err());
    }
}
