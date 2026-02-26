// DEFLATE compression/decompression for SAML HTTP Redirect binding.
//
// Per SAML Bindings Section 3.4.4.1:
// - Uses raw DEFLATE (RFC 1951), NOT gzip or zlib wrappers
// - The entire XML message is compressed

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::bindings::error::BindingError;

/// Maximum decompressed size (safety limit to prevent decompression bombs).
/// 1 MB should be more than enough for any SAML message.
const MAX_DECOMPRESSED_SIZE: usize = 1024 * 1024;

/// DEFLATE compress data (RFC 1951 raw deflate, no wrapper).
///
/// Used when encoding SAML messages for the HTTP Redirect binding.
pub fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, BindingError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| BindingError::DeflateError(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| BindingError::DeflateError(e.to_string()))
}

/// DEFLATE decompress data (RFC 1951 raw deflate, no wrapper).
///
/// Used when decoding SAML messages from the HTTP Redirect binding.
/// Enforces a maximum decompressed size to prevent decompression bombs.
pub fn deflate_decompress(data: &[u8]) -> Result<Vec<u8>, BindingError> {
    let mut decoder = DeflateDecoder::new(data);
    let mut result = Vec::new();

    // Read in chunks to enforce size limit
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| BindingError::DeflateError(e.to_string()))?;
        if n == 0 {
            break;
        }
        result.extend_from_slice(&buf[..n]);
        if result.len() > MAX_DECOMPRESSED_SIZE {
            return Err(BindingError::MessageTooLarge(result.len()));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deflate_roundtrip() {
        let xml = b"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_abc\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\"/>";
        let compressed = deflate_compress(xml).unwrap();
        assert!(compressed.len() < xml.len()); // should be smaller
        let decompressed = deflate_decompress(&compressed).unwrap();
        assert_eq!(decompressed, xml);
    }

    #[test]
    fn test_deflate_empty_input() {
        let compressed = deflate_compress(b"").unwrap();
        let decompressed = deflate_decompress(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_deflate_invalid_data() {
        let result = deflate_decompress(b"not valid deflate data");
        assert!(result.is_err());
    }

    #[test]
    fn test_deflate_realistic_saml_message() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_0c2e7ed00a9e4cee8a9c6b5f3a7d9012"
            Version="2.0"
            IssueInstant="2025-06-15T10:30:00Z"
            Destination="https://idp.example.com/sso"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            AssertionConsumerServiceURL="https://sp.example.com/acs">
            <saml:Issuer>https://sp.example.com</saml:Issuer>
        </samlp:AuthnRequest>"#;
        let compressed = deflate_compress(xml.as_bytes()).unwrap();
        let decompressed = deflate_decompress(&compressed).unwrap();
        assert_eq!(decompressed, xml.as_bytes());
        // DEFLATE should provide meaningful compression for XML
        assert!(compressed.len() < xml.len() / 2);
    }
}
