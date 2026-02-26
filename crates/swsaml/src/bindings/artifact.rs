// HTTP Artifact Binding (SAML Bindings Section 3.6).
//
// Artifact type 0x0004 binary format (44 bytes total):
//   Offset | Size | Field          | Description
//   0-1    | 2    | TypeCode       | 0x0004
//   2-3    | 2    | EndpointIndex  | Index to ArtifactResolutionService
//   4-23   | 20   | SourceID       | SHA-1(entityID)
//   24-43  | 20   | MessageHandle  | Cryptographically random (>= 16 bytes entropy)
//
// Base64-encoded to ~60 characters.
// Per E4: SAML V1.1 artifact formats MUST NOT be used.
//
// Transmitted via SAMLart query param (GET) or hidden form field (POST).

use crate::bindings::encoding::{base64_decode, base64_encode};
use crate::bindings::error::BindingError;
use crate::bindings::traits::HttpRequest;

/// SAML artifact type code 0x0004.
pub const ARTIFACT_TYPE_CODE: u16 = 0x0004;

/// Total binary length of a type 0x0004 artifact.
pub const ARTIFACT_BINARY_LEN: usize = 44;

/// A parsed SAML V2.0 type 0x0004 artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlArtifact {
    /// Endpoint index (2-byte big-endian) pointing to ArtifactResolutionService.
    pub endpoint_index: u16,
    /// SourceID: SHA-1 hash of the issuing entity ID (20 bytes).
    pub source_id: [u8; 20],
    /// MessageHandle: cryptographically random handle (20 bytes).
    pub message_handle: [u8; 20],
}

impl SamlArtifact {
    /// Create a new SAML artifact.
    ///
    /// - `endpoint_index`: index of the ArtifactResolutionService in metadata
    /// - `entity_id`: the issuer's entity ID (used to compute SourceID = SHA-1(entityID))
    /// - `random_handle`: 20 bytes of cryptographically random data
    pub fn new(endpoint_index: u16, entity_id: &str, random_handle: [u8; 20]) -> Self {
        let hash = crate::crypto::digest::sha1(entity_id.as_bytes());
        let mut source_id = [0u8; 20];
        source_id.copy_from_slice(&hash);
        SamlArtifact {
            endpoint_index,
            source_id,
            message_handle: random_handle,
        }
    }

    /// Create an artifact with a pre-computed SourceID.
    pub fn with_source_id(
        endpoint_index: u16,
        source_id: [u8; 20],
        message_handle: [u8; 20],
    ) -> Self {
        SamlArtifact {
            endpoint_index,
            source_id,
            message_handle,
        }
    }

    /// Encode the artifact to its base64 string representation.
    pub fn encode(&self) -> String {
        let mut bytes = [0u8; ARTIFACT_BINARY_LEN];
        // TypeCode (2 bytes, big-endian)
        let tc = ARTIFACT_TYPE_CODE.to_be_bytes();
        bytes[0] = tc[0];
        bytes[1] = tc[1];
        // EndpointIndex (2 bytes, big-endian)
        let ei = self.endpoint_index.to_be_bytes();
        bytes[2] = ei[0];
        bytes[3] = ei[1];
        // SourceID (20 bytes)
        bytes[4..24].copy_from_slice(&self.source_id);
        // MessageHandle (20 bytes)
        bytes[24..44].copy_from_slice(&self.message_handle);

        base64_encode(&bytes)
    }

    /// Decode an artifact from its base64 string representation.
    pub fn decode(encoded: &str) -> Result<Self, BindingError> {
        let bytes = base64_decode(encoded)?;
        if bytes.len() != ARTIFACT_BINARY_LEN {
            return Err(BindingError::InvalidArtifact(format!(
                "expected {} bytes, got {}",
                ARTIFACT_BINARY_LEN,
                bytes.len()
            )));
        }

        // Check type code
        let type_code = u16::from_be_bytes([bytes[0], bytes[1]]);
        if type_code != ARTIFACT_TYPE_CODE {
            return Err(BindingError::InvalidArtifact(format!(
                "unsupported artifact type code: 0x{:04X} (expected 0x{:04X})",
                type_code, ARTIFACT_TYPE_CODE
            )));
        }

        let endpoint_index = u16::from_be_bytes([bytes[2], bytes[3]]);

        let mut source_id = [0u8; 20];
        source_id.copy_from_slice(&bytes[4..24]);

        let mut message_handle = [0u8; 20];
        message_handle.copy_from_slice(&bytes[24..44]);

        Ok(SamlArtifact {
            endpoint_index,
            source_id,
            message_handle,
        })
    }

    /// Check if this artifact's SourceID matches the given entity ID.
    pub fn matches_entity(&self, entity_id: &str) -> bool {
        let hash = crate::crypto::digest::sha1(entity_id.as_bytes());
        hash == self.source_id
    }
}

/// Decode a SAML artifact from an HTTP request.
///
/// Checks for the `SAMLart` parameter in both query string (GET) and
/// form body (POST).
pub fn artifact_decode_request(request: &impl HttpRequest) -> Result<String, BindingError> {
    if let Some(art) = request.query_param("SAMLart") {
        return Ok(art.to_string());
    }
    if let Some(art) = request.form_param("SAMLart") {
        return Ok(art.to_string());
    }
    Err(BindingError::MissingSamlParam("SAMLart"))
}

/// Get the RelayState from an artifact binding request.
pub fn artifact_relay_state(request: &impl HttpRequest) -> Option<String> {
    request
        .query_param("RelayState")
        .or_else(|| request.form_param("RelayState"))
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_create_and_encode() {
        let handle = [0xABu8; 20];
        let artifact = SamlArtifact::new(0, "https://idp.example.com", handle);

        assert_eq!(artifact.endpoint_index, 0);
        assert_eq!(artifact.message_handle, handle);

        let encoded = artifact.encode();
        // Base64 of 44 bytes should be ~60 chars
        assert!(encoded.len() > 50 && encoded.len() < 70);
    }

    #[test]
    fn test_artifact_roundtrip() {
        let handle = [0x42u8; 20];
        let artifact = SamlArtifact::new(3, "https://idp.example.com", handle);
        let encoded = artifact.encode();
        let decoded = SamlArtifact::decode(&encoded).unwrap();

        assert_eq!(decoded.endpoint_index, 3);
        assert_eq!(decoded.source_id, artifact.source_id);
        assert_eq!(decoded.message_handle, handle);
    }

    #[test]
    fn test_artifact_matches_entity() {
        let handle = [0x01u8; 20];
        let artifact = SamlArtifact::new(0, "https://idp.example.com", handle);
        assert!(artifact.matches_entity("https://idp.example.com"));
        assert!(!artifact.matches_entity("https://other.example.com"));
    }

    #[test]
    fn test_artifact_invalid_type_code() {
        // Craft an artifact with wrong type code
        let mut bytes = [0u8; 44];
        bytes[0] = 0x00;
        bytes[1] = 0x01; // Type code 0x0001 (V1.1)
        let encoded = base64_encode(&bytes);

        let result = SamlArtifact::decode(&encoded);
        assert!(matches!(result, Err(BindingError::InvalidArtifact(_))));
    }

    #[test]
    fn test_artifact_wrong_length() {
        let encoded = base64_encode(&[0u8; 20]); // Too short
        let result = SamlArtifact::decode(&encoded);
        assert!(matches!(result, Err(BindingError::InvalidArtifact(_))));
    }

    #[test]
    fn test_artifact_source_id_is_sha1() {
        let handle = [0u8; 20];
        let artifact = SamlArtifact::new(0, "https://sp.example.com", handle);

        // The source_id should be SHA-1 of the entity ID
        let expected = crate::crypto::digest::sha1(b"https://sp.example.com");
        assert_eq!(&artifact.source_id[..], &expected[..]);
    }

    #[test]
    fn test_artifact_endpoint_index() {
        let handle = [0u8; 20];
        let artifact = SamlArtifact::new(257, "https://idp.example.com", handle);
        let encoded = artifact.encode();
        let decoded = SamlArtifact::decode(&encoded).unwrap();
        assert_eq!(decoded.endpoint_index, 257);
    }
}
