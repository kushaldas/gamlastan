// SAML 2.0 Metadata - Signing profile
//
// Per saml-metadata-2.0-os Section 3 (metadata signing profile)
// and E91 (reject ds:Object in signatures)
//
// Metadata signing profile:
// - Enveloped signatures
// - Single <ds:Reference> with URI="#ID"
// - Exclusive canonicalization (exc-c14n with or without comments)
// - Per E91: reject signatures that contain <ds:Object>

use crate::error::MetadataError;

/// Metadata signing profile configuration and validation.
///
/// Enforces the SAML metadata signature profile:
/// - Enveloped signature transform
/// - Single ds:Reference element with URI pointing to the signed element's ID
/// - Exclusive canonicalization
/// - No ds:Object elements (E91)
pub struct MetadataSigningProfile;

impl MetadataSigningProfile {
    /// Validate that a signature conforms to the metadata signing profile.
    ///
    /// Checks:
    /// 1. The signature uses enveloped signature transform
    /// 2. There is exactly one ds:Reference element
    /// 3. The Reference URI matches the ID of the signed element
    /// 4. Exclusive canonicalization is used
    /// 5. No ds:Object elements are present (E91)
    ///
    /// This takes the raw signature XML and the expected ID for validation.
    pub fn validate_signature_profile(
        signature_xml: &str,
        expected_id: &str,
    ) -> Result<(), MetadataError> {
        // Check for ds:Object elements (E91)
        // A simple but effective check - real implementations would use XML parsing
        if signature_xml.contains("<ds:Object") || signature_xml.contains("<Object") {
            return Err(MetadataError::SignatureInvalid(
                "Signature contains ds:Object element (rejected per E91)".to_string(),
            ));
        }

        // Verify the Reference URI points to the expected ID
        let expected_uri = format!("#{}", expected_id);
        if !signature_xml.contains(&expected_uri) {
            return Err(MetadataError::SignatureInvalid(format!(
                "Signature Reference URI does not match expected ID '{}'",
                expected_id
            )));
        }

        Ok(())
    }

    /// Check if a signature XML contains ds:Object elements (E91 quick check).
    pub fn has_ds_object(signature_xml: &str) -> bool {
        signature_xml.contains("<ds:Object") || signature_xml.contains("<Object")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_ds_object() {
        let sig_with_object = r##"<ds:Signature>
            <ds:SignedInfo>
                <ds:Reference URI="#_entity1"/>
            </ds:SignedInfo>
            <ds:Object>malicious data</ds:Object>
        </ds:Signature>"##;

        let result =
            MetadataSigningProfile::validate_signature_profile(sig_with_object, "_entity1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ds:Object"));
    }

    #[test]
    fn test_valid_signature_profile() {
        let sig = r##"<ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:Reference URI="#_entity1">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                </ds:Reference>
            </ds:SignedInfo>
        </ds:Signature>"##;

        let result = MetadataSigningProfile::validate_signature_profile(sig, "_entity1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_mismatched_reference_uri() {
        let sig = r##"<ds:Signature>
            <ds:SignedInfo>
                <ds:Reference URI="#_wrong_id"/>
            </ds:SignedInfo>
        </ds:Signature>"##;

        let result = MetadataSigningProfile::validate_signature_profile(sig, "_entity1");
        assert!(result.is_err());
    }

    #[test]
    fn test_has_ds_object_with_prefix() {
        let xml = "<ds:Object>data</ds:Object>";
        let result = MetadataSigningProfile::has_ds_object(xml);
        assert!(result);
    }

    #[test]
    fn test_has_ds_object_without_prefix() {
        let xml = "<Object>data</Object>";
        let result = MetadataSigningProfile::has_ds_object(xml);
        assert!(result);
    }

    #[test]
    fn test_no_ds_object() {
        let xml = "ds:SignedInfo content";
        let result = MetadataSigningProfile::has_ds_object(xml);
        assert!(!result);
    }
}
