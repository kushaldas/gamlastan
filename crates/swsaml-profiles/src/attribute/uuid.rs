// SAML 2.0 UUID Attribute Profile
//
// SAML Profiles Section 8.3
//
// - NameFormat: urn:oasis:names:tc:SAML:2.0:attrname-format:uri
// - Attribute names use urn:uuid: URIs (RFC 4122 UUIDs)

use swsaml_core::assertion::attribute::{Attribute, AttributeValue};

use crate::error::ProfileError;

/// Name format URI for the UUID Attribute Profile.
pub const UUID_NAME_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/// UUID prefix for attribute names.
pub const UUID_PREFIX: &str = "urn:uuid:";

/// Validate an attribute conforms to the UUID Attribute Profile.
///
/// Rules:
/// - NameFormat MUST be URI
/// - Name MUST begin with "urn:uuid:"
pub fn validate_uuid_attribute(attr: &Attribute) -> Result<(), ProfileError> {
    if let Some(ref fmt) = attr.name_format {
        if fmt != UUID_NAME_FORMAT {
            return Err(ProfileError::InvalidAttributeNameFormat {
                expected: UUID_NAME_FORMAT.to_string(),
                actual: fmt.clone(),
            });
        }
    }

    if !attr.name.starts_with(UUID_PREFIX) {
        return Err(ProfileError::InvalidAttributeNameFormat {
            expected: format!("name starting with {UUID_PREFIX}"),
            actual: attr.name.clone(),
        });
    }

    // Basic UUID format validation: urn:uuid:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    let uuid_part = &attr.name[UUID_PREFIX.len()..];
    if !is_valid_uuid(uuid_part) {
        return Err(ProfileError::InvalidAttributeNameFormat {
            expected: "valid UUID after urn:uuid: prefix".to_string(),
            actual: attr.name.clone(),
        });
    }

    Ok(())
}

/// Check if a string is a valid UUID (8-4-4-4-12 hex format).
fn is_valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(part, &len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Create a UUID profile attribute with string values.
pub fn uuid_string_attribute(
    uuid: &str,
    friendly_name: Option<&str>,
    values: &[&str],
) -> Attribute {
    let name = if uuid.starts_with(UUID_PREFIX) {
        uuid.to_string()
    } else {
        format!("{UUID_PREFIX}{uuid}")
    };

    Attribute {
        name,
        name_format: Some(UUID_NAME_FORMAT.to_string()),
        friendly_name: friendly_name.map(|s| s.to_string()),
        values: values
            .iter()
            .map(|v| AttributeValue::String(v.to_string()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid_attribute_ok() {
        let attr = uuid_string_attribute(
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            Some("testAttr"),
            &["value1"],
        );
        assert!(validate_uuid_attribute(&attr).is_ok());
    }

    #[test]
    fn test_validate_uuid_attribute_invalid_uuid() {
        let attr = Attribute {
            name: "urn:uuid:not-a-valid-uuid".to_string(),
            name_format: Some(UUID_NAME_FORMAT.to_string()),
            friendly_name: None,
            values: vec![],
        };
        assert!(validate_uuid_attribute(&attr).is_err());
    }

    #[test]
    fn test_validate_uuid_attribute_wrong_prefix() {
        let attr = Attribute {
            name: "not-urn-uuid".to_string(),
            name_format: Some(UUID_NAME_FORMAT.to_string()),
            friendly_name: None,
            values: vec![],
        };
        assert!(validate_uuid_attribute(&attr).is_err());
    }

    #[test]
    fn test_uuid_string_attribute_with_prefix() {
        let attr = uuid_string_attribute(
            "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            None,
            &["val"],
        );
        assert_eq!(attr.name, "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    }

    #[test]
    fn test_uuid_string_attribute_without_prefix() {
        let attr = uuid_string_attribute("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", None, &["val"]);
        assert!(attr.name.starts_with(UUID_PREFIX));
    }

    #[test]
    fn test_is_valid_uuid() {
        assert!(is_valid_uuid("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));
        assert!(is_valid_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid("f81d4fae-7dec-11d0-a765")); // too short
    }
}
