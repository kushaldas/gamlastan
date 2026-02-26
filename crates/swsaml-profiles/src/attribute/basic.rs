// SAML 2.0 Basic Attribute Profile
//
// SAML Profiles Section 8.1
//
// - NameFormat: urn:oasis:names:tc:SAML:2.0:attrname-format:basic
// - xsi:type attribute is REQUIRED on AttributeValue elements
// - Attribute names are strings (no specific structure)

use swsaml_core::assertion::attribute::{Attribute, AttributeValue};

use crate::error::ProfileError;

/// Name format URI for the Basic Attribute Profile.
pub const BASIC_NAME_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

/// Validate an attribute conforms to the Basic Attribute Profile.
///
/// Rules:
/// - NameFormat MUST be basic (or absent, treated as basic)
/// - Values should have xsi:type (in our model, non-Null AttributeValue)
pub fn validate_basic_attribute(attr: &Attribute) -> Result<(), ProfileError> {
    if let Some(ref fmt) = attr.name_format {
        if fmt != BASIC_NAME_FORMAT {
            return Err(ProfileError::InvalidAttributeNameFormat {
                expected: BASIC_NAME_FORMAT.to_string(),
                actual: fmt.clone(),
            });
        }
    }

    // In the basic profile, every AttributeValue should have a type
    // (in our model, Null means no value/type)
    for value in &attr.values {
        if matches!(value, AttributeValue::Null) {
            return Err(ProfileError::BasicProfileMissingType);
        }
    }

    Ok(())
}

/// Create a basic profile string attribute.
pub fn basic_string_attribute(name: &str, values: &[&str]) -> Attribute {
    Attribute {
        name: name.to_string(),
        name_format: Some(BASIC_NAME_FORMAT.to_string()),
        friendly_name: None,
        values: values
            .iter()
            .map(|v| AttributeValue::String(v.to_string()))
            .collect(),
    }
}

/// Create a basic profile integer attribute.
pub fn basic_integer_attribute(name: &str, values: &[i64]) -> Attribute {
    Attribute {
        name: name.to_string(),
        name_format: Some(BASIC_NAME_FORMAT.to_string()),
        friendly_name: None,
        values: values.iter().map(|v| AttributeValue::Integer(*v)).collect(),
    }
}

/// Create a basic profile boolean attribute.
pub fn basic_boolean_attribute(name: &str, value: bool) -> Attribute {
    Attribute {
        name: name.to_string(),
        name_format: Some(BASIC_NAME_FORMAT.to_string()),
        friendly_name: None,
        values: vec![AttributeValue::Boolean(value)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_basic_attribute_ok() {
        let attr = basic_string_attribute("email", &["user@example.com"]);
        assert!(validate_basic_attribute(&attr).is_ok());
    }

    #[test]
    fn test_validate_basic_attribute_wrong_format() {
        let attr = Attribute {
            name: "email".to_string(),
            name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            friendly_name: None,
            values: vec![AttributeValue::String("user@example.com".to_string())],
        };
        assert!(validate_basic_attribute(&attr).is_err());
    }

    #[test]
    fn test_validate_basic_attribute_null_value() {
        let attr = Attribute {
            name: "test".to_string(),
            name_format: Some(BASIC_NAME_FORMAT.to_string()),
            friendly_name: None,
            values: vec![AttributeValue::Null],
        };
        assert!(validate_basic_attribute(&attr).is_err());
    }

    #[test]
    fn test_basic_string_attribute() {
        let attr = basic_string_attribute("name", &["Alice", "Bob"]);
        assert_eq!(attr.name, "name");
        assert_eq!(attr.values.len(), 2);
    }

    #[test]
    fn test_basic_integer_attribute() {
        let attr = basic_integer_attribute("count", &[42]);
        assert_eq!(attr.values.len(), 1);
        assert!(matches!(attr.values[0], AttributeValue::Integer(42)));
    }

    #[test]
    fn test_basic_boolean_attribute() {
        let attr = basic_boolean_attribute("active", true);
        assert!(matches!(attr.values[0], AttributeValue::Boolean(true)));
    }
}
