// SAML 2.0 X.500/LDAP Attribute Profile
//
// SAML Profiles Section 8.2
//
// - NameFormat: urn:oasis:names:tc:SAML:2.0:attrname-format:uri
// - Attribute names use urn:oid: URIs (OID dot notation)
// - FriendlyName SHOULD be the LDAP attribute name
// - Values use LDAP string encoding

use crate::core::assertion::attribute::{Attribute, AttributeValue};

use crate::profiles::error::ProfileError;

/// Name format URI for the X.500/LDAP Attribute Profile.
pub const X500_NAME_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/// OID prefix for X.500 attributes.
pub const OID_PREFIX: &str = "urn:oid:";

// Common X.500/LDAP attribute OIDs
/// cn (commonName)
pub const OID_CN: &str = "urn:oid:2.5.4.3";
/// sn (surname)
pub const OID_SN: &str = "urn:oid:2.5.4.4";
/// givenName
pub const OID_GIVEN_NAME: &str = "urn:oid:2.5.4.42";
/// mail
pub const OID_MAIL: &str = "urn:oid:0.9.2342.19200300.100.1.3";
/// uid
pub const OID_UID: &str = "urn:oid:0.9.2342.19200300.100.1.1";
/// eduPersonPrincipalName
pub const OID_EPPN: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6";
/// eduPersonAffiliation
pub const OID_EPA: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1";
/// eduPersonEntitlement
pub const OID_EPE: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7";
/// eduPersonTargetedID
pub const OID_EPTID: &str = "urn:oid:1.3.6.1.4.1.5923.1.1.1.10";
/// displayName
pub const OID_DISPLAY_NAME: &str = "urn:oid:2.16.840.1.113730.3.1.241";

/// Validate an attribute conforms to the X.500/LDAP Attribute Profile.
///
/// Rules:
/// - NameFormat MUST be URI
/// - Name MUST begin with "urn:oid:"
pub fn validate_x500_attribute(attr: &Attribute) -> Result<(), ProfileError> {
    if let Some(ref fmt) = attr.name_format {
        if fmt != X500_NAME_FORMAT {
            return Err(ProfileError::InvalidAttributeNameFormat {
                expected: X500_NAME_FORMAT.to_string(),
                actual: fmt.clone(),
            });
        }
    }

    if !attr.name.starts_with(OID_PREFIX) {
        return Err(ProfileError::InvalidAttributeNameFormat {
            expected: format!("name starting with {OID_PREFIX}"),
            actual: attr.name.clone(),
        });
    }

    Ok(())
}

/// Create an X.500/LDAP attribute with string values.
pub fn x500_string_attribute(oid: &str, friendly_name: &str, values: &[&str]) -> Attribute {
    Attribute {
        name: oid.to_string(),
        name_format: Some(X500_NAME_FORMAT.to_string()),
        friendly_name: Some(friendly_name.to_string()),
        values: values
            .iter()
            .map(|v| AttributeValue::String(v.to_string()))
            .collect(),
    }
}

/// Create a common X.500 attribute: mail.
pub fn mail_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_MAIL, "mail", values)
}

/// Create a common X.500 attribute: cn (common name).
pub fn cn_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_CN, "cn", values)
}

/// Create a common X.500 attribute: givenName.
pub fn given_name_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_GIVEN_NAME, "givenName", values)
}

/// Create a common X.500 attribute: sn (surname).
pub fn sn_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_SN, "sn", values)
}

/// Create a common X.500 attribute: uid.
pub fn uid_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_UID, "uid", values)
}

/// Create a common eduPerson attribute: eduPersonPrincipalName.
pub fn eppn_attribute(value: &str) -> Attribute {
    x500_string_attribute(OID_EPPN, "eduPersonPrincipalName", &[value])
}

/// Create a common eduPerson attribute: eduPersonAffiliation.
pub fn epa_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_EPA, "eduPersonAffiliation", values)
}

/// Create a common eduPerson attribute: eduPersonEntitlement.
pub fn epe_attribute(values: &[&str]) -> Attribute {
    x500_string_attribute(OID_EPE, "eduPersonEntitlement", values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_x500_attribute_ok() {
        let attr = mail_attribute(&["user@example.com"]);
        assert!(validate_x500_attribute(&attr).is_ok());
    }

    #[test]
    fn test_validate_x500_attribute_wrong_format() {
        let attr = Attribute {
            name: OID_MAIL.to_string(),
            name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
            friendly_name: None,
            values: vec![],
        };
        assert!(validate_x500_attribute(&attr).is_err());
    }

    #[test]
    fn test_validate_x500_attribute_wrong_name() {
        let attr = Attribute {
            name: "email".to_string(), // not urn:oid: prefix
            name_format: Some(X500_NAME_FORMAT.to_string()),
            friendly_name: None,
            values: vec![],
        };
        assert!(validate_x500_attribute(&attr).is_err());
    }

    #[test]
    fn test_x500_string_attribute() {
        let attr = x500_string_attribute(OID_CN, "cn", &["John Doe"]);
        assert_eq!(attr.name, OID_CN);
        assert_eq!(attr.name_format, Some(X500_NAME_FORMAT.to_string()));
        assert_eq!(attr.friendly_name, Some("cn".to_string()));
        assert_eq!(attr.values.len(), 1);
    }

    #[test]
    fn test_mail_attribute() {
        let attr = mail_attribute(&["user@example.com", "admin@example.com"]);
        assert_eq!(attr.name, OID_MAIL);
        assert_eq!(attr.values.len(), 2);
    }

    #[test]
    fn test_eppn_attribute() {
        let attr = eppn_attribute("user@example.com");
        assert_eq!(attr.name, OID_EPPN);
        assert_eq!(
            attr.friendly_name,
            Some("eduPersonPrincipalName".to_string())
        );
    }
}
