// SAML 2.0 DCE PAC Attribute Profile
//
// SAML Profiles Section 8.4
//
// DCE PAC (Privilege Attribute Certificate) contains security
// attributes from a DCE security environment:
// - PAC-Realm: DCE cell name
// - PAC-PrincipalID: DCE principal UUID
// - PAC-Groups: DCE group UUIDs
//
// Note: DCE PAC is rarely used in modern SAML deployments.

use swsaml_core::assertion::attribute::{Attribute, AttributeValue};

/// Attribute name for DCE PAC realm (cell name).
pub const PAC_REALM: &str = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE:realm";

/// Attribute name for DCE PAC principal ID.
pub const PAC_PRINCIPAL_ID: &str =
    "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE:principal-id";

/// Attribute name for DCE PAC groups.
pub const PAC_GROUPS: &str = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE:groups";

/// Create a DCE PAC realm attribute.
pub fn pac_realm_attribute(realm: &str) -> Attribute {
    Attribute {
        name: PAC_REALM.to_string(),
        name_format: None,
        friendly_name: Some("PAC-Realm".to_string()),
        values: vec![AttributeValue::String(realm.to_string())],
    }
}

/// Create a DCE PAC principal ID attribute.
pub fn pac_principal_id_attribute(principal_id: &str) -> Attribute {
    Attribute {
        name: PAC_PRINCIPAL_ID.to_string(),
        name_format: None,
        friendly_name: Some("PAC-PrincipalID".to_string()),
        values: vec![AttributeValue::String(principal_id.to_string())],
    }
}

/// Create a DCE PAC groups attribute.
pub fn pac_groups_attribute(group_uuids: &[&str]) -> Attribute {
    Attribute {
        name: PAC_GROUPS.to_string(),
        name_format: None,
        friendly_name: Some("PAC-Groups".to_string()),
        values: group_uuids
            .iter()
            .map(|g| AttributeValue::String(g.to_string()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_realm_attribute() {
        let attr = pac_realm_attribute("/.../cell.example.com");
        assert_eq!(attr.name, PAC_REALM);
        assert_eq!(attr.values.len(), 1);
    }

    #[test]
    fn test_pac_principal_id_attribute() {
        let attr = pac_principal_id_attribute("f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
        assert_eq!(attr.name, PAC_PRINCIPAL_ID);
    }

    #[test]
    fn test_pac_groups_attribute() {
        let attr = pac_groups_attribute(&["group-uuid-1", "group-uuid-2"]);
        assert_eq!(attr.name, PAC_GROUPS);
        assert_eq!(attr.values.len(), 2);
    }
}
