// SAML 2.0 Metadata - ContactPerson type
//
// Per saml-metadata-2.0-os Section 2.3.2.2

use std::str::FromStr;

use super::extensions::{Extensions, ExtensionsRef};

/// Contact type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContactType {
    /// Technical contact.
    Technical,
    /// Support contact.
    Support,
    /// Administrative contact.
    Administrative,
    /// Billing contact.
    Billing,
    /// Other type of contact.
    Other,
}

impl ContactType {
    /// Convert to the XML attribute value.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContactType::Technical => "technical",
            ContactType::Support => "support",
            ContactType::Administrative => "administrative",
            ContactType::Billing => "billing",
            ContactType::Other => "other",
        }
    }
}

impl FromStr for ContactType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "technical" => Ok(ContactType::Technical),
            "support" => Ok(ContactType::Support),
            "administrative" => Ok(ContactType::Administrative),
            "billing" => Ok(ContactType::Billing),
            "other" => Ok(ContactType::Other),
            _ => Err(()),
        }
    }
}

/// Borrowed contact person - references parsed XML.
#[derive(Debug, Clone, PartialEq)]
pub struct ContactPersonRef<'a> {
    /// The contact type (required).
    pub contact_type: ContactType,
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// Optional company name.
    pub company: Option<&'a str>,
    /// Optional given name.
    pub given_name: Option<&'a str>,
    /// Optional surname.
    pub sur_name: Option<&'a str>,
    /// Email addresses (0..n).
    pub email_addresses: Vec<&'a str>,
    /// Telephone numbers (0..n).
    pub telephone_numbers: Vec<&'a str>,
}

impl<'a> ContactPersonRef<'a> {
    /// Convert to owned ContactPerson.
    pub fn to_owned(&self) -> ContactPerson {
        ContactPerson {
            contact_type: self.contact_type,
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            company: self.company.map(|s| s.to_string()),
            given_name: self.given_name.map(|s| s.to_string()),
            sur_name: self.sur_name.map(|s| s.to_string()),
            email_addresses: self.email_addresses.iter().map(|s| s.to_string()).collect(),
            telephone_numbers: self
                .telephone_numbers
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Owned contact person - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct ContactPerson {
    /// The contact type (required).
    pub contact_type: ContactType,
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// Optional company name.
    pub company: Option<String>,
    /// Optional given name.
    pub given_name: Option<String>,
    /// Optional surname.
    pub sur_name: Option<String>,
    /// Email addresses (0..n).
    pub email_addresses: Vec<String>,
    /// Telephone numbers (0..n).
    pub telephone_numbers: Vec<String>,
}

impl ContactPerson {
    /// Create a technical contact with name and email.
    pub fn technical(given_name: &str, sur_name: &str, email: &str) -> Self {
        ContactPerson {
            contact_type: ContactType::Technical,
            extensions: None,
            company: None,
            given_name: Some(given_name.to_string()),
            sur_name: Some(sur_name.to_string()),
            email_addresses: vec![email.to_string()],
            telephone_numbers: vec![],
        }
    }

    /// Create a support contact with name and email.
    pub fn support(given_name: &str, sur_name: &str, email: &str) -> Self {
        ContactPerson {
            contact_type: ContactType::Support,
            extensions: None,
            company: None,
            given_name: Some(given_name.to_string()),
            sur_name: Some(sur_name.to_string()),
            email_addresses: vec![email.to_string()],
            telephone_numbers: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_type_roundtrip() {
        for ct in [
            ContactType::Technical,
            ContactType::Support,
            ContactType::Administrative,
            ContactType::Billing,
            ContactType::Other,
        ] {
            let s = ct.as_str();
            let parsed: ContactType = s.parse().unwrap();
            assert_eq!(ct, parsed);
        }
    }

    #[test]
    fn test_contact_type_invalid() {
        let r = "unknown".parse::<ContactType>();
        assert!(r.is_err());
    }

    #[test]
    fn test_contact_person_technical() {
        let cp = ContactPerson::technical("John", "Doe", "john@example.com");
        assert_eq!(cp.contact_type, ContactType::Technical);
        assert_eq!(cp.given_name.as_deref(), Some("John"));
        assert_eq!(cp.email_addresses, vec!["john@example.com"]);
    }

    #[test]
    fn test_contact_person_ref_to_owned() {
        let r = ContactPersonRef {
            contact_type: ContactType::Support,
            extensions: None,
            company: Some("ACME Corp"),
            given_name: Some("Jane"),
            sur_name: Some("Smith"),
            email_addresses: vec!["jane@example.com", "support@example.com"],
            telephone_numbers: vec!["+1-555-0100"],
        };
        let o = r.to_owned();
        assert_eq!(o.contact_type, ContactType::Support);
        assert_eq!(o.company.as_deref(), Some("ACME Corp"));
        assert_eq!(o.email_addresses.len(), 2);
        assert_eq!(o.telephone_numbers.len(), 1);
    }
}
