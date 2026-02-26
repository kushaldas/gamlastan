// SAML 2.0 Metadata - Organization type
//
// Per saml-metadata-2.0-os Section 2.3.2.1

use super::extensions::{Extensions, ExtensionsRef};
use super::localized::{LocalizedName, LocalizedNameRef, LocalizedUri, LocalizedUriRef};

/// Borrowed organization - references parsed XML.
///
/// Specifies basic information about the organization responsible for a SAML entity.
#[derive(Debug, Clone, PartialEq)]
pub struct OrganizationRef<'a> {
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// Organization display names (1..n, required).
    pub organization_names: Vec<LocalizedNameRef<'a>>,
    /// Organization display names for display purposes (1..n, required).
    pub organization_display_names: Vec<LocalizedNameRef<'a>>,
    /// Organization URLs (1..n, required).
    pub organization_urls: Vec<LocalizedUriRef<'a>>,
}

impl<'a> OrganizationRef<'a> {
    /// Convert to owned Organization.
    pub fn to_owned(&self) -> Organization {
        Organization {
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            organization_names: self
                .organization_names
                .iter()
                .map(|n| n.to_owned())
                .collect(),
            organization_display_names: self
                .organization_display_names
                .iter()
                .map(|n| n.to_owned())
                .collect(),
            organization_urls: self
                .organization_urls
                .iter()
                .map(|u| u.to_owned())
                .collect(),
        }
    }
}

/// Owned organization - for construction and storage.
#[derive(Debug, Clone, PartialEq)]
pub struct Organization {
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// Organization display names (1..n, required).
    pub organization_names: Vec<LocalizedName>,
    /// Organization display names for display purposes (1..n, required).
    pub organization_display_names: Vec<LocalizedName>,
    /// Organization URLs (1..n, required).
    pub organization_urls: Vec<LocalizedUri>,
}

impl Organization {
    /// Create a simple organization with one name/display/url in one language.
    pub fn simple(lang: &str, name: &str, display_name: &str, url: &str) -> Self {
        Organization {
            extensions: None,
            organization_names: vec![LocalizedName::new(lang, name)],
            organization_display_names: vec![LocalizedName::new(lang, display_name)],
            organization_urls: vec![LocalizedUri::new(lang, url)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_simple() {
        let org = Organization::simple("en", "Example", "Example Inc.", "https://example.com");
        assert_eq!(org.organization_names.len(), 1);
        assert_eq!(org.organization_names[0].value, "Example");
        assert_eq!(org.organization_display_names[0].value, "Example Inc.");
        assert_eq!(org.organization_urls[0].value, "https://example.com");
    }

    #[test]
    fn test_organization_ref_to_owned() {
        let org_ref = OrganizationRef {
            extensions: None,
            organization_names: vec![LocalizedNameRef {
                lang: "en",
                value: "Test",
            }],
            organization_display_names: vec![LocalizedNameRef {
                lang: "en",
                value: "Test Org",
            }],
            organization_urls: vec![LocalizedUriRef {
                lang: "en",
                value: "https://test.example.com",
            }],
        };
        let org = org_ref.to_owned();
        assert_eq!(org.organization_names[0].value, "Test");
        assert_eq!(org.organization_urls[0].value, "https://test.example.com");
    }
}
