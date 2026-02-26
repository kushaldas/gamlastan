// SAML 2.0 Metadata - AffiliationDescriptor
//
// Per saml-metadata-2.0-os Section 2.5

use chrono::{DateTime, Utc};

use super::extensions::{Extensions, ExtensionsRef};
use super::key_descriptor::{KeyDescriptor, KeyDescriptorRef};

/// Borrowed affiliation descriptor - references parsed XML.
///
/// Groups entities under a common affiliation. Members share a common
/// affiliation identifier.
#[derive(Debug, Clone, PartialEq)]
pub struct AffiliationDescriptorRef<'a> {
    /// Affiliation owner entity ID (required).
    pub affiliation_owner_id: &'a str,
    /// Optional ID attribute.
    pub id: Option<&'a str>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<&'a str>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<ExtensionsRef<'a>>,
    /// Affiliate members (1..n, entity IDs, required).
    pub affiliate_members: Vec<&'a str>,
    /// Key descriptors (0..n).
    pub key_descriptors: Vec<KeyDescriptorRef<'a>>,
}

impl<'a> AffiliationDescriptorRef<'a> {
    /// Convert to owned AffiliationDescriptor.
    pub fn to_owned(&self) -> AffiliationDescriptor {
        AffiliationDescriptor {
            affiliation_owner_id: self.affiliation_owner_id.to_string(),
            id: self.id.map(|s| s.to_string()),
            valid_until: self.valid_until,
            cache_duration: self.cache_duration.map(|s| s.to_string()),
            has_signature: self.has_signature,
            extensions: self.extensions.as_ref().map(|e| e.to_owned()),
            affiliate_members: self
                .affiliate_members
                .iter()
                .map(|s| s.to_string())
                .collect(),
            key_descriptors: self.key_descriptors.iter().map(|k| k.to_owned()).collect(),
        }
    }
}

/// Owned affiliation descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct AffiliationDescriptor {
    /// Affiliation owner entity ID (required).
    pub affiliation_owner_id: String,
    /// Optional ID attribute.
    pub id: Option<String>,
    /// Optional valid-until datetime.
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional cache duration (ISO 8601 duration string).
    pub cache_duration: Option<String>,
    /// Whether this descriptor has a signature.
    pub has_signature: bool,
    /// Optional extensions.
    pub extensions: Option<Extensions>,
    /// Affiliate members (1..n, entity IDs, required).
    pub affiliate_members: Vec<String>,
    /// Key descriptors (0..n).
    pub key_descriptors: Vec<KeyDescriptor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affiliation_descriptor_ref_to_owned() {
        let r = AffiliationDescriptorRef {
            affiliation_owner_id: "https://federation.example.com",
            id: Some("_aff1"),
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            affiliate_members: vec!["https://sp1.example.com", "https://sp2.example.com"],
            key_descriptors: vec![],
        };
        let o = r.to_owned();
        assert_eq!(o.affiliation_owner_id, "https://federation.example.com");
        assert_eq!(o.affiliate_members.len(), 2);
    }
}
