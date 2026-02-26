// SAML 2.0 Issuer types
//
// Issuer is of type NameIDType per saml-core-2.0-os Section 2.2.5.
// It supports Format, NameQualifier, and SPNameQualifier attributes.

/// Borrowed Issuer - reference into XML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerRef<'a> {
    /// The issuer value (entity ID).
    pub value: &'a str,
    /// The format of the issuer. Must be entity format or omitted per profiles.
    pub format: Option<&'a str>,
    /// NameQualifier - security or administrative domain that qualifies the name.
    pub name_qualifier: Option<&'a str>,
    /// SPNameQualifier - further qualify a name with the name of an SP or affiliation.
    pub sp_name_qualifier: Option<&'a str>,
}

impl<'a> IssuerRef<'a> {
    /// Convert to an owned Issuer.
    pub fn to_owned(&self) -> Issuer {
        Issuer {
            value: self.value.to_string(),
            format: self.format.map(str::to_string),
            name_qualifier: self.name_qualifier.map(str::to_string),
            sp_name_qualifier: self.sp_name_qualifier.map(str::to_string),
        }
    }
}

/// Owned Issuer - for construction and storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    /// The issuer value (entity ID).
    pub value: String,
    /// The format of the issuer. Must be entity format or omitted per profiles.
    pub format: Option<String>,
    /// NameQualifier - security or administrative domain that qualifies the name.
    pub name_qualifier: Option<String>,
    /// SPNameQualifier - further qualify a name with the name of an SP or affiliation.
    pub sp_name_qualifier: Option<String>,
}

impl Issuer {
    /// Create a new Issuer with entity format (the most common case).
    pub fn entity(value: impl Into<String>) -> Self {
        Issuer {
            value: value.into(),
            format: None, // Omitted means entity format per spec
            name_qualifier: None,
            sp_name_qualifier: None,
        }
    }

    /// Create a new Issuer with explicit entity format and NameQualifier (SPID requirement).
    pub fn entity_with_qualifier(
        value: impl Into<String>,
        name_qualifier: impl Into<String>,
    ) -> Self {
        Issuer {
            value: value.into(),
            format: Some(crate::constants::NAMEID_ENTITY.to_string()),
            name_qualifier: Some(name_qualifier.into()),
            sp_name_qualifier: None,
        }
    }

    /// Get a borrowed reference.
    pub fn as_ref(&self) -> IssuerRef<'_> {
        IssuerRef {
            value: &self.value,
            format: self.format.as_deref(),
            name_qualifier: self.name_qualifier.as_deref(),
            sp_name_qualifier: self.sp_name_qualifier.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::NAMEID_ENTITY;

    #[test]
    fn test_issuer_entity() {
        let issuer = Issuer::entity("https://idp.example.com");
        assert_eq!(issuer.value, "https://idp.example.com");
        assert!(issuer.format.is_none()); // Omitted = entity format
        assert!(issuer.name_qualifier.is_none());
        assert!(issuer.sp_name_qualifier.is_none());
    }

    #[test]
    fn test_issuer_entity_with_qualifier() {
        let issuer =
            Issuer::entity_with_qualifier("https://sp.example.com/saml", "https://sp.example.com");
        assert_eq!(issuer.value, "https://sp.example.com/saml");
        assert_eq!(issuer.format.as_deref(), Some(NAMEID_ENTITY));
        assert_eq!(
            issuer.name_qualifier.as_deref(),
            Some("https://sp.example.com")
        );
    }

    #[test]
    fn test_issuer_ref_to_owned() {
        let issuer_ref = IssuerRef {
            value: "https://idp.example.com",
            format: Some(NAMEID_ENTITY),
            name_qualifier: Some("https://idp.example.com"),
            sp_name_qualifier: None,
        };
        let owned = issuer_ref.to_owned();
        assert_eq!(owned.value, "https://idp.example.com");
        assert_eq!(owned.format.as_deref(), Some(NAMEID_ENTITY));
        assert_eq!(
            owned.name_qualifier.as_deref(),
            Some("https://idp.example.com")
        );
    }
}
