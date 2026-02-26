// SAML 2.0 NameId types
//
// Per Errata:
// - E14: AllowCreate means create OR associate
// - E60, E84: Corrected NameID format URIs (SAML:1.1 namespace for some)
// - E86: Persistent ID generation flexibility

/// Borrowed NameID - references into the XML document buffer. Zero allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameIdRef<'a> {
    /// The name identifier value.
    pub value: &'a str,
    /// The format URI of the name identifier.
    pub format: Option<&'a str>,
    /// The name qualifier (security or administrative domain).
    pub name_qualifier: Option<&'a str>,
    /// The SP name qualifier.
    pub sp_name_qualifier: Option<&'a str>,
    /// The SP-provided ID.
    pub sp_provided_id: Option<&'a str>,
}

impl<'a> NameIdRef<'a> {
    /// Convert to an owned NameId.
    pub fn to_owned(&self) -> NameId {
        NameId {
            value: self.value.to_string(),
            format: self.format.map(str::to_string),
            name_qualifier: self.name_qualifier.map(str::to_string),
            sp_name_qualifier: self.sp_name_qualifier.map(str::to_string),
            sp_provided_id: self.sp_provided_id.map(str::to_string),
        }
    }
}

/// Owned NameID - for construction, storage, and crossing lifetime boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    /// The name identifier value.
    pub value: String,
    /// The format URI of the name identifier.
    pub format: Option<String>,
    /// The name qualifier (security or administrative domain).
    pub name_qualifier: Option<String>,
    /// The SP name qualifier.
    pub sp_name_qualifier: Option<String>,
    /// The SP-provided ID.
    pub sp_provided_id: Option<String>,
}

impl NameId {
    /// Get a borrowed reference to this NameId.
    pub fn as_ref(&self) -> NameIdRef<'_> {
        NameIdRef {
            value: &self.value,
            format: self.format.as_deref(),
            name_qualifier: self.name_qualifier.as_deref(),
            sp_name_qualifier: self.sp_name_qualifier.as_deref(),
            sp_provided_id: self.sp_provided_id.as_deref(),
        }
    }
}

/// Borrowed NameIDPolicy.
///
/// Per E14: AllowCreate means create OR associate an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameIdPolicyRef<'a> {
    /// The requested NameID format URI.
    pub format: Option<&'a str>,
    /// The SP name qualifier.
    pub sp_name_qualifier: Option<&'a str>,
    /// Whether the IdP is allowed to create/associate a new identifier. Per E14.
    pub allow_create: bool,
}

impl<'a> NameIdPolicyRef<'a> {
    /// Convert to an owned NameIdPolicy.
    pub fn to_owned(&self) -> NameIdPolicy {
        NameIdPolicy {
            format: self.format.map(str::to_string),
            sp_name_qualifier: self.sp_name_qualifier.map(str::to_string),
            allow_create: self.allow_create,
        }
    }
}

/// Owned NameIDPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    /// The requested NameID format URI.
    pub format: Option<String>,
    /// The SP name qualifier.
    pub sp_name_qualifier: Option<String>,
    /// Whether the IdP is allowed to create/associate a new identifier. Per E14.
    pub allow_create: bool,
}

impl NameIdPolicy {
    /// Get a borrowed reference.
    pub fn as_ref(&self) -> NameIdPolicyRef<'_> {
        NameIdPolicyRef {
            format: self.format.as_deref(),
            sp_name_qualifier: self.sp_name_qualifier.as_deref(),
            allow_create: self.allow_create,
        }
    }
}

/// An EncryptedID element (opaque encrypted data).
/// Borrowed variant holds a reference to the raw encrypted XML bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedIdRef<'a> {
    /// The raw encrypted XML element bytes.
    pub raw: &'a [u8],
}

/// Owned EncryptedID element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedId {
    /// The raw encrypted XML element bytes.
    pub raw: Vec<u8>,
}

/// Either a NameID or an EncryptedID (borrowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameIdOrEncryptedIdRef<'a> {
    /// A plaintext NameID.
    NameId(NameIdRef<'a>),
    /// An encrypted NameID.
    EncryptedId(EncryptedIdRef<'a>),
}

impl<'a> NameIdOrEncryptedIdRef<'a> {
    /// Convert to owned variant.
    pub fn to_owned(&self) -> NameIdOrEncryptedId {
        match self {
            NameIdOrEncryptedIdRef::NameId(n) => NameIdOrEncryptedId::NameId(n.to_owned()),
            NameIdOrEncryptedIdRef::EncryptedId(e) => {
                NameIdOrEncryptedId::EncryptedId(EncryptedId {
                    raw: e.raw.to_vec(),
                })
            }
        }
    }
}

/// Either a NameID or an EncryptedID (owned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameIdOrEncryptedId {
    /// A plaintext NameID.
    NameId(NameId),
    /// An encrypted NameID.
    EncryptedId(EncryptedId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    #[test]
    fn test_name_id_ref_to_owned() {
        let id_ref = NameIdRef {
            value: "user@example.com",
            format: Some(NAMEID_EMAIL),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        let owned = id_ref.to_owned();
        assert_eq!(owned.value, "user@example.com");
        assert_eq!(owned.format.as_deref(), Some(NAMEID_EMAIL));
    }

    #[test]
    fn test_name_id_as_ref() {
        let owned = NameId {
            value: "user@example.com".to_string(),
            format: Some(NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        let r = owned.as_ref();
        assert_eq!(r.value, "user@example.com");
        assert_eq!(r.format, Some(NAMEID_EMAIL));
    }

    #[test]
    fn test_name_id_policy_allow_create() {
        let policy = NameIdPolicy {
            format: Some(NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        assert!(policy.allow_create);
        let r = policy.as_ref();
        assert!(r.allow_create);
    }

    #[test]
    fn test_name_id_or_encrypted_id() {
        let name_id = NameIdOrEncryptedIdRef::NameId(NameIdRef {
            value: "test",
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        });
        let owned = name_id.to_owned();
        match owned {
            NameIdOrEncryptedId::NameId(n) => assert_eq!(n.value, "test"),
            _ => panic!("Expected NameId"),
        }
    }
}
