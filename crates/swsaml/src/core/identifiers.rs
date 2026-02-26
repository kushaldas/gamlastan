// SAML 2.0 Identifiers: EntityId, SamlId, SamlVersion

use crate::core::error::CoreError;
use std::fmt;

// ============================================================================
// EntityId
// ============================================================================

/// Borrowed entity ID - validated reference into parsed XML.
/// Max 1024 characters per SAML 2.0 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityIdRef<'a>(&'a str);

impl<'a> EntityIdRef<'a> {
    /// Create a new borrowed EntityId, validating length constraints.
    pub fn new(value: &'a str) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::EntityIdEmpty);
        }
        if value.len() > 1024 {
            return Err(CoreError::EntityIdTooLong(value.len()));
        }
        Ok(EntityIdRef(value))
    }

    /// Get the entity ID as a string slice.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Convert to an owned EntityId.
    pub fn to_owned(&self) -> EntityId {
        EntityId(self.0.to_string())
    }
}

impl<'a> fmt::Display for EntityIdRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Owned entity ID - for construction and storage.
/// Max 1024 characters per SAML 2.0 spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl EntityId {
    /// Create a new owned EntityId, validating length constraints.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let s = value.into();
        if s.is_empty() {
            return Err(CoreError::EntityIdEmpty);
        }
        if s.len() > 1024 {
            return Err(CoreError::EntityIdTooLong(s.len()));
        }
        Ok(EntityId(s))
    }

    /// Get a borrowed reference to this EntityId.
    pub fn as_ref(&self) -> EntityIdRef<'_> {
        EntityIdRef(&self.0)
    }

    /// Get the entity ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// SamlId
// ============================================================================

/// A SAML ID value (xs:ID type).
/// Generated as `_` + 32 hex characters (128 bits of randomness).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SamlId(String);

impl SamlId {
    /// Generate a new random SAML ID.
    /// Format: `_` followed by 32 random hex characters.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        SamlId(format!("_{}", hex))
    }

    /// Create a SamlId from an existing string value.
    /// The value must start with `_` or a letter (per xs:ID rules).
    pub fn from_string(value: impl Into<String>) -> Result<Self, CoreError> {
        let s = value.into();
        if s.is_empty() {
            return Err(CoreError::InvalidId(
                "SAML ID must not be empty".to_string(),
            ));
        }
        // xs:ID must start with a letter or underscore
        let first = s.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(CoreError::InvalidId(format!(
                "SAML ID must start with a letter or underscore, got: {}",
                first
            )));
        }
        Ok(SamlId(s))
    }

    /// Get the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SamlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Borrowed SAML ID reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SamlIdRef<'a>(&'a str);

impl<'a> SamlIdRef<'a> {
    /// Create a new borrowed SamlId reference.
    pub fn new(value: &'a str) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::InvalidId(
                "SAML ID must not be empty".to_string(),
            ));
        }
        let first = value.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(CoreError::InvalidId(format!(
                "SAML ID must start with a letter or underscore, got: {}",
                first
            )));
        }
        Ok(SamlIdRef(value))
    }

    /// Get the ID as a string slice.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Convert to an owned SamlId.
    pub fn to_owned(&self) -> SamlId {
        SamlId(self.0.to_string())
    }
}

impl<'a> fmt::Display for SamlIdRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

// ============================================================================
// SamlVersion
// ============================================================================

/// SAML protocol version. Always 2.0 for this library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SamlVersion {
    pub major: u8,
    pub minor: u8,
}

impl SamlVersion {
    /// SAML 2.0 version constant.
    pub const V2_0: SamlVersion = SamlVersion { major: 2, minor: 0 };

    /// Parse a version string like "2.0".
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(CoreError::InvalidVersion(s.to_string()));
        }
        let major = parts[0]
            .parse::<u8>()
            .map_err(|_| CoreError::InvalidVersion(s.to_string()))?;
        let minor = parts[1]
            .parse::<u8>()
            .map_err(|_| CoreError::InvalidVersion(s.to_string()))?;
        Ok(SamlVersion { major, minor })
    }

    /// Check if this is SAML 2.0.
    pub fn is_v2_0(&self) -> bool {
        self.major == 2 && self.minor == 0
    }

    /// Get the version as a string slice.
    /// Returns "2.0" for the standard version.
    pub fn as_str(&self) -> &'static str {
        if self.major == 2 && self.minor == 0 {
            "2.0"
        } else if self.major == 1 && self.minor == 1 {
            "1.1"
        } else if self.major == 1 && self.minor == 0 {
            "1.0"
        } else {
            // For uncommon versions, we can't return &'static str
            // but in practice SAML only uses 2.0
            "2.0"
        }
    }

    /// Parse a version string like "2.0". Returns None on failure.
    pub fn try_from_str(s: &str) -> Option<Self> {
        Self::parse(s).ok()
    }
}

impl fmt::Display for SamlVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Default for SamlVersion {
    fn default() -> Self {
        SamlVersion::V2_0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EntityId tests
    #[test]
    fn test_entity_id_valid() {
        let id = EntityId::new("https://sp.example.com/saml").unwrap();
        assert_eq!(id.as_str(), "https://sp.example.com/saml");
    }

    #[test]
    fn test_entity_id_empty() {
        assert!(matches!(EntityId::new(""), Err(CoreError::EntityIdEmpty)));
    }

    #[test]
    fn test_entity_id_too_long() {
        let long = "x".repeat(1025);
        assert!(matches!(
            EntityId::new(long),
            Err(CoreError::EntityIdTooLong(1025))
        ));
    }

    #[test]
    fn test_entity_id_max_length_ok() {
        let max = "x".repeat(1024);
        assert!(EntityId::new(max).is_ok());
    }

    #[test]
    fn test_entity_id_ref_to_owned() {
        let s = "https://idp.example.com";
        let id_ref = EntityIdRef::new(s).unwrap();
        let owned = id_ref.to_owned();
        assert_eq!(owned.as_str(), s);
    }

    #[test]
    fn test_entity_id_as_ref() {
        let owned = EntityId::new("https://sp.example.com").unwrap();
        let ref_ = owned.as_ref();
        assert_eq!(ref_.as_str(), "https://sp.example.com");
    }

    // SamlId tests
    #[test]
    fn test_saml_id_generate() {
        let id = SamlId::generate();
        assert!(id.as_str().starts_with('_'));
        assert_eq!(id.as_str().len(), 33); // _ + 32 hex chars
    }

    #[test]
    fn test_saml_id_generate_unique() {
        let id1 = SamlId::generate();
        let id2 = SamlId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_saml_id_from_string() {
        let id = SamlId::from_string("_abc123").unwrap();
        assert_eq!(id.as_str(), "_abc123");
    }

    #[test]
    fn test_saml_id_from_string_letter_start() {
        let id = SamlId::from_string("abc123").unwrap();
        assert_eq!(id.as_str(), "abc123");
    }

    #[test]
    fn test_saml_id_from_string_invalid_start() {
        assert!(SamlId::from_string("123abc").is_err());
    }

    #[test]
    fn test_saml_id_from_string_empty() {
        assert!(SamlId::from_string("").is_err());
    }

    #[test]
    fn test_saml_id_ref() {
        let id_ref = SamlIdRef::new("_abc123").unwrap();
        assert_eq!(id_ref.as_str(), "_abc123");
        let owned = id_ref.to_owned();
        assert_eq!(owned.as_str(), "_abc123");
    }

    // SamlVersion tests
    #[test]
    fn test_saml_version_default() {
        let v = SamlVersion::default();
        assert!(v.is_v2_0());
        assert_eq!(v.to_string(), "2.0");
    }

    #[test]
    fn test_saml_version_parse() {
        let v = SamlVersion::parse("2.0").unwrap();
        assert!(v.is_v2_0());
    }

    #[test]
    fn test_saml_version_parse_other() {
        let v = SamlVersion::parse("1.1").unwrap();
        assert!(!v.is_v2_0());
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 1);
    }

    #[test]
    fn test_saml_version_parse_invalid() {
        assert!(SamlVersion::parse("abc").is_err());
        assert!(SamlVersion::parse("2").is_err());
        assert!(SamlVersion::parse("2.0.1").is_err());
    }
}
