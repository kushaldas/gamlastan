// SAML 2.0 Attribute types

/// Borrowed AttributeValue.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValueRef<'a> {
    /// String value.
    Str(&'a str),
    /// Integer value.
    Integer(i64),
    /// Boolean value.
    Boolean(bool),
    /// DateTime value as string.
    DateTime(&'a str),
    /// Base64-encoded binary data.
    Base64(&'a [u8]),
    /// Raw XML content.
    Xml(&'a [u8]),
    /// Null/nil value (xsi:nil="true").
    Null,
}

impl<'a> AttributeValueRef<'a> {
    /// Convert to an owned AttributeValue.
    pub fn to_owned(&self) -> AttributeValue {
        match self {
            AttributeValueRef::Str(s) => AttributeValue::String(s.to_string()),
            AttributeValueRef::Integer(i) => AttributeValue::Integer(*i),
            AttributeValueRef::Boolean(b) => AttributeValue::Boolean(*b),
            AttributeValueRef::DateTime(s) => AttributeValue::DateTime(s.to_string()),
            AttributeValueRef::Base64(b) => AttributeValue::Base64(b.to_vec()),
            AttributeValueRef::Xml(b) => AttributeValue::Xml(b.to_vec()),
            AttributeValueRef::Null => AttributeValue::Null,
        }
    }

    /// Get the value as a string if it is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttributeValueRef::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Owned AttributeValue.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    /// String value.
    String(String),
    /// Integer value.
    Integer(i64),
    /// Boolean value.
    Boolean(bool),
    /// DateTime value as string.
    DateTime(String),
    /// Base64-encoded binary data.
    Base64(Vec<u8>),
    /// Raw XML content.
    Xml(Vec<u8>),
    /// Null/nil value.
    Null,
}

impl AttributeValue {
    /// Get the value as a string if it is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Borrowed Attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeRef<'a> {
    /// The attribute name.
    pub name: &'a str,
    /// The attribute name format URI.
    pub name_format: Option<&'a str>,
    /// A human-readable name for the attribute.
    pub friendly_name: Option<&'a str>,
    /// The attribute values.
    pub values: Vec<AttributeValueRef<'a>>,
}

impl<'a> AttributeRef<'a> {
    /// Convert to an owned Attribute.
    pub fn to_owned(&self) -> Attribute {
        Attribute {
            name: self.name.to_string(),
            name_format: self.name_format.map(str::to_string),
            friendly_name: self.friendly_name.map(str::to_string),
            values: self.values.iter().map(|v| v.to_owned()).collect(),
        }
    }
}

/// Owned Attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// The attribute name.
    pub name: String,
    /// The attribute name format URI.
    pub name_format: Option<String>,
    /// A human-readable name for the attribute.
    pub friendly_name: Option<String>,
    /// The attribute values.
    pub values: Vec<AttributeValue>,
}

/// Borrowed AttributeStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeStatementRef<'a> {
    /// The attributes in this statement.
    pub attributes: Vec<AttributeRef<'a>>,
}

impl<'a> AttributeStatementRef<'a> {
    /// Convert to an owned AttributeStatement.
    pub fn to_owned(&self) -> AttributeStatement {
        AttributeStatement {
            attributes: self.attributes.iter().map(|a| a.to_owned()).collect(),
        }
    }
}

/// Owned AttributeStatement.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeStatement {
    /// The attributes in this statement.
    pub attributes: Vec<Attribute>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::ATTRNAME_FORMAT_URI;

    #[test]
    fn test_attribute_value_str() {
        let val = AttributeValueRef::Str("hello");
        assert_eq!(val.as_str(), Some("hello"));
        let owned = val.to_owned();
        assert_eq!(owned.as_str(), Some("hello"));
    }

    #[test]
    fn test_attribute_value_types() {
        let values = vec![
            AttributeValueRef::Str("text"),
            AttributeValueRef::Integer(42),
            AttributeValueRef::Boolean(true),
            AttributeValueRef::DateTime("2024-01-15T10:00:00Z"),
            AttributeValueRef::Null,
        ];
        for val in &values {
            let _owned = val.to_owned();
        }
    }

    #[test]
    fn test_attribute_ref_to_owned() {
        let attr = AttributeRef {
            name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
            name_format: Some(ATTRNAME_FORMAT_URI),
            friendly_name: Some("eduPersonEntitlement"),
            values: vec![
                AttributeValueRef::Str("https://example.com/entitlement1"),
                AttributeValueRef::Str("https://example.com/entitlement2"),
            ],
        };
        let owned = attr.to_owned();
        assert_eq!(owned.name, "urn:oid:1.3.6.1.4.1.5923.1.1.1.7");
        assert_eq!(owned.name_format.as_deref(), Some(ATTRNAME_FORMAT_URI));
        assert_eq!(owned.values.len(), 2);
    }

    #[test]
    fn test_attribute_statement_ref_to_owned() {
        let stmt = AttributeStatementRef {
            attributes: vec![AttributeRef {
                name: "email",
                name_format: None,
                friendly_name: None,
                values: vec![AttributeValueRef::Str("user@example.com")],
            }],
        };
        let owned = stmt.to_owned();
        assert_eq!(owned.attributes.len(), 1);
        assert_eq!(owned.attributes[0].name, "email");
    }
}
