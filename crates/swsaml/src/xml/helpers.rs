// swsaml-xml helper functions for XML element navigation and attribute access.
//
// These functions simplify namespace-aware element lookup and attribute extraction
// when deserializing SAML XML using the uppsala library.

use chrono::{DateTime, Utc};
use uppsala::{Document, NodeId};

use crate::xml::error::XmlError;

/// Find the first direct child element matching the given namespace URI and local name.
pub fn find_child_element<'a>(
    doc: &'a Document<'a>,
    parent: NodeId,
    namespace_uri: &str,
    local_name: &str,
) -> Option<NodeId> {
    doc.first_child_element_by_name_ns(parent, namespace_uri, local_name)
}

/// Find all direct child elements matching the given namespace URI and local name.
pub fn find_child_elements<'a>(
    doc: &'a Document<'a>,
    parent: NodeId,
    namespace_uri: &str,
    local_name: &str,
) -> Vec<NodeId> {
    doc.child_elements_by_name_ns(parent, namespace_uri, local_name)
}

/// Get a required attribute from an element by local name.
pub fn required_attribute<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
    attr_name: &str,
) -> Result<&'a str, XmlError> {
    let elem = doc.element(node).ok_or(XmlError::NotAnElement)?;
    doc.get_attribute(node, attr_name)
        .ok_or_else(|| XmlError::MissingAttribute {
            element: elem.name.local_name.to_string(),
            attribute: attr_name.to_string(),
        })
}

/// Get an optional attribute from an element by local name.
pub fn optional_attribute<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
    attr_name: &str,
) -> Option<&'a str> {
    doc.get_attribute(node, attr_name)
}

/// Parse a required datetime attribute value.
pub fn parse_datetime_attr(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
) -> Result<DateTime<Utc>, XmlError> {
    let value = required_attribute(doc, node, attr_name)?;
    parse_datetime(value)
}

/// Parse an optional datetime attribute value.
pub fn parse_optional_datetime_attr(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
) -> Result<Option<DateTime<Utc>>, XmlError> {
    match optional_attribute(doc, node, attr_name) {
        Some(value) => Ok(Some(parse_datetime(value)?)),
        None => Ok(None),
    }
}

/// Parse an xs:dateTime string into a chrono DateTime<Utc>.
pub fn parse_datetime(s: &str) -> Result<DateTime<Utc>, XmlError> {
    // Try RFC 3339 format first (most common in SAML)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Try the common xs:dateTime format without timezone offset (assumed UTC)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(dt.and_utc());
    }
    Err(XmlError::InvalidDateTime(s.to_string()))
}

/// Format a DateTime<Utc> as xs:dateTime string (ISO 8601 / RFC 3339).
pub fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Parse an optional boolean attribute value.
/// Accepts "true", "1", "false", "0" per xs:boolean.
pub fn parse_optional_bool_attr(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
) -> Result<Option<bool>, XmlError> {
    match optional_attribute(doc, node, attr_name) {
        Some(value) => match value {
            "true" | "1" => Ok(Some(true)),
            "false" | "0" => Ok(Some(false)),
            _ => Err(XmlError::InvalidBoolean(value.to_string())),
        },
        None => Ok(None),
    }
}

/// Parse a boolean attribute with a default value.
pub fn parse_bool_attr_or(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
    default: bool,
) -> Result<bool, XmlError> {
    Ok(parse_optional_bool_attr(doc, node, attr_name)?.unwrap_or(default))
}

/// Parse an optional u16 attribute value.
pub fn parse_optional_u16_attr(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
) -> Result<Option<u16>, XmlError> {
    match optional_attribute(doc, node, attr_name) {
        Some(value) => {
            let n = value
                .parse::<u16>()
                .map_err(|_| XmlError::InvalidInteger(value.to_string()))?;
            Ok(Some(n))
        }
        None => Ok(None),
    }
}

/// Parse an optional u32 attribute value.
pub fn parse_optional_u32_attr(
    doc: &Document<'_>,
    node: NodeId,
    attr_name: &str,
) -> Result<Option<u32>, XmlError> {
    match optional_attribute(doc, node, attr_name) {
        Some(value) => {
            let n = value
                .parse::<u32>()
                .map_err(|_| XmlError::InvalidInteger(value.to_string()))?;
            Ok(Some(n))
        }
        None => Ok(None),
    }
}

/// Get the text content of a required child element.
pub fn required_child_text<'a>(
    doc: &'a Document<'a>,
    parent: NodeId,
    namespace_uri: &str,
    local_name: &str,
) -> Result<String, XmlError> {
    let child = find_child_element(doc, parent, namespace_uri, local_name).ok_or_else(|| {
        let parent_name = doc
            .element(parent)
            .map(|e| e.name.local_name.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        XmlError::MissingElement {
            parent: parent_name,
            element: local_name.to_string(),
        }
    })?;
    Ok(doc.text_content_deep(child))
}

/// Get the text content of an optional child element.
pub fn optional_child_text<'a>(
    doc: &'a Document<'a>,
    parent: NodeId,
    namespace_uri: &str,
    local_name: &str,
) -> Option<String> {
    find_child_element(doc, parent, namespace_uri, local_name)
        .map(|child| doc.text_content_deep(child))
}

/// Verify that an element has the expected namespace and local name.
pub fn verify_element(
    doc: &Document<'_>,
    node: NodeId,
    expected_ns: &str,
    expected_local: &str,
) -> Result<(), XmlError> {
    let elem = doc.element(node).ok_or(XmlError::NotAnElement)?;
    if elem.matches_name_ns(expected_ns, expected_local) {
        Ok(())
    } else {
        let local = elem.name.local_name.as_ref();
        let ns = elem.name.namespace_uri.as_ref().map(|c| c.as_ref());
        Err(XmlError::UnexpectedElement(format!(
            "Expected {{{}}}:{}, found {{{}}}:{}",
            expected_ns,
            expected_local,
            ns.unwrap_or(""),
            local,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_datetime_rfc3339() {
        let dt = parse_datetime("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    use chrono::Datelike;

    #[test]
    fn test_parse_datetime_with_offset() {
        let dt = parse_datetime("2024-01-15T10:30:00+01:00").unwrap();
        // Converted to UTC: 09:30
        assert_eq!(dt.hour(), 9);
    }

    use chrono::Timelike;

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(parse_datetime("not-a-date").is_err());
    }

    #[test]
    fn test_format_datetime() {
        let dt = parse_datetime("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(format_datetime(&dt), "2024-01-15T10:30:00Z");
    }

    #[test]
    fn test_find_child_element() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example.com</saml:Issuer></samlp:Response>"#;
        let doc = uppsala::parse(xml).unwrap();
        let root = doc.document_element().unwrap();
        let issuer = find_child_element(
            &doc,
            root,
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "Issuer",
        );
        assert!(issuer.is_some());
        let text = doc.text_content_deep(issuer.unwrap());
        assert_eq!(text, "https://idp.example.com");
    }

    #[test]
    fn test_find_child_element_not_found() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        let doc = uppsala::parse(xml).unwrap();
        let root = doc.document_element().unwrap();
        let result = find_child_element(
            &doc,
            root,
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "Issuer",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_required_attribute() {
        let xml = r#"<Response ID="_123" Version="2.0"/>"#;
        let doc = uppsala::parse(xml).unwrap();
        let root = doc.document_element().unwrap();
        assert_eq!(required_attribute(&doc, root, "ID").unwrap(), "_123");
        assert_eq!(required_attribute(&doc, root, "Version").unwrap(), "2.0");
        assert!(required_attribute(&doc, root, "Missing").is_err());
    }
}
