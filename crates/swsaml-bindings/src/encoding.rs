// Base64 and URL encoding helpers for SAML bindings.
//
// Base64: RFC 2045 STANDARD encoding for HTTP POST; NO linefeeds for Redirect.
// URL encoding: RFC 3986 percent-encoding for query string parameters.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;

use crate::error::BindingError;

/// Base64 encode bytes using standard alphabet with padding.
///
/// Used by HTTP POST binding (form field value).
pub fn base64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Base64 encode bytes using standard alphabet without padding.
///
/// Used when padding is not desired (rare).
pub fn base64_encode_no_pad(data: &[u8]) -> String {
    STANDARD_NO_PAD.encode(data)
}

/// Base64 decode a string.
///
/// Accepts standard alphabet with or without padding; tolerates whitespace.
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, BindingError> {
    // Strip whitespace before decoding (base64 values in forms may have line breaks)
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(STANDARD.decode(&cleaned)?)
}

/// URL-encode a string for use in query parameters (RFC 3986).
///
/// Encodes everything except unreserved characters: A-Z a-z 0-9 - _ . ~
pub fn url_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_UPPER[(*byte >> 4) as usize] as char);
                result.push(HEX_UPPER[(*byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

/// URL-decode a percent-encoded string.
pub fn url_decode(input: &str) -> Result<String, BindingError> {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(BindingError::UrlDecodeError(
                    "incomplete percent-encoding".to_string(),
                ));
            }
            let hi = hex_value(bytes[i + 1])
                .ok_or_else(|| BindingError::UrlDecodeError("invalid hex digit".to_string()))?;
            let lo = hex_value(bytes[i + 2])
                .ok_or_else(|| BindingError::UrlDecodeError("invalid hex digit".to_string()))?;
            result.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            // '+' is space in application/x-www-form-urlencoded
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).map_err(|e| BindingError::UrlDecodeError(e.to_string()))
}

/// Parse a query string into key-value pairs.
///
/// Does NOT URL-decode the values - returns them as-is for signature verification.
/// Per SAML spec, the redirect signature is over the exact URL-encoded values.
pub fn parse_query_string_raw(query: &str) -> Vec<(&str, &str)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key, value))
        })
        .collect()
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, SAML World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_with_whitespace() {
        // Base64 with line breaks (as might appear in form data)
        let encoded = "SGVs\nbG8s\nIFNB\nTUwg\nV29y\nbGQh";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello, SAML World!");
    }

    #[test]
    fn test_url_encode_unreserved() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("abc123"), "abc123");
        assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn test_url_encode_special() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(url_encode("100%"), "100%25");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(url_decode("a%3Db%26c%3Dd").unwrap(), "a=b&c=d");
        assert_eq!(url_decode("100%25").unwrap(), "100%");
    }

    #[test]
    fn test_url_decode_plus() {
        assert_eq!(url_decode("hello+world").unwrap(), "hello world");
    }

    #[test]
    fn test_url_roundtrip() {
        let original = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
        let encoded = url_encode(original);
        let decoded = url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_parse_query_string_raw() {
        let qs = "SAMLRequest=abc&RelayState=xyz&SigAlg=rsa-sha256";
        let pairs = parse_query_string_raw(qs);
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("SAMLRequest", "abc"));
        assert_eq!(pairs[1], ("RelayState", "xyz"));
        assert_eq!(pairs[2], ("SigAlg", "rsa-sha256"));
    }

    #[test]
    fn test_parse_query_string_raw_empty() {
        let pairs = parse_query_string_raw("");
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_parse_query_string_raw_no_value() {
        let pairs = parse_query_string_raw("key1=val1&key2=&key3");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[1], ("key2", ""));
        assert_eq!(pairs[2], ("key3", ""));
    }
}
