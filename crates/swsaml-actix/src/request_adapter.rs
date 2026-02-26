// Adapt actix_web::HttpRequest to the swsaml-bindings HttpRequest trait.
//
// This adapter wraps an actix HttpRequest (plus pre-extracted body and form data)
// to implement the framework-agnostic HttpRequest trait used by SAML bindings.
//
// IMPORTANT: query_param() and form_param() return raw (URL-encoded) values,
// because the bindings' decode functions (redirect_decode, post_decode) perform
// their own URL decoding internally. Returning pre-decoded values would cause
// double-decoding.

use swsaml_bindings::HttpRequest;

/// Wrapper around actix-web's HttpRequest that implements swsaml_bindings::HttpRequest.
///
/// The body and form data must be pre-extracted before constructing this adapter
/// because actix-web consumes the body stream.
pub struct ActixHttpRequest<'a> {
    /// Reference to the actix-web HttpRequest for method, URL, headers, etc.
    inner: &'a actix_web::HttpRequest,

    /// Pre-extracted request body bytes.
    payload: &'a [u8],

    /// Reconstructed full URL (cached).
    url: String,

    /// Pre-parsed query parameters (raw, URL-encoded values).
    query_params: Vec<(String, String)>,

    /// Pre-parsed form parameters (raw, NOT URL-decoded).
    form_params: Vec<(String, String)>,

    /// Remote address string (cached).
    remote_addr: Option<String>,
}

impl<'a> ActixHttpRequest<'a> {
    /// Create a new adapter from an actix-web request and pre-extracted body.
    ///
    /// The body should be extracted before constructing this adapter (e.g., via
    /// `actix_web::web::Bytes` extractor).
    pub fn new(inner: &'a actix_web::HttpRequest, payload: &'a [u8]) -> Self {
        // Reconstruct full URL
        let url = format!(
            "{}://{}{}",
            inner.connection_info().scheme(),
            inner.connection_info().host(),
            inner.uri()
        );

        // Parse query parameters — keep values raw (URL-encoded)
        let query_params = parse_query_string_raw(inner.query_string());

        // Parse form parameters if this is a URL-encoded POST — keep values raw
        let form_params = if is_form_urlencoded(inner) && !payload.is_empty() {
            if let Ok(body_str) = std::str::from_utf8(payload) {
                parse_query_string_raw(body_str)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Cache remote address
        let remote_addr = inner
            .connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string());

        Self {
            inner,
            payload,
            url,
            query_params,
            form_params,
            remote_addr,
        }
    }

    /// Access to the underlying actix HttpRequest.
    pub fn inner(&self) -> &actix_web::HttpRequest {
        self.inner
    }
}

impl HttpRequest for ActixHttpRequest<'_> {
    fn method(&self) -> &str {
        self.inner.method().as_str()
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn query_param(&self, name: &str) -> Option<&str> {
        self.query_params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn form_param(&self, name: &str) -> Option<&str> {
        self.form_params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.inner.headers().get(name).and_then(|v| v.to_str().ok())
    }

    fn body(&self) -> &[u8] {
        self.payload
    }

    fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }
}

/// Check if the request has a URL-encoded form content type.
fn is_form_urlencoded(req: &actix_web::HttpRequest) -> bool {
    req.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"))
}

/// Parse a query/form string into key-value pairs, keeping values raw (URL-encoded).
///
/// The keys ARE decoded (to match parameter names like "SAMLRequest"),
/// but values are kept raw because the bindings' decode functions
/// (redirect_decode, post_decode) perform their own decoding.
fn parse_query_string_raw(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            // Decode the key (parameter names are simple ASCII, but handle + and %)
            let decoded_key = url_decode_simple(key).unwrap_or_else(|_| key.to_string());
            // Keep value raw (URL-encoded)
            Some((decoded_key, value.to_string()))
        })
        .collect()
}

/// Simple URL decode (percent-decode + plus-to-space).
fn url_decode_simple(input: &str) -> Result<String, std::string::FromUtf8Error> {
    let mut result = Vec::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        match b {
            b'+' => result.push(b' '),
            b'%' => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let byte = hex_byte(hi) * 16 + hex_byte(lo);
                result.push(byte);
            }
            _ => result.push(b),
        }
    }
    String::from_utf8(result)
}

fn hex_byte(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_string_raw_empty() {
        assert!(parse_query_string_raw("").is_empty());
    }

    #[test]
    fn test_parse_query_string_raw_values_not_decoded() {
        // Values should NOT be URL-decoded (bindings do their own decoding)
        let params = parse_query_string_raw("SAMLRequest=abc%2B123&RelayState=tok%3Den");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "SAMLRequest");
        assert_eq!(params[0].1, "abc%2B123"); // raw, not decoded
        assert_eq!(params[1].0, "RelayState");
        assert_eq!(params[1].1, "tok%3Den"); // raw, not decoded
    }

    #[test]
    fn test_parse_query_string_raw_keys_decoded() {
        let params = parse_query_string_raw("SAML%52equest=abc");
        assert_eq!(params[0].0, "SAMLRequest");
    }

    #[test]
    fn test_parse_query_string_raw_no_value() {
        let params = parse_query_string_raw("key=");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "key");
        assert_eq!(params[0].1, "");
    }

    #[test]
    fn test_url_decode_simple_plus() {
        assert_eq!(url_decode_simple("hello+world").unwrap(), "hello world");
    }

    #[test]
    fn test_url_decode_simple_percent() {
        assert_eq!(url_decode_simple("hello%20world").unwrap(), "hello world");
    }
}
