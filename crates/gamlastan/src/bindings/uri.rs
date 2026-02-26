// URI Binding (SAML Bindings Section 3.7).
//
// - HTTP GET with ?ID=<assertion_id> query param
// - Response Content-Type: application/samlassertion+xml
// - Returns bare <saml:Assertion> element (not wrapped in Response)
// - HTTPS required; HTTP errors: 403 (refuse), 404 (not found)

use crate::core::constants::MIME_SAML_ASSERTION;

use crate::bindings::error::BindingError;
use crate::bindings::traits::HttpRequest;

/// Decode an assertion ID from a URI binding request.
///
/// Extracts the `ID` query parameter from an HTTP GET request.
pub fn uri_decode_assertion_id(request: &impl HttpRequest) -> Result<String, BindingError> {
    if request.method() != "GET" {
        return Err(BindingError::HttpError(405));
    }

    let id = request
        .query_param("ID")
        .ok_or(BindingError::MissingSamlParam("ID"))?;

    if id.is_empty() {
        return Err(BindingError::MissingSamlParam("ID (empty)"));
    }

    Ok(id.to_string())
}

/// Build response headers for a URI binding response.
///
/// Returns the Content-Type header for SAML assertion XML.
pub fn uri_response_headers() -> Vec<(&'static str, &'static str)> {
    vec![("Content-Type", MIME_SAML_ASSERTION)]
}

/// Build the URI for requesting an assertion by ID.
///
/// Constructs a URL with the `ID` query parameter.
pub fn uri_build_request_url(endpoint: &str, assertion_id: &str) -> String {
    let separator = if endpoint.contains('?') { "&" } else { "?" };
    format!("{}{}ID={}", endpoint, separator, assertion_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_response_headers() {
        let headers = uri_response_headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "application/samlassertion+xml");
    }

    #[test]
    fn test_uri_build_request_url() {
        let url = uri_build_request_url("https://idp.example.com/assertions", "_abc123");
        assert_eq!(url, "https://idp.example.com/assertions?ID=_abc123");
    }

    #[test]
    fn test_uri_build_request_url_existing_query() {
        let url = uri_build_request_url("https://idp.example.com/assertions?v=2", "_abc123");
        assert_eq!(url, "https://idp.example.com/assertions?v=2&ID=_abc123");
    }
}
