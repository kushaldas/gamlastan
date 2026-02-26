// Framework-agnostic HTTP transport traits for SAML bindings.
//
// These traits abstract over the HTTP framework (actix-web, axum, etc.)
// to keep the binding logic reusable.
//
// Reference: saml-bindings-2.0-os Section 3

/// Framework-agnostic HTTP request abstraction.
///
/// Implemented by framework-specific adapters (e.g., `swsaml-actix` wraps
/// `actix_web::HttpRequest`).
pub trait HttpRequest {
    /// HTTP method (GET, POST, etc.).
    fn method(&self) -> &str;

    /// Full request URL including query string.
    fn url(&self) -> &str;

    /// Extract a query string parameter by name.
    fn query_param(&self, name: &str) -> Option<&str>;

    /// Extract a form/POST body parameter by name.
    fn form_param(&self, name: &str) -> Option<&str>;

    /// Get an HTTP header value by name (case-insensitive lookup).
    fn header(&self, name: &str) -> Option<&str>;

    /// Raw request body bytes.
    fn body(&self) -> &[u8];

    /// Remote address of the client, if available.
    fn remote_addr(&self) -> Option<&str>;
}

/// Framework-agnostic HTTP response builder.
///
/// Implemented by framework-specific adapters to produce the correct
/// response type for the web framework in use.
pub trait HttpResponseBuilder {
    /// The concrete response type produced.
    type Response;

    /// Create an HTTP redirect response (302/303).
    fn redirect(url: &str, status: u16) -> Self::Response;

    /// Create an HTML response (for HTTP POST auto-submit forms).
    fn html(body: &str, headers: Vec<(&str, &str)>) -> Self::Response;

    /// Create a SOAP response.
    fn soap_response(body: &[u8], headers: Vec<(&str, &str)>) -> Self::Response;

    /// Create an error response with the given HTTP status code.
    fn error(status: u16) -> Self::Response;
}

/// Back-channel SOAP transport for artifact resolution and SLO.
///
/// This trait abstracts the HTTP client used for back-channel SOAP
/// communication (artifact resolution, logout over SOAP, etc.).
pub trait SoapTransport {
    /// Error type for transport failures.
    type Error: std::error::Error;

    /// Send a SOAP request to the specified endpoint.
    ///
    /// - `endpoint`: The URL to send the SOAP request to.
    /// - `soap_body`: The complete SOAP envelope XML bytes.
    /// - `soap_action`: Optional SOAPAction header value.
    ///
    /// Returns the complete SOAP response envelope bytes.
    fn send_soap_request(
        &self,
        endpoint: &str,
        soap_body: &[u8],
        soap_action: Option<&str>,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Artifact store for one-time-use artifact enforcement.
///
/// Per SAML Bindings Section 3.6: artifacts MUST be one-time-use.
/// An implementation SHOULD alarm on repeated resolution attempts
/// for the same artifact.
pub trait ArtifactStore {
    /// Store a pending artifact mapped to its SAML message XML.
    ///
    /// Returns `Err` if the artifact already exists.
    fn store(&self, artifact: &str, message_xml: &[u8]) -> Result<(), crate::error::BindingError>;

    /// Resolve and consume an artifact (one-time retrieval).
    ///
    /// Returns `Some(message_xml)` on first call, `None` on subsequent calls.
    /// Implementations SHOULD log/alarm on repeated resolution attempts.
    fn resolve_and_consume(
        &self,
        artifact: &str,
    ) -> Result<Option<Vec<u8>>, crate::error::BindingError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple in-memory HTTP request for testing.
    struct TestRequest {
        method: String,
        url: String,
        query: Vec<(String, String)>,
        form: Vec<(String, String)>,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl TestRequest {
        fn get(url: &str) -> Self {
            Self {
                method: "GET".to_string(),
                url: url.to_string(),
                query: Vec::new(),
                form: Vec::new(),
                headers: Vec::new(),
                body: Vec::new(),
            }
        }

        fn with_query(mut self, name: &str, value: &str) -> Self {
            self.query.push((name.to_string(), value.to_string()));
            self
        }

        fn with_form(mut self, name: &str, value: &str) -> Self {
            self.form.push((name.to_string(), value.to_string()));
            self
        }
    }

    impl HttpRequest for TestRequest {
        fn method(&self) -> &str {
            &self.method
        }
        fn url(&self) -> &str {
            &self.url
        }
        fn query_param(&self, name: &str) -> Option<&str> {
            self.query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
        fn form_param(&self, name: &str) -> Option<&str> {
            self.form
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
        fn header(&self, name: &str) -> Option<&str> {
            let name_lower = name.to_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.as_str())
        }
        fn body(&self) -> &[u8] {
            &self.body
        }
        fn remote_addr(&self) -> Option<&str> {
            None
        }
    }

    #[test]
    fn test_http_request_trait() {
        let req = TestRequest::get("https://sp.example.com/acs")
            .with_query("SAMLResponse", "abc123")
            .with_query("RelayState", "token");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.url(), "https://sp.example.com/acs");
        assert_eq!(req.query_param("SAMLResponse"), Some("abc123"));
        assert_eq!(req.query_param("RelayState"), Some("token"));
        assert_eq!(req.query_param("Missing"), None);
    }

    #[test]
    fn test_http_request_form_params() {
        let req = TestRequest::get("https://sp.example.com/acs")
            .with_form("SAMLResponse", "base64data")
            .with_form("RelayState", "state_token");
        assert_eq!(req.form_param("SAMLResponse"), Some("base64data"));
        assert_eq!(req.form_param("RelayState"), Some("state_token"));
    }
}
