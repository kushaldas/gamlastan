// SAML message extractors for actix-web.
//
// Provides FromRequest implementations that auto-detect the SAML binding
// from the incoming request (HTTP Redirect, POST, SOAP, PAOS, Artifact).
//
// Reference: saml-bindings-2.0-os Sections 3.2-3.7

use actix_web::dev::Payload;
use actix_web::web::Bytes;
use actix_web::{FromRequest, HttpRequest};
use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;

use swsaml_bindings::HttpRequest as SamlHttpRequest;
use swsaml_bindings::DecodedMessage;

use crate::error::SamlActixError;
use crate::request_adapter::ActixHttpRequest;

/// Detected SAML binding type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlBinding {
    /// HTTP Redirect binding (DEFLATE + query string).
    HttpRedirect,
    /// HTTP POST binding (base64 form).
    HttpPost,
    /// HTTP Artifact binding (GET or POST with SAMLart).
    HttpArtifact,
    /// SOAP binding (POST with text/xml body).
    Soap,
    /// PAOS binding (reverse SOAP for ECP).
    Paos,
}

impl SamlBinding {
    /// Return the SAML binding URI.
    pub fn as_uri(&self) -> &'static str {
        match self {
            Self::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Self::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Self::HttpArtifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            Self::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
            Self::Paos => "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
        }
    }
}

/// Extracted SAML message from any binding.
///
/// Auto-detects the binding from the request:
/// - `GET` with `SAMLRequest`/`SAMLResponse` query param -> HTTP Redirect
/// - `GET` with `SAMLart` query param -> HTTP Artifact (GET variant)
/// - `POST` with `SAMLRequest`/`SAMLResponse` form param -> HTTP POST
/// - `POST` with `SAMLart` form param -> HTTP Artifact (POST variant)
/// - `POST` with `Content-Type: text/xml` -> SOAP
/// - Request with PAOS Accept + PAOS version header -> PAOS
pub struct SamlMessage {
    /// The decoded SAML XML bytes.
    pub saml_xml: Vec<u8>,

    /// RelayState, if present.
    pub relay_state: Option<String>,

    /// Whether this is a SAMLRequest (true) or SAMLResponse (false).
    pub is_request: bool,

    /// The detected binding type.
    pub binding: SamlBinding,

    /// Redirect-binding signature data (for later verification).
    pub redirect_signature: Option<RedirectSignatureData>,
}

/// Signature data from the HTTP Redirect binding.
///
/// Preserved for later verification (the SP/IdP handler will verify
/// using the partner's signing key).
#[derive(Debug, Clone)]
pub struct RedirectSignatureData {
    /// Signature algorithm URI.
    pub sig_alg: String,
    /// Signature bytes (base64-decoded).
    pub signature: Vec<u8>,
    /// The original URL-encoded query string portion used for signing.
    pub signature_input: String,
}

impl FromRequest for SamlMessage {
    type Error = SamlActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let req_clone = req.clone();
        let bytes_fut = Bytes::from_request(req, payload);

        Box::pin(async move {
            let body = bytes_fut
                .await
                .map_err(|e| SamlActixError::BodyRead(e.to_string()))?;

            extract_saml_message(&req_clone, &body)
        })
    }
}

/// Detect and extract a SAML message from the request.
fn extract_saml_message(req: &HttpRequest, body: &[u8]) -> Result<SamlMessage, SamlActixError> {
    let adapter = ActixHttpRequest::new(req, body);

    // Check for PAOS (reverse SOAP for ECP) first
    if is_paos_request(&adapter) {
        return extract_paos(&adapter);
    }

    let method = SamlHttpRequest::method(&adapter);
    match method {
        "GET" => extract_from_get(&adapter),
        "POST" => extract_from_post(&adapter),
        _ => Err(SamlActixError::UnsupportedBinding(format!(
            "unsupported HTTP method: {method}",
        ))),
    }
}

/// Check if this is a PAOS request (ECP profile).
fn is_paos_request(req: &ActixHttpRequest<'_>) -> bool {
    use swsaml_bindings::HttpRequest as _;
    let has_paos_accept = req
        .header("Accept")
        .is_some_and(|h| h.contains("application/vnd.paos+xml"));
    let has_paos_version = req
        .header("PAOS")
        .is_some_and(|h| h.contains("urn:liberty:paos:2003-08"));
    has_paos_accept && has_paos_version
}

/// Extract SAML message from a GET request.
///
/// Checks for HTTP Redirect (SAMLRequest/SAMLResponse) or Artifact (SAMLart).
fn extract_from_get(req: &ActixHttpRequest<'_>) -> Result<SamlMessage, SamlActixError> {
    use swsaml_bindings::HttpRequest as _;

    // Check for Artifact binding first (SAMLart param)
    if let Some(artifact) = req.query_param("SAMLart") {
        return Ok(SamlMessage {
            saml_xml: artifact.as_bytes().to_vec(),
            relay_state: req.query_param("RelayState").map(|s| s.to_string()),
            is_request: true, // Artifacts can be either; caller determines
            binding: SamlBinding::HttpArtifact,
            redirect_signature: None,
        });
    }

    // Check for HTTP Redirect binding — delegate to bindings decode
    let has_saml_request = req.query_param("SAMLRequest").is_some();
    let has_saml_response = req.query_param("SAMLResponse").is_some();

    if has_saml_request || has_saml_response {
        let decoded = swsaml_bindings::redirect::redirect_decode(req)?;
        let redirect_sig = match (decoded.sig_alg, decoded.signature, decoded.signature_input) {
            (Some(alg), Some(sig), Some(input)) => Some(RedirectSignatureData {
                sig_alg: alg,
                signature: sig,
                signature_input: input,
            }),
            _ => None,
        };
        return Ok(SamlMessage {
            saml_xml: decoded.saml_xml,
            relay_state: decoded.relay_state,
            is_request: decoded.is_request,
            binding: SamlBinding::HttpRedirect,
            redirect_signature: redirect_sig,
        });
    }

    Err(SamlActixError::NoSamlMessage)
}

/// Extract SAML message from a POST request.
///
/// Checks for HTTP POST (form-encoded), Artifact (SAMLart form param), or SOAP (text/xml body).
fn extract_from_post(req: &ActixHttpRequest<'_>) -> Result<SamlMessage, SamlActixError> {
    use swsaml_bindings::HttpRequest as _;

    let content_type = req.header("content-type").unwrap_or("");

    // SOAP binding: text/xml content type
    if content_type.starts_with("text/xml") || content_type.starts_with("application/xml") {
        let decoded = swsaml_bindings::soap::soap_decode(req)?;
        return Ok(SamlMessage {
            saml_xml: decoded.body_xml.into_bytes(),
            relay_state: None, // SOAP doesn't use RelayState
            is_request: true,  // Caller determines from parsed XML
            binding: SamlBinding::Soap,
            redirect_signature: None,
        });
    }

    // Form-encoded POST: check for Artifact, then SAMLRequest/SAMLResponse
    if let Some(artifact) = req.form_param("SAMLart") {
        return Ok(SamlMessage {
            saml_xml: artifact.as_bytes().to_vec(),
            relay_state: req.form_param("RelayState").map(|s| s.to_string()),
            is_request: true,
            binding: SamlBinding::HttpArtifact,
            redirect_signature: None,
        });
    }

    // Delegate to bindings post_decode for SAMLRequest/SAMLResponse
    let has_saml_request = req.form_param("SAMLRequest").is_some();
    let has_saml_response = req.form_param("SAMLResponse").is_some();

    if has_saml_request || has_saml_response {
        let decoded = swsaml_bindings::post::post_decode(req)?;
        return Ok(SamlMessage {
            saml_xml: decoded.saml_xml,
            relay_state: decoded.relay_state,
            is_request: decoded.is_request,
            binding: SamlBinding::HttpPost,
            redirect_signature: None,
        });
    }

    Err(SamlActixError::NoSamlMessage)
}

/// Extract PAOS message (reverse SOAP for ECP).
fn extract_paos(req: &ActixHttpRequest<'_>) -> Result<SamlMessage, SamlActixError> {
    use swsaml_bindings::HttpRequest as _;

    let body = req.body();
    if body.is_empty() {
        return Err(SamlActixError::NoSamlMessage);
    }

    // PAOS uses SOAP envelope format
    let decoded = swsaml_bindings::soap::soap_decode(req)?;
    Ok(SamlMessage {
        saml_xml: decoded.body_xml.into_bytes(),
        relay_state: None,
        is_request: true,
        binding: SamlBinding::Paos,
        redirect_signature: None,
    })
}

/// Convert an owned SamlMessage to a DecodedMessage with borrowed lifetime.
impl SamlMessage {
    /// Create a `DecodedMessage` borrowing from this `SamlMessage`.
    pub fn as_decoded(&self) -> DecodedMessage<'_> {
        DecodedMessage {
            saml_xml: Cow::Borrowed(&self.saml_xml),
            relay_state: self.relay_state.as_deref(),
            is_request: self.is_request,
            signature_valid: None,
        }
    }

    /// Parse the SAML XML as a string.
    pub fn saml_xml_str(&self) -> Result<&str, SamlActixError> {
        std::str::from_utf8(&self.saml_xml)
            .map_err(|e| SamlActixError::Internal(format!("SAML XML is not valid UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_binding_uri() {
        assert_eq!(
            SamlBinding::HttpRedirect.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        );
        assert_eq!(
            SamlBinding::HttpPost.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
        assert_eq!(
            SamlBinding::HttpArtifact.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        );
        assert_eq!(
            SamlBinding::Soap.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        );
        assert_eq!(
            SamlBinding::Paos.as_uri(),
            "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
        );
    }

    #[test]
    fn test_saml_binding_equality() {
        assert_eq!(SamlBinding::HttpRedirect, SamlBinding::HttpRedirect);
        assert_ne!(SamlBinding::HttpRedirect, SamlBinding::HttpPost);
    }
}
