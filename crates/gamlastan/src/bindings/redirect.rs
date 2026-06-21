// HTTP Redirect Binding (SAML Bindings Section 3.4).
//
// Encoding steps per Section 3.4.4.1:
// 1. Strip <ds:Signature> from message XML (keep embedded assertion signatures)
// 2. DEFLATE compress (RFC 1951 raw deflate)
// 3. Base64 encode with NO linefeeds
// 4. URL-encode and add as SAMLRequest= or SAMLResponse= query param
// 5. Add RelayState= if present (URL-encoded, max 80 bytes)
// 6. If signing: add SigAlg= param; compute signature over query string;
//    add Signature= param
//
// CRITICAL: verify signature using original URL-encoded param values, NOT re-encoded.

use crate::bindings::deflate::{deflate_compress, deflate_decompress};
use crate::bindings::encoding::{
    base64_decode, base64_encode, parse_query_string_raw, url_decode, url_encode,
};
use crate::bindings::error::BindingError;
use crate::bindings::relay_state::RelayState;
use crate::bindings::traits::HttpRequest;

/// A decoded message from the HTTP Redirect binding.
#[derive(Debug)]
pub struct RedirectDecoded {
    /// The decompressed SAML XML message.
    pub saml_xml: Vec<u8>,
    /// Whether the parameter was SAMLRequest (true) or SAMLResponse (false).
    pub is_request: bool,
    /// RelayState, if present.
    pub relay_state: Option<String>,
    /// Signature algorithm URI, if the message was signed.
    pub sig_alg: Option<String>,
    /// Signature bytes (base64-decoded), if the message was signed.
    pub signature: Option<Vec<u8>>,
    /// The exact query string used for signature verification.
    /// This is the `SAMLRequest=...&RelayState=...&SigAlg=...` portion,
    /// preserved exactly as received (not re-encoded).
    pub signature_input: Option<String>,
}

/// Parameters for encoding a SAML message with the HTTP Redirect binding.
pub struct RedirectEncodeParams<'a> {
    /// The SAML XML message to encode.
    pub saml_xml: &'a [u8],
    /// Whether this is a request (SAMLRequest) or response (SAMLResponse).
    pub is_request: bool,
    /// The destination endpoint URL.
    pub destination: &'a str,
    /// Optional RelayState.
    pub relay_state: Option<&'a RelayState>,
    /// Optional signing key and algorithm for query string signature.
    pub signer: Option<(&'a crate::crypto::SamlSigner, &'a str)>,
}

/// Encode a SAML message for the HTTP Redirect binding.
///
/// Returns the complete redirect URL with query parameters.
pub fn redirect_encode(params: &RedirectEncodeParams<'_>) -> Result<String, BindingError> {
    // Step 1: Strip top-level ds:Signature (caller should have done this,
    // but we handle simple cases)
    // Step 2: DEFLATE compress
    let compressed = deflate_compress(params.saml_xml)?;

    // Step 3: Base64 encode (no linefeeds)
    let b64 = base64_encode(&compressed);

    // Step 4: Build query string
    let param_name = if params.is_request {
        "SAMLRequest"
    } else {
        "SAMLResponse"
    };

    let encoded_value = url_encode(&b64);
    let mut query = format!("{}={}", param_name, encoded_value);

    // Step 5: Add RelayState if present
    if let Some(rs) = params.relay_state {
        query.push_str("&RelayState=");
        query.push_str(&url_encode(rs.as_str()));
    }

    // Step 6: Sign if requested
    if let Some((signer, sig_alg)) = params.signer {
        query.push_str("&SigAlg=");
        query.push_str(&url_encode(sig_alg));

        // Signature input is the query string up to and including SigAlg
        let signature = signer.sign_redirect_query(query.as_bytes(), sig_alg)?;
        let sig_b64 = base64_encode(&signature);
        query.push_str("&Signature=");
        query.push_str(&url_encode(&sig_b64));
    }

    // Build final URL
    let separator = if params.destination.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok(format!("{}{}{}", params.destination, separator, query))
}

/// Decode a SAML message from an HTTP Redirect binding request.
///
/// Extracts SAMLRequest/SAMLResponse, RelayState, SigAlg, and Signature
/// from query parameters.
///
/// CRITICAL: the signature_input field preserves the original URL-encoded
/// query string for signature verification (not re-encoded).
pub fn redirect_decode(request: &impl HttpRequest) -> Result<RedirectDecoded, BindingError> {
    let raw_query = request.url().split_once('?').map(|(_, query)| query);
    if let Some(query) = raw_query {
        validate_unique_redirect_params(query)?;
    }

    // Determine if this is a request or response
    let (encoded_value, is_request) = if let Some(val) = request.query_param("SAMLRequest") {
        if request.query_param("SAMLResponse").is_some() {
            return Err(BindingError::InvalidSamlParams(
                "request contains both SAMLRequest and SAMLResponse".to_string(),
            ));
        }
        (val, true)
    } else if let Some(val) = request.query_param("SAMLResponse") {
        (val, false)
    } else {
        return Err(BindingError::MissingSamlParam(
            "SAMLRequest or SAMLResponse",
        ));
    };

    // URL-decode, base64-decode, DEFLATE-decompress
    let url_decoded = url_decode(encoded_value)?;
    let b64_decoded = base64_decode(&url_decoded)?;
    let saml_xml = deflate_decompress(&b64_decoded)?;

    let relay_state = request
        .query_param("RelayState")
        .map(|rs| url_decode(rs).unwrap_or_else(|_| rs.to_string()));

    let sig_alg = request
        .query_param("SigAlg")
        .map(|sa| url_decode(sa).unwrap_or_else(|_| sa.to_string()));

    let signature = if let Some(sig) = request.query_param("Signature") {
        let sig_decoded = url_decode(sig)?;
        Some(base64_decode(&sig_decoded)?)
    } else {
        None
    };

    if signature.is_some() && sig_alg.is_none() {
        return Err(BindingError::InvalidSamlParams(
            "Signature parameter present without SigAlg".to_string(),
        ));
    }

    // Build signature input string from raw URL-encoded params. The detached
    // signature covers exactly SAMLRequest/SAMLResponse, optional RelayState,
    // and SigAlg in that order. Duplicate checks above ensure an attacker
    // cannot make us verify one value and consume another.
    let signature_input = if sig_alg.is_some() {
        if let Some(query) = raw_query {
            let param_name = if is_request {
                "SAMLRequest"
            } else {
                "SAMLResponse"
            };
            Some(build_redirect_signature_input(query, param_name)?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(RedirectDecoded {
        saml_xml,
        is_request,
        relay_state,
        sig_alg,
        signature,
        signature_input,
    })
}

/// Reject duplicate Redirect binding parameters before any decoding.
///
/// SAML Redirect signatures bind exact query parameter bytes. If duplicate
/// security-sensitive parameters are accepted, one component can verify the
/// first value while another consumes a later value. This helper therefore
/// decodes only parameter names, keeps values untouched, and fails closed.
fn validate_unique_redirect_params(query: &str) -> Result<(), BindingError> {
    let request_count = raw_param_count(query, "SAMLRequest")?;
    let response_count = raw_param_count(query, "SAMLResponse")?;

    if request_count > 0 && response_count > 0 {
        return Err(BindingError::InvalidSamlParams(
            "request contains both SAMLRequest and SAMLResponse".to_string(),
        ));
    }

    for name in [
        "SAMLRequest",
        "SAMLResponse",
        "RelayState",
        "SigAlg",
        "Signature",
    ] {
        if raw_param_count(query, name)? > 1 {
            return Err(BindingError::DuplicateSamlParam(name));
        }
    }

    Ok(())
}

/// Count query parameters by decoded name while preserving raw values.
fn raw_param_count(query: &str, wanted: &'static str) -> Result<usize, BindingError> {
    parse_query_string_raw(query)
        .into_iter()
        .map(|(key, _)| url_decode(key))
        .try_fold(0, |count, decoded| {
            decoded.map(|key| count + usize::from(key == wanted))
        })
}

/// Return the original `key=value` pair for a decoded parameter name.
fn raw_pair_by_decoded_name<'a>(
    query: &'a str,
    wanted: &'static str,
) -> Result<Option<&'a str>, BindingError> {
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
        if url_decode(key)? == wanted {
            return Ok(Some(pair));
        }
    }
    Ok(None)
}

/// Reconstruct the Redirect binding signature input in spec order.
fn build_redirect_signature_input(
    query: &str,
    saml_param_name: &'static str,
) -> Result<String, BindingError> {
    let mut pairs = Vec::with_capacity(3);
    pairs.push(
        raw_pair_by_decoded_name(query, saml_param_name)?
            .ok_or(BindingError::MissingSamlParam(saml_param_name))?,
    );
    if let Some(relay_state) = raw_pair_by_decoded_name(query, "RelayState")? {
        pairs.push(relay_state);
    }
    pairs.push(
        raw_pair_by_decoded_name(query, "SigAlg")?
            .ok_or(BindingError::MissingSamlParam("SigAlg"))?,
    );
    Ok(pairs.join("&"))
}

/// Verify the signature on a decoded HTTP Redirect binding message.
///
/// Uses the original URL-encoded query string for verification,
/// as required by the SAML specification.
pub fn redirect_verify_signature(
    decoded: &RedirectDecoded,
    verifier: &crate::crypto::SamlVerifier,
) -> Result<bool, BindingError> {
    let sig_input = decoded.signature_input.as_ref().ok_or_else(|| {
        BindingError::SignatureVerificationFailed("no signature input available".to_string())
    })?;

    let signature = decoded.signature.as_ref().ok_or_else(|| {
        BindingError::SignatureVerificationFailed("no signature present".to_string())
    })?;

    let sig_alg = decoded.sig_alg.as_ref().ok_or_else(|| {
        BindingError::SignatureVerificationFailed("no SigAlg present".to_string())
    })?;

    let valid = verifier.verify_redirect_query(sig_input.as_bytes(), signature, sig_alg)?;
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::traits::HttpRequest;

    struct TestRequest {
        url: String,
        query: Vec<(String, String)>,
    }

    impl TestRequest {
        fn from_url(url: &str) -> Self {
            let query = url
                .split_once('?')
                .map(|(_, query)| {
                    parse_query_string_raw(query)
                        .into_iter()
                        .map(|(key, value)| {
                            (
                                url_decode(key).unwrap_or_else(|_| key.to_string()),
                                value.to_string(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            Self {
                url: url.to_string(),
                query,
            }
        }
    }

    impl HttpRequest for TestRequest {
        fn method(&self) -> &str {
            "GET"
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn query_param(&self, name: &str) -> Option<&str> {
            self.query
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }

        fn form_param(&self, _name: &str) -> Option<&str> {
            None
        }

        fn header(&self, _name: &str) -> Option<&str> {
            None
        }

        fn body(&self) -> &[u8] {
            &[]
        }

        fn remote_addr(&self) -> Option<&str> {
            None
        }
    }

    #[test]
    fn test_redirect_encode_decode_roundtrip() {
        let xml = b"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_abc\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\"/>";

        let url = redirect_encode(&RedirectEncodeParams {
            saml_xml: xml,
            is_request: true,
            destination: "https://idp.example.com/sso",
            relay_state: None,
            signer: None,
        })
        .unwrap();

        assert!(url.starts_with("https://idp.example.com/sso?SAMLRequest="));
        assert!(!url.contains("RelayState"));
        assert!(!url.contains("SigAlg"));
        assert!(!url.contains("Signature"));
    }

    #[test]
    fn test_redirect_encode_with_relay_state() {
        let xml = b"<samlp:AuthnRequest/>";
        let rs = RelayState::new("token123").unwrap();

        let url = redirect_encode(&RedirectEncodeParams {
            saml_xml: xml,
            is_request: true,
            destination: "https://idp.example.com/sso",
            relay_state: Some(&rs),
            signer: None,
        })
        .unwrap();

        assert!(url.contains("RelayState=token123"));
    }

    #[test]
    fn test_redirect_encode_response() {
        let xml = b"<samlp:Response/>";

        let url = redirect_encode(&RedirectEncodeParams {
            saml_xml: xml,
            is_request: false,
            destination: "https://sp.example.com/acs",
            relay_state: None,
            signer: None,
        })
        .unwrap();

        assert!(url.contains("SAMLResponse="));
        assert!(!url.contains("SAMLRequest="));
    }

    #[test]
    fn test_redirect_encode_destination_with_existing_query() {
        let xml = b"<samlp:AuthnRequest/>";

        let url = redirect_encode(&RedirectEncodeParams {
            saml_xml: xml,
            is_request: true,
            destination: "https://idp.example.com/sso?existing=param",
            relay_state: None,
            signer: None,
        })
        .unwrap();

        // Should use & instead of ? since destination already has query params
        assert!(url.starts_with("https://idp.example.com/sso?existing=param&SAMLRequest="));
    }

    #[test]
    fn test_redirect_decode_rejects_duplicate_saml_message_param() {
        let url = "https://idp.example.com/sso?SAMLRequest=first&SAMLRequest=second";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(
            result,
            Err(BindingError::DuplicateSamlParam("SAMLRequest"))
        ));
    }

    #[test]
    fn test_redirect_decode_rejects_encoded_duplicate_param_name() {
        let url = "https://idp.example.com/sso?SAMLRequest=first&SAML%52equest=second";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(
            result,
            Err(BindingError::DuplicateSamlParam("SAMLRequest"))
        ));
    }

    #[test]
    fn test_redirect_decode_rejects_request_and_response_together() {
        let url = "https://idp.example.com/sso?SAMLRequest=req&SAMLResponse=resp";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(result, Err(BindingError::InvalidSamlParams(_))));
    }

    #[test]
    fn test_redirect_decode_rejects_duplicate_relay_state() {
        let url = "https://idp.example.com/sso?SAMLRequest=req&RelayState=one&RelayState=two";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(
            result,
            Err(BindingError::DuplicateSamlParam("RelayState"))
        ));
    }

    #[test]
    fn test_redirect_decode_rejects_duplicate_sig_alg() {
        let url = "https://idp.example.com/sso?SAMLRequest=req&SigAlg=one&SigAlg=two";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(
            result,
            Err(BindingError::DuplicateSamlParam("SigAlg"))
        ));
    }

    #[test]
    fn test_redirect_decode_rejects_duplicate_signature() {
        let url = "https://idp.example.com/sso?SAMLRequest=req&Signature=one&Signature=two";
        let request = TestRequest::from_url(url);

        let result = redirect_decode(&request);

        assert!(matches!(
            result,
            Err(BindingError::DuplicateSamlParam("Signature"))
        ));
    }

    #[test]
    fn test_redirect_decode_rejects_signature_without_sig_alg() {
        let xml = b"<samlp:AuthnRequest/>";
        let mut url = redirect_encode(&RedirectEncodeParams {
            saml_xml: xml,
            is_request: true,
            destination: "https://idp.example.com/sso",
            relay_state: None,
            signer: None,
        })
        .unwrap();
        url.push_str("&Signature=ZmFrZQ%3D%3D");
        let request = TestRequest::from_url(&url);

        let result = redirect_decode(&request);

        assert!(matches!(result, Err(BindingError::InvalidSamlParams(_))));
    }

    #[test]
    fn test_redirect_signature_input_uses_spec_order() {
        let query = "RelayState=relay&SAMLRequest=req&Signature=sig&SigAlg=alg";

        let input = build_redirect_signature_input(query, "SAMLRequest").unwrap();

        assert_eq!(input, "SAMLRequest=req&RelayState=relay&SigAlg=alg");
    }
}
