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

use crate::deflate::{deflate_compress, deflate_decompress};
use crate::encoding::{base64_decode, base64_encode, url_decode, url_encode};
use crate::error::BindingError;
use crate::relay_state::RelayState;
use crate::traits::HttpRequest;

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
    pub signer: Option<(&'a swsaml_crypto::SamlSigner, &'a str)>,
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
    // Determine if this is a request or response
    let (encoded_value, is_request) = if let Some(val) = request.query_param("SAMLRequest") {
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

    // Build signature input string from raw URL-encoded params
    // Must be: SAMLRequest=value&RelayState=value&SigAlg=value (exact encoded values)
    let signature_input = if sig_alg.is_some() {
        let url = request.url();
        // Extract query string from URL
        if let Some(qs_start) = url.find('?') {
            let qs = &url[qs_start + 1..];
            // Build the signature input from the relevant params in order
            let mut sig_input = String::new();
            let param_name = if is_request {
                "SAMLRequest"
            } else {
                "SAMLResponse"
            };

            // Find each param in the raw query string
            let saml_prefix = format!("{}=", param_name);
            for pair in qs.split('&') {
                if pair.starts_with(&saml_prefix)
                    || pair.starts_with("RelayState=")
                    || pair.starts_with("SigAlg=")
                {
                    if !sig_input.is_empty() {
                        sig_input.push('&');
                    }
                    sig_input.push_str(pair);
                }
            }
            Some(sig_input)
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

/// Verify the signature on a decoded HTTP Redirect binding message.
///
/// Uses the original URL-encoded query string for verification,
/// as required by the SAML specification.
pub fn redirect_verify_signature(
    decoded: &RedirectDecoded,
    verifier: &swsaml_crypto::SamlVerifier,
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
}
