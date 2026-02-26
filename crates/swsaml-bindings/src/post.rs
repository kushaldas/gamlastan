// HTTP POST Binding (SAML Bindings Section 3.5).
//
// Encoding:
// - Base64-encode the full XML message (may include signature)
// - Place in hidden form field: <input type="hidden" name="SAMLRequest" value="...">
// - Generate XHTML 1.0 document with onload auto-submit + noscript fallback
// - Optional RelayState hidden field (max 80 bytes)
// - Form action = endpoint URL, method = POST
// - Destination attribute validation when signed

use crate::encoding::{base64_decode, base64_encode};
use crate::error::BindingError;
use crate::relay_state::RelayState;
use crate::traits::HttpRequest;

/// A decoded message from the HTTP POST binding.
#[derive(Debug)]
pub struct PostDecoded {
    /// The SAML XML message (base64-decoded).
    pub saml_xml: Vec<u8>,
    /// Whether the parameter was SAMLRequest (true) or SAMLResponse (false).
    pub is_request: bool,
    /// RelayState, if present.
    pub relay_state: Option<String>,
}

/// Encode a SAML message for the HTTP POST binding.
///
/// Returns a complete XHTML 1.0 Strict document with auto-submit JavaScript
/// and a `<noscript>` fallback button.
pub fn post_encode(
    saml_xml: &[u8],
    is_request: bool,
    destination: &str,
    relay_state: Option<&RelayState>,
) -> String {
    let b64 = base64_encode(saml_xml);
    let param_name = if is_request {
        "SAMLRequest"
    } else {
        "SAMLResponse"
    };

    // HTML-escape the destination URL for the form action
    let escaped_dest = html_escape(destination);
    // The base64 value is safe for HTML attribute values (A-Z, a-z, 0-9, +, /, =)
    // but we escape it anyway for correctness
    let escaped_b64 = html_escape(&b64);

    let mut html = String::with_capacity(1024 + b64.len());

    html.push_str(
        r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>SAML POST Binding</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below to continue.</p>
</noscript>
<form method="post" action=""#,
    );
    html.push_str(&escaped_dest);
    html.push_str("\">\n");

    // Hidden field for SAML message
    html.push_str("<input type=\"hidden\" name=\"");
    html.push_str(param_name);
    html.push_str("\" value=\"");
    html.push_str(&escaped_b64);
    html.push_str("\" />\n");

    // Hidden field for RelayState
    if let Some(rs) = relay_state {
        html.push_str("<input type=\"hidden\" name=\"RelayState\" value=\"");
        html.push_str(&html_escape(rs.as_str()));
        html.push_str("\" />\n");
    }

    html.push_str("<noscript><input type=\"submit\" value=\"Continue\" /></noscript>\n");
    html.push_str("</form>\n</body>\n</html>");

    html
}

/// Decode a SAML message from an HTTP POST binding request.
///
/// Extracts the base64-encoded SAMLRequest or SAMLResponse from the form body.
pub fn post_decode(request: &impl HttpRequest) -> Result<PostDecoded, BindingError> {
    let (encoded_value, is_request) = if let Some(val) = request.form_param("SAMLRequest") {
        (val, true)
    } else if let Some(val) = request.form_param("SAMLResponse") {
        (val, false)
    } else {
        return Err(BindingError::MissingSamlParam(
            "SAMLRequest or SAMLResponse",
        ));
    };

    let saml_xml = base64_decode(encoded_value)?;

    let relay_state = request.form_param("RelayState").map(|s| s.to_string());

    Ok(PostDecoded {
        saml_xml,
        is_request,
        relay_state,
    })
}

/// HTML-escape a string for safe inclusion in HTML attribute values.
fn html_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_encode_request() {
        let xml = b"<samlp:AuthnRequest/>";
        let html = post_encode(xml, true, "https://idp.example.com/sso", None);

        assert!(html.contains("SAMLRequest"));
        assert!(html.contains("https://idp.example.com/sso"));
        assert!(html.contains("document.forms[0].submit()"));
        assert!(html.contains("<noscript>"));
        assert!(!html.contains("RelayState"));
    }

    #[test]
    fn test_post_encode_response_with_relay_state() {
        let xml = b"<samlp:Response/>";
        let rs = RelayState::new("token123").unwrap();
        let html = post_encode(xml, false, "https://sp.example.com/acs", Some(&rs));

        assert!(html.contains("SAMLResponse"));
        assert!(html.contains("RelayState"));
        assert!(html.contains("token123"));
    }

    #[test]
    fn test_post_encode_html_escape_destination() {
        let xml = b"<samlp:AuthnRequest/>";
        let html = post_encode(xml, true, "https://idp.example.com/sso?a=1&b=2", None);

        // & should be escaped in HTML
        assert!(html.contains("https://idp.example.com/sso?a=1&amp;b=2"));
    }

    #[test]
    fn test_post_encode_xhtml_strict_doctype() {
        let xml = b"<samlp:AuthnRequest/>";
        let html = post_encode(xml, true, "https://idp.example.com/sso", None);

        assert!(html.contains("XHTML 1.0 Strict"));
        assert!(html.contains("xmlns=\"http://www.w3.org/1999/xhtml\""));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("a\"b'c"), "a&quot;b&#x27;c");
    }
}
