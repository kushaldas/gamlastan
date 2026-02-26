// HTTP caching header generation for SAML bindings.
//
// Per SAML Bindings spec:
// - All bindings: Cache-Control: no-cache, no-store + Pragma: no-cache
// - SOAP responders additionally: must-revalidate, private
// - No Last-Modified or ETag headers

use crate::core::constants::{CACHE_CONTROL_SOAP, CACHE_CONTROL_VALUE, PRAGMA_VALUE};

/// Cache-control headers for standard SAML bindings (Redirect, POST, Artifact).
///
/// Returns header pairs: `[("Cache-Control", "no-cache, no-store"), ("Pragma", "no-cache")]`
pub fn saml_cache_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Cache-Control", CACHE_CONTROL_VALUE),
        ("Pragma", PRAGMA_VALUE),
    ]
}

/// Cache-control headers for SOAP responses.
///
/// Returns header pairs with the extended SOAP cache-control values.
pub fn soap_cache_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Cache-Control", CACHE_CONTROL_SOAP),
        ("Pragma", PRAGMA_VALUE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_cache_headers() {
        let headers = saml_cache_headers();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("Cache-Control", "no-cache, no-store"));
        assert_eq!(headers[1], ("Pragma", "no-cache"));
    }

    #[test]
    fn test_soap_cache_headers() {
        let headers = soap_cache_headers();
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            (
                "Cache-Control",
                "no-cache, no-store, must-revalidate, private"
            )
        );
        assert_eq!(headers[1], ("Pragma", "no-cache"));
    }
}
