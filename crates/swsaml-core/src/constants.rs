// SAML 2.0 Constants
//
// Binding URIs, profile URIs, status codes, NameID formats, confirmation methods.
// Corrected per saml-v2.0-errata05.

// ============================================================================
// Binding URIs (saml-bindings-2.0-os Section 3)
// ============================================================================

/// SOAP binding URI
pub const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

/// Reverse SOAP (PAOS) binding URI
pub const BINDING_PAOS: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";

/// HTTP Redirect binding URI
pub const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// HTTP POST binding URI
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// HTTP Artifact binding URI
pub const BINDING_HTTP_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";

/// URI binding URI
pub const BINDING_URI: &str = "urn:oasis:names:tc:SAML:2.0:bindings:URI";

/// DEFLATE encoding URI (used with HTTP Redirect)
pub const ENCODING_DEFLATE: &str = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";

// ============================================================================
// Subject Confirmation Method URIs (saml-core-2.0-os Section 3)
// ============================================================================

/// Bearer confirmation method
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Holder-of-key confirmation method
pub const CM_HOLDER_OF_KEY: &str = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

/// Sender-vouches confirmation method
pub const CM_SENDER_VOUCHES: &str = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

// ============================================================================
// NameID Format URIs (corrected per Errata E60, E84)
// ============================================================================

/// Unspecified name identifier format (SAML 1.1 namespace per E60)
pub const NAMEID_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// Email address name identifier format (SAML 1.1 namespace per E60)
pub const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// X.509 subject name identifier format (SAML 1.1 namespace per E60)
pub const NAMEID_X509: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

/// Windows domain qualified name identifier format (SAML 1.1 namespace per E60)
pub const NAMEID_WINDOWS: &str =
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";

/// Entity name identifier format (SAML 2.0 namespace)
pub const NAMEID_ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// Persistent name identifier format (SAML 2.0 namespace)
pub const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/// Transient name identifier format (SAML 2.0 namespace)
pub const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

/// Kerberos principal name identifier format (SAML 2.0 namespace)
pub const NAMEID_KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";

/// Encrypted name identifier format (SAML 2.0 namespace)
pub const NAMEID_ENCRYPTED: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";

// ============================================================================
// Status Code URIs (saml-core-2.0-os Section 3.2.2.2)
// ============================================================================

// --- Top-level status codes ---

/// Success status
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// Requester error status
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";

/// Responder error status
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";

/// Version mismatch status
pub const STATUS_VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

// --- Second-level status codes (optional per E65) ---

/// Authentication failed
pub const STATUS_AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

/// Invalid attribute name or value
pub const STATUS_INVALID_ATTR_NAME_OR_VALUE: &str =
    "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";

/// Invalid NameID policy
pub const STATUS_INVALID_NAMEID_POLICY: &str =
    "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";

/// No authentication context
pub const STATUS_NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";

/// No available identity provider
pub const STATUS_NO_AVAILABLE_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP";

/// No passive authentication
pub const STATUS_NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

/// No supported identity provider
pub const STATUS_NO_SUPPORTED_IDP: &str = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP";

/// Partial logout
pub const STATUS_PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";

/// Proxy count exceeded
pub const STATUS_PROXY_COUNT_EXCEEDED: &str =
    "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded";

/// Request denied
pub const STATUS_REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";

/// Request unsupported
pub const STATUS_REQUEST_UNSUPPORTED: &str =
    "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported";

/// Request version deprecated
pub const STATUS_REQUEST_VERSION_DEPRECATED: &str =
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated";

/// Request version too high
pub const STATUS_REQUEST_VERSION_TOO_HIGH: &str =
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh";

/// Request version too low
pub const STATUS_REQUEST_VERSION_TOO_LOW: &str =
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow";

/// Resource not recognized
pub const STATUS_RESOURCE_NOT_RECOGNIZED: &str =
    "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized";

/// Too many responses
pub const STATUS_TOO_MANY_RESPONSES: &str = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses";

/// Unknown attribute profile
pub const STATUS_UNKNOWN_ATTR_PROFILE: &str =
    "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile";

/// Unknown principal
pub const STATUS_UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

/// Unsupported binding
pub const STATUS_UNSUPPORTED_BINDING: &str =
    "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";

// ============================================================================
// Authentication Context Class URIs (saml-authn-context-2.0-os)
// ============================================================================

/// Internet Protocol authentication context
pub const AUTHN_CONTEXT_INTERNET_PROTOCOL: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol";

/// Internet Protocol Password authentication context
pub const AUTHN_CONTEXT_IP_PASSWORD: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword";

/// Kerberos authentication context
pub const AUTHN_CONTEXT_KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";

/// Password authentication context
pub const AUTHN_CONTEXT_PASSWORD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

/// Password-protected transport authentication context
pub const AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

/// Previous session authentication context
pub const AUTHN_CONTEXT_PREVIOUS_SESSION: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";

/// X.509 public key authentication context
pub const AUTHN_CONTEXT_X509: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";

/// Unspecified authentication context
pub const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

// ============================================================================
// Consent URIs (saml-core-2.0-os Section 8.4)
// ============================================================================

/// Unspecified consent
pub const CONSENT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:consent:unspecified";

/// Consent obtained
pub const CONSENT_OBTAINED: &str = "urn:oasis:names:tc:SAML:2.0:consent:obtained";

/// Prior consent
pub const CONSENT_PRIOR: &str = "urn:oasis:names:tc:SAML:2.0:consent:prior";

/// Implicit consent (current interaction)
pub const CONSENT_IMPLICIT: &str = "urn:oasis:names:tc:SAML:2.0:consent:current-implicit";

/// Explicit consent (current interaction)
pub const CONSENT_EXPLICIT: &str = "urn:oasis:names:tc:SAML:2.0:consent:current-explicit";

/// Unavailable consent
pub const CONSENT_UNAVAILABLE: &str = "urn:oasis:names:tc:SAML:2.0:consent:unavailable";

/// Inapplicable consent
pub const CONSENT_INAPPLICABLE: &str = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable";

// ============================================================================
// Attribute Name Format URIs (saml-core-2.0-os Section 8.3)
// ============================================================================

/// Unspecified attribute name format
pub const ATTRNAME_FORMAT_UNSPECIFIED: &str =
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// URI attribute name format
pub const ATTRNAME_FORMAT_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/// Basic attribute name format
pub const ATTRNAME_FORMAT_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

// ============================================================================
// Logout Reason URIs (E10: must be URIs)
// ============================================================================

/// User-initiated logout
pub const LOGOUT_REASON_USER: &str = "urn:oasis:names:tc:SAML:2.0:logout:user";

/// Admin-initiated logout
pub const LOGOUT_REASON_ADMIN: &str = "urn:oasis:names:tc:SAML:2.0:logout:admin";

// ============================================================================
// MIME types
// ============================================================================

/// SAML metadata MIME type
pub const MIME_SAML_METADATA: &str = "application/samlmetadata+xml";

/// SAML assertion MIME type (for URI binding)
pub const MIME_SAML_ASSERTION: &str = "application/samlassertion+xml";

// ============================================================================
// SOAP constants
// ============================================================================

/// SOAPAction header value for SAML
pub const SOAP_ACTION_SAML: &str = "http://www.oasis-open.org/committees/security";

/// SOAP Content-Type
pub const SOAP_CONTENT_TYPE: &str = "text/xml";

// ============================================================================
// HTTP Cache-Control headers
// ============================================================================

/// Standard cache-control header for SAML bindings
pub const CACHE_CONTROL_VALUE: &str = "no-cache, no-store";

/// Pragma header for SAML bindings
pub const PRAGMA_VALUE: &str = "no-cache";

/// Extended cache-control for SOAP responders
pub const CACHE_CONTROL_SOAP: &str = "no-cache, no-store, must-revalidate, private";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_uris_start_with_urn() {
        assert!(BINDING_SOAP.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
        assert!(BINDING_PAOS.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
        assert!(BINDING_HTTP_REDIRECT.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
        assert!(BINDING_HTTP_POST.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
        assert!(BINDING_HTTP_ARTIFACT.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
        assert!(BINDING_URI.starts_with("urn:oasis:names:tc:SAML:2.0:bindings:"));
    }

    #[test]
    fn test_confirmation_methods_start_with_urn() {
        assert!(CM_BEARER.starts_with("urn:oasis:names:tc:SAML:2.0:cm:"));
        assert!(CM_HOLDER_OF_KEY.starts_with("urn:oasis:names:tc:SAML:2.0:cm:"));
        assert!(CM_SENDER_VOUCHES.starts_with("urn:oasis:names:tc:SAML:2.0:cm:"));
    }

    #[test]
    fn test_nameid_format_v11_uris() {
        // Per E60/E84: unspecified, email, x509, windows use SAML:1.1 namespace
        assert!(NAMEID_UNSPECIFIED.contains("SAML:1.1"));
        assert!(NAMEID_EMAIL.contains("SAML:1.1"));
        assert!(NAMEID_X509.contains("SAML:1.1"));
        assert!(NAMEID_WINDOWS.contains("SAML:1.1"));
    }

    #[test]
    fn test_nameid_format_v20_uris() {
        // SAML 2.0 namespace formats
        assert!(NAMEID_ENTITY.contains("SAML:2.0"));
        assert!(NAMEID_PERSISTENT.contains("SAML:2.0"));
        assert!(NAMEID_TRANSIENT.contains("SAML:2.0"));
        assert!(NAMEID_KERBEROS.contains("SAML:2.0"));
        assert!(NAMEID_ENCRYPTED.contains("SAML:2.0"));
    }

    #[test]
    fn test_top_level_status_codes() {
        assert!(STATUS_SUCCESS.ends_with("Success"));
        assert!(STATUS_REQUESTER.ends_with("Requester"));
        assert!(STATUS_RESPONDER.ends_with("Responder"));
        assert!(STATUS_VERSION_MISMATCH.ends_with("VersionMismatch"));
    }

    #[test]
    fn test_all_status_codes_are_urns() {
        let codes = [
            STATUS_SUCCESS,
            STATUS_REQUESTER,
            STATUS_RESPONDER,
            STATUS_VERSION_MISMATCH,
            STATUS_AUTHN_FAILED,
            STATUS_INVALID_ATTR_NAME_OR_VALUE,
            STATUS_INVALID_NAMEID_POLICY,
            STATUS_NO_AUTHN_CONTEXT,
            STATUS_NO_AVAILABLE_IDP,
            STATUS_NO_PASSIVE,
            STATUS_NO_SUPPORTED_IDP,
            STATUS_PARTIAL_LOGOUT,
            STATUS_PROXY_COUNT_EXCEEDED,
            STATUS_REQUEST_DENIED,
            STATUS_REQUEST_UNSUPPORTED,
            STATUS_REQUEST_VERSION_DEPRECATED,
            STATUS_REQUEST_VERSION_TOO_HIGH,
            STATUS_REQUEST_VERSION_TOO_LOW,
            STATUS_RESOURCE_NOT_RECOGNIZED,
            STATUS_TOO_MANY_RESPONSES,
            STATUS_UNKNOWN_ATTR_PROFILE,
            STATUS_UNKNOWN_PRINCIPAL,
            STATUS_UNSUPPORTED_BINDING,
        ];
        for code in &codes {
            assert!(
                code.starts_with("urn:oasis:names:tc:SAML:2.0:status:"),
                "Bad status code: {}",
                code
            );
        }
    }
}
