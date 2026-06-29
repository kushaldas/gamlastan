// SAML 2.0 actix-web integration errors.

use actix_web::http::StatusCode;
use actix_web::HttpResponse;

/// Errors produced by the SAML actix-web integration layer.
#[derive(Debug, thiserror::Error)]
pub enum SamlActixError {
    /// Failed to read request body.
    #[error("failed to read request body: {0}")]
    BodyRead(String),

    /// Failed to decode SAML message from binding.
    #[error("binding decode error: {0}")]
    BindingDecode(#[from] gamlastan::bindings::BindingError),

    /// Profile-level error (SSO, SLO, etc.).
    #[error("profile error: {0}")]
    Profile(#[from] gamlastan::profiles::ProfileError),

    /// Security validation error.
    #[error("security error: {0}")]
    Security(#[from] gamlastan::security::error::SecurityError),

    /// Missing or invalid configuration.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// No SAML message found in the request.
    #[error("no SAML message found in request")]
    NoSamlMessage,

    /// Unsupported binding type.
    #[error("unsupported binding: {0}")]
    UnsupportedBinding(String),

    /// XML deserialization error.
    #[error("XML error: {0}")]
    Xml(#[from] gamlastan::xml::error::XmlError),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl actix_web::ResponseError for SamlActixError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyRead(_) => StatusCode::BAD_REQUEST,
            Self::BindingDecode(_) => StatusCode::BAD_REQUEST,
            Self::NoSamlMessage => StatusCode::BAD_REQUEST,
            Self::UnsupportedBinding(_) => StatusCode::BAD_REQUEST,
            Self::Xml(_) => StatusCode::BAD_REQUEST,
            Self::Security(_) => StatusCode::FORBIDDEN,
            Self::Profile(_) => StatusCode::FORBIDDEN,
            Self::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .content_type("text/plain; charset=utf-8")
            .body(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::ResponseError;

    #[test]
    fn test_error_display() {
        let err = SamlActixError::NoSamlMessage;
        assert_eq!(err.to_string(), "no SAML message found in request");
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            SamlActixError::NoSamlMessage.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            SamlActixError::Configuration("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            SamlActixError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // Profile-level errors are request authentication/validation failures
        // (e.g. an AuthnRequest ACS URL not in trusted metadata) and must map to
        // 403, not 500 -- attacker-controlled input must not surface as an
        // internal server error.
        assert_eq!(
            SamlActixError::Profile(gamlastan::profiles::ProfileError::AcsUrlMismatch)
                .status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_error_response() {
        use actix_web::ResponseError;
        let err = SamlActixError::NoSamlMessage;
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
