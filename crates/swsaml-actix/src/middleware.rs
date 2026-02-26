// Optional SAML authentication middleware for actix-web.
//
// This middleware checks if the user has an active SAML session before
// allowing requests through to protected routes. If no valid session
// is found, it redirects the user to the SAML login endpoint.
//
// Session state is stored via actix-web's `HttpRequest::extensions()`.

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{HttpMessage, HttpResponse};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;

/// SAML session data stored in request extensions.
///
/// Downstream handlers can access this via `req.extensions().get::<SamlSession>()`.
#[derive(Debug, Clone)]
pub struct SamlSession {
    /// The user's NameID value from the SAML assertion.
    pub name_id: String,
    /// The NameID format (e.g., email, persistent).
    pub name_id_format: Option<String>,
    /// Session index from the IdP (used for Single Logout).
    pub session_index: Option<String>,
    /// When the session expires (ISO 8601 string).
    pub session_not_on_or_after: Option<String>,
    /// Additional user attributes from the assertion.
    pub attributes: Vec<(String, Vec<String>)>,
}

/// Session lookup function type.
///
/// Given a request, returns `Some(SamlSession)` if the user has a valid session,
/// or `None` to trigger a redirect to the login endpoint.
pub type SessionLookup =
    dyn Fn(&ServiceRequest) -> Option<SamlSession> + Send + Sync + 'static;

/// SAML authentication middleware factory.
///
/// Wraps actix-web services to enforce SAML authentication. Requests without
/// a valid session are redirected to the login URL.
///
/// # Example
///
/// ```rust,no_run
/// use actix_web::{web, App, HttpServer, HttpMessage};
/// use swsaml_actix::middleware::{SamlAuth, SamlSession};
///
/// let auth = SamlAuth::new(
///     "/saml/login",
///     Box::new(|req| {
///         // Check your session store (cookie, DB, etc.)
///         req.extensions().get::<SamlSession>().cloned()
///     }),
/// );
///
/// // Apply to protected routes:
/// // App::new().service(
/// //     web::scope("/protected").wrap(auth).route("/", web::get().to(handler))
/// // )
/// ```
pub struct SamlAuth {
    login_url: Rc<str>,
    session_lookup: Rc<SessionLookup>,
}

impl SamlAuth {
    /// Create a new SAML auth middleware.
    ///
    /// - `login_url`: URL to redirect to when no session is found (e.g., "/saml/login")
    /// - `session_lookup`: function to check for an existing SAML session
    pub fn new(login_url: &str, session_lookup: Box<SessionLookup>) -> Self {
        Self {
            login_url: Rc::from(login_url),
            session_lookup: Rc::from(session_lookup),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SamlAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = SamlAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SamlAuthMiddleware {
            service: Rc::new(service),
            login_url: self.login_url.clone(),
            session_lookup: self.session_lookup.clone(),
        }))
    }
}

/// The actual middleware service.
pub struct SamlAuthMiddleware<S> {
    service: Rc<S>,
    login_url: Rc<str>,
    session_lookup: Rc<SessionLookup>,
}

impl<S, B> Service<ServiceRequest> for SamlAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let login_url = self.login_url.clone();
        let session_lookup = self.session_lookup.clone();

        Box::pin(async move {
            // Check if user has a valid SAML session
            if let Some(session) = session_lookup(&req) {
                // Insert session into request extensions for downstream handlers
                req.extensions_mut().insert(session);

                // Proceed to the wrapped service
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            } else {
                // No session: redirect to login with RelayState = original URL
                let original_url = req.uri().to_string();
                let redirect_url = if login_url.contains('?') {
                    format!("{login_url}&RelayState={}", urlencoded(&original_url))
                } else {
                    format!("{login_url}?RelayState={}", urlencoded(&original_url))
                };

                let response = HttpResponse::Found()
                    .insert_header(("Location", redirect_url))
                    .finish();

                Ok(req.into_response(response).map_into_right_body())
            }
        })
    }
}

/// Simple percent-encoding for the redirect URL.
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push(char::from(HEX_CHARS[(b >> 4) as usize]));
                result.push(char::from(HEX_CHARS[(b & 0x0f) as usize]));
            }
        }
    }
    result
}

const HEX_CHARS: [u8; 16] = *b"0123456789ABCDEF";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencoded() {
        assert_eq!(urlencoded("hello"), "hello");
        assert_eq!(urlencoded("/protected/page"), "%2Fprotected%2Fpage");
        assert_eq!(
            urlencoded("https://example.com/path?q=1"),
            "https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1"
        );
    }

    #[test]
    fn test_saml_session_debug() {
        let session = SamlSession {
            name_id: "user@example.com".to_string(),
            name_id_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()),
            session_index: Some("_session_123".to_string()),
            session_not_on_or_after: None,
            attributes: vec![
                ("email".to_string(), vec!["user@example.com".to_string()]),
            ],
        };
        let debug = format!("{session:?}");
        assert!(debug.contains("user@example.com"));
        assert!(debug.contains("_session_123"));
    }

    #[test]
    fn test_saml_session_clone() {
        let session = SamlSession {
            name_id: "user@example.com".to_string(),
            name_id_format: None,
            session_index: None,
            session_not_on_or_after: None,
            attributes: vec![],
        };
        let cloned = session.clone();
        assert_eq!(session.name_id, cloned.name_id);
    }
}
