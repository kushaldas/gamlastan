// Adapt gamlastan::bindings HttpResponseBuilder to produce actix-web HttpResponse.
//
// Implements the HttpResponseBuilder trait so SAML binding functions
// can produce actix_web::HttpResponse values directly.

use actix_web::http::header;
use actix_web::HttpResponse;
use gamlastan::bindings::HttpResponseBuilder;

/// Actix-web response builder implementing `gamlastan::bindings::HttpResponseBuilder`.
///
/// All methods are stateless constructors producing `actix_web::HttpResponse`.
pub struct ActixResponseBuilder;

impl HttpResponseBuilder for ActixResponseBuilder {
    type Response = HttpResponse;

    fn redirect(url: &str, status: u16) -> HttpResponse {
        let status_code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::FOUND);
        HttpResponse::build(status_code)
            .insert_header((header::LOCATION, url))
            .insert_header((header::CACHE_CONTROL, "no-cache, no-store"))
            .insert_header((header::PRAGMA, "no-cache"))
            .finish()
    }

    fn html(body: &str, headers: Vec<(&str, &str)>) -> HttpResponse {
        let mut builder = HttpResponse::Ok();
        builder.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
        for (name, value) in headers {
            builder.insert_header((
                actix_web::http::header::HeaderName::try_from(name)
                    .unwrap_or(header::CACHE_CONTROL),
                value,
            ));
        }
        builder.body(body.to_string())
    }

    fn soap_response(body: &[u8], headers: Vec<(&str, &str)>) -> HttpResponse {
        let mut builder = HttpResponse::Ok();
        builder.insert_header((header::CONTENT_TYPE, "text/xml; charset=utf-8"));
        for (name, value) in headers {
            builder.insert_header((
                actix_web::http::header::HeaderName::try_from(name)
                    .unwrap_or(header::CACHE_CONTROL),
                value,
            ));
        }
        builder.body(body.to_vec())
    }

    fn error(status: u16) -> HttpResponse {
        let status_code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
        HttpResponse::build(status_code).finish()
    }
}

/// Create an XML metadata response (Content-Type: application/samlmetadata+xml).
pub fn metadata_response(xml: &str) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        ))
        .insert_header((header::CACHE_CONTROL, "public, max-age=3600"))
        .body(xml.to_string())
}

/// Create a SAML POST binding response (XHTML auto-submit form).
pub fn post_binding_response(html_form: &str) -> HttpResponse {
    ActixResponseBuilder::html(
        html_form,
        vec![
            ("Cache-Control", "no-cache, no-store"),
            ("Pragma", "no-cache"),
        ],
    )
}

/// Create a redirect binding response.
pub fn redirect_binding_response(url: &str) -> HttpResponse {
    ActixResponseBuilder::redirect(url, 302)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_response() {
        let resp =
            ActixResponseBuilder::redirect("https://idp.example.com/sso?SAMLRequest=abc", 302);
        assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);
        assert!(resp.headers().contains_key("location"));
    }

    #[test]
    fn test_redirect_303() {
        let resp = ActixResponseBuilder::redirect("https://example.com/slo", 303);
        assert_eq!(resp.status(), actix_web::http::StatusCode::SEE_OTHER);
    }

    #[test]
    fn test_html_response() {
        let resp = ActixResponseBuilder::html(
            "<html><body>test</body></html>",
            vec![("Cache-Control", "no-cache")],
        );
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_soap_response() {
        let resp = ActixResponseBuilder::soap_response(b"<soap:Envelope/>", vec![]);
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_error_response() {
        let resp = ActixResponseBuilder::error(400);
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_metadata_response() {
        let resp = metadata_response("<md:EntityDescriptor/>");
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_post_binding_response() {
        let resp = post_binding_response("<html><body><form>...</form></body></html>");
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_redirect_binding_response() {
        let resp = redirect_binding_response("https://idp.example.com/sso?SAMLRequest=abc");
        assert_eq!(resp.status(), actix_web::http::StatusCode::FOUND);
    }
}
