// SAML response types that implement actix-web's Responder trait.
//
// These allow handler functions to return SAML protocol messages directly,
// with the library handling XML serialization and binding encoding.

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, Responder};

use swsaml_xml::serialize::SamlSerialize;

/// A SAML metadata XML response.
///
/// Wraps a serialized EntityDescriptor and returns it with the
/// `application/samlmetadata+xml` content type.
pub struct MetadataXml(pub String);

impl Responder for MetadataXml {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                "application/samlmetadata+xml; charset=utf-8",
            ))
            .insert_header((header::CACHE_CONTROL, "public, max-age=3600"))
            .body(self.0)
    }
}

/// A SAML POST binding response (auto-submit XHTML form).
///
/// The inner string is the complete XHTML document with the form.
pub struct PostBindingHtml(pub String);

impl Responder for PostBindingHtml {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .insert_header((header::CACHE_CONTROL, "no-cache, no-store"))
            .insert_header((header::PRAGMA, "no-cache"))
            .body(self.0)
    }
}

/// A SAML Redirect binding response (302 redirect with SAML query params).
pub struct RedirectBindingUrl(pub String);

impl Responder for RedirectBindingUrl {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Found()
            .insert_header((header::LOCATION, self.0.as_str()))
            .insert_header((header::CACHE_CONTROL, "no-cache, no-store"))
            .insert_header((header::PRAGMA, "no-cache"))
            .finish()
    }
}

/// A SOAP binding response (text/xml).
pub struct SoapXml(pub Vec<u8>);

impl Responder for SoapXml {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "text/xml; charset=utf-8"))
            .body(self.0)
    }
}

/// A generic SAML protocol message that can be serialized to XML.
///
/// Use this to return any SAML message type that implements `SamlSerialize`.
pub struct SamlXml<T: SamlSerialize>(pub T);

impl<T: SamlSerialize> Responder for SamlXml<T> {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        match self.0.to_xml_string() {
            Ok(xml) => HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "application/xml; charset=utf-8"))
                .body(xml),
            Err(e) => {
                HttpResponse::InternalServerError().body(format!("XML serialization error: {e}"))
            }
        }
    }
}

/// Helper to serialize a SAML message and wrap it in a SOAP envelope for response.
pub fn soap_wrap_response(saml_xml: &str) -> SoapXml {
    let envelope = swsaml_bindings::soap::soap_envelope_wrap(saml_xml, None);
    SoapXml(envelope.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_xml_responder() {
        let resp = MetadataXml("<md:EntityDescriptor/>".to_string());
        let http_req = actix_web::test::TestRequest::default().to_http_request();
        let http_resp = resp.respond_to(&http_req);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_post_binding_html_responder() {
        let resp = PostBindingHtml("<html><body>form</body></html>".to_string());
        let http_req = actix_web::test::TestRequest::default().to_http_request();
        let http_resp = resp.respond_to(&http_req);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_redirect_binding_url_responder() {
        let resp = RedirectBindingUrl("https://idp.example.com/sso?SAMLRequest=abc".to_string());
        let http_req = actix_web::test::TestRequest::default().to_http_request();
        let http_resp = resp.respond_to(&http_req);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::FOUND);
    }

    #[test]
    fn test_soap_xml_responder() {
        let resp = SoapXml(b"<soap:Envelope/>".to_vec());
        let http_req = actix_web::test::TestRequest::default().to_http_request();
        let http_resp = resp.respond_to(&http_req);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_soap_wrap_response() {
        let resp = soap_wrap_response("<samlp:Response/>");
        assert!(!resp.0.is_empty());
        let xml = String::from_utf8(resp.0).unwrap();
        assert!(xml.contains("soap:Envelope"));
        assert!(xml.contains("<samlp:Response/>"));
    }
}
