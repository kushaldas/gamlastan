// SignMessage [SC.DSS.Ext] and SADRequest [SC.SAP] AuthnRequest extensions,
// used for "Authentication for Signature" (section 7).

use crate::bindings::encoding::base64_encode;
use crate::xml::XmlWriter;

use super::constants;

/// The MIME type of a sign message (section 7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMessageMimeType {
    /// Plain text (`text`).
    Text,
    /// HTML (`text/html`).
    Html,
    /// Markdown (`text/markdown`).
    Markdown,
}

impl SignMessageMimeType {
    /// The MIME type string used in the `MimeType` attribute.
    pub fn as_str(self) -> &'static str {
        match self {
            SignMessageMimeType::Text => "text",
            SignMessageMimeType::Html => "text/html",
            SignMessageMimeType::Markdown => "text/markdown",
        }
    }
}

/// A `<csig:SignMessage>` element to be carried in the `<saml2p:Extensions>` of
/// an `AuthnRequest` from a Signature Service (section 7.1.1).
///
/// Identity Providers compliant with the profile MUST be able to parse this
/// extension and, when `must_show` is set, MUST fail with an error if the
/// message cannot be displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessage {
    /// The `DisplayEntity` — the entityID of the IdP expected to display the
    /// message.
    pub display_entity: Option<String>,
    /// The MIME type of the message.
    pub mime_type: Option<SignMessageMimeType>,
    /// Whether the message MUST be displayed (`MustShow`).
    pub must_show: bool,
    /// The Base64-encoded message content (the body of `<csig:Message>`).
    ///
    /// Per the schema, the message is always Base64-encoded. When the message is
    /// encrypted the body is a `<xenc:EncryptedData>` element instead — see
    /// [`SignMessage::encrypted`].
    pub message_base64: String,
    /// Whether `message_base64` holds an encrypted message
    /// (`<csig:EncryptedMessage>` rather than `<csig:Message>`).
    pub encrypted: bool,
}

impl SignMessage {
    /// Build a cleartext sign message from a UTF-8 string, Base64-encoding it.
    pub fn cleartext(
        message: &str,
        mime_type: SignMessageMimeType,
        must_show: bool,
        display_entity: Option<String>,
    ) -> Self {
        SignMessage {
            display_entity,
            mime_type: Some(mime_type),
            must_show,
            message_base64: base64_encode(message.as_bytes()),
            encrypted: false,
        }
    }

    /// Serialize the `<csig:SignMessage>` element (namespace-qualified).
    pub fn to_xml_string(&self) -> String {
        let mut w = XmlWriter::new();
        let mut attrs: Vec<(&str, &str)> = vec![("xmlns:csig", constants::NS_DSS_EXT)];
        if let Some(de) = &self.display_entity {
            attrs.push(("DisplayEntity", de.as_str()));
        }
        if let Some(mt) = self.mime_type {
            attrs.push(("MimeType", mt.as_str()));
        }
        if self.must_show {
            attrs.push(("MustShow", "true"));
        }
        w.start_element("csig:SignMessage", &attrs);
        let elem = if self.encrypted {
            "csig:EncryptedMessage"
        } else {
            "csig:Message"
        };
        w.start_element(elem, &[]);
        if self.encrypted {
            // The body is a raw `<xenc:EncryptedData>` element; emit it verbatim.
            // Escaping it would turn the element into inert text and corrupt the
            // message.
            w.raw(&self.message_base64);
        } else {
            // Base64 content is XML-safe, but text() escapes defensively.
            w.text(&self.message_base64);
        }
        w.end_element(elem);
        w.end_element("csig:SignMessage");
        w.into_string()
    }
}

/// A `<sap:SADRequest>` element requesting Signature Activation Data for SCAL2
/// (section 7.1.2). MUST be accompanied by a [`SignMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SadRequest {
    /// The unique ID of this SAD request.
    pub id: String,
    /// The entityID of the Signature Requestor.
    pub requester_id: String,
    /// The ID of the `<SignRequest>` that triggered this authentication.
    pub sign_request_id: String,
    /// The number of documents to be signed.
    pub doc_count: u32,
    /// The requested SAP version (e.g. `1.0`).
    pub requested_version: String,
}

impl SadRequest {
    /// Create a SAD request with `RequestedVersion` defaulting to `1.0`.
    pub fn new(
        id: impl Into<String>,
        requester_id: impl Into<String>,
        sign_request_id: impl Into<String>,
        doc_count: u32,
    ) -> Self {
        SadRequest {
            id: id.into(),
            requester_id: requester_id.into(),
            sign_request_id: sign_request_id.into(),
            doc_count,
            requested_version: "1.0".to_string(),
        }
    }

    /// Serialize the `<sap:SADRequest>` element (namespace-qualified).
    pub fn to_xml_string(&self) -> String {
        let mut w = XmlWriter::new();
        w.start_element(
            "sap:SADRequest",
            &[("xmlns:sap", constants::NS_SAP), ("ID", &self.id)],
        );
        w.start_element("sap:RequesterID", &[]);
        w.text(&self.requester_id);
        w.end_element("sap:RequesterID");
        w.start_element("sap:SignRequestID", &[]);
        w.text(&self.sign_request_id);
        w.end_element("sap:SignRequestID");
        w.start_element("sap:DocCount", &[]);
        w.text(&self.doc_count.to_string());
        w.end_element("sap:DocCount");
        w.start_element("sap:RequestedVersion", &[]);
        w.text(&self.requested_version);
        w.end_element("sap:RequestedVersion");
        w.end_element("sap:SADRequest");
        w.into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::encoding::base64_decode;

    #[test]
    fn test_sign_message_cleartext() {
        let sm = SignMessage::cleartext(
            "Sign this contract",
            SignMessageMimeType::Text,
            true,
            Some("https://idp.example.se".to_string()),
        );
        let xml = sm.to_xml_string();
        assert!(xml.contains("csig:SignMessage"));
        assert!(xml.contains(constants::NS_DSS_EXT));
        assert!(xml.contains("DisplayEntity=\"https://idp.example.se\""));
        assert!(xml.contains("MimeType=\"text\""));
        assert!(xml.contains("MustShow=\"true\""));
        assert!(xml.contains("<csig:Message>"));
        // Body is Base64 of the original message.
        let decoded = base64_decode(&sm.message_base64).unwrap();
        assert_eq!(decoded, b"Sign this contract");
    }

    #[test]
    fn test_sign_message_no_must_show() {
        let sm = SignMessage::cleartext("hi", SignMessageMimeType::Html, false, None);
        let xml = sm.to_xml_string();
        assert!(!xml.contains("MustShow"));
        assert!(!xml.contains("DisplayEntity"));
        assert!(xml.contains("MimeType=\"text/html\""));
    }

    #[test]
    fn test_sign_message_encrypted_body_not_escaped() {
        // An encrypted body is a raw <xenc:EncryptedData> element and must be
        // emitted verbatim, not escaped into inert text.
        let sm = SignMessage {
            display_entity: None,
            mime_type: Some(SignMessageMimeType::Text),
            must_show: true,
            message_base64: "<xenc:EncryptedData>cipher</xenc:EncryptedData>".to_string(),
            encrypted: true,
        };
        let xml = sm.to_xml_string();
        assert!(xml.contains("<csig:EncryptedMessage><xenc:EncryptedData>cipher</xenc:EncryptedData></csig:EncryptedMessage>"));
        assert!(!xml.contains("&lt;xenc:EncryptedData"));
    }

    #[test]
    fn test_sad_request() {
        let sad = SadRequest::new("_sad1", "https://sp.example.se", "_signreq1", 1);
        let xml = sad.to_xml_string();
        assert!(xml.contains("sap:SADRequest"));
        assert!(xml.contains("ID=\"_sad1\""));
        assert!(xml.contains("<sap:RequesterID>https://sp.example.se</sap:RequesterID>"));
        assert!(xml.contains("<sap:SignRequestID>_signreq1</sap:SignRequestID>"));
        assert!(xml.contains("<sap:DocCount>1</sap:DocCount>"));
        assert!(xml.contains("<sap:RequestedVersion>1.0</sap:RequestedVersion>"));
    }
}
