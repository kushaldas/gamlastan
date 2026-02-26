// swsaml-xml serialization trait and support.
//
// The SamlSerialize trait provides serialization of owned SAML types
// to XML using the uppsala XmlWriter.

use uppsala::XmlWriter;

use crate::error::XmlError;

/// Serialization of owned SAML types to XML.
///
/// Implementors produce XML output using the streaming XmlWriter API.
/// This trait is implemented for owned SAML types (e.g., `AuthnRequest`,
/// `Response`, `Assertion`, etc.).
pub trait SamlSerialize {
    /// Serialize this SAML type to XML using the provided writer.
    ///
    /// # Arguments
    ///
    /// * `writer` - The XML writer to emit elements and attributes to.
    fn to_xml(&self, writer: &mut XmlWriter) -> Result<(), XmlError>;

    /// Convenience method: serialize to a complete XML string.
    ///
    /// Writes the XML declaration followed by the serialized element.
    fn to_xml_string(&self) -> Result<String, XmlError> {
        let mut writer = XmlWriter::new();
        self.to_xml(&mut writer)?;
        Ok(writer.into_string())
    }

    /// Convenience method: serialize to XML with the XML declaration header.
    fn to_xml_document(&self) -> Result<String, XmlError> {
        let mut writer = XmlWriter::new();
        writer.write_declaration();
        self.to_xml(&mut writer)?;
        Ok(writer.into_string())
    }
}
