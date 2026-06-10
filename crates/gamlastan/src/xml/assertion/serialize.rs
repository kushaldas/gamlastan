// SamlSerialize implementations for owned assertion types.
//
// Each impl serializes the owned SAML type to XML using the uppsala XmlWriter.

use uppsala::XmlWriter;

use crate::core::assertion::attribute::{Attribute, AttributeStatement, AttributeValue};
use crate::core::assertion::authn::{AuthnContext, AuthnStatement, SubjectLocality};
use crate::core::assertion::authz::{Action, AuthzDecisionStatement, Evidence};
use crate::core::assertion::conditions::{AudienceRestriction, Conditions, ProxyRestriction};
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId, NameIdPolicy};
use crate::core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use crate::core::assertion::types::Assertion;
use crate::core::namespace::{SAML_ASSERTION_NS, XSI_NS, XS_NS};

use crate::xml::error::XmlError;
use crate::xml::helpers::format_datetime;
use crate::xml::serialize::SamlSerialize;

// ── Issuer ──────────────────────────────────────────────────────────────────

impl SamlSerialize for Issuer {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref format) = self.format {
            attrs.push(("Format", format));
        }
        if let Some(ref nq) = self.name_qualifier {
            attrs.push(("NameQualifier", nq));
        }
        if let Some(ref spnq) = self.sp_name_qualifier {
            attrs.push(("SPNameQualifier", spnq));
        }
        w.start_element("saml:Issuer", &attrs);
        w.text(&self.value);
        w.end_element("saml:Issuer");
        Ok(())
    }
}

// ── NameId ──────────────────────────────────────────────────────────────────

impl SamlSerialize for NameId {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref format) = self.format {
            attrs.push(("Format", format));
        }
        if let Some(ref nq) = self.name_qualifier {
            attrs.push(("NameQualifier", nq));
        }
        if let Some(ref spnq) = self.sp_name_qualifier {
            attrs.push(("SPNameQualifier", spnq));
        }
        if let Some(ref spid) = self.sp_provided_id {
            attrs.push(("SPProvidedID", spid));
        }
        w.start_element("saml:NameID", &attrs);
        w.text(&self.value);
        w.end_element("saml:NameID");
        Ok(())
    }
}

// ── NameIdOrEncryptedId ─────────────────────────────────────────────────────

impl SamlSerialize for NameIdOrEncryptedId {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        match self {
            NameIdOrEncryptedId::NameId(name_id) => name_id.to_xml(w),
            NameIdOrEncryptedId::EncryptedId(encrypted_id) => {
                // Write the raw encrypted XML
                let raw_str = std::str::from_utf8(&encrypted_id.raw)
                    .map_err(|e| XmlError::SerializationError(e.to_string()))?;
                w.raw(raw_str);
                Ok(())
            }
        }
    }
}

// ── NameIdPolicy ────────────────────────────────────────────────────────────

impl SamlSerialize for NameIdPolicy {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref format) = self.format {
            attrs.push(("Format", format));
        }
        if let Some(ref spnq) = self.sp_name_qualifier {
            attrs.push(("SPNameQualifier", spnq));
        }
        let allow_create_str;
        if self.allow_create {
            allow_create_str = "true";
            attrs.push(("AllowCreate", allow_create_str));
        }
        w.empty_element("samlp:NameIDPolicy", &attrs);
        Ok(())
    }
}

// ── SubjectConfirmationData ─────────────────────────────────────────────────

impl SamlSerialize for SubjectConfirmationData {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, String)> = Vec::new();
        if let Some(ref nb) = self.not_before {
            attrs.push(("NotBefore", format_datetime(nb)));
        }
        if let Some(ref nooa) = self.not_on_or_after {
            attrs.push(("NotOnOrAfter", format_datetime(nooa)));
        }
        if let Some(ref recipient) = self.recipient {
            attrs.push(("Recipient", recipient.clone()));
        }
        if let Some(ref irt) = self.in_response_to {
            attrs.push(("InResponseTo", irt.clone()));
        }
        if let Some(ref addr) = self.address {
            attrs.push(("Address", addr.clone()));
        }
        if self.key_info_x509_certs.is_empty() {
            w.empty_element_with(
                "saml:SubjectConfirmationData",
                attrs.iter().map(|(k, v)| (*k, v.as_str())),
            );
        } else {
            // KeyInfoConfirmationDataType (Holder-of-Key)
            w.start_element_with(
                "saml:SubjectConfirmationData",
                attrs.iter().map(|(k, v)| (*k, v.as_str())),
            );
            w.start_element(
                "ds:KeyInfo",
                &[("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")],
            );
            w.start_element("ds:X509Data", &[]);
            for cert in &self.key_info_x509_certs {
                w.start_element("ds:X509Certificate", &[]);
                w.text(cert);
                w.end_element("ds:X509Certificate");
            }
            w.end_element("ds:X509Data");
            w.end_element("ds:KeyInfo");
            w.end_element("saml:SubjectConfirmationData");
        }
        Ok(())
    }
}

// ── SubjectConfirmation ─────────────────────────────────────────────────────

impl SamlSerialize for SubjectConfirmation {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element(
            "saml:SubjectConfirmation",
            &[("Method", self.method.as_str())],
        );
        if let Some(ref name_id) = self.name_id {
            name_id.to_xml(w)?;
        }
        if let Some(ref scd) = self.subject_confirmation_data {
            scd.to_xml(w)?;
        }
        w.end_element("saml:SubjectConfirmation");
        Ok(())
    }
}

// ── Subject ─────────────────────────────────────────────────────────────────

impl SamlSerialize for Subject {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:Subject", &[]);
        if let Some(ref name_id) = self.name_id {
            name_id.to_xml(w)?;
        }
        for sc in &self.subject_confirmations {
            sc.to_xml(w)?;
        }
        w.end_element("saml:Subject");
        Ok(())
    }
}

// ── AudienceRestriction ─────────────────────────────────────────────────────

impl SamlSerialize for AudienceRestriction {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:AudienceRestriction", &[]);
        for audience in &self.audiences {
            w.start_element("saml:Audience", &[]);
            w.text(audience);
            w.end_element("saml:Audience");
        }
        w.end_element("saml:AudienceRestriction");
        Ok(())
    }
}

// ── ProxyRestriction ────────────────────────────────────────────────────────

impl SamlSerialize for ProxyRestriction {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let count_str;
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(count) = self.count {
            count_str = count.to_string();
            attrs.push(("Count", &count_str));
        }
        w.start_element("saml:ProxyRestriction", &attrs);
        for audience in &self.audiences {
            w.start_element("saml:Audience", &[]);
            w.text(audience);
            w.end_element("saml:Audience");
        }
        w.end_element("saml:ProxyRestriction");
        Ok(())
    }
}

// ── Conditions ──────────────────────────────────────────────────────────────

impl SamlSerialize for Conditions {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, String)> = Vec::new();
        if let Some(ref nb) = self.not_before {
            attrs.push(("NotBefore", format_datetime(nb)));
        }
        if let Some(ref nooa) = self.not_on_or_after {
            attrs.push(("NotOnOrAfter", format_datetime(nooa)));
        }
        w.start_element_with(
            "saml:Conditions",
            attrs.iter().map(|(k, v)| (*k, v.as_str())),
        );
        for ar in &self.audience_restrictions {
            ar.to_xml(w)?;
        }
        if self.one_time_use {
            w.empty_element("saml:OneTimeUse", &[]);
        }
        if let Some(ref pr) = self.proxy_restriction {
            pr.to_xml(w)?;
        }
        w.end_element("saml:Conditions");
        Ok(())
    }
}

// ── SubjectLocality ─────────────────────────────────────────────────────────

impl SamlSerialize for SubjectLocality {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref addr) = self.address {
            attrs.push(("Address", addr));
        }
        if let Some(ref dns) = self.dns_name {
            attrs.push(("DNSName", dns));
        }
        w.empty_element("saml:SubjectLocality", &attrs);
        Ok(())
    }
}

// ── AuthnContext ────────────────────────────────────────────────────────────

impl SamlSerialize for AuthnContext {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:AuthnContext", &[]);
        if let Some(ref class_ref) = self.authn_context_class_ref {
            w.start_element("saml:AuthnContextClassRef", &[]);
            w.text(class_ref);
            w.end_element("saml:AuthnContextClassRef");
        }
        if let Some(ref decl_ref) = self.authn_context_decl_ref {
            w.start_element("saml:AuthnContextDeclRef", &[]);
            w.text(decl_ref);
            w.end_element("saml:AuthnContextDeclRef");
        }
        for authority in &self.authenticating_authorities {
            w.start_element("saml:AuthenticatingAuthority", &[]);
            w.text(authority);
            w.end_element("saml:AuthenticatingAuthority");
        }
        w.end_element("saml:AuthnContext");
        Ok(())
    }
}

// ── AuthnStatement ──────────────────────────────────────────────────────────

impl SamlSerialize for AuthnStatement {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let instant_str = format_datetime(&self.authn_instant);
        let mut attrs: Vec<(&str, &str)> = vec![("AuthnInstant", &instant_str)];
        if let Some(ref si) = self.session_index {
            attrs.push(("SessionIndex", si));
        }
        let session_nooa_str;
        if let Some(ref snooa) = self.session_not_on_or_after {
            session_nooa_str = format_datetime(snooa);
            attrs.push(("SessionNotOnOrAfter", &session_nooa_str));
        }
        w.start_element("saml:AuthnStatement", &attrs);
        if let Some(ref sl) = self.subject_locality {
            sl.to_xml(w)?;
        }
        self.authn_context.to_xml(w)?;
        w.end_element("saml:AuthnStatement");
        Ok(())
    }
}

// ── Action ──────────────────────────────────────────────────────────────────

impl SamlSerialize for Action {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:Action", &[("Namespace", self.namespace.as_str())]);
        w.text(&self.value);
        w.end_element("saml:Action");
        Ok(())
    }
}

// ── Evidence ────────────────────────────────────────────────────────────────

impl SamlSerialize for Evidence {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:Evidence", &[]);
        for id_ref in &self.assertion_id_refs {
            w.start_element("saml:AssertionIDRef", &[]);
            w.text(id_ref);
            w.end_element("saml:AssertionIDRef");
        }
        for uri_ref in &self.assertion_uri_refs {
            w.start_element("saml:AssertionURIRef", &[]);
            w.text(uri_ref);
            w.end_element("saml:AssertionURIRef");
        }
        w.end_element("saml:Evidence");
        Ok(())
    }
}

// ── AuthzDecisionStatement ──────────────────────────────────────────────────

impl SamlSerialize for AuthzDecisionStatement {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element(
            "saml:AuthzDecisionStatement",
            &[
                ("Resource", self.resource.as_str()),
                ("Decision", self.decision.as_str()),
            ],
        );
        for action in &self.actions {
            action.to_xml(w)?;
        }
        if let Some(ref evidence) = self.evidence {
            evidence.to_xml(w)?;
        }
        w.end_element("saml:AuthzDecisionStatement");
        Ok(())
    }
}

// ── AttributeValue ──────────────────────────────────────────────────────────

impl SamlSerialize for AttributeValue {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        match self {
            AttributeValue::String(s) => {
                w.start_element(
                    "saml:AttributeValue",
                    &[
                        ("xmlns:xsi", XSI_NS),
                        ("xmlns:xs", XS_NS),
                        ("xsi:type", "xs:string"),
                    ],
                );
                w.text(s);
                w.end_element("saml:AttributeValue");
            }
            AttributeValue::Integer(i) => {
                w.start_element(
                    "saml:AttributeValue",
                    &[
                        ("xmlns:xsi", XSI_NS),
                        ("xmlns:xs", XS_NS),
                        ("xsi:type", "xs:integer"),
                    ],
                );
                let s = i.to_string();
                w.text(&s);
                w.end_element("saml:AttributeValue");
            }
            AttributeValue::Boolean(b) => {
                w.start_element(
                    "saml:AttributeValue",
                    &[
                        ("xmlns:xsi", XSI_NS),
                        ("xmlns:xs", XS_NS),
                        ("xsi:type", "xs:boolean"),
                    ],
                );
                w.text(if *b { "true" } else { "false" });
                w.end_element("saml:AttributeValue");
            }
            AttributeValue::DateTime(dt) => {
                w.start_element(
                    "saml:AttributeValue",
                    &[
                        ("xmlns:xsi", XSI_NS),
                        ("xmlns:xs", XS_NS),
                        ("xsi:type", "xs:dateTime"),
                    ],
                );
                w.text(dt);
                w.end_element("saml:AttributeValue");
            }
            AttributeValue::Base64(data) => {
                w.start_element(
                    "saml:AttributeValue",
                    &[
                        ("xmlns:xsi", XSI_NS),
                        ("xmlns:xs", XS_NS),
                        ("xsi:type", "xs:base64Binary"),
                    ],
                );
                let encoded = std::str::from_utf8(data).unwrap_or("");
                w.text(encoded);
                w.end_element("saml:AttributeValue");
            }
            AttributeValue::Xml(data) => {
                // Raw XML content injected verbatim
                let raw_str = std::str::from_utf8(data)
                    .map_err(|e| XmlError::SerializationError(e.to_string()))?;
                w.raw(raw_str);
            }
            AttributeValue::Null => {
                w.empty_element(
                    "saml:AttributeValue",
                    &[("xmlns:xsi", XSI_NS), ("xsi:nil", "true")],
                );
            }
        }
        Ok(())
    }
}

// ── Attribute ───────────────────────────────────────────────────────────────

impl SamlSerialize for Attribute {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut attrs: Vec<(&str, &str)> = vec![("Name", &self.name)];
        if let Some(ref nf) = self.name_format {
            attrs.push(("NameFormat", nf));
        }
        if let Some(ref fn_) = self.friendly_name {
            attrs.push(("FriendlyName", fn_));
        }
        w.start_element("saml:Attribute", &attrs);
        for value in &self.values {
            value.to_xml(w)?;
        }
        w.end_element("saml:Attribute");
        Ok(())
    }
}

// ── AttributeStatement ──────────────────────────────────────────────────────

impl SamlSerialize for AttributeStatement {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("saml:AttributeStatement", &[]);
        for attr in &self.attributes {
            attr.to_xml(w)?;
        }
        w.end_element("saml:AttributeStatement");
        Ok(())
    }
}

// ── Assertion ───────────────────────────────────────────────────────────────

impl SamlSerialize for Assertion {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let instant_str = format_datetime(&self.issue_instant);
        w.start_element(
            "saml:Assertion",
            &[
                ("xmlns:saml", SAML_ASSERTION_NS),
                ("ID", &self.id),
                ("Version", self.version.as_str()),
                ("IssueInstant", &instant_str),
            ],
        );
        self.issuer.to_xml(w)?;
        // Note: Signature is NOT serialized here - it's added by the signing layer
        if let Some(ref subject) = self.subject {
            subject.to_xml(w)?;
        }
        if let Some(ref conditions) = self.conditions {
            conditions.to_xml(w)?;
        }
        for stmt in &self.authn_statements {
            stmt.to_xml(w)?;
        }
        for stmt in &self.authz_decision_statements {
            stmt.to_xml(w)?;
        }
        for stmt in &self.attribute_statements {
            stmt.to_xml(w)?;
        }
        w.end_element("saml:Assertion");
        Ok(())
    }
}
