// SamlDeserialize implementations for borrowed assertion types.
//
// Each impl deserializes from an uppsala Document node into the zero-copy
// borrowed SAML type, with all &str fields borrowing from the document buffer.

use uppsala::{Document, NodeId};

use crate::core::assertion::attribute::{AttributeRef, AttributeStatementRef, AttributeValueRef};
use crate::core::assertion::authn::{AuthnContextRef, AuthnStatementRef, SubjectLocalityRef};
use crate::core::assertion::authz::{
    ActionRef, AuthzDecisionStatementRef, DecisionType, EvidenceRef,
};
use crate::core::assertion::conditions::{
    AudienceRestrictionRef, ConditionsRef, ProxyRestrictionRef,
};
use crate::core::assertion::issuer::IssuerRef;
use crate::core::assertion::name_id::{
    EncryptedIdRef, NameIdOrEncryptedIdRef, NameIdPolicyRef, NameIdRef,
};
use crate::core::assertion::subject::{
    SubjectConfirmationDataRef, SubjectConfirmationRef, SubjectRef,
};
use crate::core::assertion::types::{AssertionRef, EncryptedAssertionRef};
use crate::core::identifiers::SamlVersion;
use crate::core::namespace::{SAML_ASSERTION_NS, XMLDSIG_NS, XSI_NS};

use crate::xml::deserialize::SamlDeserialize;
use crate::xml::error::XmlError;
use crate::xml::helpers::{
    find_child_element, find_child_elements, optional_attribute, parse_datetime_attr,
    parse_optional_bool_attr, parse_optional_datetime_attr, parse_optional_u32_attr,
    required_attribute, verify_element,
};

// ── Issuer ──────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for IssuerRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Issuer")?;
        let format = optional_attribute(doc, node, "Format");
        let name_qualifier = optional_attribute(doc, node, "NameQualifier");
        let sp_name_qualifier = optional_attribute(doc, node, "SPNameQualifier");
        // Use element_text for zero-copy text content.
        let value = doc.element_text(node).unwrap_or("");
        Ok(IssuerRef {
            value,
            format,
            name_qualifier,
            sp_name_qualifier,
        })
    }
}

// ── NameId ──────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for NameIdRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "NameID")?;
        let value = doc.element_text(node).unwrap_or("");
        let format = optional_attribute(doc, node, "Format");
        let name_qualifier = optional_attribute(doc, node, "NameQualifier");
        let sp_name_qualifier = optional_attribute(doc, node, "SPNameQualifier");
        let sp_provided_id = optional_attribute(doc, node, "SPProvidedID");
        Ok(NameIdRef {
            value,
            format,
            name_qualifier,
            sp_name_qualifier,
            sp_provided_id,
        })
    }
}

// ── NameIdOrEncryptedId ─────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for NameIdOrEncryptedIdRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        let elem = doc.element(node).ok_or(XmlError::NotAnElement)?;
        let local = elem.name.local_name.as_ref();
        match local {
            "NameID" => {
                let name_id = NameIdRef::from_xml(doc, node)?;
                Ok(NameIdOrEncryptedIdRef::NameId(name_id))
            }
            "EncryptedID" => {
                // Store raw XML bytes for later decryption via zero-copy node_source
                let raw = doc.node_source(node).map(|s| s.as_bytes()).unwrap_or(b"");
                Ok(NameIdOrEncryptedIdRef::EncryptedId(EncryptedIdRef { raw }))
            }
            _ => Err(XmlError::UnexpectedElement(format!(
                "Expected NameID or EncryptedID, found {}",
                local
            ))),
        }
    }
}

// ── NameIdPolicy ────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for NameIdPolicyRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        let format = optional_attribute(doc, node, "Format");
        let sp_name_qualifier = optional_attribute(doc, node, "SPNameQualifier");
        let allow_create = parse_optional_bool_attr(doc, node, "AllowCreate")?.unwrap_or(false);
        Ok(NameIdPolicyRef {
            format,
            sp_name_qualifier,
            allow_create,
        })
    }
}

// ── SubjectConfirmationData ─────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for SubjectConfirmationDataRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        let not_before = parse_optional_datetime_attr(doc, node, "NotBefore")?;
        let not_on_or_after = parse_optional_datetime_attr(doc, node, "NotOnOrAfter")?;
        let recipient = optional_attribute(doc, node, "Recipient");
        let in_response_to = optional_attribute(doc, node, "InResponseTo");
        let address = optional_attribute(doc, node, "Address");
        Ok(SubjectConfirmationDataRef {
            not_before,
            not_on_or_after,
            recipient,
            in_response_to,
            address,
        })
    }
}

// ── SubjectConfirmation ─────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for SubjectConfirmationRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "SubjectConfirmation")?;
        let method = required_attribute(doc, node, "Method")?;

        // Optional NameID or EncryptedID child
        let name_id = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID")
            .map(|n| NameIdOrEncryptedIdRef::from_xml(doc, n))
            .or_else(|| {
                find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID")
                    .map(|n| NameIdOrEncryptedIdRef::from_xml(doc, n))
            })
            .transpose()?;

        // Optional SubjectConfirmationData
        let subject_confirmation_data =
            find_child_element(doc, node, SAML_ASSERTION_NS, "SubjectConfirmationData")
                .map(|n| SubjectConfirmationDataRef::from_xml(doc, n))
                .transpose()?;

        Ok(SubjectConfirmationRef {
            method,
            name_id,
            subject_confirmation_data,
        })
    }
}

// ── Subject ─────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for SubjectRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Subject")?;

        // Optional NameID or EncryptedID
        let name_id = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID")
            .map(|n| NameIdOrEncryptedIdRef::from_xml(doc, n))
            .or_else(|| {
                find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID")
                    .map(|n| NameIdOrEncryptedIdRef::from_xml(doc, n))
            })
            .transpose()?;

        // SubjectConfirmation elements
        let sc_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "SubjectConfirmation");
        let mut subject_confirmations = Vec::with_capacity(sc_nodes.len());
        for sc_node in sc_nodes {
            subject_confirmations.push(SubjectConfirmationRef::from_xml(doc, sc_node)?);
        }

        Ok(SubjectRef {
            name_id,
            subject_confirmations,
        })
    }
}

// ── AudienceRestriction ─────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AudienceRestrictionRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "AudienceRestriction")?;
        let audience_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Audience");
        let mut audiences = Vec::with_capacity(audience_nodes.len());
        for aud_node in audience_nodes {
            audiences.push(doc.element_text(aud_node).unwrap_or(""));
        }
        Ok(AudienceRestrictionRef { audiences })
    }
}

// ── ProxyRestriction ────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ProxyRestrictionRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "ProxyRestriction")?;
        let count = parse_optional_u32_attr(doc, node, "Count")?;
        let audience_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Audience");
        let mut audiences = Vec::with_capacity(audience_nodes.len());
        for aud_node in audience_nodes {
            audiences.push(doc.element_text(aud_node).unwrap_or(""));
        }
        Ok(ProxyRestrictionRef { count, audiences })
    }
}

// ── Conditions ──────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ConditionsRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Conditions")?;
        let not_before = parse_optional_datetime_attr(doc, node, "NotBefore")?;
        let not_on_or_after = parse_optional_datetime_attr(doc, node, "NotOnOrAfter")?;

        // AudienceRestriction elements
        let ar_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AudienceRestriction");
        let mut audience_restrictions = Vec::with_capacity(ar_nodes.len());
        for ar_node in ar_nodes {
            audience_restrictions.push(AudienceRestrictionRef::from_xml(doc, ar_node)?);
        }

        // OneTimeUse
        let one_time_use = find_child_element(doc, node, SAML_ASSERTION_NS, "OneTimeUse").is_some();

        // ProxyRestriction
        let proxy_restriction =
            find_child_element(doc, node, SAML_ASSERTION_NS, "ProxyRestriction")
                .map(|n| ProxyRestrictionRef::from_xml(doc, n))
                .transpose()?;

        Ok(ConditionsRef {
            not_before,
            not_on_or_after,
            audience_restrictions,
            one_time_use,
            proxy_restriction,
        })
    }
}

// ── SubjectLocality ─────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for SubjectLocalityRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        let address = optional_attribute(doc, node, "Address");
        let dns_name = optional_attribute(doc, node, "DNSName");
        Ok(SubjectLocalityRef { address, dns_name })
    }
}

// ── AuthnContext ────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthnContextRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "AuthnContext")?;

        // AuthnContextClassRef
        let authn_context_class_ref =
            find_child_element(doc, node, SAML_ASSERTION_NS, "AuthnContextClassRef")
                .map(|n| doc.element_text(n).unwrap_or(""));

        // AuthnContextDeclRef
        let authn_context_decl_ref =
            find_child_element(doc, node, SAML_ASSERTION_NS, "AuthnContextDeclRef")
                .map(|n| doc.element_text(n).unwrap_or(""));

        // AuthenticatingAuthority elements
        let auth_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "AuthenticatingAuthority");
        let mut authenticating_authorities = Vec::with_capacity(auth_nodes.len());
        for auth_node in auth_nodes {
            authenticating_authorities.push(doc.element_text(auth_node).unwrap_or(""));
        }

        Ok(AuthnContextRef {
            authn_context_class_ref,
            authn_context_decl_ref,
            authenticating_authorities,
        })
    }
}

// ── AuthnStatement ──────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthnStatementRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "AuthnStatement")?;
        let authn_instant = parse_datetime_attr(doc, node, "AuthnInstant")?;
        let session_index = optional_attribute(doc, node, "SessionIndex");
        let session_not_on_or_after =
            parse_optional_datetime_attr(doc, node, "SessionNotOnOrAfter")?;

        // SubjectLocality
        let subject_locality = find_child_element(doc, node, SAML_ASSERTION_NS, "SubjectLocality")
            .map(|n| SubjectLocalityRef::from_xml(doc, n))
            .transpose()?;

        // AuthnContext (required)
        let authn_context_node = find_child_element(doc, node, SAML_ASSERTION_NS, "AuthnContext")
            .ok_or_else(|| XmlError::MissingElement {
            parent: "AuthnStatement".to_string(),
            element: "AuthnContext".to_string(),
        })?;
        let authn_context = AuthnContextRef::from_xml(doc, authn_context_node)?;

        Ok(AuthnStatementRef {
            authn_instant,
            session_index,
            session_not_on_or_after,
            subject_locality,
            authn_context,
        })
    }
}

// ── Action ──────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ActionRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Action")?;
        let namespace = required_attribute(doc, node, "Namespace")?;
        let value = doc.element_text(node).unwrap_or("");
        Ok(ActionRef { namespace, value })
    }
}

// ── Evidence ────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for EvidenceRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Evidence")?;

        let id_ref_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AssertionIDRef");
        let mut assertion_id_refs = Vec::with_capacity(id_ref_nodes.len());
        for n in id_ref_nodes {
            assertion_id_refs.push(doc.element_text(n).unwrap_or(""));
        }

        let uri_ref_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AssertionURIRef");
        let mut assertion_uri_refs = Vec::with_capacity(uri_ref_nodes.len());
        for n in uri_ref_nodes {
            assertion_uri_refs.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(EvidenceRef {
            assertion_id_refs,
            assertion_uri_refs,
        })
    }
}

// ── AuthzDecisionStatement ──────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthzDecisionStatementRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "AuthzDecisionStatement")?;
        let resource = required_attribute(doc, node, "Resource")?;
        let decision_str = required_attribute(doc, node, "Decision")?;
        let decision: DecisionType =
            decision_str
                .parse()
                .map_err(|_| XmlError::InvalidAttributeValue {
                    element: "AuthzDecisionStatement".to_string(),
                    attribute: "Decision".to_string(),
                    value: decision_str.to_string(),
                })?;

        let action_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Action");
        let mut actions = Vec::with_capacity(action_nodes.len());
        for action_node in action_nodes {
            actions.push(ActionRef::from_xml(doc, action_node)?);
        }

        let evidence = find_child_element(doc, node, SAML_ASSERTION_NS, "Evidence")
            .map(|n| EvidenceRef::from_xml(doc, n))
            .transpose()?;

        Ok(AuthzDecisionStatementRef {
            resource,
            decision,
            actions,
            evidence,
        })
    }
}

// ── AttributeValue ──────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AttributeValueRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        // Check for xsi:nil="true"
        if let Some(elem) = doc.element(node) {
            if let Some(nil_val) = elem.get_attribute_ns(XSI_NS, "nil") {
                if nil_val == "true" || nil_val == "1" {
                    return Ok(AttributeValueRef::Null);
                }
            }
            // Check xsi:type to determine the value type
            if let Some(xsi_type) = elem.get_attribute_ns(XSI_NS, "type") {
                // Handle common XSD types
                if xsi_type.ends_with(":integer") || xsi_type == "integer" {
                    let text = doc.element_text(node).unwrap_or("");
                    let val = text
                        .parse::<i64>()
                        .map_err(|_| XmlError::InvalidInteger(text.to_string()))?;
                    return Ok(AttributeValueRef::Integer(val));
                }
                if xsi_type.ends_with(":boolean") || xsi_type == "boolean" {
                    let text = doc.element_text(node).unwrap_or("");
                    let val = match text {
                        "true" | "1" => true,
                        "false" | "0" => false,
                        _ => {
                            return Err(XmlError::InvalidBoolean(text.to_string()));
                        }
                    };
                    return Ok(AttributeValueRef::Boolean(val));
                }
                if xsi_type.ends_with(":dateTime") || xsi_type == "dateTime" {
                    let text = doc.element_text(node).unwrap_or("");
                    return Ok(AttributeValueRef::DateTime(text));
                }
                if xsi_type.ends_with(":base64Binary") || xsi_type == "base64Binary" {
                    let text = doc.element_text(node).unwrap_or("");
                    return Ok(AttributeValueRef::Base64(text.as_bytes()));
                }
            }
        }

        // Check if there are child elements (XML content)
        let has_element_children = doc.children_iter(node).any(|c| doc.element(c).is_some());
        if has_element_children {
            // Contains XML elements - store as raw XML bytes
            let raw = doc.node_source(node).map(|s| s.as_bytes()).unwrap_or(b"");
            return Ok(AttributeValueRef::Xml(raw));
        }

        // Default: treat as string
        let text = doc.element_text(node).unwrap_or("");
        Ok(AttributeValueRef::Str(text))
    }
}

// ── Attribute ───────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AttributeRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Attribute")?;
        let name = required_attribute(doc, node, "Name")?;
        let name_format = optional_attribute(doc, node, "NameFormat");
        let friendly_name = optional_attribute(doc, node, "FriendlyName");

        let value_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AttributeValue");
        let mut values = Vec::with_capacity(value_nodes.len());
        for val_node in value_nodes {
            values.push(AttributeValueRef::from_xml(doc, val_node)?);
        }

        Ok(AttributeRef {
            name,
            name_format,
            friendly_name,
            values,
        })
    }
}

// ── AttributeStatement ──────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AttributeStatementRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "AttributeStatement")?;
        let attr_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Attribute");
        let mut attributes = Vec::with_capacity(attr_nodes.len());
        for attr_node in attr_nodes {
            attributes.push(AttributeRef::from_xml(doc, attr_node)?);
        }
        Ok(AttributeStatementRef { attributes })
    }
}

// ── Assertion ───────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AssertionRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "Assertion")?;
        let id = required_attribute(doc, node, "ID")?;
        let version_str = required_attribute(doc, node, "Version")?;
        let version = SamlVersion::try_from_str(version_str).ok_or_else(|| {
            XmlError::InvalidAttributeValue {
                element: "Assertion".to_string(),
                attribute: "Version".to_string(),
                value: version_str.to_string(),
            }
        })?;
        let issue_instant = parse_datetime_attr(doc, node, "IssueInstant")?;

        // Issuer (required)
        let issuer_node =
            find_child_element(doc, node, SAML_ASSERTION_NS, "Issuer").ok_or_else(|| {
                XmlError::MissingElement {
                    parent: "Assertion".to_string(),
                    element: "Issuer".to_string(),
                }
            })?;
        let issuer = IssuerRef::from_xml(doc, issuer_node)?;

        // Signature presence check
        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        // Subject (optional)
        let subject = find_child_element(doc, node, SAML_ASSERTION_NS, "Subject")
            .map(|n| SubjectRef::from_xml(doc, n))
            .transpose()?;

        // Conditions (optional)
        let conditions = find_child_element(doc, node, SAML_ASSERTION_NS, "Conditions")
            .map(|n| ConditionsRef::from_xml(doc, n))
            .transpose()?;

        // AuthnStatement elements
        let authn_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AuthnStatement");
        let mut authn_statements = Vec::with_capacity(authn_nodes.len());
        for authn_node in authn_nodes {
            authn_statements.push(AuthnStatementRef::from_xml(doc, authn_node)?);
        }

        // AuthzDecisionStatement elements
        let authz_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "AuthzDecisionStatement");
        let mut authz_decision_statements = Vec::with_capacity(authz_nodes.len());
        for authz_node in authz_nodes {
            authz_decision_statements.push(AuthzDecisionStatementRef::from_xml(doc, authz_node)?);
        }

        // AttributeStatement elements
        let attr_stmt_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "AttributeStatement");
        let mut attribute_statements = Vec::with_capacity(attr_stmt_nodes.len());
        for attr_stmt_node in attr_stmt_nodes {
            attribute_statements.push(AttributeStatementRef::from_xml(doc, attr_stmt_node)?);
        }

        Ok(AssertionRef {
            id,
            issue_instant,
            version,
            issuer,
            has_signature,
            subject,
            conditions,
            authn_statements,
            authz_decision_statements,
            attribute_statements,
        })
    }
}

// ── EncryptedAssertion ──────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for EncryptedAssertionRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_ASSERTION_NS, "EncryptedAssertion")?;
        let raw = doc.node_source(node).map(|s| s.as_bytes()).unwrap_or(b"");
        Ok(EncryptedAssertionRef { raw })
    }
}
