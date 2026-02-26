// SamlDeserialize implementations for borrowed protocol types.
//
// Each impl deserializes from an uppsala Document node into the zero-copy
// borrowed SAML protocol type, with all &str fields borrowing from the document buffer.

use uppsala::{Document, NodeId};

use swsaml_core::assertion::attribute::AttributeRef;
use swsaml_core::assertion::authz::{ActionRef, EvidenceRef};
use swsaml_core::assertion::conditions::ConditionsRef;
use swsaml_core::assertion::issuer::IssuerRef;
use swsaml_core::assertion::name_id::{NameIdOrEncryptedIdRef, NameIdPolicyRef};
use swsaml_core::assertion::subject::SubjectRef;
use swsaml_core::assertion::types::{AssertionRef, EncryptedAssertionRef};
use swsaml_core::identifiers::SamlVersion;
use swsaml_core::namespace::{SAML_ASSERTION_NS, SAML_PROTOCOL_NS, XMLDSIG_NS};
use swsaml_core::protocol::artifact::{ArtifactResolveRef, ArtifactResponseRef};
use swsaml_core::protocol::logout::{LogoutRequestRef, LogoutResponseRef};
use swsaml_core::protocol::name_id_mapping::{NameIdMappingRequestRef, NameIdMappingResponseRef};
use swsaml_core::protocol::name_id_mgmt::{
    ManageNameIdRequestRef, ManageNameIdResponseRef, NewIdOrTerminateRef,
};
use swsaml_core::protocol::query::{
    AssertionIdRequestRef, AttributeQueryRef, AuthnQueryRef, AuthzDecisionQueryRef,
};
use swsaml_core::protocol::request::{
    AuthnContextComparison, AuthnRequestRef, RequestBaseRef, RequestedAuthnContextRef, ScopingRef,
};
use swsaml_core::protocol::response::{ResponseBaseRef, ResponseRef};
use swsaml_core::protocol::status::{StatusCodeRef, StatusRef};

use crate::deserialize::SamlDeserialize;
use crate::error::XmlError;
use crate::helpers::{
    find_child_element, find_child_elements, optional_attribute, parse_datetime_attr,
    parse_optional_bool_attr, parse_optional_datetime_attr, parse_optional_u16_attr,
    parse_optional_u32_attr, required_attribute, verify_element,
};

// ── StatusCode ─────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for StatusCodeRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "StatusCode")?;
        let value = required_attribute(doc, node, "Value")?;

        // Optional nested StatusCode (per E65: second-level is optional)
        let sub_status = find_child_element(doc, node, SAML_PROTOCOL_NS, "StatusCode")
            .map(|n| StatusCodeRef::from_xml(doc, n))
            .transpose()?
            .map(Box::new);

        Ok(StatusCodeRef { value, sub_status })
    }
}

// ── Status ─────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for StatusRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "Status")?;

        // StatusCode (required)
        let status_code_node = find_child_element(doc, node, SAML_PROTOCOL_NS, "StatusCode")
            .ok_or_else(|| XmlError::MissingElement {
                parent: "Status".to_string(),
                element: "StatusCode".to_string(),
            })?;
        let status_code = StatusCodeRef::from_xml(doc, status_code_node)?;

        // Optional StatusMessage
        let status_message = find_child_element(doc, node, SAML_PROTOCOL_NS, "StatusMessage")
            .map(|n| doc.element_text(n).unwrap_or(""));

        // Optional StatusDetail (store as raw XML source for later inspection)
        let status_detail = find_child_element(doc, node, SAML_PROTOCOL_NS, "StatusDetail")
            .and_then(|n| doc.node_source(n));

        Ok(StatusRef {
            status_code,
            status_message,
            status_detail,
        })
    }
}

// ── Helper: parse common request base fields ────────────────────────────────

/// Parse common request fields (ID, Version, IssueInstant, Destination, Consent, Issuer, Signature)
/// from any request-type element.
fn parse_request_base<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<RequestBaseRef<'a>, XmlError> {
    let id = required_attribute(doc, node, "ID")?;
    let version_str = required_attribute(doc, node, "Version")?;
    let version =
        SamlVersion::try_from_str(version_str).ok_or_else(|| XmlError::InvalidAttributeValue {
            element: "Request".to_string(),
            attribute: "Version".to_string(),
            value: version_str.to_string(),
        })?;
    let issue_instant = parse_datetime_attr(doc, node, "IssueInstant")?;
    let destination = optional_attribute(doc, node, "Destination");
    let consent = optional_attribute(doc, node, "Consent");

    let issuer = find_child_element(doc, node, SAML_ASSERTION_NS, "Issuer")
        .map(|n| IssuerRef::from_xml(doc, n))
        .transpose()?;

    let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

    Ok(RequestBaseRef {
        id,
        version,
        issue_instant,
        destination,
        consent,
        issuer,
        has_signature,
    })
}

// ── Helper: parse common response base fields ───────────────────────────────

/// Parse common response fields (request base + InResponseTo + Status).
fn parse_response_base<'a>(
    doc: &'a Document<'a>,
    node: NodeId,
) -> Result<ResponseBaseRef<'a>, XmlError> {
    let id = required_attribute(doc, node, "ID")?;
    let version_str = required_attribute(doc, node, "Version")?;
    let version =
        SamlVersion::try_from_str(version_str).ok_or_else(|| XmlError::InvalidAttributeValue {
            element: "Response".to_string(),
            attribute: "Version".to_string(),
            value: version_str.to_string(),
        })?;
    let issue_instant = parse_datetime_attr(doc, node, "IssueInstant")?;
    let destination = optional_attribute(doc, node, "Destination");
    let consent = optional_attribute(doc, node, "Consent");
    let in_response_to = optional_attribute(doc, node, "InResponseTo");

    let issuer = find_child_element(doc, node, SAML_ASSERTION_NS, "Issuer")
        .map(|n| IssuerRef::from_xml(doc, n))
        .transpose()?;

    let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

    // Status (required)
    let status_node =
        find_child_element(doc, node, SAML_PROTOCOL_NS, "Status").ok_or_else(|| {
            XmlError::MissingElement {
                parent: "StatusResponseType".to_string(),
                element: "Status".to_string(),
            }
        })?;
    let status = StatusRef::from_xml(doc, status_node)?;

    Ok(ResponseBaseRef {
        id,
        version,
        issue_instant,
        destination,
        consent,
        issuer,
        has_signature,
        in_response_to,
        status,
    })
}

// ── RequestedAuthnContext ────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for RequestedAuthnContextRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "RequestedAuthnContext")?;

        let comparison_str = optional_attribute(doc, node, "Comparison").unwrap_or("exact");
        let comparison: AuthnContextComparison =
            comparison_str
                .parse()
                .map_err(|_| XmlError::InvalidAttributeValue {
                    element: "RequestedAuthnContext".to_string(),
                    attribute: "Comparison".to_string(),
                    value: comparison_str.to_string(),
                })?;

        let class_ref_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "AuthnContextClassRef");
        let mut authn_context_class_refs = Vec::with_capacity(class_ref_nodes.len());
        for n in class_ref_nodes {
            authn_context_class_refs.push(doc.element_text(n).unwrap_or(""));
        }

        let decl_ref_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "AuthnContextDeclRef");
        let mut authn_context_decl_refs = Vec::with_capacity(decl_ref_nodes.len());
        for n in decl_ref_nodes {
            authn_context_decl_refs.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(RequestedAuthnContextRef {
            authn_context_class_refs,
            authn_context_decl_refs,
            comparison,
        })
    }
}

// ── Scoping ─────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ScopingRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "Scoping")?;

        let proxy_count = parse_optional_u32_attr(doc, node, "ProxyCount")?;

        // IDPList -> IDPEntry elements
        let mut idp_list = Vec::new();
        if let Some(idp_list_node) = find_child_element(doc, node, SAML_PROTOCOL_NS, "IDPList") {
            let entry_nodes = find_child_elements(doc, idp_list_node, SAML_PROTOCOL_NS, "IDPEntry");
            for entry_node in entry_nodes {
                if let Some(provider_id) = optional_attribute(doc, entry_node, "ProviderID") {
                    idp_list.push(provider_id);
                }
            }
        }

        // RequesterID elements
        let requester_id_nodes = find_child_elements(doc, node, SAML_PROTOCOL_NS, "RequesterID");
        let mut requester_ids = Vec::with_capacity(requester_id_nodes.len());
        for n in requester_id_nodes {
            requester_ids.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(ScopingRef {
            proxy_count,
            idp_list,
            requester_ids,
        })
    }
}

// ── AuthnRequest ────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthnRequestRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "AuthnRequest")?;
        let base = parse_request_base(doc, node)?;

        let force_authn = parse_optional_bool_attr(doc, node, "ForceAuthn")?;
        let is_passive = parse_optional_bool_attr(doc, node, "IsPassive")?;
        let assertion_consumer_service_index =
            parse_optional_u16_attr(doc, node, "AssertionConsumerServiceIndex")?;
        let assertion_consumer_service_url =
            optional_attribute(doc, node, "AssertionConsumerServiceURL");
        let protocol_binding = optional_attribute(doc, node, "ProtocolBinding");
        let attribute_consuming_service_index =
            parse_optional_u16_attr(doc, node, "AttributeConsumingServiceIndex")?;
        let provider_name = optional_attribute(doc, node, "ProviderName");

        // Optional Subject
        let subject = find_child_element(doc, node, SAML_ASSERTION_NS, "Subject")
            .map(|n| SubjectRef::from_xml(doc, n))
            .transpose()?;

        // Optional NameIDPolicy
        let name_id_policy = find_child_element(doc, node, SAML_PROTOCOL_NS, "NameIDPolicy")
            .map(|n| NameIdPolicyRef::from_xml(doc, n))
            .transpose()?;

        // Optional Conditions
        let conditions = find_child_element(doc, node, SAML_ASSERTION_NS, "Conditions")
            .map(|n| ConditionsRef::from_xml(doc, n))
            .transpose()?;

        // Optional RequestedAuthnContext
        let requested_authn_context =
            find_child_element(doc, node, SAML_PROTOCOL_NS, "RequestedAuthnContext")
                .map(|n| RequestedAuthnContextRef::from_xml(doc, n))
                .transpose()?;

        // Optional Scoping
        let scoping = find_child_element(doc, node, SAML_PROTOCOL_NS, "Scoping")
            .map(|n| ScopingRef::from_xml(doc, n))
            .transpose()?;

        Ok(AuthnRequestRef {
            base,
            subject,
            name_id_policy,
            conditions,
            requested_authn_context,
            scoping,
            force_authn,
            is_passive,
            assertion_consumer_service_index,
            assertion_consumer_service_url,
            protocol_binding,
            attribute_consuming_service_index,
            provider_name,
        })
    }
}

// ── Response ────────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "Response")?;
        let base = parse_response_base(doc, node)?;

        // Assertion elements (per E26: multiple allowed)
        let assertion_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Assertion");
        let mut assertions = Vec::with_capacity(assertion_nodes.len());
        for assertion_node in assertion_nodes {
            assertions.push(AssertionRef::from_xml(doc, assertion_node)?);
        }

        // EncryptedAssertion elements
        let enc_assertion_nodes =
            find_child_elements(doc, node, SAML_ASSERTION_NS, "EncryptedAssertion");
        let mut encrypted_assertions = Vec::with_capacity(enc_assertion_nodes.len());
        for enc_node in enc_assertion_nodes {
            encrypted_assertions.push(EncryptedAssertionRef::from_xml(doc, enc_node)?);
        }

        Ok(ResponseRef {
            base,
            assertions,
            encrypted_assertions,
        })
    }
}

// ── LogoutRequest ───────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for LogoutRequestRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "LogoutRequest")?;

        let id = required_attribute(doc, node, "ID")?;
        let version_str = required_attribute(doc, node, "Version")?;
        let version = SamlVersion::try_from_str(version_str).ok_or_else(|| {
            XmlError::InvalidAttributeValue {
                element: "LogoutRequest".to_string(),
                attribute: "Version".to_string(),
                value: version_str.to_string(),
            }
        })?;
        let issue_instant = parse_datetime_attr(doc, node, "IssueInstant")?;
        let destination = optional_attribute(doc, node, "Destination");
        let consent = optional_attribute(doc, node, "Consent");
        let not_on_or_after = parse_optional_datetime_attr(doc, node, "NotOnOrAfter")?;
        let reason = optional_attribute(doc, node, "Reason");

        let issuer = find_child_element(doc, node, SAML_ASSERTION_NS, "Issuer")
            .map(|n| IssuerRef::from_xml(doc, n))
            .transpose()?;

        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        // NameID or EncryptedID (required)
        let name_id = if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else {
            return Err(XmlError::MissingElement {
                parent: "LogoutRequest".to_string(),
                element: "NameID or EncryptedID".to_string(),
            });
        };

        // SessionIndex elements
        let session_index_nodes = find_child_elements(doc, node, SAML_PROTOCOL_NS, "SessionIndex");
        let mut session_indexes = Vec::with_capacity(session_index_nodes.len());
        for n in session_index_nodes {
            session_indexes.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(LogoutRequestRef {
            id,
            version,
            issue_instant,
            destination,
            consent,
            issuer,
            has_signature,
            not_on_or_after,
            reason,
            name_id,
            session_indexes,
        })
    }
}

// ── LogoutResponse ──────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for LogoutResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "LogoutResponse")?;

        let id = required_attribute(doc, node, "ID")?;
        let version_str = required_attribute(doc, node, "Version")?;
        let version = SamlVersion::try_from_str(version_str).ok_or_else(|| {
            XmlError::InvalidAttributeValue {
                element: "LogoutResponse".to_string(),
                attribute: "Version".to_string(),
                value: version_str.to_string(),
            }
        })?;
        let issue_instant = parse_datetime_attr(doc, node, "IssueInstant")?;
        let destination = optional_attribute(doc, node, "Destination");
        let consent = optional_attribute(doc, node, "Consent");
        let in_response_to = optional_attribute(doc, node, "InResponseTo");

        let issuer = find_child_element(doc, node, SAML_ASSERTION_NS, "Issuer")
            .map(|n| IssuerRef::from_xml(doc, n))
            .transpose()?;

        let has_signature = find_child_element(doc, node, XMLDSIG_NS, "Signature").is_some();

        // Status (required)
        let status_node =
            find_child_element(doc, node, SAML_PROTOCOL_NS, "Status").ok_or_else(|| {
                XmlError::MissingElement {
                    parent: "LogoutResponse".to_string(),
                    element: "Status".to_string(),
                }
            })?;
        let status = StatusRef::from_xml(doc, status_node)?;

        Ok(LogoutResponseRef {
            id,
            version,
            issue_instant,
            destination,
            consent,
            issuer,
            has_signature,
            in_response_to,
            status,
        })
    }
}

// ── ArtifactResolve ─────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ArtifactResolveRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "ArtifactResolve")?;
        let base = parse_request_base(doc, node)?;

        // Artifact (required)
        let artifact_node = find_child_element(doc, node, SAML_PROTOCOL_NS, "Artifact")
            .ok_or_else(|| XmlError::MissingElement {
                parent: "ArtifactResolve".to_string(),
                element: "Artifact".to_string(),
            })?;
        let artifact = doc.element_text(artifact_node).unwrap_or("");

        Ok(ArtifactResolveRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            artifact,
        })
    }
}

// ── ArtifactResponse ────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ArtifactResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "ArtifactResponse")?;
        let base = parse_response_base(doc, node)?;

        // The resolved message is any child element that is NOT Issuer, Signature, Status, or Extensions.
        // It's the actual SAML protocol message embedded in the response.
        // We store its raw XML source as bytes.
        let mut message: Option<&'a [u8]> = None;
        for child in doc.children_iter(node) {
            if let Some(elem) = doc.element(child) {
                // Skip standard StatusResponseType children
                if elem.matches_name_ns(SAML_ASSERTION_NS, "Issuer")
                    || elem.matches_name_ns(XMLDSIG_NS, "Signature")
                    || elem.matches_name_ns(SAML_PROTOCOL_NS, "Status")
                    || elem.matches_name_ns(SAML_PROTOCOL_NS, "Extensions")
                {
                    continue;
                }
                // This is the embedded SAML message
                if let Some(src) = doc.node_source(child) {
                    message = Some(src.as_bytes());
                }
                break;
            }
        }

        Ok(ArtifactResponseRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            in_response_to: base.in_response_to,
            status: base.status,
            message,
        })
    }
}

// ── ManageNameIdRequest ─────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ManageNameIdRequestRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "ManageNameIDRequest")?;
        let base = parse_request_base(doc, node)?;

        // NameID or EncryptedID (required)
        let name_id = if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else {
            return Err(XmlError::MissingElement {
                parent: "ManageNameIDRequest".to_string(),
                element: "NameID or EncryptedID".to_string(),
            });
        };

        // NewID, NewEncryptedID, or Terminate
        let new_id_or_terminate = if let Some(n) =
            find_child_element(doc, node, SAML_PROTOCOL_NS, "NewID")
        {
            let text = doc.element_text(n).unwrap_or("");
            NewIdOrTerminateRef::NewId(text)
        } else if let Some(n) = find_child_element(doc, node, SAML_PROTOCOL_NS, "NewEncryptedID") {
            let raw = doc.node_source(n).map(|s| s.as_bytes()).unwrap_or(b"");
            NewIdOrTerminateRef::NewEncryptedId(raw)
        } else if find_child_element(doc, node, SAML_PROTOCOL_NS, "Terminate").is_some() {
            NewIdOrTerminateRef::Terminate
        } else {
            return Err(XmlError::MissingElement {
                parent: "ManageNameIDRequest".to_string(),
                element: "NewID, NewEncryptedID, or Terminate".to_string(),
            });
        };

        Ok(ManageNameIdRequestRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            name_id,
            new_id_or_terminate,
        })
    }
}

// ── ManageNameIdResponse ────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for ManageNameIdResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "ManageNameIDResponse")?;
        let base = parse_response_base(doc, node)?;

        Ok(ManageNameIdResponseRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            in_response_to: base.in_response_to,
            status: base.status,
        })
    }
}

// ── NameIdMappingRequest ────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for NameIdMappingRequestRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "NameIDMappingRequest")?;
        let base = parse_request_base(doc, node)?;

        // NameID or EncryptedID (required)
        let name_id = if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID") {
            NameIdOrEncryptedIdRef::from_xml(doc, n)?
        } else {
            return Err(XmlError::MissingElement {
                parent: "NameIDMappingRequest".to_string(),
                element: "NameID or EncryptedID".to_string(),
            });
        };

        // NameIDPolicy (required)
        let name_id_policy_node = find_child_element(doc, node, SAML_PROTOCOL_NS, "NameIDPolicy")
            .ok_or_else(|| XmlError::MissingElement {
            parent: "NameIDMappingRequest".to_string(),
            element: "NameIDPolicy".to_string(),
        })?;
        let name_id_policy = NameIdPolicyRef::from_xml(doc, name_id_policy_node)?;

        Ok(NameIdMappingRequestRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            name_id,
            name_id_policy,
        })
    }
}

// ── NameIdMappingResponse ───────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for NameIdMappingResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "NameIDMappingResponse")?;
        let base = parse_response_base(doc, node)?;

        // Optional NameID or EncryptedID (present only on success)
        let name_id = if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "NameID") {
            Some(NameIdOrEncryptedIdRef::from_xml(doc, n)?)
        } else if let Some(n) = find_child_element(doc, node, SAML_ASSERTION_NS, "EncryptedID") {
            Some(NameIdOrEncryptedIdRef::from_xml(doc, n)?)
        } else {
            None
        };

        Ok(NameIdMappingResponseRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            in_response_to: base.in_response_to,
            status: base.status,
            name_id,
        })
    }
}

// ── AssertionIdRequest ──────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AssertionIdRequestRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "AssertionIDRequest")?;
        let base = parse_request_base(doc, node)?;

        // AssertionIDRef elements (one or more required)
        let id_ref_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "AssertionIDRef");
        let mut assertion_id_refs = Vec::with_capacity(id_ref_nodes.len());
        for n in id_ref_nodes {
            assertion_id_refs.push(doc.element_text(n).unwrap_or(""));
        }

        Ok(AssertionIdRequestRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            assertion_id_refs,
        })
    }
}

// ── AuthnQuery ──────────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthnQueryRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "AuthnQuery")?;
        let base = parse_request_base(doc, node)?;

        let session_index = optional_attribute(doc, node, "SessionIndex");

        // Subject (required for queries)
        let subject_node =
            find_child_element(doc, node, SAML_ASSERTION_NS, "Subject").ok_or_else(|| {
                XmlError::MissingElement {
                    parent: "AuthnQuery".to_string(),
                    element: "Subject".to_string(),
                }
            })?;
        let subject = SubjectRef::from_xml(doc, subject_node)?;

        // Optional RequestedAuthnContext
        let requested_authn_context =
            find_child_element(doc, node, SAML_PROTOCOL_NS, "RequestedAuthnContext")
                .map(|n| RequestedAuthnContextRef::from_xml(doc, n))
                .transpose()?;

        Ok(AuthnQueryRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            subject,
            session_index,
            requested_authn_context,
        })
    }
}

// ── AttributeQuery ──────────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AttributeQueryRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "AttributeQuery")?;
        let base = parse_request_base(doc, node)?;

        // Subject (required for queries)
        let subject_node =
            find_child_element(doc, node, SAML_ASSERTION_NS, "Subject").ok_or_else(|| {
                XmlError::MissingElement {
                    parent: "AttributeQuery".to_string(),
                    element: "Subject".to_string(),
                }
            })?;
        let subject = SubjectRef::from_xml(doc, subject_node)?;

        // Attribute elements (optional, empty means all)
        let attr_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Attribute");
        let mut attributes = Vec::with_capacity(attr_nodes.len());
        for attr_node in attr_nodes {
            attributes.push(AttributeRef::from_xml(doc, attr_node)?);
        }

        Ok(AttributeQueryRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            subject,
            attributes,
        })
    }
}

// ── AuthzDecisionQuery ──────────────────────────────────────────────────────

impl<'a> SamlDeserialize<'a> for AuthzDecisionQueryRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "AuthzDecisionQuery")?;
        let base = parse_request_base(doc, node)?;

        let resource = required_attribute(doc, node, "Resource")?;

        // Subject (required for queries)
        let subject_node =
            find_child_element(doc, node, SAML_ASSERTION_NS, "Subject").ok_or_else(|| {
                XmlError::MissingElement {
                    parent: "AuthzDecisionQuery".to_string(),
                    element: "Subject".to_string(),
                }
            })?;
        let subject = SubjectRef::from_xml(doc, subject_node)?;

        // Action elements (one or more required)
        let action_nodes = find_child_elements(doc, node, SAML_ASSERTION_NS, "Action");
        let mut actions = Vec::with_capacity(action_nodes.len());
        for action_node in action_nodes {
            actions.push(ActionRef::from_xml(doc, action_node)?);
        }

        // Optional Evidence
        let evidence = find_child_element(doc, node, SAML_ASSERTION_NS, "Evidence")
            .map(|n| EvidenceRef::from_xml(doc, n))
            .transpose()?;

        Ok(AuthzDecisionQueryRef {
            id: base.id,
            version: base.version,
            issue_instant: base.issue_instant,
            destination: base.destination,
            consent: base.consent,
            issuer: base.issuer,
            has_signature: base.has_signature,
            subject,
            resource,
            actions,
            evidence,
        })
    }
}
