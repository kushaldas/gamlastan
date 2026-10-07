// SamlDeserialize implementations for borrowed protocol types.
//
// Each impl deserializes from an uppsala Document node into the zero-copy
// borrowed SAML protocol type, with all &str fields borrowing from the document buffer.

use uppsala::{Document, NodeId};

use crate::core::assertion::attribute::AttributeRef;
use crate::core::assertion::authz::{ActionRef, EvidenceRef};
use crate::core::assertion::conditions::ConditionsRef;
use crate::core::assertion::issuer::IssuerRef;
use crate::core::assertion::name_id::{NameIdOrEncryptedIdRef, NameIdPolicyRef};
use crate::core::assertion::subject::SubjectRef;
use crate::core::assertion::types::{AssertionRef, EncryptedAssertionRef};
use crate::core::identifiers::SamlVersion;
use crate::core::namespace::{SAML_ASSERTION_NS, SAML_PROTOCOL_NS, XMLDSIG_NS};
use crate::core::protocol::artifact::{ArtifactResolveRef, ArtifactResponseRef};
use crate::core::protocol::logout::{LogoutRequestRef, LogoutResponseRef};
use crate::core::protocol::name_id_mapping::{NameIdMappingRequestRef, NameIdMappingResponseRef};
use crate::core::protocol::name_id_mgmt::{
    ManageNameIdRequestRef, ManageNameIdResponseRef, NewIdOrTerminateRef,
};
use crate::core::protocol::query::{
    AssertionIdRequestRef, AttributeQueryRef, AuthnQueryRef, AuthzDecisionQueryRef,
};
use crate::core::protocol::request::{
    AuthnContextComparison, AuthnRequestRef, RequestBaseRef, RequestedAuthnContextRef, ScopingRef,
};
use crate::core::protocol::response::{ResponseBaseRef, ResponseRef};
use crate::core::protocol::status::{StatusCodeRef, StatusRef};

use crate::xml::deserialize::SamlDeserialize;
use crate::xml::error::XmlError;
use crate::xml::helpers::{
    find_child_element, find_child_elements, find_unique_child_element, optional_attribute,
    parse_datetime_attr, parse_optional_bool_attr, parse_optional_datetime_attr,
    parse_optional_u16_attr, parse_optional_u32_attr, required_attribute, verify_element,
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
        if let Some(idp_list_node) =
            find_unique_child_element(doc, node, SAML_PROTOCOL_NS, "IDPList")?
        {
            let entry_nodes = find_child_elements(doc, idp_list_node, SAML_PROTOCOL_NS, "IDPEntry");
            for entry_node in entry_nodes {
                // ProviderID is required. Dropping an entry that lacks it would
                // quietly turn a restrictive list into a shorter, or empty,
                // one, and an empty list reads as "no restriction".
                idp_list.push(required_attribute(doc, entry_node, "ProviderID")?);
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
        let subject = find_unique_child_element(doc, node, SAML_ASSERTION_NS, "Subject")?
            .map(|n| SubjectRef::from_xml(doc, n))
            .transpose()?;

        // Optional NameIDPolicy
        let name_id_policy =
            find_unique_child_element(doc, node, SAML_PROTOCOL_NS, "NameIDPolicy")?
                .map(|n| NameIdPolicyRef::from_xml(doc, n))
                .transpose()?;

        // Optional Conditions
        let conditions = find_unique_child_element(doc, node, SAML_ASSERTION_NS, "Conditions")?
            .map(|n| ConditionsRef::from_xml(doc, n))
            .transpose()?;

        // Optional RequestedAuthnContext
        let requested_authn_context =
            find_unique_child_element(doc, node, SAML_PROTOCOL_NS, "RequestedAuthnContext")?
                .map(|n| RequestedAuthnContextRef::from_xml(doc, n))
                .transpose()?;

        // Optional Scoping
        let scoping = find_unique_child_element(doc, node, SAML_PROTOCOL_NS, "Scoping")?
            .map(|n| ScopingRef::from_xml(doc, n))
            .transpose()?;

        // Optional Extensions (kept as raw XML; content is opaque here)
        let extensions = find_child_element(doc, node, SAML_PROTOCOL_NS, "Extensions")
            .and_then(|n| doc.node_source(n));

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
            extensions,
        })
    }
}

// ── Response ────────────────────────────────────────────────────────────────

/// SAML protocol *request* elements that must never appear as a direct child
/// of a `<samlp:Response>`. Their presence indicates a signature-wrapping /
/// request-smuggling attempt rather than a legitimate response.
const FORBIDDEN_RESPONSE_CHILDREN: &[&str] = &[
    "AuthnRequest",
    "LogoutRequest",
    "ArtifactResolve",
    "AttributeQuery",
    "AuthnQuery",
    "AuthzDecisionQuery",
    "AssertionIDRequest",
    "ManageNameIDRequest",
    "NameIDMappingRequest",
];

impl<'a> SamlDeserialize<'a> for ResponseRef<'a> {
    fn from_xml(doc: &'a Document<'a>, node: NodeId) -> Result<Self, XmlError> {
        verify_element(doc, node, SAML_PROTOCOL_NS, "Response")?;

        // Reject smuggled protocol *request* elements. A well-formed Response's
        // only protocol-namespace children are Status (and, per binding, an
        // enveloped Signature/Extensions); a nested request such as
        // AuthnRequest is never legitimate and is a classic wrapping vector, so
        // fail closed if one appears as a direct child.
        for forbidden in FORBIDDEN_RESPONSE_CHILDREN {
            if !find_child_elements(doc, node, SAML_PROTOCOL_NS, forbidden).is_empty() {
                return Err(XmlError::UnexpectedElement(format!(
                    "{forbidden} element is not allowed inside a SAML Response"
                )));
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;

    fn authn_request(children: &str) -> String {
        format!(
            r#"<samlp:AuthnRequest {NS} ID="_a1" Version="2.0" IssueInstant="2026-10-01T00:00:00Z"><saml:Issuer>https://sp.example.org</saml:Issuer>{children}</samlp:AuthnRequest>"#
        )
    }

    fn parse(xml: &str) -> Result<(), XmlError> {
        let doc = uppsala::parse(xml).unwrap();
        let root = doc.document_element().unwrap();
        AuthnRequestRef::from_xml(&doc, root).map(|_| ())
    }

    const SUBJECT: &str = "<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>";
    const POLICY: &str = r#"<samlp:NameIDPolicy AllowCreate="true"/>"#;
    const CLASS_CONTEXT: &str = "<samlp:RequestedAuthnContext><saml:AuthnContextClassRef>urn:c</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>";
    const DECL_CONTEXT: &str = "<samlp:RequestedAuthnContext><saml:AuthnContextDeclRef>urn:d</saml:AuthnContextDeclRef></samlp:RequestedAuthnContext>";
    const SCOPING: &str = r#"<samlp:Scoping ProxyCount="1"><samlp:IDPList><samlp:IDPEntry ProviderID="https://idp.example.org"/></samlp:IDPList></samlp:Scoping>"#;

    #[test]
    fn each_singleton_child_may_appear_once() {
        let xml = authn_request(&format!(
            "{SUBJECT}{POLICY}<saml:Conditions/>{CLASS_CONTEXT}{SCOPING}"
        ));
        parse(&xml).expect("a request with each element once is well formed");
    }

    #[test]
    fn a_duplicated_singleton_child_is_rejected_not_silently_read_once() {
        // Reading only the first of two would ignore the second, so a later
        // RequestedAuthnContext carrying a declaration would never be seen.
        for (name, doubled) in [
            ("Subject", format!("{SUBJECT}{SUBJECT}")),
            ("NameIDPolicy", format!("{POLICY}{POLICY}")),
            (
                "Conditions",
                "<saml:Conditions/><saml:Conditions/>".to_string(),
            ),
            (
                "RequestedAuthnContext",
                format!("{CLASS_CONTEXT}{DECL_CONTEXT}"),
            ),
            ("Scoping", format!("{SCOPING}{SCOPING}")),
        ] {
            let err = parse(&authn_request(&doubled)).expect_err(name);
            assert!(
                matches!(&err, XmlError::UnexpectedElement(m) if m.contains(name)),
                "{name}: {err}"
            );
        }
    }

    #[test]
    fn an_idp_entry_without_a_provider_id_is_rejected() {
        // ProviderID is required. Dropping the entry would shrink a restrictive
        // list, possibly to an empty one, which reads as "no restriction".
        let xml = authn_request(
            r#"<samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="https://a.example.org"/><samlp:IDPEntry/></samlp:IDPList></samlp:Scoping>"#,
        );
        assert!(matches!(
            parse(&xml),
            Err(XmlError::MissingAttribute { ref attribute, .. }) if attribute == "ProviderID"
        ));
    }

    #[test]
    fn a_duplicated_idp_list_is_rejected() {
        let xml = authn_request(
            r#"<samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="https://a.example.org"/></samlp:IDPList><samlp:IDPList/></samlp:Scoping>"#,
        );
        assert!(matches!(parse(&xml), Err(XmlError::UnexpectedElement(_))));
    }

    #[test]
    fn scoping_entries_are_read_when_well_formed() {
        let xml = authn_request(SCOPING);
        let doc = uppsala::parse(&xml).unwrap();
        let root = doc.document_element().unwrap();
        let request = AuthnRequestRef::from_xml(&doc, root).unwrap();
        let scoping = request.scoping.expect("scoping");
        assert_eq!(scoping.proxy_count, Some(1));
        assert_eq!(scoping.idp_list, vec!["https://idp.example.org"]);
    }
}
