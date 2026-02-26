// SamlSerialize implementations for owned protocol types.
//
// Each impl serializes the owned SAML protocol type to XML using the
// uppsala XmlWriter.

use uppsala::XmlWriter;

use swsaml_core::assertion::issuer::Issuer;
use swsaml_core::namespace::{SAML_ASSERTION_NS, SAML_PROTOCOL_NS};
use swsaml_core::protocol::artifact::{ArtifactResolve, ArtifactResponse};
use swsaml_core::protocol::logout::{LogoutRequest, LogoutResponse};
use swsaml_core::protocol::name_id_mapping::{NameIdMappingRequest, NameIdMappingResponse};
use swsaml_core::protocol::name_id_mgmt::{
    ManageNameIdRequest, ManageNameIdResponse, NewIdOrTerminate,
};
use swsaml_core::protocol::query::{
    AssertionIdRequest, AttributeQuery, AuthnQuery, AuthzDecisionQuery,
};
use swsaml_core::protocol::request::{AuthnRequest, RequestedAuthnContext, Scoping};
use swsaml_core::protocol::response::Response;
use swsaml_core::protocol::status::{Status, StatusCode};

use crate::error::XmlError;
use crate::helpers::format_datetime;
use crate::serialize::SamlSerialize;

// ── StatusCode ─────────────────────────────────────────────────────────────

impl SamlSerialize for StatusCode {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        if self.sub_status.is_some() {
            w.start_element("samlp:StatusCode", &[("Value", &self.value)]);
            if let Some(ref sub) = self.sub_status {
                sub.to_xml(w)?;
            }
            w.end_element("samlp:StatusCode");
        } else {
            w.empty_element("samlp:StatusCode", &[("Value", &self.value)]);
        }
        Ok(())
    }
}

// ── Status ─────────────────────────────────────────────────────────────────

impl SamlSerialize for Status {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element("samlp:Status", &[]);
        self.status_code.to_xml(w)?;
        if let Some(ref msg) = self.status_message {
            w.start_element("samlp:StatusMessage", &[]);
            w.text(msg);
            w.end_element("samlp:StatusMessage");
        }
        if let Some(ref detail) = self.status_detail {
            // StatusDetail raw XML
            w.raw(detail);
        }
        w.end_element("samlp:Status");
        Ok(())
    }
}

// ── Helper: write common request attributes ─────────────────────────────────

/// Common fields shared by all SAML request/response types, used to reduce
/// argument count when writing opening elements.
struct RequestStartParams<'a> {
    element_name: &'a str,
    id: &'a str,
    version: swsaml_core::identifiers::SamlVersion,
    issue_instant: &'a chrono::DateTime<chrono::Utc>,
    destination: Option<&'a str>,
    consent: Option<&'a str>,
    extra_attrs: &'a [(&'a str, &'a str)],
}

/// Write the opening element for a request type with all common attributes.
fn write_request_start(w: &mut XmlWriter, params: &RequestStartParams<'_>) {
    let instant_str = format_datetime(params.issue_instant);
    let mut attrs: Vec<(&str, &str)> = vec![
        ("xmlns:samlp", SAML_PROTOCOL_NS),
        ("xmlns:saml", SAML_ASSERTION_NS),
        ("ID", params.id),
        ("Version", params.version.as_str()),
        ("IssueInstant", &instant_str),
    ];
    if let Some(dest) = params.destination {
        attrs.push(("Destination", dest));
    }
    if let Some(c) = params.consent {
        attrs.push(("Consent", c));
    }
    for (k, v) in params.extra_attrs {
        attrs.push((k, v));
    }
    w.start_element(params.element_name, &attrs);
}

/// Write optional Issuer element.
fn write_issuer(w: &mut XmlWriter, issuer: &Option<Issuer>) -> Result<(), XmlError> {
    if let Some(ref iss) = issuer {
        iss.to_xml(w)?;
    }
    Ok(())
}

// ── RequestedAuthnContext ────────────────────────────────────────────────────

impl SamlSerialize for RequestedAuthnContext {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        w.start_element(
            "samlp:RequestedAuthnContext",
            &[("Comparison", self.comparison.as_str())],
        );
        for class_ref in &self.authn_context_class_refs {
            w.start_element("saml:AuthnContextClassRef", &[]);
            w.text(class_ref);
            w.end_element("saml:AuthnContextClassRef");
        }
        for decl_ref in &self.authn_context_decl_refs {
            w.start_element("saml:AuthnContextDeclRef", &[]);
            w.text(decl_ref);
            w.end_element("saml:AuthnContextDeclRef");
        }
        w.end_element("samlp:RequestedAuthnContext");
        Ok(())
    }
}

// ── Scoping ─────────────────────────────────────────────────────────────────

impl SamlSerialize for Scoping {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let proxy_count_str;
        let mut attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(count) = self.proxy_count {
            proxy_count_str = count.to_string();
            attrs.push(("ProxyCount", &proxy_count_str));
        }
        w.start_element("samlp:Scoping", &attrs);

        // IDPList
        if !self.idp_list.is_empty() {
            w.start_element("samlp:IDPList", &[]);
            for idp in &self.idp_list {
                w.empty_element("samlp:IDPEntry", &[("ProviderID", idp.as_str())]);
            }
            w.end_element("samlp:IDPList");
        }

        // RequesterID elements
        for requester_id in &self.requester_ids {
            w.start_element("samlp:RequesterID", &[]);
            w.text(requester_id);
            w.end_element("samlp:RequesterID");
        }

        w.end_element("samlp:Scoping");
        Ok(())
    }
}

// ── AuthnRequest ────────────────────────────────────────────────────────────

impl SamlSerialize for AuthnRequest {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, String)> = Vec::new();
        if let Some(fa) = self.force_authn {
            extra_attrs.push(("ForceAuthn", fa.to_string()));
        }
        if let Some(ip) = self.is_passive {
            extra_attrs.push(("IsPassive", ip.to_string()));
        }
        if let Some(idx) = self.assertion_consumer_service_index {
            extra_attrs.push(("AssertionConsumerServiceIndex", idx.to_string()));
        }
        if let Some(ref url) = self.assertion_consumer_service_url {
            extra_attrs.push(("AssertionConsumerServiceURL", url.clone()));
        }
        if let Some(ref pb) = self.protocol_binding {
            extra_attrs.push(("ProtocolBinding", pb.clone()));
        }
        if let Some(idx) = self.attribute_consuming_service_index {
            extra_attrs.push(("AttributeConsumingServiceIndex", idx.to_string()));
        }
        if let Some(ref pn) = self.provider_name {
            extra_attrs.push(("ProviderName", pn.clone()));
        }

        let extra_refs: Vec<(&str, &str)> =
            extra_attrs.iter().map(|(k, v)| (*k, v.as_str())).collect();

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:AuthnRequest",
                id: &self.base.id,
                version: self.base.version,
                issue_instant: &self.base.issue_instant,
                destination: self.base.destination.as_deref(),
                consent: self.base.consent.as_deref(),
                extra_attrs: &extra_refs,
            },
        );

        write_issuer(w, &self.base.issuer)?;
        // Note: Signature is NOT serialized here - it's added by the signing layer

        if let Some(ref subject) = self.subject {
            subject.to_xml(w)?;
        }
        if let Some(ref nip) = self.name_id_policy {
            nip.to_xml(w)?;
        }
        if let Some(ref conditions) = self.conditions {
            conditions.to_xml(w)?;
        }
        if let Some(ref rac) = self.requested_authn_context {
            rac.to_xml(w)?;
        }
        if let Some(ref scoping) = self.scoping {
            scoping.to_xml(w)?;
        }

        w.end_element("samlp:AuthnRequest");
        Ok(())
    }
}

// ── Response ────────────────────────────────────────────────────────────────

impl SamlSerialize for Response {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref irt) = self.base.in_response_to {
            extra_attrs.push(("InResponseTo", irt));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:Response",
                id: &self.base.id,
                version: self.base.version,
                issue_instant: &self.base.issue_instant,
                destination: self.base.destination.as_deref(),
                consent: self.base.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.base.issuer)?;
        // Note: Signature is NOT serialized here - it's added by the signing layer
        self.base.status.to_xml(w)?;

        for assertion in &self.assertions {
            assertion.to_xml(w)?;
        }
        for enc_assertion in &self.encrypted_assertions {
            let raw_str = std::str::from_utf8(&enc_assertion.raw)
                .map_err(|e| XmlError::SerializationError(e.to_string()))?;
            w.raw(raw_str);
        }

        w.end_element("samlp:Response");
        Ok(())
    }
}

// ── LogoutRequest ───────────────────────────────────────────────────────────

impl SamlSerialize for LogoutRequest {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, String)> = Vec::new();
        if let Some(ref nooa) = self.not_on_or_after {
            extra_attrs.push(("NotOnOrAfter", format_datetime(nooa)));
        }
        if let Some(ref reason) = self.reason {
            extra_attrs.push(("Reason", reason.clone()));
        }

        let extra_refs: Vec<(&str, &str)> =
            extra_attrs.iter().map(|(k, v)| (*k, v.as_str())).collect();

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:LogoutRequest",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_refs,
            },
        );

        write_issuer(w, &self.issuer)?;

        self.name_id.to_xml(w)?;

        for si in &self.session_indexes {
            w.start_element("samlp:SessionIndex", &[]);
            w.text(si);
            w.end_element("samlp:SessionIndex");
        }

        w.end_element("samlp:LogoutRequest");
        Ok(())
    }
}

// ── LogoutResponse ──────────────────────────────────────────────────────────

impl SamlSerialize for LogoutResponse {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref irt) = self.in_response_to {
            extra_attrs.push(("InResponseTo", irt));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:LogoutResponse",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.issuer)?;
        self.status.to_xml(w)?;

        w.end_element("samlp:LogoutResponse");
        Ok(())
    }
}

// ── ArtifactResolve ─────────────────────────────────────────────────────────

impl SamlSerialize for ArtifactResolve {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:ArtifactResolve",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[],
            },
        );

        write_issuer(w, &self.issuer)?;

        w.start_element("samlp:Artifact", &[]);
        w.text(&self.artifact);
        w.end_element("samlp:Artifact");

        w.end_element("samlp:ArtifactResolve");
        Ok(())
    }
}

// ── ArtifactResponse ────────────────────────────────────────────────────────

impl SamlSerialize for ArtifactResponse {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref irt) = self.in_response_to {
            extra_attrs.push(("InResponseTo", irt));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:ArtifactResponse",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.issuer)?;
        self.status.to_xml(w)?;

        // Embedded SAML message as raw XML
        if let Some(ref msg) = self.message {
            let raw_str = std::str::from_utf8(msg)
                .map_err(|e| XmlError::SerializationError(e.to_string()))?;
            w.raw(raw_str);
        }

        w.end_element("samlp:ArtifactResponse");
        Ok(())
    }
}

// ── ManageNameIdRequest ─────────────────────────────────────────────────────

impl SamlSerialize for ManageNameIdRequest {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:ManageNameIDRequest",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[],
            },
        );

        write_issuer(w, &self.issuer)?;

        self.name_id.to_xml(w)?;

        match &self.new_id_or_terminate {
            NewIdOrTerminate::NewId(new_id) => {
                w.start_element("samlp:NewID", &[]);
                w.text(new_id);
                w.end_element("samlp:NewID");
            }
            NewIdOrTerminate::NewEncryptedId(raw) => {
                let raw_str = std::str::from_utf8(raw)
                    .map_err(|e| XmlError::SerializationError(e.to_string()))?;
                w.raw(raw_str);
            }
            NewIdOrTerminate::Terminate => {
                w.empty_element("samlp:Terminate", &[]);
            }
        }

        w.end_element("samlp:ManageNameIDRequest");
        Ok(())
    }
}

// ── ManageNameIdResponse ────────────────────────────────────────────────────

impl SamlSerialize for ManageNameIdResponse {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref irt) = self.in_response_to {
            extra_attrs.push(("InResponseTo", irt));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:ManageNameIDResponse",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.issuer)?;
        self.status.to_xml(w)?;

        w.end_element("samlp:ManageNameIDResponse");
        Ok(())
    }
}

// ── NameIdMappingRequest ────────────────────────────────────────────────────

impl SamlSerialize for NameIdMappingRequest {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:NameIDMappingRequest",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[],
            },
        );

        write_issuer(w, &self.issuer)?;

        self.name_id.to_xml(w)?;
        self.name_id_policy.to_xml(w)?;

        w.end_element("samlp:NameIDMappingRequest");
        Ok(())
    }
}

// ── NameIdMappingResponse ───────────────────────────────────────────────────

impl SamlSerialize for NameIdMappingResponse {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref irt) = self.in_response_to {
            extra_attrs.push(("InResponseTo", irt));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:NameIDMappingResponse",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.issuer)?;
        self.status.to_xml(w)?;

        if let Some(ref name_id) = self.name_id {
            name_id.to_xml(w)?;
        }

        w.end_element("samlp:NameIDMappingResponse");
        Ok(())
    }
}

// ── AssertionIdRequest ──────────────────────────────────────────────────────

impl SamlSerialize for AssertionIdRequest {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:AssertionIDRequest",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[],
            },
        );

        write_issuer(w, &self.issuer)?;

        for id_ref in &self.assertion_id_refs {
            w.start_element("saml:AssertionIDRef", &[]);
            w.text(id_ref);
            w.end_element("saml:AssertionIDRef");
        }

        w.end_element("samlp:AssertionIDRequest");
        Ok(())
    }
}

// ── AuthnQuery ──────────────────────────────────────────────────────────────

impl SamlSerialize for AuthnQuery {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        let mut extra_attrs: Vec<(&str, &str)> = Vec::new();
        if let Some(ref si) = self.session_index {
            extra_attrs.push(("SessionIndex", si));
        }

        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:AuthnQuery",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &extra_attrs,
            },
        );

        write_issuer(w, &self.issuer)?;

        self.subject.to_xml(w)?;

        if let Some(ref rac) = self.requested_authn_context {
            rac.to_xml(w)?;
        }

        w.end_element("samlp:AuthnQuery");
        Ok(())
    }
}

// ── AttributeQuery ──────────────────────────────────────────────────────────

impl SamlSerialize for AttributeQuery {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:AttributeQuery",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[],
            },
        );

        write_issuer(w, &self.issuer)?;

        self.subject.to_xml(w)?;

        for attr in &self.attributes {
            attr.to_xml(w)?;
        }

        w.end_element("samlp:AttributeQuery");
        Ok(())
    }
}

// ── AuthzDecisionQuery ──────────────────────────────────────────────────────

impl SamlSerialize for AuthzDecisionQuery {
    fn to_xml(&self, w: &mut XmlWriter) -> Result<(), XmlError> {
        write_request_start(
            w,
            &RequestStartParams {
                element_name: "samlp:AuthzDecisionQuery",
                id: &self.id,
                version: self.version,
                issue_instant: &self.issue_instant,
                destination: self.destination.as_deref(),
                consent: self.consent.as_deref(),
                extra_attrs: &[("Resource", &self.resource)],
            },
        );

        write_issuer(w, &self.issuer)?;

        self.subject.to_xml(w)?;

        for action in &self.actions {
            action.to_xml(w)?;
        }

        if let Some(ref evidence) = self.evidence {
            evidence.to_xml(w)?;
        }

        w.end_element("samlp:AuthzDecisionQuery");
        Ok(())
    }
}
