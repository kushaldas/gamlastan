// SAML 2.0 Web Browser SSO Profile - IdP side
//
// SAML Profiles Section 4.1
//
// IdP-side operations:
// - process_authn_request: Validate incoming AuthnRequest from SP
// - create_response: Build Response with assertions for SP
// - create_unsolicited_response: Build unsolicited (IdP-initiated) Response

use chrono::{DateTime, TimeDelta, Utc};

use crate::core::assertion::attribute::{Attribute, AttributeStatement};
use crate::core::assertion::authn::{AuthnContext, AuthnStatement, SubjectLocality};
use crate::core::assertion::conditions::{AudienceRestriction, Conditions};
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use crate::core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
use crate::core::assertion::types::{Advice, Assertion, EncryptedAssertion};
use crate::core::constants;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::namespace;
use crate::core::protocol::request::AuthnRequest;
use crate::core::protocol::response::{Response, ResponseBase};
use crate::core::protocol::status::Status;
use crate::crypto::encryptor::{
    encrypted_data_template_for_cert, CertEncryptionOptions, SamlEncryptor,
};
use crate::metadata::types::sp::SpSsoDescriptor;

use crate::crypto::SamlSigner;
use crate::profiles::error::ProfileError;
use crate::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use crate::xml::serialize::SamlSerialize;

/// Result of processing an AuthnRequest on the IdP side.
#[derive(Debug, Clone)]
pub struct ProcessedAuthnRequest {
    /// The request ID (for InResponseTo).
    pub request_id: String,

    /// SP entity ID (from Issuer).
    pub sp_entity_id: String,

    /// The ACS URL where the response should be sent.
    pub acs_url: String,

    /// The ACS binding to use for the response.
    pub acs_binding: String,

    /// Whether to force re-authentication.
    pub force_authn: bool,

    /// Whether the IdP should not visually interact with the user.
    pub is_passive: bool,

    /// Requested NameID format (from NameIDPolicy).
    pub requested_name_id_format: Option<String>,

    /// Whether creation of new identifiers is allowed (E14).
    pub allow_create: bool,

    /// Requested authentication context class refs.
    pub requested_authn_context_class_refs: Vec<String>,

    /// Authentication context comparison type.
    pub authn_context_comparison: Option<crate::core::protocol::request::AuthnContextComparison>,

    /// AttributeConsumingServiceIndex.
    pub attribute_consuming_service_index: Option<u16>,

    /// Raw XML of the request's `samlp:Extensions` element, if present
    /// (e.g. PEFIM SPCertEnc; see `profiles::pefim`).
    pub extensions: Option<String>,
}

/// Process an incoming AuthnRequest on the IdP side.
///
/// Validates the request structure and extracts parameters needed for
/// authentication and response generation.
///
/// Per Profiles 4.1.4.1:
/// - Verify ACS URL belongs to the SP (MITM prevention)
/// - Respect ForceAuthn and IsPassive
/// - Respect RequestedAuthnContext
pub fn process_authn_request(
    request: &AuthnRequest,
    sp_metadata: Option<&SpSsoDescriptor>,
) -> Result<ProcessedAuthnRequest, ProfileError> {
    // Extract SP entity ID from Issuer
    let sp_entity_id = request
        .base
        .issuer
        .as_ref()
        .ok_or(ProfileError::MissingIssuer)?
        .value
        .clone();

    // Determine ACS URL and binding
    let (acs_url, acs_binding) = resolve_acs_endpoint(request, sp_metadata)?;

    // Extract ForceAuthn and IsPassive
    let force_authn = request.force_authn.unwrap_or(false);
    let is_passive = request.is_passive.unwrap_or(false);

    // Extract NameIDPolicy
    let (requested_name_id_format, allow_create) = match &request.name_id_policy {
        Some(policy) => (policy.format.clone(), policy.allow_create),
        None => (None, false),
    };

    // Extract RequestedAuthnContext
    let (requested_authn_context_class_refs, authn_context_comparison) =
        match &request.requested_authn_context {
            Some(ctx) => (ctx.authn_context_class_refs.clone(), Some(ctx.comparison)),
            None => (vec![], None),
        };

    Ok(ProcessedAuthnRequest {
        request_id: request.base.id.clone(),
        sp_entity_id,
        acs_url,
        acs_binding,
        force_authn,
        is_passive,
        requested_name_id_format,
        allow_create,
        requested_authn_context_class_refs,
        authn_context_comparison,
        attribute_consuming_service_index: request.attribute_consuming_service_index,
        extensions: request.extensions.clone(),
    })
}

/// Resolve the ACS endpoint URL and binding from the AuthnRequest and SP metadata.
///
/// Priority:
/// 1. AssertionConsumerServiceURL + ProtocolBinding from request (must be verified against metadata)
/// 2. AssertionConsumerServiceIndex from request
/// 3. Default ACS from SP metadata
fn resolve_acs_endpoint(
    request: &AuthnRequest,
    sp_metadata: Option<&SpSsoDescriptor>,
) -> Result<(String, String), ProfileError> {
    // Option 1: URL directly specified in request
    if let Some(url) = &request.assertion_consumer_service_url {
        let binding = request
            .protocol_binding
            .as_deref()
            .unwrap_or("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        // If we have SP metadata, verify the URL is legitimate
        if let Some(sp) = sp_metadata {
            let found = sp
                .assertion_consumer_services
                .iter()
                .any(|ep| ep.endpoint.location == *url);
            if !found {
                return Err(ProfileError::AcsUrlMismatch);
            }
        }

        return Ok((url.clone(), binding.to_string()));
    }

    // Option 2: Index specified in request
    if let Some(index) = request.assertion_consumer_service_index {
        if let Some(sp) = sp_metadata {
            if let Some(ep) = sp
                .assertion_consumer_services
                .iter()
                .find(|e| e.index == index)
            {
                return Ok((ep.endpoint.location.clone(), ep.endpoint.binding.clone()));
            }
        }
        return Err(ProfileError::NoAcsEndpoint(format!(
            "index {} not found in SP metadata",
            index
        )));
    }

    // Option 3: Default from SP metadata
    if let Some(sp) = sp_metadata {
        let default =
            crate::profiles::sso::sp::find_default_acs_endpoint(&sp.assertion_consumer_services);
        if let Some(ep) = default {
            return Ok((ep.endpoint.location.clone(), ep.endpoint.binding.clone()));
        }
    }

    Err(ProfileError::NoAcsEndpoint(
        "no ACS endpoint could be resolved".to_string(),
    ))
}

/// Create a SAML Response for SP-initiated SSO.
///
/// Per Profiles 4.1.4.2:
/// - At least one Assertion with AuthnStatement
/// - Bearer SubjectConfirmation with Recipient (= ACS URL) + NotOnOrAfter
/// - InResponseTo = request ID
/// - AudienceRestriction with SP entity ID
/// - SessionIndex for SLO support
pub fn create_response(
    options: &ResponseOptions,
    principal_name_id: &NameId,
    times: ResponseTimes,
) -> Response {
    // Everything except AuthnInstant derives from the document issue instant.
    let now = times.issue_instant;
    let assertion_lifetime = TimeDelta::seconds(options.assertion_lifetime_seconds as i64);
    let not_on_or_after = now + assertion_lifetime;

    // Build SubjectConfirmation (bearer)
    let subject_confirmation = SubjectConfirmation {
        method: constants::CM_BEARER.to_string(),
        name_id: None,
        subject_confirmation_data: Some(SubjectConfirmationData {
            not_before: None,
            not_on_or_after: Some(not_on_or_after),
            recipient: Some(options.acs_url.clone()),
            in_response_to: options.in_response_to.clone(),
            address: options.client_address.clone(),
            key_info_x509_certs: vec![],
        }),
    };

    // Build Subject
    let subject = Subject {
        name_id: Some(NameIdOrEncryptedId::NameId(principal_name_id.clone())),
        subject_confirmations: vec![subject_confirmation],
    };

    // Build Conditions with AudienceRestriction
    let conditions = Conditions {
        not_before: Some(now),
        not_on_or_after: Some(not_on_or_after),
        audience_restrictions: vec![AudienceRestriction {
            audiences: vec![options.sp_entity_id.clone()],
        }],
        one_time_use: false,
        proxy_restriction: None,
    };

    // Build AuthnStatement
    let authn_statement = AuthnStatement {
        authn_instant: times.authn_instant,
        session_index: options.session_index.clone(),
        session_not_on_or_after: options.session_not_on_or_after,
        subject_locality: options.client_address.as_ref().map(|addr| SubjectLocality {
            address: Some(addr.clone()),
            dns_name: None,
        }),
        authn_context: AuthnContext {
            authn_context_class_ref: options.authn_context_class_ref.clone(),
            authn_context_decl_ref: None,
            authenticating_authorities: vec![],
        },
    };

    // Build AttributeStatement (if attributes provided)
    let attribute_statements = if options.attributes.is_empty() {
        vec![]
    } else {
        vec![AttributeStatement {
            attributes: options.attributes.clone(),
        }]
    };

    // Build Assertion
    let assertion = Assertion {
        id: SamlId::generate().as_str().to_string(),
        version: SamlVersion::V2_0,
        issue_instant: now,
        issuer: Issuer::entity(&options.idp_entity_id),
        has_signature: false,
        subject: Some(subject),
        conditions: Some(conditions),
        advice: None,
        authn_statements: vec![authn_statement],
        authz_decision_statements: vec![],
        attribute_statements,
    };

    // Build Response
    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some(options.acs_url.clone()),
            consent: None,
            issuer: Some(Issuer::entity(&options.idp_entity_id)),
            has_signature: false,
            in_response_to: options.in_response_to.clone(),
            status: Status::success(),
        },
        assertions: vec![assertion],
        encrypted_assertions: vec![],
    }
}

/// Build an error `Response` carrying the given (non-success) status and no
/// assertions.
///
/// Per Core 3.2.2 an error response keeps `InResponseTo` when it answers a
/// request, and per Profiles 4.1.4.2 it is delivered to the SP's ACS like any
/// other response. The response is returned unsigned; assertion-less error
/// responses are commonly sent without a signature, but callers may sign the
/// envelope before delivery if their deployment profile requires it.
pub fn create_error_response(
    idp_entity_id: &str,
    in_response_to: Option<&str>,
    acs_url: &str,
    status: Status,
    now: DateTime<Utc>,
) -> Response {
    Response {
        base: ResponseBase {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            destination: Some(acs_url.to_string()),
            consent: None,
            issuer: Some(Issuer::entity(idp_entity_id)),
            has_signature: false,
            in_response_to: in_response_to.map(|s| s.to_string()),
            status,
        },
        assertions: vec![],
        encrypted_assertions: vec![],
    }
}

// ── Per-request encryption & encrypted Advice ──────────────────────────────

/// Serialize an assertion as a self-contained (namespace-complete) XML
/// document, suitable for standalone encryption.
///
/// The serializer declares `xmlns:saml` on the `<saml:Assertion>` element
/// and every nested namespace (xsi/xs/ds) inline, so the produced fragment
/// decrypts and parses without inheriting declarations from a parent
/// document (pysaml2 `encrypt_assertion_self_contained`).
pub fn assertion_to_self_contained_xml(assertion: &Assertion) -> Result<String, ProfileError> {
    use crate::xml::serialize::SamlSerialize;
    Ok(assertion.to_xml_string()?)
}

/// Encrypt one assertion toward a recipient certificate (DER) supplied at
/// request time — the PEFIM `encrypt_cert_assertion` flow.
///
/// The cert typically comes from the AuthnRequest's `pefim:SPCertEnc`
/// extension (see [`crate::profiles::pefim::first_encryption_cert_der`])
/// rather than from SP metadata.
pub fn encrypt_assertion_to_cert(
    assertion: &Assertion,
    recipient_cert_der: &[u8],
    options: Option<&CertEncryptionOptions>,
) -> Result<EncryptedAssertion, ProfileError> {
    let default_options = CertEncryptionOptions::default();
    let options = options.unwrap_or(&default_options);

    // Fresh session key per call; wrapped for the supplied cert's RSA key.
    let encryptor = SamlEncryptor::for_certificate(recipient_cert_der)?;
    let template = encrypted_data_template_for_cert(recipient_cert_der, options);

    let plaintext = assertion_to_self_contained_xml(assertion)?;
    let encrypted = encryptor.encrypt(&template, plaintext.as_bytes())?;

    // Wrap the EncryptedData in the SAML envelope element.
    let wrapped = format!(
        "<saml:EncryptedAssertion xmlns:saml=\"{}\">{}</saml:EncryptedAssertion>",
        crate::core::namespace::SAML_ASSERTION_NS,
        encrypted
    );
    Ok(EncryptedAssertion {
        raw: wrapped.into_bytes(),
    })
}

/// Encrypt every cleartext assertion in `response` toward the
/// request-supplied cert, moving each into `response.encrypted_assertions`.
///
/// The cleartext `assertions` vector is drained, so no assertion is encrypted
/// twice and re-invoking this on the result is a no-op. Assertions already
/// present in `encrypted_assertions` are preserved as-is (not re-encrypted and
/// not dropped); the freshly encrypted assertions are appended after them.
pub fn encrypt_response_assertions_to_cert(
    mut response: Response,
    recipient_cert_der: &[u8],
    options: Option<&CertEncryptionOptions>,
) -> Result<Response, ProfileError> {
    let assertions = std::mem::take(&mut response.assertions);
    let mut newly_encrypted = Vec::with_capacity(assertions.len());
    for assertion in &assertions {
        newly_encrypted.push(encrypt_assertion_to_cert(
            assertion,
            recipient_cert_der,
            options,
        )?);
    }
    response.encrypted_assertions.extend(newly_encrypted);
    Ok(response)
}

/// Attach an encrypted assertion inside the main assertion's `saml:Advice`
/// (pysaml2 `encrypted_advice_attributes` + `encrypt_cert_advice`).
///
/// The advice assertion (typically carrying the attribute statement) is
/// encrypted toward the supplied certificate and embedded; relying parties
/// that cannot process it may ignore it, per Core 2.6.1.
pub fn add_encrypted_advice(
    assertion: &mut Assertion,
    advice_assertion: &Assertion,
    recipient_cert_der: &[u8],
    options: Option<&CertEncryptionOptions>,
) -> Result<(), ProfileError> {
    let encrypted = encrypt_assertion_to_cert(advice_assertion, recipient_cert_der, options)?;
    assertion
        .advice
        .get_or_insert_with(Advice::default)
        .encrypted_assertions
        .push(encrypted);
    Ok(())
}

/// Create an unsolicited (IdP-initiated) SAML Response.
///
/// Per Profiles 4.1.5:
/// - No InResponseTo
/// - Use default ACS endpoint from metadata
#[allow(clippy::too_many_arguments)]
pub fn create_unsolicited_response(
    idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    principal_name_id: &NameId,
    attributes: &[Attribute],
    authn_context_class_ref: Option<&str>,
    assertion_lifetime_seconds: u64,
    session_index: Option<&str>,
    session_not_on_or_after: Option<DateTime<Utc>>,
    client_address: Option<&str>,
    times: ResponseTimes,
) -> Response {
    let options = ResponseOptions {
        idp_entity_id: idp_entity_id.to_string(),
        in_response_to: None, // unsolicited: no InResponseTo
        sp_entity_id: sp_entity_id.to_string(),
        acs_url: acs_url.to_string(),
        assertion_lifetime_seconds,
        session_index: session_index.map(|s| s.to_string()),
        session_not_on_or_after,
        authn_context_class_ref: authn_context_class_ref.map(|s| s.to_string()),
        client_address: client_address.map(|s| s.to_string()),
        attributes: attributes.to_vec(),
    };

    create_response(&options, principal_name_id, times)
}

// ---------------------------------------------------------------------------
// Response / assertion signing
//
// `create_response` returns an unsigned `Response`. Delivering it to an SP that
// requires signatures means splicing an enveloped `<ds:Signature>` template into
// the serialized XML and filling it in with `SamlSigner::sign_enveloped`. These
// helpers do that, so callers (and language bindings) no longer hand-roll the
// template and the splice. See ADR 0033.
// ---------------------------------------------------------------------------

/// XML-DSig digest algorithm emitted by [`signature_template`] (SHA-256).
const DIGEST_METHOD_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Build an empty enveloped `<ds:Signature>` template referencing `reference_id`.
///
/// The template carries empty `<ds:DigestValue/>` and `<ds:SignatureValue/>`
/// placeholders that [`SamlSigner::sign_enveloped`] fills in, a single
/// `<ds:Reference URI="#reference_id">` with the enveloped-signature + exclusive
/// canonicalization transforms, and the signing certificate (base64 DER, no PEM
/// armor) in `<ds:KeyInfo>`. `signature_method_uri` is the `<ds:SignatureMethod>`
/// algorithm - e.g. the value returned by [`SamlSigner::signature_method_uri`].
///
/// The certificate is embedded explicitly so the template is valid on both the
/// in-process and the HSM signing paths (bergshamra-dsig does not populate
/// `<ds:KeyInfo>` from the key manager on the HSM path).
///
/// `reference_id` and `signature_method_uri` land in double-quoted attribute
/// values and `cert_der_b64` in element text; all three are escaped with
/// bergshamra's C14N entity-escaping helpers ([`bergshamra_c14n::escape`]) so a
/// caller-supplied value containing `&`, `<`, or `"` cannot break out of its
/// context or inject markup.
pub fn signature_template(
    reference_id: &str,
    cert_der_b64: &str,
    signature_method_uri: &str,
) -> String {
    use bergshamra_c14n::escape::{escape_attr, escape_text};
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{sig_alg}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="{digest}"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
        id = escape_attr(reference_id),
        cert = escape_text(cert_der_b64),
        sig_alg = escape_attr(signature_method_uri),
        digest = DIGEST_METHOD_SHA256,
    )
}

/// Insert `sig_template` into `xml` immediately after the `<saml:Issuer>` of the
/// `(namespace_uri, local_name)` element (e.g. SAML-assertion `Assertion` or
/// SAML-protocol `Response`) whose `ID` attribute equals `reference_id`.
///
/// The element is parsed and located by namespace + `ID` rather than by a string
/// scan for the first occurrence of the tag, so the splice always lands in the
/// same element the signature template's `<ds:Reference URI="#reference_id">`
/// points at - even when the Response carries several elements of the same tag
/// (e.g. multiple `<saml:Assertion>`). Going through the parser also keeps the
/// match namespace-aware and immune to `ID="..."` text appearing inside comments,
/// CDATA, or unrelated attributes.
///
/// SAML schema orders `<ds:Signature>` *after* `<saml:Issuer>` (and before
/// `<saml:Subject>` / `<samlp:Status>`), so the template is anchored at the end of
/// the matched element's own `<saml:Issuer>` child rather than as its first child.
fn insert_signature_after_issuer(
    xml: &str,
    namespace_uri: &str,
    local_name: &str,
    reference_id: &str,
    sig_template: &str,
) -> Result<String, ProfileError> {
    let doc = crate::xml::parse_secure(xml)
        .map_err(|e| ProfileError::Other(format!("cannot parse XML to place signature: {e}")))?;

    let elem = doc
        .get_elements_by_tag_name_ns(namespace_uri, local_name)
        .into_iter()
        .find(|&n| doc.get_attribute(n, "ID") == Some(reference_id))
        .ok_or_else(|| {
            ProfileError::Other(format!(
                r#"cannot find <{local_name}> with ID="{reference_id}" to sign"#
            ))
        })?;

    let issuer = doc
        .first_child_element_by_name_ns(elem, namespace::SAML_ASSERTION_NS, "Issuer")
        .ok_or_else(|| {
            ProfileError::Other(format!(
                "<{local_name}> has no <saml:Issuer> to anchor the signature"
            ))
        })?;

    // `node_range(issuer).end` is the byte offset just past `</saml:Issuer>`.
    let insert_at = doc
        .node_range(issuer)
        .ok_or_else(|| ProfileError::Other("Issuer node has no source range".to_string()))?
        .end;

    Ok(format!(
        "{}{}{}",
        &xml[..insert_at],
        sig_template,
        &xml[insert_at..]
    ))
}

/// Sign a serialized SAML `Response`, optionally signing the assertion, the
/// response envelope, or both, with enveloped XML-DSig.
///
/// When both are requested the assertion (inner) is signed first, then the
/// response (outer), so the response signature covers the already-signed
/// assertion. `cert_der_b64` is the base64 DER signing certificate placed in
/// `<ds:KeyInfo>`; `assertion_id` is required when `sign_assertions` is set. Each
/// signature is placed after its element's `<saml:Issuer>`, per the SAML schema.
pub fn sign_response_xml(
    response_xml: &str,
    signer: &SamlSigner,
    cert_der_b64: &str,
    response_id: &str,
    assertion_id: Option<&str>,
    sign_assertions: bool,
    sign_responses: bool,
) -> Result<String, ProfileError> {
    let mut xml = response_xml.to_string();

    if sign_assertions {
        let assertion_id = assertion_id.ok_or_else(|| {
            ProfileError::Other("sign_assertions requested without an assertion_id".to_string())
        })?;
        let sig = signature_template(assertion_id, cert_der_b64, signer.signature_method_uri()?);
        xml = insert_signature_after_issuer(
            &xml,
            namespace::SAML_ASSERTION_NS,
            "Assertion",
            assertion_id,
            &sig,
        )?;
        xml = signer.sign_enveloped(&xml)?;
    }

    if sign_responses {
        let sig = signature_template(response_id, cert_der_b64, signer.signature_method_uri()?);
        xml = insert_signature_after_issuer(
            &xml,
            namespace::SAML_PROTOCOL_NS,
            "Response",
            response_id,
            &sig,
        )?;
        xml = signer.sign_enveloped(&xml)?;
    }

    Ok(xml)
}

/// Build an SP-solicited `Response` (via [`create_response`]) and return it as
/// signed XML, ready to deliver over a binding.
///
/// One-call equivalent of `create_response` + serialize + [`sign_response_xml`].
/// `sign_assertions` signs the assertion (the usual Web Browser SSO posture);
/// `sign_responses` additionally signs the response envelope. `cert_der_b64` is
/// the base64 DER signing certificate for `<ds:KeyInfo>`.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_response(
    options: &ResponseOptions,
    principal_name_id: &NameId,
    times: ResponseTimes,
    signer: &SamlSigner,
    cert_der_b64: &str,
    sign_assertions: bool,
    sign_responses: bool,
) -> Result<String, ProfileError> {
    let response = create_response(options, principal_name_id, times);
    let response_id = response.base.id.clone();
    let assertion_id = response.assertions.first().map(|a| a.id.clone());
    let xml = response.to_xml_string()?;
    sign_response_xml(
        &xml,
        signer,
        cert_der_b64,
        &response_id,
        assertion_id.as_deref(),
        sign_assertions,
        sign_responses,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::name_id::NameIdPolicy;
    use crate::core::protocol::request::{
        AuthnContextComparison, RequestBase, RequestedAuthnContext,
    };
    use crate::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
    use crate::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

    fn make_sp_metadata() -> SpSsoDescriptor {
        SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base: RoleDescriptorBase::new(vec![
                    "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
                ]),
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![],
            },
            authn_requests_signed: None,
            want_assertions_signed: Some(true),
            assertion_consumer_services: vec![
                IndexedEndpoint::new_default(
                    Endpoint::new(
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                        "https://sp.example.com/acs/post",
                    ),
                    0,
                ),
                IndexedEndpoint::new(
                    Endpoint::new(
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                        "https://sp.example.com/acs/redirect",
                    ),
                    1,
                ),
            ],
            attribute_consuming_services: vec![],
        }
    }

    fn make_authn_request() -> AuthnRequest {
        AuthnRequest {
            base: RequestBase {
                id: "_req123".to_string(),
                version: SamlVersion::V2_0,
                issue_instant: Utc::now(),
                destination: Some("https://idp.example.com/sso".to_string()),
                consent: None,
                issuer: Some(Issuer::entity("https://sp.example.com")),
                has_signature: false,
            },
            subject: None,
            name_id_policy: Some(NameIdPolicy {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                sp_name_qualifier: None,
                allow_create: true,
            }),
            conditions: None,
            requested_authn_context: Some(RequestedAuthnContext {
                authn_context_class_refs: vec![constants::AUTHN_CONTEXT_PASSWORD.to_string()],
                authn_context_decl_refs: vec![],
                comparison: AuthnContextComparison::Exact,
            }),
            scoping: None,
            force_authn: Some(true),
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: Some("https://sp.example.com/acs/post".to_string()),
            protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
            attribute_consuming_service_index: None,
            provider_name: Some("Test SP".to_string()),
            extensions: None,
        }
    }

    #[test]
    fn test_process_authn_request() {
        let request = make_authn_request();
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();

        assert_eq!(result.request_id, "_req123");
        assert_eq!(result.sp_entity_id, "https://sp.example.com");
        assert_eq!(result.acs_url, "https://sp.example.com/acs/post");
        assert!(result.force_authn);
        assert!(!result.is_passive);
        assert_eq!(
            result.requested_name_id_format,
            Some(constants::NAMEID_EMAIL.to_string())
        );
        assert!(result.allow_create);
        assert_eq!(result.requested_authn_context_class_refs.len(), 1);
    }

    #[test]
    fn test_process_authn_request_acs_url_mismatch() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = Some("https://evil.example.com/acs".to_string());
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta));
        assert!(matches!(result, Err(ProfileError::AcsUrlMismatch)));
    }

    #[test]
    fn test_process_authn_request_by_index() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = None;
        request.protocol_binding = None;
        request.assertion_consumer_service_index = Some(1);
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();
        assert_eq!(result.acs_url, "https://sp.example.com/acs/redirect");
    }

    #[test]
    fn test_process_authn_request_default_acs() {
        let mut request = make_authn_request();
        request.assertion_consumer_service_url = None;
        request.protocol_binding = None;
        request.assertion_consumer_service_index = None;
        let sp_meta = make_sp_metadata();
        let result = process_authn_request(&request, Some(&sp_meta)).unwrap();
        assert_eq!(result.acs_url, "https://sp.example.com/acs/post");
    }

    #[test]
    fn test_process_authn_request_missing_issuer() {
        let mut request = make_authn_request();
        request.base.issuer = None;
        let result = process_authn_request(&request, None);
        assert!(matches!(result, Err(ProfileError::MissingIssuer)));
    }

    #[test]
    fn test_create_response() {
        let now = Utc::now();
        let options = ResponseOptions {
            idp_entity_id: "https://idp.example.com".to_string(),
            in_response_to: Some("_req123".to_string()),
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            assertion_lifetime_seconds: 300,
            session_index: Some("_sess1".to_string()),
            session_not_on_or_after: Some(now + TimeDelta::hours(8)),
            authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
            client_address: Some("192.168.1.100".to_string()),
            attributes: vec![Attribute {
                name: "email".to_string(),
                name_format: None,
                friendly_name: None,
                values: vec![],
            }],
        };
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        let response = create_response(&options, &name_id, ResponseTimes::at(now));

        // Check Response
        assert!(response.base.status.is_success());
        assert_eq!(response.base.in_response_to, Some("_req123".to_string()));
        assert_eq!(
            response.base.destination,
            Some("https://sp.example.com/acs".to_string())
        );
        assert_eq!(
            response.base.issuer.as_ref().unwrap().value,
            "https://idp.example.com"
        );

        // Check Assertion
        assert_eq!(response.assertions.len(), 1);
        let assertion = &response.assertions[0];
        assert_eq!(assertion.issuer.value, "https://idp.example.com");

        // Check Subject with bearer confirmation
        let subject = assertion.subject.as_ref().unwrap();
        assert_eq!(subject.subject_confirmations.len(), 1);
        let conf = &subject.subject_confirmations[0];
        assert_eq!(conf.method, constants::CM_BEARER);
        let data = conf.subject_confirmation_data.as_ref().unwrap();
        assert_eq!(
            data.recipient,
            Some("https://sp.example.com/acs".to_string())
        );
        assert_eq!(data.in_response_to, Some("_req123".to_string()));

        // Check Conditions
        let conditions = assertion.conditions.as_ref().unwrap();
        assert_eq!(conditions.audience_restrictions.len(), 1);
        assert_eq!(
            conditions.audience_restrictions[0].audiences[0],
            "https://sp.example.com"
        );

        // Check AuthnStatement
        assert_eq!(assertion.authn_statements.len(), 1);
        let stmt = &assertion.authn_statements[0];
        assert_eq!(stmt.session_index, Some("_sess1".to_string()));
        assert_eq!(
            stmt.authn_context.authn_context_class_ref,
            Some(constants::AUTHN_CONTEXT_PASSWORD.to_string())
        );

        // Check AttributeStatement
        assert_eq!(assertion.attribute_statements.len(), 1);
        assert_eq!(assertion.attribute_statements[0].attributes.len(), 1);

        // ResponseTimes::at collapses both instants to `now`.
        assert_eq!(stmt.authn_instant, now);
        assert_eq!(assertion.issue_instant, now);
    }

    #[test]
    fn test_create_response_distinct_authn_instant() {
        // A reused SSO session: the principal authenticated earlier than the
        // response is generated. AuthnInstant must reflect the earlier time
        // while every issue/validity instant tracks document generation.
        let issued = Utc::now();
        let authenticated = issued - TimeDelta::hours(2);
        let options = ResponseOptions {
            idp_entity_id: "https://idp.example.com".to_string(),
            in_response_to: Some("_req123".to_string()),
            sp_entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            assertion_lifetime_seconds: 300,
            session_index: Some("_sess1".to_string()),
            session_not_on_or_after: None,
            authn_context_class_ref: Some(constants::AUTHN_CONTEXT_PASSWORD.to_string()),
            client_address: None,
            attributes: vec![],
        };
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        let response = create_response(
            &options,
            &name_id,
            ResponseTimes {
                issue_instant: issued,
                authn_instant: authenticated,
            },
        );

        let assertion = &response.assertions[0];
        // Document/validity instants track generation time.
        assert_eq!(response.base.issue_instant, issued);
        assert_eq!(assertion.issue_instant, issued);
        let conditions = assertion.conditions.as_ref().unwrap();
        assert_eq!(conditions.not_before, Some(issued));
        assert_eq!(
            conditions.not_on_or_after,
            Some(issued + TimeDelta::seconds(300))
        );
        // AuthnInstant reflects the (earlier) authentication time.
        assert_eq!(assertion.authn_statements[0].authn_instant, authenticated);
    }

    #[test]
    fn test_create_error_response() {
        let now = Utc::now();
        let status = Status::with_sub_status(
            constants::STATUS_REQUESTER,
            constants::STATUS_INVALID_NAMEID_POLICY,
            Some("Unsupported NameIDPolicy".to_string()),
        );
        let resp = create_error_response(
            "https://idp.example.com",
            Some("_req123"),
            "https://sp.example.com/acs",
            status,
            now,
        );

        assert!(resp.assertions.is_empty());
        assert!(resp.encrypted_assertions.is_empty());
        assert!(!resp.base.status.is_success());
        assert_eq!(resp.base.in_response_to, Some("_req123".to_string()));
        assert_eq!(
            resp.base.destination,
            Some("https://sp.example.com/acs".to_string())
        );
        assert_eq!(
            resp.base.issuer.as_ref().unwrap().value,
            "https://idp.example.com"
        );
        assert_eq!(
            resp.base
                .status
                .status_code
                .sub_status
                .as_ref()
                .unwrap()
                .value,
            constants::STATUS_INVALID_NAMEID_POLICY
        );
    }

    #[test]
    fn test_create_unsolicited_response() {
        let now = Utc::now();
        let name_id = NameId {
            value: "user@example.com".to_string(),
            format: Some(constants::NAMEID_EMAIL.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };

        let response = create_unsolicited_response(
            "https://idp.example.com",
            "https://sp.example.com",
            "https://sp.example.com/acs",
            &name_id,
            &[],
            Some(constants::AUTHN_CONTEXT_PASSWORD),
            300,
            Some("_sess1"),
            None,
            None,
            ResponseTimes::at(now),
        );

        // No InResponseTo for unsolicited
        assert!(response.base.in_response_to.is_none());
        assert!(response.base.status.is_success());

        // Assertion has no InResponseTo in SubjectConfirmationData
        let assertion = &response.assertions[0];
        let conf = &assertion.subject.as_ref().unwrap().subject_confirmations[0];
        assert!(conf
            .subject_confirmation_data
            .as_ref()
            .unwrap()
            .in_response_to
            .is_none());
    }

    const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    #[test]
    fn test_signature_template_contents() {
        let tmpl = signature_template("_a1", "CERTB64", RSA_SHA256_URI);
        // References the target id, advertises the requested SignatureMethod and
        // SHA-256 digest, the enveloped + exc-c14n transforms, empty value
        // placeholders to fill, and embeds the certificate.
        assert!(tmpl.contains(r##"<ds:Reference URI="#_a1">"##));
        assert!(tmpl.contains(&format!(
            r#"<ds:SignatureMethod Algorithm="{RSA_SHA256_URI}"/>"#
        )));
        assert!(tmpl.contains("xmlenc#sha256"));
        assert!(tmpl.contains("enveloped-signature"));
        assert!(tmpl.contains("<ds:DigestValue/>"));
        assert!(tmpl.contains("<ds:SignatureValue/>"));
        assert!(tmpl.contains("<ds:X509Certificate>CERTB64</ds:X509Certificate>"));
    }

    #[test]
    fn test_signature_template_escapes_inputs() {
        // Hostile inputs in attribute (id, sig_alg) and text (cert) contexts must
        // be entity-escaped, not interpolated raw, so they cannot break out of the
        // attribute/element or inject markup.
        let tmpl = signature_template(r#"a"&<b"#, "cert&<value", r#"urn:alg"><evil/>"#);
        // Attribute values escaped (note: '>' is legal unescaped in attributes).
        assert!(tmpl.contains(r##"<ds:Reference URI="#a&quot;&amp;&lt;b">"##));
        assert!(tmpl.contains(r#"Algorithm="urn:alg&quot;>&lt;evil/>""#));
        // Text content escaped.
        assert!(tmpl.contains("<ds:X509Certificate>cert&amp;&lt;value</ds:X509Certificate>"));
        // No raw injected element survived.
        assert!(!tmpl.contains("<evil/>"));
    }

    #[test]
    fn test_insert_signature_after_issuer_assertion() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">"#,
            "<saml:Issuer>idp</saml:Issuer><samlp:Status/>",
            r#"<saml:Assertion ID="_a1"><saml:Issuer>idp</saml:Issuer>"#,
            "<saml:Subject/></saml:Assertion></samlp:Response>",
        );
        let out = insert_signature_after_issuer(
            xml,
            namespace::SAML_ASSERTION_NS,
            "Assertion",
            "_a1",
            "<SIG/>",
        )
        .unwrap();
        // The signature lands after the ASSERTION's Issuer (the second one) and
        // before the Subject - schema-correct ordering, not as the first child.
        assert!(out.contains(
            r#"<saml:Assertion ID="_a1"><saml:Issuer>idp</saml:Issuer><SIG/><saml:Subject/>"#
        ));
        // The response-level Issuer is left untouched.
        assert!(out.contains("<saml:Issuer>idp</saml:Issuer><samlp:Status/>"));
    }

    #[test]
    fn test_insert_signature_targets_assertion_by_id() {
        // Two assertions: the signature must land in the one whose ID matches the
        // reference, not in the first <saml:Assertion> encountered.
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">"#,
            "<saml:Issuer>idp</saml:Issuer><samlp:Status/>",
            r#"<saml:Assertion ID="_a1"><saml:Issuer>idp</saml:Issuer><saml:Subject/></saml:Assertion>"#,
            r#"<saml:Assertion ID="_a2"><saml:Issuer>idp</saml:Issuer><saml:Subject/></saml:Assertion>"#,
            "</samlp:Response>",
        );
        let out = insert_signature_after_issuer(
            xml,
            namespace::SAML_ASSERTION_NS,
            "Assertion",
            "_a2",
            "<SIG/>",
        )
        .unwrap();
        // Second assertion got the signature ...
        assert!(out.contains(
            r#"<saml:Assertion ID="_a2"><saml:Issuer>idp</saml:Issuer><SIG/><saml:Subject/>"#
        ));
        // ... and the first one was left untouched.
        assert!(out
            .contains(r#"<saml:Assertion ID="_a1"><saml:Issuer>idp</saml:Issuer><saml:Subject/>"#));
    }

    #[test]
    fn test_insert_signature_unknown_id_errors() {
        let xml = concat!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">"#,
            "<saml:Issuer>idp</saml:Issuer><saml:Subject/></saml:Assertion>",
        );
        let err = insert_signature_after_issuer(
            xml,
            namespace::SAML_ASSERTION_NS,
            "Assertion",
            "_nope",
            "<SIG/>",
        )
        .unwrap_err();
        assert!(err.to_string().contains(r#"ID="_nope""#));
    }

    #[test]
    fn test_insert_signature_after_issuer_response() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">"#,
            "<saml:Issuer>idp</saml:Issuer><samlp:Status/></samlp:Response>",
        );
        let out = insert_signature_after_issuer(
            xml,
            namespace::SAML_PROTOCOL_NS,
            "Response",
            "_r1",
            "<SIG/>",
        )
        .unwrap();
        assert!(out.contains("<saml:Issuer>idp</saml:Issuer><SIG/><samlp:Status/>"));
    }

    #[test]
    fn test_insert_signature_missing_element_errors() {
        let xml = concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">"#,
            "<saml:Issuer>idp</saml:Issuer></samlp:Response>",
        );
        let err = insert_signature_after_issuer(
            xml,
            namespace::SAML_ASSERTION_NS,
            "Assertion",
            "_a1",
            "<SIG/>",
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot find <Assertion>"));
    }
}
