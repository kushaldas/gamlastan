// SP-side AuthnRequest construction (section 5).
//
// Builds a profile-conformant `<saml2p:AuthnRequest>` on top of the Web Browser
// SSO SP profile (`profiles::sso::sp`), applying the Sweden Connect constraints:
//
// - explicit `ForceAuthn` (section 5.3),
// - `Destination` MUST be present (section 5.3 / 5.4.1),
// - `AssertionConsumerServiceURL` xor `AssertionConsumerServiceIndex` (section 5.3),
// - `<saml2p:RequestedAuthnContext>` with exact comparison and LoA URIs (5.3.1),
// - persistent NameID format by default (section 3),
// - response delivered via HTTP-POST.
//
// The `SignMessage`, `SADRequest`, and `PrincipalSelection` extensions are
// returned as a serialized `<saml2p:Extensions>` block via
// [`SwedenConnectAuthnRequest::extensions_xml`], because the core
// `AuthnRequest` type does not model a generic extensions container. Callers
// inject this block into the serialized request before signing.

use crate::core::protocol::request::{AuthnRequest, Scoping};
use crate::profiles::sso::sp as sp_profile;
use crate::profiles::sso::web_browser::{bindings, AuthnRequestOptions};

use super::authn_context::requested_authn_context;
use super::config::SwedenConnectConfig;
use super::constants;
use super::error::SwedenConnectError;
use super::principal_selection::PrincipalSelection;
use super::sign_message::{SadRequest, SignMessage};

/// Options for building a Sweden Connect `AuthnRequest`.
#[derive(Debug, Clone, Default)]
pub struct SwedenConnectAuthnOptions {
    /// The IdP `SingleSignOnService` URL the request is sent to. Required — it
    /// becomes the `Destination` attribute (section 5.4.1).
    pub destination: String,

    /// The desired `AssertionConsumerServiceURL`. Mutually exclusive with
    /// [`acs_index`](Self::acs_index).
    pub acs_url: Option<String>,

    /// The desired `AssertionConsumerServiceIndex`. Mutually exclusive with
    /// [`acs_url`](Self::acs_url).
    pub acs_index: Option<u16>,

    /// The explicit `ForceAuthn` value. Defaults to `true` (section 5.3
    /// recommends always setting it explicitly to avoid accidental SSO).
    pub force_authn: bool,

    /// The `IsPassive` value (optional).
    pub is_passive: Option<bool>,

    /// Whether to allow creation of a new identifier (`NameIDPolicy/@AllowCreate`).
    pub allow_create: bool,

    /// `AttributeConsumingServiceIndex` (section 5.3).
    pub attribute_consuming_service_index: Option<u16>,

    /// `<saml2p:Scoping>/<saml2p:IDPList>` entity IDs (section 5.3.2) — e.g. to
    /// pre-select an eIDAS country proxy service.
    pub scoping_idp_list: Vec<String>,

    /// `<saml2p:Scoping>/<saml2p:RequesterID>` entity IDs (section 7.1) —
    /// the Signature Requestor for a Signature Service.
    pub requester_ids: Vec<String>,

    /// `<saml2p:Scoping>/@ProxyCount`.
    pub proxy_count: Option<u32>,

    /// A `<psc:PrincipalSelection>` extension (sections 5.3.3, 7.1).
    pub principal_selection: Option<PrincipalSelection>,

    /// A `<csig:SignMessage>` extension (section 7.1.1) — Signature Service only.
    pub sign_message: Option<SignMessage>,

    /// A `<sap:SADRequest>` extension (section 7.1.2) — Signature Service only.
    pub sad_request: Option<SadRequest>,
}

impl SwedenConnectAuthnOptions {
    /// Construct options targeting `destination`, defaulting `ForceAuthn` to
    /// `true` and requesting a freshly creatable identifier.
    pub fn to(destination: impl Into<String>) -> Self {
        SwedenConnectAuthnOptions {
            destination: destination.into(),
            force_authn: true,
            allow_create: true,
            ..Default::default()
        }
    }
}

/// A built Sweden Connect authentication request.
#[derive(Debug, Clone)]
pub struct SwedenConnectAuthnRequest {
    /// The typed `AuthnRequest` (serialize with `SamlSerialize`).
    pub request: AuthnRequest,

    /// The serialized `<saml2p:Extensions>` block, if any extension
    /// (SignMessage / SADRequest / PrincipalSelection) was requested. This must
    /// be spliced into the serialized request immediately after the
    /// `<saml2:Issuer>` element, before signing.
    pub extensions_xml: Option<String>,
}

/// Combine extension element fragments into a single `<saml2p:Extensions>`
/// block, or return `None` if there are no fragments.
pub fn request_extensions_xml(fragments: &[String]) -> Option<String> {
    if fragments.is_empty() {
        return None;
    }
    let mut w = crate::xml::XmlWriter::new();
    w.start_element(
        "saml2p:Extensions",
        &[("xmlns:saml2p", constants::NS_SAML_PROTOCOL)],
    );
    for f in fragments {
        // Fragments are already-serialized, trusted XML element snippets.
        w.raw(f);
    }
    w.end_element("saml2p:Extensions");
    Some(w.into_string())
}

/// Build a Sweden Connect conformant `AuthnRequest`.
pub fn build_authn_request(
    cfg: &SwedenConnectConfig,
    opts: &SwedenConnectAuthnOptions,
) -> Result<SwedenConnectAuthnRequest, SwedenConnectError> {
    if opts.destination.trim().is_empty() {
        return Err(SwedenConnectError::Other(
            "Destination is required (section 5.4.1)".to_string(),
        ));
    }
    if opts.acs_url.is_some() && opts.acs_index.is_some() {
        return Err(SwedenConnectError::Other(
            "AssertionConsumerServiceURL and AssertionConsumerServiceIndex are mutually exclusive \
             (section 5.3)"
                .to_string(),
        ));
    }

    // A Signature Service MUST sign its requests and SHOULD set ForceAuthn=true
    // (section 7.1). We surface ForceAuthn explicitly here; signing is applied
    // by the binding layer.
    let force_authn = if cfg.is_signature_service() {
        true
    } else {
        opts.force_authn
    };

    let builder_opts = AuthnRequestOptions {
        sp_entity_id: cfg.entity_id.clone(),
        acs_url: opts.acs_url.clone(),
        acs_index: opts.acs_index,
        protocol_binding: Some(bindings::HTTP_POST.to_string()),
        force_authn: Some(force_authn),
        is_passive: opts.is_passive,
        name_id_format: Some(cfg.name_id_format.clone()),
        allow_create: opts.allow_create,
        sp_name_qualifier: None,
        authn_context_class_refs: cfg.requested_loas.clone(),
        authn_context_comparison: Some(
            crate::core::protocol::request::AuthnContextComparison::Exact,
        ),
        provider_name: None,
        destination: Some(opts.destination.clone()),
        proxy_count: opts.proxy_count,
        requester_ids: opts.requester_ids.clone(),
        attribute_consuming_service_index: opts.attribute_consuming_service_index,
        extensions: None,
    };

    let mut request = sp_profile::create_authn_request(&builder_opts)?;

    // The underlying builder only models Scoping/RequesterID; merge an IDPList
    // (section 5.3.2) directly onto the request when requested.
    if !opts.scoping_idp_list.is_empty() {
        let mut scoping = request.scoping.take().unwrap_or(Scoping {
            proxy_count: opts.proxy_count,
            idp_list: vec![],
            requester_ids: opts.requester_ids.clone(),
        });
        scoping.idp_list = opts.scoping_idp_list.clone();
        request.scoping = Some(scoping);
    }

    // Force the requested authn context to use exact comparison even if the
    // builder defaulted differently (defensive — section 5.3.1).
    if !cfg.requested_loas.is_empty() {
        request.requested_authn_context = Some(requested_authn_context(&cfg.requested_loas));
    }

    // Assemble the extensions block.
    let mut fragments = Vec::new();
    if let Some(sm) = &opts.sign_message {
        fragments.push(sm.to_xml_string());
    }
    if let Some(sad) = &opts.sad_request {
        fragments.push(sad.to_xml_string());
    }
    if let Some(ps) = &opts.principal_selection {
        fragments.push(ps.to_xml_string());
    }
    let extensions_xml = request_extensions_xml(&fragments);

    Ok(SwedenConnectAuthnRequest {
        request,
        extensions_xml,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::protocol::request::AuthnContextComparison;
    use crate::profiles::swedenconnect::principal_selection::MatchValue;
    use crate::profiles::swedenconnect::sign_message::SignMessageMimeType;

    fn sp_cfg() -> SwedenConnectConfig {
        SwedenConnectConfig::service_provider("https://sp.example.se", vec![constants::LOA3.into()])
    }

    #[test]
    fn test_basic_request() {
        let cfg = sp_cfg();
        let opts = SwedenConnectAuthnOptions {
            acs_url: Some("https://sp.example.se/acs".into()),
            ..SwedenConnectAuthnOptions::to("https://idp.example.se/sso")
        };
        let built = build_authn_request(&cfg, &opts).unwrap();
        let req = &built.request;

        assert_eq!(
            req.base.issuer.as_ref().unwrap().value,
            "https://sp.example.se"
        );
        assert_eq!(
            req.base.destination.as_deref(),
            Some("https://idp.example.se/sso")
        );
        assert_eq!(req.force_authn, Some(true));
        assert_eq!(
            req.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example.se/acs")
        );
        assert_eq!(req.protocol_binding.as_deref(), Some(bindings::HTTP_POST));
        // Persistent NameID format requested by default.
        assert_eq!(
            req.name_id_policy.as_ref().unwrap().format.as_deref(),
            Some(constants::NAMEID_PERSISTENT)
        );
        // RequestedAuthnContext is exact with LoA3.
        let rac = req.requested_authn_context.as_ref().unwrap();
        assert_eq!(rac.comparison, AuthnContextComparison::Exact);
        assert_eq!(
            rac.authn_context_class_refs,
            vec![constants::LOA3.to_string()]
        );
        // No extensions in the basic case.
        assert!(built.extensions_xml.is_none());
    }

    #[test]
    fn test_acs_mutual_exclusion() {
        let cfg = sp_cfg();
        let opts = SwedenConnectAuthnOptions {
            acs_url: Some("https://sp.example.se/acs".into()),
            acs_index: Some(0),
            ..SwedenConnectAuthnOptions::to("https://idp.example.se/sso")
        };
        assert!(build_authn_request(&cfg, &opts).is_err());
    }

    #[test]
    fn test_missing_destination() {
        let cfg = sp_cfg();
        let opts = SwedenConnectAuthnOptions::default();
        assert!(build_authn_request(&cfg, &opts).is_err());
    }

    #[test]
    fn test_scoping_idp_list() {
        let cfg = sp_cfg();
        let opts = SwedenConnectAuthnOptions {
            scoping_idp_list: vec![
                "http://id.swedenconnect.se/eidas/1.0/proxy-service/no".to_string()
            ],
            ..SwedenConnectAuthnOptions::to("https://connector.example.se/sso")
        };
        let built = build_authn_request(&cfg, &opts).unwrap();
        let scoping = built.request.scoping.as_ref().unwrap();
        assert_eq!(scoping.idp_list.len(), 1);
        assert!(scoping.idp_list[0].contains("proxy-service/no"));
    }

    #[test]
    fn test_signature_service_extensions() {
        let cfg = SwedenConnectConfig::signature_service(
            "https://sign.example.se",
            vec![constants::LOA3.into()],
        );
        let opts = SwedenConnectAuthnOptions {
            acs_url: Some("https://sign.example.se/acs".into()),
            force_authn: false, // should be overridden to true for a sig service
            requester_ids: vec!["https://sp.example.se".into()],
            principal_selection: Some(PrincipalSelection::new(vec![
                MatchValue::personal_identity_number("197001012380"),
            ])),
            sign_message: Some(SignMessage::cleartext(
                "Please sign",
                SignMessageMimeType::Text,
                true,
                Some("https://idp.example.se".into()),
            )),
            sad_request: Some(SadRequest::new("_sad1", "https://sp.example.se", "_sr1", 1)),
            ..SwedenConnectAuthnOptions::to("https://idp.example.se/sso")
        };
        let built = build_authn_request(&cfg, &opts).unwrap();
        assert_eq!(built.request.force_authn, Some(true));
        let ext = built.extensions_xml.unwrap();
        assert!(ext.contains("saml2p:Extensions"));
        assert!(ext.contains("csig:SignMessage"));
        assert!(ext.contains("sap:SADRequest"));
        assert!(ext.contains("psc:PrincipalSelection"));
        // Scoping/RequesterID present.
        let scoping = built.request.scoping.as_ref().unwrap();
        assert_eq!(
            scoping.requester_ids,
            vec!["https://sp.example.se".to_string()]
        );
    }
}
