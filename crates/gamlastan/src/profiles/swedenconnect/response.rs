// SP-side Response processing (section 6).
//
// Validates a `<saml2p:Response>` per the profile's processing requirements,
// layered on the 32-check `AssertionValidator`. The Sweden Connect specific
// additions over the base Web Browser SSO profile are:
//
// - unsolicited responses are rejected unless explicitly enabled (section 6.1),
// - the `<saml2p:Response>` MUST have been signed and verified (section 6.1),
// - the assertion MUST have arrived as an `<saml2:EncryptedAssertion>` (6.1),
// - exactly one `<saml2:AuthnStatement>` and one `<saml2:AttributeStatement>`
//   (section 6.2),
// - the SubjectConfirmation method is bearer or holder-of-key (section 6.2),
// - the delivered Level of Assurance matches a requested one (section 6.3.4).
//
// The caller is responsible for verifying the response signature and decrypting
// the assertion before calling [`process_response`]; [`decrypt_response`] is a
// helper for the latter.

use chrono::{DateTime, Utc};

use crate::core::assertion::name_id::NameIdOrEncryptedId;
use crate::core::assertion::types::{Assertion, AssertionRef};
use crate::core::protocol::response::{Response, ResponseRef};
use crate::crypto::{SamlDecryptor, SamlVerifier, VerifyResult};
use crate::profiles::error::ProfileError;
use crate::profiles::sso::web_browser::{self, AuthnResult};
use crate::security::replay::ReplayCache;
use crate::security::validation::{AssertionValidator, ValidationParams};
use crate::xml::deserialize::parse_saml;
use crate::xml::uppsala;

use super::authn_context::validate_authn_context;
use super::config::SwedenConnectConfig;
use super::constants;
use super::error::SwedenConnectError;

const NS_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const NS_XMLENC11: &str = "http://www.w3.org/2009/xmlenc11#";

/// Inputs for [`process_response`].
pub struct SwedenConnectResponseParams<'a> {
    /// The URL at which the response was received (Destination/Recipient check).
    pub received_url: &'a str,
    /// The SP's ACS URL.
    pub acs_url: &'a str,
    /// The expected IdP `entityID` (from the IdP's metadata).
    pub expected_idp_entity_id: &'a str,
    /// The ID of the `AuthnRequest` this response answers, or `None` for an
    /// unsolicited response.
    pub expected_request_id: Option<&'a str>,
    /// Whether the caller cryptographically verified the `<saml2p:Response>`
    /// signature against the IdP's metadata key (section 6.3.1).
    pub response_signature_verified: bool,
    /// Whether the assertion arrived encrypted (set by [`decrypt_response`]).
    pub assertion_was_encrypted: bool,
    /// Replay-prevention cache (section 6.3.5). The profile *mandates* replay
    /// protection ("the Service Provider MUST ensure that the same assertion is
    /// not processed more than once"), so this is required, not optional.
    pub replay_cache: &'a dyn ReplayCache,
    /// The RelayState, for sanitization checks.
    pub relay_state: Option<&'a str>,
    /// The client address, for the optional Address check.
    pub client_address: Option<&'a str>,
    /// The current time (injectable for testing).
    pub now: DateTime<Utc>,
}

/// A successful Sweden Connect authentication result.
#[derive(Debug, Clone)]
pub struct SwedenConnectAuthnResult {
    /// The underlying Web Browser SSO result (identity, session, attributes).
    pub authn: AuthnResult,
    /// The delivered Level of Assurance authentication context URI.
    pub level_of_assurance: String,
    /// Whether the assertion carried a `signMessageDigest` attribute, i.e. the
    /// IdP displayed and the user accepted a sign message (section 7.2).
    pub sign_message_displayed: bool,
}

#[derive(Clone, Copy, Default)]
struct AlgorithmContext {
    in_encrypted_key: bool,
    in_encrypted_data: bool,
}

/// Validate that the raw response XML only uses algorithms permitted by
/// section 8 of the profile.
pub fn validate_response_algorithms(response_xml: &str) -> Result<(), SwedenConnectError> {
    let doc = uppsala::parse(response_xml)
        .map_err(|e| SwedenConnectError::Xml(crate::xml::XmlError::ParseError(e)))?;
    let root = doc.document_element().ok_or_else(|| {
        SwedenConnectError::Other("response XML has no document element".to_string())
    })?;
    validate_algorithms_recursive(&doc, root, AlgorithmContext::default())
}

fn validate_algorithms_recursive<'a>(
    doc: &'a uppsala::Document<'a>,
    node: uppsala::NodeId,
    ctx: AlgorithmContext,
) -> Result<(), SwedenConnectError> {
    let mut next_ctx = ctx;

    if let Some(elem) = doc.element(node) {
        let ns = elem.name.namespace_uri.as_deref();
        let local = elem.name.local_name.as_ref();

        if matches!(ns, Some(NS_XMLENC) | Some(NS_XMLENC11)) {
            match local {
                "EncryptedKey" => next_ctx.in_encrypted_key = true,
                "EncryptedData" => next_ctx.in_encrypted_data = true,
                "EncryptionMethod" => {
                    let algorithm = doc.get_attribute(node, "Algorithm").ok_or_else(|| {
                        SwedenConnectError::Other(
                            "EncryptionMethod is missing Algorithm".to_string(),
                        )
                    })?;
                    if ctx.in_encrypted_key {
                        if !constants::is_allowed_key_transport_algorithm(algorithm) {
                            return Err(SwedenConnectError::DisallowedAlgorithm {
                                kind: "key transport",
                                uri: algorithm.to_string(),
                            });
                        }
                    } else if ctx.in_encrypted_data
                        && !constants::is_allowed_block_encryption_algorithm(algorithm)
                    {
                        return Err(SwedenConnectError::DisallowedAlgorithm {
                            kind: "block encryption",
                            uri: algorithm.to_string(),
                        });
                    }
                }
                _ => {}
            }
        } else if ns == Some(constants::NS_DS) {
            match local {
                "SignatureMethod" => {
                    let algorithm = doc.get_attribute(node, "Algorithm").ok_or_else(|| {
                        SwedenConnectError::Other(
                            "SignatureMethod is missing Algorithm".to_string(),
                        )
                    })?;
                    if !constants::is_allowed_signature_algorithm(algorithm) {
                        return Err(SwedenConnectError::DisallowedAlgorithm {
                            kind: "signature",
                            uri: algorithm.to_string(),
                        });
                    }
                }
                "DigestMethod" => {
                    let algorithm = doc.get_attribute(node, "Algorithm").ok_or_else(|| {
                        SwedenConnectError::Other("DigestMethod is missing Algorithm".to_string())
                    })?;
                    let allowed = if ctx.in_encrypted_key {
                        constants::is_allowed_digest_algorithm(algorithm)
                            || algorithm == constants::DIGEST_SHA1
                    } else {
                        constants::is_allowed_digest_algorithm(algorithm)
                    };
                    if !allowed {
                        return Err(SwedenConnectError::DisallowedAlgorithm {
                            kind: "digest",
                            uri: algorithm.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    for child in doc.children_iter(node) {
        if doc.element(child).is_some() {
            validate_algorithms_recursive(doc, child, next_ctx)?;
        }
    }

    Ok(())
}

/// Decrypt all `<saml2:EncryptedAssertion>` elements in a parsed response XML,
/// returning a `Response` whose `assertions` hold the decrypted assertions and
/// a flag indicating whether any encrypted assertion was present.
///
/// The response signature MUST be verified before calling this (decryption does
/// not by itself authenticate the message).
pub fn decrypt_response(
    response_xml: &str,
    decryptor: &SamlDecryptor,
) -> Result<(Response, bool), SwedenConnectError> {
    let doc = uppsala::parse(response_xml)
        .map_err(|e| SwedenConnectError::Xml(crate::xml::XmlError::ParseError(e)))?;
    let response_ref = parse_saml::<ResponseRef<'_>>(&doc)?;
    let mut response = response_ref.to_owned();

    // Section 6.1: the *entire* assertion MUST be encrypted, so a conformant
    // response carries no cleartext <saml2:Assertion>. Reject any that are
    // present rather than silently merging them with the decrypted assertions:
    // because assertion signatures are not required by this profile, an injected
    // cleartext assertion would otherwise be processed as authoritative (an XML
    // Signature Wrapping vector).
    if !response.assertions.is_empty() {
        return Err(SwedenConnectError::CleartextAssertion);
    }

    let was_encrypted = !response.encrypted_assertions.is_empty();

    let encrypted = std::mem::take(&mut response.encrypted_assertions);
    for ea in &encrypted {
        let enc_xml = std::str::from_utf8(&ea.raw)
            .map_err(|e| SwedenConnectError::Other(format!("non-UTF8 EncryptedAssertion: {e}")))?;
        let plaintext = decryptor.decrypt(enc_xml)?;
        let assertion_doc = uppsala::parse(&plaintext)
            .map_err(|e| SwedenConnectError::Xml(crate::xml::XmlError::ParseError(e)))?;
        let assertion_ref = parse_saml::<AssertionRef<'_>>(&assertion_doc)?;
        response.assertions.push(assertion_ref.to_owned());
    }

    Ok((response, was_encrypted))
}

/// Validate a (decrypted, signature-verified) response per the profile.
pub fn process_response(
    cfg: &SwedenConnectConfig,
    response: &Response,
    params: &SwedenConnectResponseParams<'_>,
) -> Result<SwedenConnectAuthnResult, SwedenConnectError> {
    // Status MUST be Success (section 6.4: error responses carry no assertion).
    if !response.base.status.is_success() {
        let msg = response
            .base
            .status
            .status_message
            .clone()
            .unwrap_or_else(|| response.base.status.status_code.value.clone());
        return Err(SwedenConnectError::Profile(ProfileError::ResponseFailure(
            msg,
        )));
    }

    // Section 6.1: the Response MUST contain an Issuer, and it identifies the IdP
    // that signed the message. Bind its value to the expected IdP — the shared
    // validator only checks the *assertion* issuer value and the response issuer
    // *format*, so this is the response-level binding (defence-in-depth).
    let response_issuer = response
        .base
        .issuer
        .as_ref()
        .map(|i| i.value.as_str())
        .ok_or(SwedenConnectError::MissingResponseIssuer)?;
    if response_issuer != params.expected_idp_entity_id {
        return Err(SwedenConnectError::ResponseIssuerMismatch {
            received: response_issuer.to_string(),
            expected: params.expected_idp_entity_id.to_string(),
        });
    }

    // Section 6.1: do not accept unsolicited responses unless configured to.
    if params.expected_request_id.is_none() && !cfg.accept_unsolicited {
        return Err(SwedenConnectError::UnsolicitedNotAllowed);
    }

    // Defence-in-depth: when we are not expecting a specific request — whether
    // genuinely unsolicited, or a solicited response whose InResponseTo did not
    // match a tracked request — the message MUST NOT claim to answer one. A
    // dangling InResponseTo signals a stale, replayed, or misdirected response.
    if params.expected_request_id.is_none() {
        if let Some(irt) = response.base.in_response_to.as_deref() {
            return Err(SwedenConnectError::UnexpectedInResponseTo(irt.to_string()));
        }
        if let Some(irt) = response.assertions.iter().find_map(|a| {
            a.subject.as_ref().and_then(|s| {
                s.subject_confirmations
                    .iter()
                    .find_map(|sc| sc.subject_confirmation_data.as_ref())
                    .and_then(|scd| scd.in_response_to.as_deref())
            })
        }) {
            return Err(SwedenConnectError::UnexpectedInResponseTo(irt.to_string()));
        }
    }

    // Section 6.1: the response MUST be signed and the signature verified.
    if !params.response_signature_verified {
        return Err(SwedenConnectError::ResponseNotSigned);
    }

    // Section 6.1: the assertion MUST have arrived encrypted.
    if !params.assertion_was_encrypted {
        return Err(SwedenConnectError::AssertionNotEncrypted);
    }

    if response.assertions.is_empty() {
        return Err(SwedenConnectError::Profile(ProfileError::NoAssertions));
    }

    // Section 6.2: a successful response carries exactly one assertion (which,
    // per section 6.1, must have arrived encrypted). Reject extra assertions —
    // identity and attributes below are otherwise drawn from whichever assertion
    // happens to be first / from all of them.
    if response.assertions.len() != 1 {
        return Err(SwedenConnectError::AssertionCount(
            response.assertions.len(),
        ));
    }

    // Run the 32-check validator with the profile's security configuration,
    // threading the externally-performed response signature verification.
    let security = cfg.security_config();
    let validator = AssertionValidator::new(&security).with_replay_cache(params.replay_cache);
    let validation_params = ValidationParams {
        received_url: params.received_url,
        expected_idp_entity_id: params.expected_idp_entity_id,
        sp_entity_id: &cfg.entity_id,
        acs_url: params.acs_url,
        expected_request_id: params.expected_request_id,
        client_address: params.client_address,
        relay_state: params.relay_state,
        response_signature_xml: None,
        response_signature_verified: Some(true),
        current_proxy_depth: 0,
        now: params.now,
    };
    let validation = validator.validate_response(response, &validation_params);
    if !validation.is_valid() {
        let errors: Vec<String> = validation
            .failures()
            .iter()
            .map(|c| {
                format!(
                    "{}: {}",
                    c.check_name,
                    c.detail.as_deref().unwrap_or("failed")
                )
            })
            .collect();
        return Err(SwedenConnectError::Profile(
            ProfileError::AssertionValidation(errors.join("; ")),
        ));
    }

    // Pick the assertion bearing the authentication statement.
    let assertion = response
        .assertions
        .iter()
        .find(|a| !a.authn_statements.is_empty())
        .ok_or(SwedenConnectError::Profile(ProfileError::NoAuthnStatement))?;

    // Section 6.2: exactly one AuthnStatement and one AttributeStatement.
    if assertion.authn_statements.len() != 1 {
        return Err(SwedenConnectError::AuthnStatementCount(
            assertion.authn_statements.len(),
        ));
    }
    if assertion.attribute_statements.len() != 1 {
        return Err(SwedenConnectError::AttributeStatementCount(
            assertion.attribute_statements.len(),
        ));
    }

    // Section 6.2: SubjectConfirmation method must be bearer or holder-of-key.
    check_confirmation_method(assertion)?;

    // Section 6.3.4: LoA must match one of the requested authn contexts.
    let authn_stmt = &assertion.authn_statements[0];
    let received_loa = authn_stmt.authn_context.authn_context_class_ref.as_deref();
    validate_authn_context(received_loa, &cfg.requested_loas)?;
    let level_of_assurance = received_loa
        .ok_or(SwedenConnectError::MissingAuthnContextClassRef)?
        .to_string();

    // Build the identity result.
    let (name_id_value, name_id_format, name_qualifier, sp_name_qualifier) =
        extract_name_id(assertion)?;
    let attributes: Vec<_> = response
        .assertions
        .iter()
        .flat_map(|a| web_browser::extract_attributes(&a.attribute_statements))
        .collect();
    let sign_message_displayed = attributes
        .iter()
        .any(|a| a.name == constants::ATTR_SIGN_MESSAGE_DIGEST);

    let authn = AuthnResult {
        name_id: name_id_value,
        name_id_format,
        name_qualifier,
        sp_name_qualifier,
        session_index: authn_stmt.session_index.clone(),
        session_not_on_or_after: authn_stmt.session_not_on_or_after,
        authn_instant: authn_stmt.authn_instant,
        authn_context_class_ref: authn_stmt.authn_context.authn_context_class_ref.clone(),
        authn_context_decl_ref: authn_stmt.authn_context.authn_context_decl_ref.clone(),
        authenticating_authorities: authn_stmt.authn_context.authenticating_authorities.clone(),
        attributes,
        idp_entity_id: assertion.issuer.value.clone(),
        assertion_id: assertion.id.clone(),
        response_id: response.base.id.clone(),
    };

    Ok(SwedenConnectAuthnResult {
        authn,
        level_of_assurance,
        sign_message_displayed,
    })
}

/// Verify, decrypt and validate a raw `<saml2p:Response>` in one secure step.
///
/// **This is the recommended entry point.** Unlike the low-level
/// [`decrypt_response`] + [`process_response`] pair (which trust the
/// `response_signature_verified` / `assertion_was_encrypted` booleans the caller
/// supplies), this function establishes those facts itself, binding them to the
/// exact `response_xml` bytes:
///
/// 1. it verifies the enveloped XML signature over `response_xml` with
///    `verifier` — whose default configuration enforces trusted-keys-only,
///    XML-Signature-Wrapping reference-position checks, and E91 `ds:Object`
///    rejection (section 6.1, 6.3.1);
/// 2. it decrypts the `<saml2:EncryptedAssertion>` with `decryptor`, rejecting
///    any response that also carries a cleartext assertion (section 6.1);
/// 3. it runs [`process_response`] with the verified signature and encryption
///    facts established here.
///
/// The `response_signature_verified` and `assertion_was_encrypted` fields of
/// `params` are ignored — this function overrides them.
pub fn verify_and_process_response(
    cfg: &SwedenConnectConfig,
    response_xml: &str,
    verifier: &SamlVerifier,
    decryptor: &SamlDecryptor,
    params: &SwedenConnectResponseParams<'_>,
) -> Result<SwedenConnectAuthnResult, SwedenConnectError> {
    validate_response_algorithms(response_xml)?;

    // 1. Verify the response signature over the exact received bytes.
    match verifier.verify_enveloped(response_xml)? {
        VerifyResult::Valid { .. } => {}
        VerifyResult::Invalid { reason } => {
            return Err(SwedenConnectError::InvalidResponseSignature(reason));
        }
    }

    // 2. Decrypt the assertion (rejects cleartext assertions per section 6.1).
    let (response, was_encrypted) = decrypt_response(response_xml, decryptor)?;

    // 3. Process with the signature/encryption facts established above rather
    //    than trusted from the caller.
    let resolved = SwedenConnectResponseParams {
        response_signature_verified: true,
        assertion_was_encrypted: was_encrypted,
        ..*params
    };
    process_response(cfg, &response, &resolved)
}

fn check_confirmation_method(assertion: &Assertion) -> Result<(), SwedenConnectError> {
    let subject = assertion
        .subject
        .as_ref()
        .ok_or(SwedenConnectError::Profile(ProfileError::MissingNameId))?;
    for sc in &subject.subject_confirmations {
        if sc.method == constants::CM_BEARER || sc.method == constants::CM_HOLDER_OF_KEY {
            return Ok(());
        }
    }
    let found = subject
        .subject_confirmations
        .first()
        .map(|s| s.method.clone())
        .unwrap_or_else(|| "<none>".to_string());
    Err(SwedenConnectError::UnexpectedConfirmationMethod(found))
}

type ExtractedNameId = (String, Option<String>, Option<String>, Option<String>);

fn extract_name_id(assertion: &Assertion) -> Result<ExtractedNameId, SwedenConnectError> {
    let subject = assertion
        .subject
        .as_ref()
        .ok_or(SwedenConnectError::Profile(ProfileError::MissingNameId))?;
    match &subject.name_id {
        Some(NameIdOrEncryptedId::NameId(nid)) => Ok((
            nid.value.clone(),
            nid.format.clone(),
            nid.name_qualifier.clone(),
            nid.sp_name_qualifier.clone(),
        )),
        Some(NameIdOrEncryptedId::EncryptedId(_)) => Err(SwedenConnectError::Other(
            "EncryptedID MUST NOT be used; the whole assertion is encrypted (section 6.1)"
                .to_string(),
        )),
        None => Err(SwedenConnectError::Profile(ProfileError::MissingNameId)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::assertion::attribute::{Attribute, AttributeStatement};
    use crate::core::assertion::authn::{AuthnContext, AuthnStatement};
    use crate::core::assertion::conditions::{AudienceRestriction, Conditions};
    use crate::core::assertion::issuer::Issuer;
    use crate::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
    use crate::core::assertion::subject::{Subject, SubjectConfirmation, SubjectConfirmationData};
    use crate::core::identifiers::{SamlId, SamlVersion};
    use crate::core::protocol::response::ResponseBase;
    use crate::core::protocol::status::Status;
    use crate::security::replay::InMemoryReplayCache;
    use chrono::TimeDelta;

    const IDP: &str = "https://idp.example.se";
    const SP: &str = "https://sp.example.se";
    const ACS: &str = "https://sp.example.se/acs";
    const REQ_ID: &str = "_req_1";

    fn cfg() -> SwedenConnectConfig {
        SwedenConnectConfig::service_provider(SP, vec![constants::LOA3.into()])
    }

    fn make_response(now: DateTime<Utc>, loa: &str, with_attr_stmt: bool) -> Response {
        let assertion = Assertion {
            id: SamlId::generate().as_str().to_string(),
            version: SamlVersion::V2_0,
            issue_instant: now,
            issuer: Issuer::entity(IDP),
            has_signature: false,
            subject: Some(Subject {
                name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                    value: "abc-persistent-id".to_string(),
                    format: Some(constants::NAMEID_PERSISTENT.to_string()),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: vec![SubjectConfirmation {
                    method: constants::CM_BEARER.to_string(),
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationData {
                        not_before: None,
                        not_on_or_after: Some(now + TimeDelta::minutes(5)),
                        recipient: Some(ACS.to_string()),
                        in_response_to: Some(REQ_ID.to_string()),
                        address: None,
                        key_info_x509_certs: vec![],
                    }),
                }],
            }),
            conditions: Some(Conditions {
                not_before: Some(now - TimeDelta::seconds(5)),
                not_on_or_after: Some(now + TimeDelta::minutes(5)),
                audience_restrictions: vec![AudienceRestriction {
                    audiences: vec![SP.to_string()],
                }],
                one_time_use: false,
                proxy_restriction: None,
            }),
            advice: None,
            authn_statements: vec![AuthnStatement {
                authn_instant: now,
                session_index: Some("_sess_1".to_string()),
                session_not_on_or_after: Some(now + TimeDelta::hours(1)),
                subject_locality: None,
                authn_context: AuthnContext {
                    authn_context_class_ref: Some(loa.to_string()),
                    authn_context_decl_ref: None,
                    authenticating_authorities: vec![],
                },
            }],
            authz_decision_statements: vec![],
            attribute_statements: if with_attr_stmt {
                vec![AttributeStatement {
                    attributes: vec![Attribute {
                        name: constants::ATTR_PERSONAL_IDENTITY_NUMBER.to_string(),
                        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                        friendly_name: Some("personalIdentityNumber".to_string()),
                        values: vec![],
                    }],
                }]
            } else {
                vec![]
            },
        };

        Response {
            base: ResponseBase {
                id: SamlId::generate().as_str().to_string(),
                version: SamlVersion::V2_0,
                issue_instant: now,
                destination: Some(ACS.to_string()),
                consent: None,
                issuer: Some(Issuer::entity(IDP)),
                has_signature: true,
                in_response_to: Some(REQ_ID.to_string()),
                status: Status::success(),
            },
            assertions: vec![assertion],
            encrypted_assertions: vec![],
        }
    }

    fn params<'a>(
        now: DateTime<Utc>,
        replay_cache: &'a dyn ReplayCache,
    ) -> SwedenConnectResponseParams<'a> {
        SwedenConnectResponseParams {
            received_url: ACS,
            acs_url: ACS,
            expected_idp_entity_id: IDP,
            expected_request_id: Some(REQ_ID),
            response_signature_verified: true,
            assertion_was_encrypted: true,
            replay_cache,
            relay_state: None,
            client_address: None,
            now,
        }
    }

    #[test]
    fn test_happy_path() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, true);
        let result = process_response(&cfg(), &resp, &params(now, &cache)).unwrap();
        assert_eq!(result.level_of_assurance, constants::LOA3);
        assert_eq!(result.authn.name_id, "abc-persistent-id");
        assert!(!result.sign_message_displayed);
    }

    #[test]
    fn test_rejects_unsolicited() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, true);
        let mut p = params(now, &cache);
        p.expected_request_id = None;
        assert!(matches!(
            process_response(&cfg(), &resp, &p),
            Err(SwedenConnectError::UnsolicitedNotAllowed)
        ));
    }

    #[test]
    fn test_rejects_response_issuer_mismatch() {
        // INFO-1: the response-level Issuer must identify the expected IdP.
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let mut resp = make_response(now, constants::LOA3, true);
        resp.base.issuer = Some(Issuer::entity("https://evil.example.se"));
        assert!(matches!(
            process_response(&cfg(), &resp, &params(now, &cache)),
            Err(SwedenConnectError::ResponseIssuerMismatch { .. })
        ));
    }

    #[test]
    fn test_rejects_dangling_in_response_to() {
        // INFO-2: an unsolicited response (no expected request) that nonetheless
        // carries an InResponseTo is rejected.
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, true); // base.in_response_to = Some(REQ_ID)
        let mut c = cfg();
        c.accept_unsolicited = true; // get past the unsolicited gate
        let mut p = params(now, &cache);
        p.expected_request_id = None;
        assert!(matches!(
            process_response(&c, &resp, &p),
            Err(SwedenConnectError::UnexpectedInResponseTo(_))
        ));
    }

    #[test]
    fn test_requires_signed_response() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, true);
        let mut p = params(now, &cache);
        p.response_signature_verified = false;
        assert!(matches!(
            process_response(&cfg(), &resp, &p),
            Err(SwedenConnectError::ResponseNotSigned)
        ));
    }

    #[test]
    fn test_requires_encryption() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, true);
        let mut p = params(now, &cache);
        p.assertion_was_encrypted = false;
        assert!(matches!(
            process_response(&cfg(), &resp, &p),
            Err(SwedenConnectError::AssertionNotEncrypted)
        ));
    }

    #[test]
    fn test_loa_mismatch() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA2, true);
        assert!(matches!(
            process_response(&cfg(), &resp, &params(now, &cache)),
            Err(SwedenConnectError::LevelOfAssuranceMismatch { .. })
        ));
    }

    #[test]
    fn test_requires_attribute_statement() {
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let resp = make_response(now, constants::LOA3, false);
        assert!(matches!(
            process_response(&cfg(), &resp, &params(now, &cache)),
            Err(SwedenConnectError::AttributeStatementCount(0))
        ));
    }

    #[test]
    fn test_rejects_extra_assertion() {
        // Section 6.2 / H-1: a second assertion (e.g. an injected cleartext one)
        // must cause rejection, not be silently merged.
        let now = Utc::now();
        let cache = InMemoryReplayCache::new();
        let mut resp = make_response(now, constants::LOA3, true);
        let extra = resp.assertions[0].clone();
        resp.assertions.push(extra);
        assert!(matches!(
            process_response(&cfg(), &resp, &params(now, &cache)),
            Err(SwedenConnectError::AssertionCount(2))
        ));
    }

    #[test]
    fn test_decrypt_rejects_cleartext_assertion() {
        // H-1: decrypt_response must reject a response carrying a cleartext
        // <saml2:Assertion> (section 6.1 requires the whole assertion encrypted).
        use crate::crypto::{KeysManager, SamlDecryptor};
        let xml = format!(
            r#"<saml2p:Response xmlns:saml2p="{p}" xmlns:saml2="{a}" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                 <saml2:Issuer>{idp}</saml2:Issuer>
                 <saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>
                 <saml2:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                   <saml2:Issuer>{idp}</saml2:Issuer>
                 </saml2:Assertion>
               </saml2p:Response>"#,
            p = constants::NS_SAML_PROTOCOL,
            a = constants::NS_SAML_ASSERTION,
            idp = IDP,
        );
        let decryptor = SamlDecryptor::new(KeysManager::new());
        assert!(matches!(
            decrypt_response(&xml, &decryptor),
            Err(SwedenConnectError::CleartextAssertion)
        ));
    }

    #[test]
    fn test_sign_message_digest_detected() {
        let now = Utc::now();
        let mut resp = make_response(now, constants::LOA3, true);
        resp.assertions[0].attribute_statements[0]
            .attributes
            .push(Attribute {
                name: constants::ATTR_SIGN_MESSAGE_DIGEST.to_string(),
                name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
                friendly_name: None,
                values: vec![],
            });
        let cache = InMemoryReplayCache::new();
        let result = process_response(&cfg(), &resp, &params(now, &cache)).unwrap();
        assert!(result.sign_message_displayed);
    }

    #[test]
    fn test_validate_response_algorithms_rejects_sha1_signature() {
        let xml = format!(
            r##"<saml2p:Response xmlns:saml2p="{p}" xmlns:ds="{ds}" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                                 <ds:Signature>
                                     <ds:SignedInfo>
                                         <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                                         <ds:Reference URI="#_r1">
                                             <ds:DigestMethod Algorithm="{sha256}"/>
                                         </ds:Reference>
                                     </ds:SignedInfo>
                                 </ds:Signature>
                             </saml2p:Response>"##,
            p = constants::NS_SAML_PROTOCOL,
            ds = constants::NS_DS,
            sha256 = constants::DIGEST_SHA256,
        );

        assert!(matches!(
            validate_response_algorithms(&xml),
            Err(SwedenConnectError::DisallowedAlgorithm {
                kind: "signature",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_response_algorithms_rejects_disallowed_block_encryption() {
        let xml = format!(
            r##"<saml2p:Response xmlns:saml2p="{p}" xmlns:xenc="{xenc}" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                                 <xenc:EncryptedData>
                                     <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
                                 </xenc:EncryptedData>
                             </saml2p:Response>"##,
            p = constants::NS_SAML_PROTOCOL,
            xenc = NS_XMLENC,
        );

        assert!(matches!(
            validate_response_algorithms(&xml),
            Err(SwedenConnectError::DisallowedAlgorithm {
                kind: "block encryption",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_response_algorithms_allows_oaep_sha1_digest() {
        let xml = format!(
            r##"<saml2p:Response xmlns:saml2p="{p}" xmlns:ds="{ds}" xmlns:xenc="{xenc}" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                                 <xenc:EncryptedKey>
                                     <xenc:EncryptionMethod Algorithm="{oaep}">
                                         <ds:DigestMethod Algorithm="{sha1}"/>
                                     </xenc:EncryptionMethod>
                                 </xenc:EncryptedKey>
                                 <xenc:EncryptedData>
                                     <xenc:EncryptionMethod Algorithm="{aes}"/>
                                 </xenc:EncryptedData>
                             </saml2p:Response>"##,
            p = constants::NS_SAML_PROTOCOL,
            ds = constants::NS_DS,
            xenc = NS_XMLENC,
            oaep = constants::KEYTRANSPORT_RSA_OAEP_MGF1P,
            sha1 = constants::DIGEST_SHA1,
            aes = constants::ENC_AES256_CBC,
        );

        assert!(validate_response_algorithms(&xml).is_ok());
    }
}
