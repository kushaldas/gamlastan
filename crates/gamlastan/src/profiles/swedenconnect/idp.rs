// IdP-side Response construction (sections 6, 6.4).
//
// Layers the profile's response requirements on top of the Web Browser SSO IdP
// profile (`profiles::sso::idp`):
//
// - a successful assertion carries exactly one `<saml2:AttributeStatement>`
//   and an authentication context class ref (LoA) (section 6.2),
// - the assertion is delivered encrypted as `<saml2:EncryptedAssertion>` (6.1),
// - error responses use the standard plus Sweden Connect status codes (6.4).
//
// The response signature itself is applied by the crypto layer
// (`crypto::SamlSigner`) after construction.

use chrono::{DateTime, Utc};

use crate::core::assertion::attribute::AttributeStatement;
use crate::core::assertion::issuer::Issuer;
use crate::core::assertion::name_id::NameId;
use crate::core::assertion::types::EncryptedAssertion;
use crate::core::identifiers::{SamlId, SamlVersion};
use crate::core::protocol::response::{Response, ResponseBase};
use crate::core::protocol::status::Status;
use crate::crypto::SamlEncryptor;
use crate::profiles::sso::idp as idp_profile;
use crate::profiles::sso::web_browser::ResponseOptions;
use crate::xml::serialize::SamlSerialize;

use super::config::SwedenConnectConfig;
use super::constants;
use super::error::SwedenConnectError;

/// Build a profile-conformant success `Response` (still in cleartext — encrypt
/// it with [`encrypt_assertions`] and sign it before sending).
///
/// Beyond the base Web Browser SSO response this guarantees that the assertion
/// carries exactly one `<saml2:AttributeStatement>` (section 6.2) and, when the
/// caller has not set one, fills the authentication context class ref from the
/// first configured LoA.
pub fn create_response(
    cfg: &SwedenConnectConfig,
    options: &ResponseOptions,
    principal_name_id: &NameId,
    now: DateTime<Utc>,
) -> Response {
    let mut options = options.clone();
    if options.authn_context_class_ref.is_none() {
        options.authn_context_class_ref = cfg.requested_loas.first().cloned();
    }

    let mut response = idp_profile::create_response(&options, principal_name_id, now);

    // Section 6.2: a successful response MUST contain exactly one
    // AttributeStatement. The base builder omits it when there are no
    // attributes; ensure one is always present.
    for assertion in &mut response.assertions {
        if assertion.attribute_statements.is_empty() {
            assertion
                .attribute_statements
                .push(AttributeStatement { attributes: vec![] });
        }
    }

    response
}

/// Replace every cleartext `<saml2:Assertion>` in `response` with an
/// `<saml2:EncryptedAssertion>`, per section 6.1.
///
/// `encryption_template` is the XML-Encryption template describing the recipient
/// key (typically derived from the SP's `use="encryption"` `<md:KeyDescriptor>`)
/// in the form expected by [`SamlEncryptor::encrypt`].
pub fn encrypt_assertions(
    mut response: Response,
    encryptor: &SamlEncryptor,
    encryption_template: &str,
) -> Result<Response, SwedenConnectError> {
    let assertions = std::mem::take(&mut response.assertions);
    for assertion in &assertions {
        let plaintext = assertion.to_xml_string()?;
        let encrypted = encryptor.encrypt(encryption_template, plaintext.as_bytes())?;
        let wrapped = format!(
            "<saml2:EncryptedAssertion xmlns:saml2=\"{}\">{}</saml2:EncryptedAssertion>",
            constants::NS_SAML_ASSERTION,
            encrypted
        );
        response.encrypted_assertions.push(EncryptedAssertion {
            raw: wrapped.into_bytes(),
        });
    }
    Ok(response)
}

/// Build an error `Response` carrying the given status and no assertions
/// (section 6.4).
pub fn error_response(
    cfg: &SwedenConnectConfig,
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
            issuer: Some(Issuer::entity(&cfg.entity_id)),
            has_signature: false,
            in_response_to: in_response_to.map(|s| s.to_string()),
            status,
        },
        assertions: vec![],
        encrypted_assertions: vec![],
    }
}

/// Status for a user-cancelled authentication (section 6.4).
pub fn cancel_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_CANCEL,
        Some("User cancelled the authentication".to_string()),
    )
}

/// Status for a determined fraud (section 6.4).
pub fn fraud_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_FRAUD,
        Some("Authentication aborted due to fraud".to_string()),
    )
}

/// Status for a suspected fraud (section 6.4).
pub fn possible_fraud_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_RESPONDER,
        constants::STATUS_POSSIBLE_FRAUD,
        Some("Authentication aborted due to suspected fraud".to_string()),
    )
}

/// Status for a request whose requested authentication context cannot be
/// satisfied (section 5.4.4).
pub fn no_authn_context_status() -> Status {
    Status::with_sub_status(
        constants::STATUS_REQUESTER,
        constants::STATUS_NO_AUTHN_CONTEXT,
        Some("No requested authentication context is supported".to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idp_cfg() -> SwedenConnectConfig {
        SwedenConnectConfig::identity_provider(
            "https://idp.example.se",
            vec![constants::LOA3.into()],
        )
    }

    fn options() -> ResponseOptions {
        ResponseOptions {
            idp_entity_id: "https://idp.example.se".to_string(),
            in_response_to: Some("_req1".to_string()),
            sp_entity_id: "https://sp.example.se".to_string(),
            acs_url: "https://sp.example.se/acs".to_string(),
            assertion_lifetime_seconds: 300,
            session_index: Some("_sess1".to_string()),
            session_not_on_or_after: None,
            authn_context_class_ref: None,
            client_address: None,
            attributes: vec![],
        }
    }

    fn name_id() -> NameId {
        NameId {
            value: "persistent-abc".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    #[test]
    fn test_create_response_fills_loa_and_attr_statement() {
        let now = Utc::now();
        let resp = create_response(&idp_cfg(), &options(), &name_id(), now);
        let assertion = &resp.assertions[0];
        // Exactly one AttributeStatement even though none were supplied.
        assert_eq!(assertion.attribute_statements.len(), 1);
        // LoA defaulted from config.
        assert_eq!(
            assertion.authn_statements[0]
                .authn_context
                .authn_context_class_ref
                .as_deref(),
            Some(constants::LOA3)
        );
    }

    #[test]
    fn test_error_response_has_no_assertions() {
        let now = Utc::now();
        let resp = error_response(
            &idp_cfg(),
            Some("_req1"),
            "https://sp.example.se/acs",
            cancel_status(),
            now,
        );
        assert!(resp.assertions.is_empty());
        assert!(resp.encrypted_assertions.is_empty());
        assert!(!resp.base.status.is_success());
        assert_eq!(
            resp.base
                .status
                .status_code
                .sub_status
                .as_ref()
                .unwrap()
                .value,
            constants::STATUS_CANCEL
        );
    }

    #[test]
    fn test_status_builders() {
        assert_eq!(
            fraud_status().status_code.sub_status.unwrap().value,
            constants::STATUS_FRAUD
        );
        assert_eq!(
            possible_fraud_status()
                .status_code
                .sub_status
                .unwrap()
                .value,
            constants::STATUS_POSSIBLE_FRAUD
        );
        assert_eq!(
            no_authn_context_status().status_code.value,
            constants::STATUS_REQUESTER
        );
    }
}
