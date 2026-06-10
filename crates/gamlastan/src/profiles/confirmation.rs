// SAML 2.0 Subject Confirmation Method implementations
//
// Section 3.2 of SAML Core defines Subject and SubjectConfirmation.
// Section 3.1 of SAML Profiles defines the following confirmation methods:
// - Bearer (urn:oasis:names:tc:SAML:2.0:cm:bearer)
// - Holder-of-Key (urn:oasis:names:tc:SAML:2.0:cm:holder-of-key)
// - Sender-Vouches (urn:oasis:names:tc:SAML:2.0:cm:sender-vouches)

use chrono::{DateTime, Utc};

use crate::core::assertion::subject::{SubjectConfirmation, SubjectConfirmationData};
use crate::core::constants;

use crate::profiles::error::ProfileError;

/// Result of validating a subject confirmation.
#[derive(Debug, Clone)]
pub struct ConfirmationResult {
    /// The confirmation method that was validated.
    pub method: String,
    /// Whether the confirmation was successful.
    pub valid: bool,
    /// If invalid, the reason.
    pub reason: Option<String>,
}

/// Parameters for validating a bearer subject confirmation.
#[derive(Debug)]
pub struct BearerValidationParams<'a> {
    /// The expected recipient URL (ACS URL).
    pub recipient: &'a str,
    /// The InResponseTo value from the request (None for unsolicited).
    pub in_response_to: Option<&'a str>,
    /// The current time.
    pub now: DateTime<Utc>,
    /// Clock skew tolerance in seconds (E92).
    pub clock_skew_seconds: u64,
    /// Whether to verify Address attribute against client IP.
    pub check_address: bool,
    /// The client's IP address (if checking).
    pub client_address: Option<&'a str>,
}

/// Validate a bearer SubjectConfirmation per SAML Profiles 4.1.4.2:
///
/// 1. SubjectConfirmationData MUST be present
/// 2. Recipient MUST be present and match the ACS URL
/// 3. NotOnOrAfter MUST be present and not expired (with clock skew)
/// 4. InResponseTo must match the request ID (if SP-initiated)
/// 5. NotBefore must not be violated (if present)
/// 6. Address may be checked against client IP
pub fn validate_bearer(
    confirmation: &SubjectConfirmation,
    params: &BearerValidationParams<'_>,
) -> ConfirmationResult {
    // Method must be bearer
    if confirmation.method != constants::CM_BEARER {
        return ConfirmationResult {
            method: confirmation.method.clone(),
            valid: false,
            reason: Some(format!(
                "expected bearer method, got: {}",
                confirmation.method
            )),
        };
    }

    // SubjectConfirmationData MUST be present
    let data = match &confirmation.subject_confirmation_data {
        Some(d) => d,
        None => {
            return ConfirmationResult {
                method: constants::CM_BEARER.to_string(),
                valid: false,
                reason: Some("missing SubjectConfirmationData".to_string()),
            };
        }
    };

    // Recipient MUST be present and match ACS URL
    match &data.recipient {
        Some(recipient) if recipient == params.recipient => {}
        Some(recipient) => {
            return ConfirmationResult {
                method: constants::CM_BEARER.to_string(),
                valid: false,
                reason: Some(format!(
                    "Recipient mismatch: expected {}, got {}",
                    params.recipient, recipient
                )),
            };
        }
        None => {
            return ConfirmationResult {
                method: constants::CM_BEARER.to_string(),
                valid: false,
                reason: Some("missing Recipient in SubjectConfirmationData".to_string()),
            };
        }
    }

    // NotOnOrAfter MUST be present and not expired
    match data.not_on_or_after {
        Some(not_on_or_after) => {
            let skew = chrono::TimeDelta::seconds(params.clock_skew_seconds as i64);
            if params.now - skew >= not_on_or_after {
                return ConfirmationResult {
                    method: constants::CM_BEARER.to_string(),
                    valid: false,
                    reason: Some(format!(
                        "SubjectConfirmationData expired: NotOnOrAfter={}, now={}",
                        not_on_or_after, params.now
                    )),
                };
            }
        }
        None => {
            return ConfirmationResult {
                method: constants::CM_BEARER.to_string(),
                valid: false,
                reason: Some("missing NotOnOrAfter in SubjectConfirmationData".to_string()),
            };
        }
    }

    // NotBefore (if present) must not be violated
    if let Some(not_before) = data.not_before {
        let skew = chrono::TimeDelta::seconds(params.clock_skew_seconds as i64);
        if params.now + skew < not_before {
            return ConfirmationResult {
                method: constants::CM_BEARER.to_string(),
                valid: false,
                reason: Some(format!(
                    "SubjectConfirmationData not yet valid: NotBefore={}, now={}",
                    not_before, params.now
                )),
            };
        }
    }

    // InResponseTo must match (SP-initiated flow)
    if let Some(expected_irt) = params.in_response_to {
        match &data.in_response_to {
            Some(irt) if irt == expected_irt => {}
            Some(irt) => {
                return ConfirmationResult {
                    method: constants::CM_BEARER.to_string(),
                    valid: false,
                    reason: Some(format!(
                        "InResponseTo mismatch: expected {}, got {}",
                        expected_irt, irt
                    )),
                };
            }
            None => {
                return ConfirmationResult {
                    method: constants::CM_BEARER.to_string(),
                    valid: false,
                    reason: Some(
                        "missing InResponseTo in SubjectConfirmationData for SP-initiated flow"
                            .to_string(),
                    ),
                };
            }
        }
    }

    // Address check (optional)
    if params.check_address {
        if let (Some(expected_addr), Some(data_addr)) = (params.client_address, &data.address) {
            if data_addr != expected_addr {
                return ConfirmationResult {
                    method: constants::CM_BEARER.to_string(),
                    valid: false,
                    reason: Some(format!(
                        "Address mismatch: expected {}, got {}",
                        expected_addr, data_addr
                    )),
                };
            }
        }
    }

    ConfirmationResult {
        method: constants::CM_BEARER.to_string(),
        valid: true,
        reason: None,
    }
}

/// Build a bearer SubjectConfirmation for use in assertions.
///
/// Used by IdP when constructing assertions for Web Browser SSO.
pub fn build_bearer_confirmation(
    recipient: &str,
    not_on_or_after: DateTime<Utc>,
    in_response_to: Option<&str>,
    address: Option<&str>,
) -> SubjectConfirmation {
    SubjectConfirmation {
        method: constants::CM_BEARER.to_string(),
        name_id: None,
        subject_confirmation_data: Some(SubjectConfirmationData {
            not_before: None,
            not_on_or_after: Some(not_on_or_after),
            recipient: Some(recipient.to_string()),
            in_response_to: in_response_to.map(|s| s.to_string()),
            address: address.map(|s| s.to_string()),
            key_info_x509_certs: vec![],
        }),
    }
}

/// Validate a holder-of-key SubjectConfirmation against the key the
/// presenter actually proved possession of.
///
/// Per the SAML Holder-of-Key profiles, SubjectConfirmationData is of
/// KeyInfoConfirmationDataType and carries one or more `ds:KeyInfo`
/// elements identifying the subject's key. The presenter proves possession
/// at the transport layer (TLS client authentication) or message layer; the
/// relying party MUST then check that the proven key matches a key in the
/// confirmation.
///
/// `presented_cert_der` is the DER encoding of the certificate the presenter
/// authenticated with (e.g. the TLS client certificate). Pass `None` when no
/// proof of possession is available — the confirmation is then rejected.
pub fn validate_holder_of_key(
    confirmation: &SubjectConfirmation,
    presented_cert_der: Option<&[u8]>,
) -> ConfirmationResult {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    if confirmation.method != constants::CM_HOLDER_OF_KEY {
        return ConfirmationResult {
            method: confirmation.method.clone(),
            valid: false,
            reason: Some(format!(
                "expected holder-of-key method, got: {}",
                confirmation.method
            )),
        };
    }

    let invalid = |reason: String| ConfirmationResult {
        method: constants::CM_HOLDER_OF_KEY.to_string(),
        valid: false,
        reason: Some(reason),
    };

    // SubjectConfirmationData with ds:KeyInfo MUST be present
    let Some(data) = &confirmation.subject_confirmation_data else {
        return invalid("missing SubjectConfirmationData".to_string());
    };
    if data.key_info_x509_certs.is_empty() {
        return invalid(
            "holder-of-key SubjectConfirmationData has no ds:KeyInfo X509Certificate".to_string(),
        );
    }

    // The presenter must have proven possession of a key
    let Some(presented) = presented_cert_der else {
        return invalid("no client certificate presented for proof of possession".to_string());
    };

    // Compare DER bytes against each confirmed certificate
    let matched = data.key_info_x509_certs.iter().any(|cert_b64| {
        STANDARD
            .decode(cert_b64)
            .map(|der| der == presented)
            .unwrap_or(false)
    });

    if matched {
        ConfirmationResult {
            method: constants::CM_HOLDER_OF_KEY.to_string(),
            valid: true,
            reason: None,
        }
    } else {
        invalid("presented certificate does not match any holder-of-key KeyInfo".to_string())
    }
}

/// Build a holder-of-key SubjectConfirmation binding the subject to a
/// certificate (used by the IdP when issuing HoK assertions).
pub fn build_holder_of_key_confirmation(
    subject_cert_der: &[u8],
    not_on_or_after: Option<DateTime<Utc>>,
    recipient: Option<&str>,
    in_response_to: Option<&str>,
) -> SubjectConfirmation {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    SubjectConfirmation {
        method: constants::CM_HOLDER_OF_KEY.to_string(),
        name_id: None,
        subject_confirmation_data: Some(SubjectConfirmationData {
            not_before: None,
            not_on_or_after,
            recipient: recipient.map(|s| s.to_string()),
            in_response_to: in_response_to.map(|s| s.to_string()),
            address: None,
            key_info_x509_certs: vec![STANDARD.encode(subject_cert_der)],
        }),
    }
}

/// Validate a sender-vouches SubjectConfirmation.
///
/// Sender-Vouches means the attesting entity (sender) vouches for the subject.
/// This is typically used with SOAP and requires a trusted transport.
pub fn validate_sender_vouches(confirmation: &SubjectConfirmation) -> ConfirmationResult {
    if confirmation.method != constants::CM_SENDER_VOUCHES {
        return ConfirmationResult {
            method: confirmation.method.clone(),
            valid: false,
            reason: Some(format!(
                "expected sender-vouches method, got: {}",
                confirmation.method
            )),
        };
    }

    // Sender-Vouches just means the sender asserts the identity.
    // Actual trust is established by transport-level authentication.
    ConfirmationResult {
        method: constants::CM_SENDER_VOUCHES.to_string(),
        valid: true,
        reason: None,
    }
}

/// Validate any subject confirmation, dispatching by method.
///
/// `hok_presented_cert_der` is the DER certificate the presenter proved
/// possession of (TLS client certificate), used for holder-of-key.
pub fn validate_confirmation(
    confirmation: &SubjectConfirmation,
    bearer_params: Option<&BearerValidationParams<'_>>,
    hok_presented_cert_der: Option<&[u8]>,
) -> Result<ConfirmationResult, ProfileError> {
    match confirmation.method.as_str() {
        m if m == constants::CM_BEARER => {
            let params = bearer_params.ok_or(ProfileError::BearerMissingConfirmationData)?;
            Ok(validate_bearer(confirmation, params))
        }
        m if m == constants::CM_HOLDER_OF_KEY => {
            Ok(validate_holder_of_key(confirmation, hok_presented_cert_der))
        }
        m if m == constants::CM_SENDER_VOUCHES => Ok(validate_sender_vouches(confirmation)),
        other => Err(ProfileError::UnsupportedConfirmationMethod(
            other.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn make_bearer_data(
        recipient: &str,
        not_on_or_after: DateTime<Utc>,
        in_response_to: Option<&str>,
    ) -> SubjectConfirmation {
        SubjectConfirmation {
            method: constants::CM_BEARER.to_string(),
            name_id: None,
            subject_confirmation_data: Some(SubjectConfirmationData {
                not_before: None,
                not_on_or_after: Some(not_on_or_after),
                recipient: Some(recipient.to_string()),
                in_response_to: in_response_to.map(|s| s.to_string()),
                address: None,
                key_info_x509_certs: vec![],
            }),
        }
    }

    fn default_bearer_params() -> BearerValidationParams<'static> {
        BearerValidationParams {
            recipient: "https://sp.example.com/acs",
            in_response_to: Some("_req123"),
            now: Utc::now(),
            clock_skew_seconds: 180,
            check_address: false,
            client_address: None,
        }
    }

    #[test]
    fn test_valid_bearer() {
        let future = Utc::now() + TimeDelta::minutes(5);
        let conf = make_bearer_data("https://sp.example.com/acs", future, Some("_req123"));
        let params = default_bearer_params();
        let result = validate_bearer(&conf, &params);
        assert!(result.valid, "expected valid, got: {:?}", result.reason);
    }

    #[test]
    fn test_bearer_missing_data() {
        let conf = SubjectConfirmation {
            method: constants::CM_BEARER.to_string(),
            name_id: None,
            subject_confirmation_data: None,
        };
        let params = default_bearer_params();
        let result = validate_bearer(&conf, &params);
        assert!(!result.valid);
        assert!(result
            .reason
            .unwrap()
            .contains("missing SubjectConfirmationData"));
    }

    #[test]
    fn test_bearer_recipient_mismatch() {
        let future = Utc::now() + TimeDelta::minutes(5);
        let conf = make_bearer_data("https://evil.example.com/acs", future, Some("_req123"));
        let params = default_bearer_params();
        let result = validate_bearer(&conf, &params);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Recipient mismatch"));
    }

    #[test]
    fn test_bearer_expired() {
        let past = Utc::now() - TimeDelta::minutes(10);
        let conf = make_bearer_data("https://sp.example.com/acs", past, Some("_req123"));
        let params = default_bearer_params();
        let result = validate_bearer(&conf, &params);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("expired"));
    }

    #[test]
    fn test_bearer_in_response_to_mismatch() {
        let future = Utc::now() + TimeDelta::minutes(5);
        let conf = make_bearer_data("https://sp.example.com/acs", future, Some("_wrong"));
        let params = default_bearer_params();
        let result = validate_bearer(&conf, &params);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("InResponseTo mismatch"));
    }

    #[test]
    fn test_bearer_unsolicited_no_in_response_to() {
        let future = Utc::now() + TimeDelta::minutes(5);
        let conf = make_bearer_data(
            "https://sp.example.com/acs",
            future,
            None, // no InResponseTo in confirmation
        );
        let params = BearerValidationParams {
            in_response_to: None, // unsolicited
            ..default_bearer_params()
        };
        let result = validate_bearer(&conf, &params);
        assert!(result.valid, "expected valid, got: {:?}", result.reason);
    }

    #[test]
    fn test_bearer_address_check() {
        let future = Utc::now() + TimeDelta::minutes(5);
        let mut conf = make_bearer_data("https://sp.example.com/acs", future, Some("_req123"));
        conf.subject_confirmation_data.as_mut().unwrap().address =
            Some("192.168.1.100".to_string());

        let params = BearerValidationParams {
            check_address: true,
            client_address: Some("10.0.0.1"),
            ..default_bearer_params()
        };
        let result = validate_bearer(&conf, &params);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Address mismatch"));
    }

    #[test]
    fn test_build_bearer_confirmation() {
        let not_on_or_after = Utc::now() + TimeDelta::minutes(5);
        let conf = build_bearer_confirmation(
            "https://sp.example.com/acs",
            not_on_or_after,
            Some("_req123"),
            Some("192.168.1.1"),
        );
        assert_eq!(conf.method, constants::CM_BEARER);
        let data = conf.subject_confirmation_data.unwrap();
        assert_eq!(data.recipient.unwrap(), "https://sp.example.com/acs");
        assert_eq!(data.in_response_to.unwrap(), "_req123");
        assert_eq!(data.address.unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_holder_of_key_matching_cert() {
        let cert_der: &[u8] = b"\x30\x82\x01\x00fake-der-cert";
        let conf = build_holder_of_key_confirmation(cert_der, None, None, None);
        let result = validate_holder_of_key(&conf, Some(cert_der));
        assert!(result.valid, "expected valid, got: {:?}", result.reason);
    }

    #[test]
    fn test_holder_of_key_wrong_cert() {
        let conf = build_holder_of_key_confirmation(b"the-real-cert", None, None, None);
        let result = validate_holder_of_key(&conf, Some(b"a-different-cert"));
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("does not match"));
    }

    #[test]
    fn test_holder_of_key_no_presented_cert() {
        let conf = build_holder_of_key_confirmation(b"the-real-cert", None, None, None);
        let result = validate_holder_of_key(&conf, None);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("no client certificate"));
    }

    #[test]
    fn test_holder_of_key_missing_key_info() {
        let conf = SubjectConfirmation {
            method: constants::CM_HOLDER_OF_KEY.to_string(),
            name_id: None,
            subject_confirmation_data: None,
        };
        let result = validate_holder_of_key(&conf, Some(b"cert"));
        assert!(!result.valid);
        assert!(result
            .reason
            .unwrap()
            .contains("missing SubjectConfirmationData"));

        let conf = SubjectConfirmation {
            method: constants::CM_HOLDER_OF_KEY.to_string(),
            name_id: None,
            subject_confirmation_data: Some(SubjectConfirmationData {
                not_before: None,
                not_on_or_after: None,
                recipient: None,
                in_response_to: None,
                address: None,
                key_info_x509_certs: vec![],
            }),
        };
        let result = validate_holder_of_key(&conf, Some(b"cert"));
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("no ds:KeyInfo"));
    }

    #[test]
    fn test_holder_of_key_xml_roundtrip() {
        use crate::core::assertion::subject::{Subject, SubjectRef};
        use crate::xml::deserialize::SamlDeserialize;
        use crate::xml::serialize::SamlSerialize;

        let cert_der: &[u8] = b"roundtrip-cert";
        let conf = build_holder_of_key_confirmation(
            cert_der,
            Some(Utc::now() + TimeDelta::minutes(5)),
            Some("https://sp.example.com/acs"),
            None,
        );
        let subject = Subject {
            name_id: None,
            subject_confirmations: vec![conf],
        };

        let xml = subject.to_xml_string().unwrap();
        assert!(xml.contains("ds:KeyInfo"));
        assert!(xml.contains("ds:X509Certificate"));

        let wrapped =
            format!(r#"<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{xml}</root>"#);
        let doc = uppsala::parse(&wrapped).unwrap();
        let root = doc.document_element().unwrap();
        let subject_node = doc
            .first_child_element_by_name_ns(
                root,
                "urn:oasis:names:tc:SAML:2.0:assertion",
                "Subject",
            )
            .unwrap();
        let parsed = SubjectRef::from_xml(&doc, subject_node).unwrap().to_owned();

        let confirmation = &parsed.subject_confirmations[0];
        let data = confirmation.subject_confirmation_data.as_ref().unwrap();
        assert_eq!(data.key_info_x509_certs.len(), 1);

        let result = validate_holder_of_key(confirmation, Some(cert_der));
        assert!(result.valid, "expected valid, got: {:?}", result.reason);
    }

    #[test]
    fn test_holder_of_key_via_dispatch() {
        let cert_der: &[u8] = b"dispatch-cert";
        let conf = build_holder_of_key_confirmation(cert_der, None, None, None);
        let result = validate_confirmation(&conf, None, Some(cert_der)).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_sender_vouches() {
        let conf = SubjectConfirmation {
            method: constants::CM_SENDER_VOUCHES.to_string(),
            name_id: None,
            subject_confirmation_data: None,
        };
        let result = validate_sender_vouches(&conf);
        assert!(result.valid);
    }

    #[test]
    fn test_unsupported_method() {
        let conf = SubjectConfirmation {
            method: "urn:unknown:method".to_string(),
            name_id: None,
            subject_confirmation_data: None,
        };
        let result = validate_confirmation(&conf, None, None);
        assert!(result.is_err());
    }
}
