// SAML 2.0 Subject types

use super::name_id::{NameIdOrEncryptedId, NameIdOrEncryptedIdRef};
use chrono::{DateTime, Utc};

/// Borrowed Subject.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectRef<'a> {
    /// The subject's name identifier (NameID or EncryptedID).
    pub name_id: Option<NameIdOrEncryptedIdRef<'a>>,
    /// Subject confirmation elements.
    pub subject_confirmations: Vec<SubjectConfirmationRef<'a>>,
}

impl<'a> SubjectRef<'a> {
    /// Convert to an owned Subject.
    pub fn to_owned(&self) -> Subject {
        Subject {
            name_id: self.name_id.as_ref().map(|n| n.to_owned()),
            subject_confirmations: self
                .subject_confirmations
                .iter()
                .map(|sc| sc.to_owned())
                .collect(),
        }
    }
}

/// Owned Subject.
#[derive(Debug, Clone, PartialEq)]
pub struct Subject {
    /// The subject's name identifier (NameID or EncryptedID).
    pub name_id: Option<NameIdOrEncryptedId>,
    /// Subject confirmation elements.
    pub subject_confirmations: Vec<SubjectConfirmation>,
}

/// Borrowed SubjectConfirmation.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectConfirmationRef<'a> {
    /// The confirmation method URI (e.g., bearer, holder-of-key, sender-vouches).
    pub method: &'a str,
    /// Optional NameID within the confirmation.
    pub name_id: Option<NameIdOrEncryptedIdRef<'a>>,
    /// Confirmation data.
    pub subject_confirmation_data: Option<SubjectConfirmationDataRef<'a>>,
}

impl<'a> SubjectConfirmationRef<'a> {
    /// Convert to an owned SubjectConfirmation.
    pub fn to_owned(&self) -> SubjectConfirmation {
        SubjectConfirmation {
            method: self.method.to_string(),
            name_id: self.name_id.as_ref().map(|n| n.to_owned()),
            subject_confirmation_data: self
                .subject_confirmation_data
                .as_ref()
                .map(|d| d.to_owned()),
        }
    }
}

/// Owned SubjectConfirmation.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectConfirmation {
    /// The confirmation method URI.
    pub method: String,
    /// Optional NameID within the confirmation.
    pub name_id: Option<NameIdOrEncryptedId>,
    /// Confirmation data.
    pub subject_confirmation_data: Option<SubjectConfirmationData>,
}

/// Borrowed SubjectConfirmationData.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectConfirmationDataRef<'a> {
    /// The earliest time instant at which the subject can be confirmed (SHOULD NOT be present for bearer per profiles).
    pub not_before: Option<DateTime<Utc>>,
    /// The time instant at which the subject can no longer be confirmed.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// The URI to which the assertion must be delivered (ACS URL for bearer).
    pub recipient: Option<&'a str>,
    /// The ID of the request this is in response to.
    pub in_response_to: Option<&'a str>,
    /// The network address from which the assertion subject is expected.
    pub address: Option<&'a str>,
}

impl<'a> SubjectConfirmationDataRef<'a> {
    /// Convert to an owned SubjectConfirmationData.
    pub fn to_owned(&self) -> SubjectConfirmationData {
        SubjectConfirmationData {
            not_before: self.not_before,
            not_on_or_after: self.not_on_or_after,
            recipient: self.recipient.map(str::to_string),
            in_response_to: self.in_response_to.map(str::to_string),
            address: self.address.map(str::to_string),
        }
    }
}

/// Owned SubjectConfirmationData.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectConfirmationData {
    /// The earliest time instant at which the subject can be confirmed.
    pub not_before: Option<DateTime<Utc>>,
    /// The time instant at which the subject can no longer be confirmed.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// The URI to which the assertion must be delivered.
    pub recipient: Option<String>,
    /// The ID of the request this is in response to.
    pub in_response_to: Option<String>,
    /// The network address from which the assertion subject is expected.
    pub address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::CM_BEARER;

    #[test]
    fn test_subject_ref_to_owned() {
        let subject_ref = SubjectRef {
            name_id: None,
            subject_confirmations: vec![SubjectConfirmationRef {
                method: CM_BEARER,
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationDataRef {
                    not_before: None,
                    not_on_or_after: None,
                    recipient: Some("https://sp.example.com/acs"),
                    in_response_to: Some("_abc123"),
                    address: None,
                }),
            }],
        };
        let owned = subject_ref.to_owned();
        assert!(owned.name_id.is_none());
        assert_eq!(owned.subject_confirmations.len(), 1);
        assert_eq!(owned.subject_confirmations[0].method, CM_BEARER);
        assert_eq!(
            owned.subject_confirmations[0]
                .subject_confirmation_data
                .as_ref()
                .unwrap()
                .recipient
                .as_deref(),
            Some("https://sp.example.com/acs")
        );
    }
}
