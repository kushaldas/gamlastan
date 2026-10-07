//! Denial reasons for the response orchestrator.
//!
//! A [`Denial`] is a *protocol* refusal — the SP asked for something the IdP
//! cannot or will not provide, or authentication did not complete (it failed
//! or the user cancelled) — as opposed to a programming or configuration
//! fault (which is a `ProfileError`). Every denial is rendered as a **signed**
//! SAML protocol error response, matching what `example-idp` does today: an
//! unsigned denial is trivially forgeable, so the Response envelope is always
//! signed, unconditionally (not gated on `SignTargets`).
//!
//! The enum is closed and its [`Denial::status`] mapping is fixed and total.
//! The `StatusMessage` is always a fixed, IdP-controlled string — never an
//! echo of SP-supplied input — so a hostile `NameIDPolicy`, attribute name, or
//! other request field cannot inject markup into the signed error.

use crate::core::constants;
use crate::core::protocol::status::Status;

/// A protocol-level refusal to satisfy an AuthnRequest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// `IsPassive` was set but no reusable session exists (or `ForceAuthn`
    /// defeated reuse). The IdP cannot authenticate without user interaction.
    NoPassive,
    /// The requested `RequestedAuthnContext` cannot be satisfied by any
    /// registered authentication method. Also used for a request that names
    /// only authentication context *declaration* refs: a method carries a
    /// class ref only, so a declaration constraint cannot be shown to be met
    /// and is refused rather than ignored.
    NoAuthnContext,
    /// The `NameIDPolicy` cannot be satisfied: either `@Format` is not one
    /// this IdP can issue, or `@SPNameQualifier` names an entity other than
    /// the verified requester (which this IdP cannot honor without
    /// affiliation-membership verification it does not implement).
    InvalidNameIdPolicy,
    /// The `NameIDPolicy` forbids creating a new identifier (`AllowCreate=false`)
    /// and no existing identifier is available.
    NameIdCreationNotAllowed,
    /// A required attribute (per the SP's `AttributeConsumingService` and
    /// `fail_on_missing_requested`) could not be released.
    MissingRequiredAttributes,
    /// The request named an explicit `AttributeConsumingServiceIndex` that
    /// does not correspond to any service declared in the SP's metadata.
    /// Falling through silently would resolve to "no requirements" instead,
    /// which — for an SP whose release policy has no entity categories
    /// configured — bypasses that service's own declared attribute scoping
    /// and releases the subject's entire attribute set.
    InvalidAttributeConsumingServiceIndex,
    /// Authentication was attempted and did not succeed (wrong credentials,
    /// an upstream failure, a method the user could not complete). SAML has no
    /// finer-grained status for this than `AuthnFailed`.
    AuthnFailed,
    /// The user abandoned the login. SAML has no dedicated "cancelled"
    /// status, so this is the same `AuthnFailed` status as
    /// [`Denial::AuthnFailed`] with a message that says it was a cancellation,
    /// which lets an SP show "cancelled" rather than "failed". Kept a distinct
    /// variant so an integrator can still tell the two apart for logging.
    Cancelled,
}

impl Denial {
    /// The SAML `Status` this denial maps to.
    ///
    /// The mapping is fixed:
    /// - `NoPassive` → `Responder/NoPassive`
    /// - `NoAuthnContext` → `Responder/NoAuthnContext`
    /// - `InvalidNameIdPolicy` / `NameIdCreationNotAllowed` →
    ///   `Requester/InvalidNameIDPolicy`
    /// - `MissingRequiredAttributes` → `Requester/InvalidAttrNameOrValue`
    /// - `InvalidAttributeConsumingServiceIndex` → `Requester/ResourceNotRecognized`
    /// - `AuthnFailed` / `Cancelled` → `Responder/AuthnFailed`
    pub fn status(&self) -> Status {
        match self {
            Denial::NoPassive => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_PASSIVE,
                Some(
                    "Passive authentication is not possible without a reusable session".to_string(),
                ),
            ),
            Denial::NoAuthnContext => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_AUTHN_CONTEXT,
                Some("The requested authentication context is unavailable".to_string()),
            ),
            Denial::InvalidNameIdPolicy => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
                Some("The requested NameIDPolicy cannot be satisfied".to_string()),
            ),
            Denial::NameIdCreationNotAllowed => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
                Some("The NameIDPolicy does not allow creating a new identifier".to_string()),
            ),
            Denial::MissingRequiredAttributes => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_ATTR_NAME_OR_VALUE,
                Some("A required attribute is missing".to_string()),
            ),
            Denial::InvalidAttributeConsumingServiceIndex => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_RESOURCE_NOT_RECOGNIZED,
                Some(
                    "The requested AttributeConsumingServiceIndex does not correspond to any \
                     declared service"
                        .to_string(),
                ),
            ),
            Denial::AuthnFailed => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_AUTHN_FAILED,
                Some("Authentication failed".to_string()),
            ),
            Denial::Cancelled => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_AUTHN_FAILED,
                Some("Authentication was cancelled".to_string()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive mapping: every denial variant produces exactly the expected
    /// (top-level, sub-status) pair and a non-empty, fixed message.
    #[test]
    fn status_mapping_is_fixed_and_total() {
        let cases: &[(Denial, &str, &str)] = &[
            (
                Denial::NoPassive,
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_PASSIVE,
            ),
            (
                Denial::NoAuthnContext,
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_AUTHN_CONTEXT,
            ),
            (
                Denial::InvalidNameIdPolicy,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
            ),
            (
                Denial::NameIdCreationNotAllowed,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
            ),
            (
                Denial::MissingRequiredAttributes,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_ATTR_NAME_OR_VALUE,
            ),
            (
                Denial::InvalidAttributeConsumingServiceIndex,
                constants::STATUS_REQUESTER,
                constants::STATUS_RESOURCE_NOT_RECOGNIZED,
            ),
            (
                Denial::AuthnFailed,
                constants::STATUS_RESPONDER,
                constants::STATUS_AUTHN_FAILED,
            ),
            (
                Denial::Cancelled,
                constants::STATUS_RESPONDER,
                constants::STATUS_AUTHN_FAILED,
            ),
        ];

        for (denial, expected_top, expected_sub) in cases {
            let status = denial.status();
            assert!(
                !status.is_success(),
                "{denial:?} must not be a success status"
            );
            assert_eq!(
                status.status_code.value.as_str(),
                *expected_top,
                "{denial:?} top-level status"
            );
            let sub = status
                .status_code
                .sub_status
                .as_ref()
                .expect("{denial:?} must carry a sub-status");
            assert_eq!(sub.value.as_str(), *expected_sub, "{denial:?} sub-status");
            // The message is always present and is a fixed IdP string.
            assert!(
                status
                    .status_message
                    .as_ref()
                    .is_some_and(|m| !m.is_empty()),
                "{denial:?} must carry a status message"
            );
        }
    }

    /// The two NameID denials share a wire status but are distinct variants, so
    /// an integrator can still tell them apart for logging.
    #[test]
    fn nameid_denials_share_status_but_are_distinct() {
        assert_ne!(
            Denial::InvalidNameIdPolicy,
            Denial::NameIdCreationNotAllowed
        );
        assert_eq!(
            Denial::InvalidNameIdPolicy.status().status_code.value,
            Denial::NameIdCreationNotAllowed.status().status_code.value
        );
        assert_eq!(
            Denial::InvalidNameIdPolicy
                .status()
                .status_code
                .sub_status
                .unwrap()
                .value,
            Denial::NameIdCreationNotAllowed
                .status()
                .status_code
                .sub_status
                .unwrap()
                .value
        );
    }

    /// A cancellation and a plain failure share the `AuthnFailed` wire status but
    /// carry different messages, so an SP can tell them apart.
    #[test]
    fn cancelled_and_authn_failed_share_status_but_differ_in_message() {
        assert_ne!(Denial::AuthnFailed, Denial::Cancelled);
        let failed = Denial::AuthnFailed.status();
        let cancelled = Denial::Cancelled.status();
        assert_eq!(failed.status_code, cancelled.status_code);
        assert_ne!(failed.status_message, cancelled.status_message);
    }

    /// No denial message interpolates SP-supplied input: the message is one of a
    /// fixed set, so a hostile request field cannot inject markup.
    #[test]
    fn messages_are_a_fixed_set() {
        let messages: Vec<String> = [
            Denial::NoPassive,
            Denial::NoAuthnContext,
            Denial::InvalidNameIdPolicy,
            Denial::NameIdCreationNotAllowed,
            Denial::MissingRequiredAttributes,
            Denial::InvalidAttributeConsumingServiceIndex,
            Denial::AuthnFailed,
            Denial::Cancelled,
        ]
        .iter()
        .map(|d| d.status().status_message.clone().unwrap())
        .collect();

        // Every message is non-empty and contains no markup-significant
        // characters that a hostile input could have introduced.
        for m in &messages {
            assert!(!m.is_empty());
            assert!(!m.contains('<'), "message must not contain '<': {m}");
            assert!(!m.contains('>'), "message must not contain '>': {m}");
        }
    }
}
