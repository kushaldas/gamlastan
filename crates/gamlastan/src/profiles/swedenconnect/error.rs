// Errors specific to the Deployment Profile for the Swedish eID Framework.

use crate::core::protocol::status::Status;
use crate::profiles::error::ProfileError;

use super::constants;

/// Errors raised by Sweden Connect profile processing.
#[derive(Debug)]
pub enum SwedenConnectError {
    /// The profile requires at least one requested Level of Assurance, but none
    /// were configured (section 5.3.1).
    NoRequestedLoa,

    /// The `<saml2p:Response>` was not signed (section 6.1 — responses MUST be
    /// signed).
    ResponseNotSigned,

    /// The Identity Provider did not return an `<saml2:EncryptedAssertion>`
    /// (section 6.1 — assertions MUST be encrypted).
    AssertionNotEncrypted,

    /// The response carried a cleartext `<saml2:Assertion>`; section 6.1 requires
    /// the entire assertion to be encrypted, so cleartext assertions are rejected.
    CleartextAssertion,

    /// The response did not contain exactly one assertion (section 6.2).
    AssertionCount(usize),

    /// The `<saml2p:Response>` signature failed cryptographic verification
    /// (section 6.3.1).
    InvalidResponseSignature(String),

    /// The `<saml2p:Response>` carried no `<saml2:Issuer>` (section 6.1 — the
    /// response MUST contain an Issuer).
    MissingResponseIssuer,

    /// The response-level `<saml2:Issuer>` did not identify the expected Identity
    /// Provider (section 6.1 / 6.3.1).
    ResponseIssuerMismatch {
        /// The Issuer value carried in the response.
        received: String,
        /// The IdP entityID expected from metadata.
        expected: String,
    },

    /// The response is not the answer to a tracked `AuthnRequest` (no expected
    /// request ID), yet it carries an `InResponseTo` — a stale, replayed, or
    /// misdirected message (section 6.1, 6.3.3).
    UnexpectedInResponseTo(String),

    /// An unsolicited response was received but the deployment does not accept
    /// them (section 6.1).
    UnsolicitedNotAllowed,

    /// A successful response did not contain exactly one `<saml2:AuthnStatement>`
    /// (section 6.2).
    AuthnStatementCount(usize),

    /// A successful response did not contain exactly one
    /// `<saml2:AttributeStatement>` (section 6.2).
    AttributeStatementCount(usize),

    /// The assertion carried no authentication context class reference
    /// (section 6.3.4).
    MissingAuthnContextClassRef,

    /// The delivered Level of Assurance did not match any requested one
    /// (section 6.3.4).
    LevelOfAssuranceMismatch {
        /// The authn context class ref returned by the IdP.
        received: String,
        /// The set of authn context class refs requested by the SP.
        requested: Vec<String>,
    },

    /// The subject confirmation method was neither bearer nor holder-of-key
    /// (section 6.2).
    UnexpectedConfirmationMethod(String),

    /// The clock skew configured exceeds the profile maximum of 1 minute
    /// (section 6.3.5).
    ClockSkewTooLarge(u64),

    /// The response used a cryptographic algorithm outside the profile's
    /// allowed set for the given purpose (section 8).
    DisallowedAlgorithm {
        /// The algorithm usage being checked.
        kind: &'static str,
        /// The disallowed algorithm URI.
        uri: String,
    },

    /// An error from the underlying Web Browser SSO profile processing.
    Profile(ProfileError),

    /// A cryptographic error (decryption, signature verification).
    Crypto(crate::crypto::CryptoError),

    /// An XML parsing/serialization error.
    Xml(crate::xml::XmlError),

    /// Any other profile violation.
    Other(String),
}

impl SwedenConnectError {
    /// Map this error to the SAML `<saml2p:Status>` an Identity Provider should
    /// return, per section 6.4. Service-Provider-side faults map to
    /// `Requester`, everything else to `Responder`.
    pub fn to_status(&self) -> Status {
        match self {
            SwedenConnectError::NoRequestedLoa
            | SwedenConnectError::UnsolicitedNotAllowed
            | SwedenConnectError::UnexpectedConfirmationMethod(_) => {
                Status::requester(Some(self.to_string()))
            }
            SwedenConnectError::LevelOfAssuranceMismatch { .. }
            | SwedenConnectError::MissingAuthnContextClassRef => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_NO_AUTHN_CONTEXT,
                Some(self.to_string()),
            ),
            _ => Status::responder(Some(self.to_string())),
        }
    }
}

impl std::fmt::Display for SwedenConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwedenConnectError::NoRequestedLoa => {
                write!(f, "no requested Level of Assurance configured")
            }
            SwedenConnectError::ResponseNotSigned => write!(f, "Response message was not signed"),
            SwedenConnectError::AssertionNotEncrypted => {
                write!(
                    f,
                    "assertion was not encrypted (EncryptedAssertion required)"
                )
            }
            SwedenConnectError::CleartextAssertion => {
                write!(
                    f,
                    "response contains a cleartext Assertion; the entire assertion MUST be \
                     encrypted (section 6.1)"
                )
            }
            SwedenConnectError::AssertionCount(n) => {
                write!(f, "expected exactly one assertion, found {n}")
            }
            SwedenConnectError::InvalidResponseSignature(reason) => {
                write!(f, "Response signature verification failed: {reason}")
            }
            SwedenConnectError::MissingResponseIssuer => {
                write!(f, "Response message is missing an Issuer (section 6.1)")
            }
            SwedenConnectError::ResponseIssuerMismatch { received, expected } => write!(
                f,
                "Response Issuer {received:?} does not match the expected IdP {expected:?}"
            ),
            SwedenConnectError::UnexpectedInResponseTo(irt) => write!(
                f,
                "Response carries InResponseTo {irt:?} but no matching request was expected"
            ),
            SwedenConnectError::UnsolicitedNotAllowed => {
                write!(f, "unsolicited Response messages are not accepted")
            }
            SwedenConnectError::AuthnStatementCount(n) => {
                write!(f, "expected exactly one AuthnStatement, found {n}")
            }
            SwedenConnectError::AttributeStatementCount(n) => {
                write!(f, "expected exactly one AttributeStatement, found {n}")
            }
            SwedenConnectError::MissingAuthnContextClassRef => {
                write!(f, "assertion is missing an AuthnContextClassRef")
            }
            SwedenConnectError::LevelOfAssuranceMismatch {
                received,
                requested,
            } => write!(
                f,
                "delivered LoA {received:?} does not match any requested LoA {requested:?}"
            ),
            SwedenConnectError::UnexpectedConfirmationMethod(m) => {
                write!(f, "unexpected SubjectConfirmation method: {m}")
            }
            SwedenConnectError::ClockSkewTooLarge(s) => {
                write!(f, "clock skew {s}s exceeds the profile maximum of 60s")
            }
            SwedenConnectError::DisallowedAlgorithm { kind, uri } => {
                write!(f, "response uses disallowed {kind} algorithm {uri:?}")
            }
            SwedenConnectError::Profile(e) => write!(f, "profile error: {e}"),
            SwedenConnectError::Crypto(e) => write!(f, "crypto error: {e}"),
            SwedenConnectError::Xml(e) => write!(f, "XML error: {e}"),
            SwedenConnectError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SwedenConnectError {}

impl From<ProfileError> for SwedenConnectError {
    fn from(e: ProfileError) -> Self {
        SwedenConnectError::Profile(e)
    }
}

impl From<crate::crypto::CryptoError> for SwedenConnectError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        SwedenConnectError::Crypto(e)
    }
}

impl From<crate::xml::XmlError> for SwedenConnectError {
    fn from(e: crate::xml::XmlError) -> Self {
        SwedenConnectError::Xml(e)
    }
}
