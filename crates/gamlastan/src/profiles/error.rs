// SAML 2.0 Profile errors

use thiserror::Error;

/// Errors that can occur during SAML profile operations.
#[derive(Debug, Error)]
pub enum ProfileError {
    // --- SSO Profile errors ---
    #[error("missing Issuer element in AuthnRequest")]
    MissingIssuer,

    #[error("Issuer format must be entity or omitted, got: {0}")]
    InvalidIssuerFormat(String),

    #[error("AuthnRequest Subject must not contain SubjectConfirmation")]
    SubjectConfirmationInAuthnRequest,

    #[error("no SSO endpoint found for IdP with binding: {0}")]
    NoSsoEndpoint(String),

    #[error("no ACS endpoint found for SP with binding: {0}")]
    NoAcsEndpoint(String),

    #[error("ACS URL in AuthnRequest does not match any SP endpoint")]
    AcsUrlMismatch,

    #[error("response status indicates failure: {0}")]
    ResponseFailure(String),

    #[error("no assertions found in response")]
    NoAssertions,

    #[error("no AuthnStatement found in assertion")]
    NoAuthnStatement,

    #[error("assertion validation failed: {0}")]
    AssertionValidation(String),

    // --- Logout Profile errors ---
    #[error("missing NameID in LogoutRequest")]
    MissingNameId,

    #[error("missing SessionIndex in LogoutRequest")]
    MissingSessionIndex,

    #[error("session not found for NameID")]
    SessionNotFound,

    #[error("partial logout: {success} of {total} participants logged out")]
    PartialLogout { success: usize, total: usize },

    // --- Artifact Resolution errors ---
    #[error("artifact resolution failed: {0}")]
    ArtifactResolutionFailed(String),

    #[error("artifact response status indicates failure: {0}")]
    ArtifactResponseFailure(String),

    // --- Name ID Management errors ---
    #[error("name ID management failed: {0}")]
    NameIdManagementFailed(String),

    // --- Name ID Mapping errors ---
    #[error("name ID mapping failed: {0}")]
    NameIdMappingFailed(String),

    #[error("name ID mapping response missing NameID")]
    MappingResponseMissingNameId,

    // --- ECP errors ---
    #[error("AssertionConsumerServiceURL does not match PAOS responseConsumerURL")]
    EcpAcsUrlMismatch,

    #[error("missing PAOS header in ECP request")]
    MissingPaosHeader,

    // --- Subject Confirmation errors ---
    #[error("subject confirmation method not supported: {0}")]
    UnsupportedConfirmationMethod(String),

    #[error("bearer confirmation missing SubjectConfirmationData")]
    BearerMissingConfirmationData,

    #[error("bearer confirmation missing Recipient")]
    BearerMissingRecipient,

    #[error("bearer confirmation Recipient mismatch: expected {expected}, got {actual}")]
    BearerRecipientMismatch { expected: String, actual: String },

    #[error("bearer confirmation expired (NotOnOrAfter)")]
    BearerExpired,

    #[error("bearer confirmation has InResponseTo mismatch")]
    BearerInResponseToMismatch,

    // --- Attribute Profile errors ---
    #[error("attribute missing required xsi:type for basic profile")]
    BasicProfileMissingType,

    #[error("invalid attribute name format: expected {expected}, got {actual}")]
    InvalidAttributeNameFormat { expected: String, actual: String },

    // --- IdP Discovery errors ---
    #[error("invalid Common Domain Cookie value")]
    InvalidCommonDomainCookie,

    // --- General errors ---
    #[error("metadata error: {0}")]
    Metadata(String),

    #[error("binding error: {0}")]
    Binding(#[from] crate::bindings::BindingError),

    #[error("core error: {0}")]
    Core(#[from] crate::core::error::CoreError),

    #[error("security error: {0}")]
    Security(#[from] crate::security::SecurityError),

    #[error("unsolicited SSO response not allowed by configuration")]
    UnsolicitedNotAllowed,

    #[error("{0}")]
    Other(String),
}
