// Assertion module - SAML 2.0 assertion types in dual Ref<'a>/Owned pattern

pub mod attribute;
pub mod authn;
pub mod authz;
pub mod conditions;
pub mod issuer;
pub mod name_id;
pub mod subject;
pub mod types;

// Re-exports
pub use attribute::{
    Attribute, AttributeRef, AttributeStatement, AttributeStatementRef, AttributeValue,
    AttributeValueRef,
};
pub use authn::{
    AuthnContext, AuthnContextRef, AuthnStatement, AuthnStatementRef, SubjectLocality,
    SubjectLocalityRef,
};
pub use authz::{
    Action, ActionRef, AuthzDecisionStatement, AuthzDecisionStatementRef, DecisionType, Evidence,
    EvidenceRef,
};
pub use conditions::{
    AudienceRestriction, AudienceRestrictionRef, Conditions, ConditionsRef, ProxyRestriction,
    ProxyRestrictionRef,
};
pub use issuer::{Issuer, IssuerRef};
pub use name_id::{
    NameId, NameIdOrEncryptedId, NameIdOrEncryptedIdRef, NameIdPolicy, NameIdPolicyRef, NameIdRef,
};
pub use subject::{
    Subject, SubjectConfirmation, SubjectConfirmationData, SubjectConfirmationDataRef,
    SubjectConfirmationRef, SubjectRef,
};
pub use types::{Assertion, AssertionRef};
