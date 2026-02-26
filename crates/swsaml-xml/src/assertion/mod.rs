// SamlDeserialize and SamlSerialize implementations for assertion types.
//
// Covers: Issuer, NameId, NameIdPolicy, Subject, SubjectConfirmation,
//         SubjectConfirmationData, Conditions, AudienceRestriction,
//         ProxyRestriction, AuthnStatement, AuthnContext, SubjectLocality,
//         AuthzDecisionStatement, Action, Evidence, DecisionType,
//         AttributeStatement, Attribute, AttributeValue, Assertion.

pub mod deserialize;
pub mod serialize;
