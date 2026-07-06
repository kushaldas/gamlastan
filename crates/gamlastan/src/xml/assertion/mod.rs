//! XML serialization and deserialization implementations for assertion types.
//!
//! This module is normally used through [`crate::xml::SamlSerialize`] and
//! [`crate::xml::SamlDeserialize`]. It covers Issuer, NameID, NameIDPolicy,
//! Subject, SubjectConfirmation, Conditions, AuthnStatement, AuthnContext,
//! AttributeStatement, Attribute, AttributeValue, AuthzDecisionStatement, and
//! Assertion.

pub mod deserialize;
pub mod serialize;
