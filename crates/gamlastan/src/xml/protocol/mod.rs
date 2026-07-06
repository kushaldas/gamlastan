//! XML serialization and deserialization implementations for protocol types.
//!
//! This module is normally used through [`crate::xml::SamlSerialize`] and
//! [`crate::xml::SamlDeserialize`]. It covers Status, AuthnRequest, Response,
//! LogoutRequest/Response, ArtifactResolve/Response, ManageNameID,
//! NameIDMapping, AssertionIDRequest, AuthnQuery, AttributeQuery, and
//! AuthzDecisionQuery.

pub mod deserialize;
pub mod serialize;
