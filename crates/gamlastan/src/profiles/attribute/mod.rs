//! SAML 2.0 attribute profile helpers.
//!
//! Attribute profiles describe how an attribute should be named and typed on the
//! wire. Use these helpers when constructing attributes manually for a response
//! or when validating that a received attribute follows a profile.
//!
//! - [`basic`] - Basic Attribute Profile (`xsi:type`-oriented values);
//! - [`x500`] - X.500/LDAP profile using `urn:oid` names, including common
//!   helpers for `mail`, `cn`, `givenName`, `sn`, `uid`, ePPN, affiliation, and
//!   entitlement;
//! - [`uuid`] - UUID Attribute Profile;
//! - [`dce_pac`] - DCE PAC Attribute Profile.
//!
//! For ordinary name conversion between local names and wire OIDs, prefer
//! [`crate::attribute_map`]. Use this module when profile-specific construction
//! or validation matters.

pub mod basic;
pub mod dce_pac;
pub mod uuid;
pub mod x500;
