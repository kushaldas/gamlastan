// SAML 2.0 Attribute Profiles
//
// Submodules:
// - basic: Basic Attribute Profile (xsi:type required)
// - x500: X.500/LDAP Attribute Profile (urn:oid names)
// - uuid: UUID Attribute Profile (urn:uuid names)
// - dce_pac: DCE PAC Attribute Profile

pub mod basic;
pub mod dce_pac;
pub mod uuid;
pub mod x500;
