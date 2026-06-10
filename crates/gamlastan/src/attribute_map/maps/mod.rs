// Shipped attribute maps, generated from pysaml2's curated attribute
// map collection by `scripts/gen_attribute_maps.py`.
//
// Each module exposes `IDENTIFIER` (the SAML attribute NameFormat the map
// applies to), `FRO` (wire name -> local name) and `TO` (local name -> wire
// name). The maps are data only; the conversion logic lives in
// [`crate::attribute_map`].

pub mod adfs_v1x;
pub mod adfs_v20;
pub mod basic;
pub mod saml_uri;
pub mod shibboleth_uri;
