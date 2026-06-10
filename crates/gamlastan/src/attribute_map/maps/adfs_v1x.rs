// Generated from pysaml2's curated `adfs_v1x` attribute map by
// scripts/gen_attribute_maps.py — do not edit by hand.

/// Attribute NameFormat this map applies to.
pub const IDENTIFIER: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// (wire name, local name) pairs for wire-to-local conversion.
pub static FRO: &[(&str, &str)] = &[
    ("http://schemas.xmlsoap.org/claims/commonname", "commonName"),
    (
        "http://schemas.xmlsoap.org/claims/emailaddress",
        "emailAddress",
    ),
    ("http://schemas.xmlsoap.org/claims/group", "group"),
    ("http://schemas.xmlsoap.org/claims/upn", "upn"),
];

/// (local name, wire name) pairs for local-to-wire conversion.
pub static TO: &[(&str, &str)] = &[
    ("commonName", "http://schemas.xmlsoap.org/claims/commonname"),
    (
        "emailAddress",
        "http://schemas.xmlsoap.org/claims/emailaddress",
    ),
    ("group", "http://schemas.xmlsoap.org/claims/group"),
    ("upn", "http://schemas.xmlsoap.org/claims/upn"),
];
