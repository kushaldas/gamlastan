// Generated from pysaml2's curated `adfs_v20` attribute map by
// scripts/gen_attribute_maps.py — do not edit by hand.

/// Attribute NameFormat this map applies to.
pub const IDENTIFIER: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// (wire name, local name) pairs for wire-to-local conversion.
pub static FRO: &[(&str, &str)] = &[
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
        "authenticationMethod",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid",
        "denyOnlyPrimaryGroupSid",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid",
        "denyOnlyPrimarySid",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "groupSid",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid",
        "primaryGroupSid",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
        "primarySid",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "role",
    ),
    (
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
        "windowsAccountName",
    ),
    (
        "http://schemas.xmlsoap.com/ws/2005/05/identity/claims/denyonlysid",
        "denyOnlySid",
    ),
    ("http://schemas.xmlsoap.org/claims/commonname", "commonName"),
    ("http://schemas.xmlsoap.org/claims/group", "group"),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "emailAddress",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "givenName",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "name",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "nameId",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier",
        "privatePersonalId",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "surname",
    ),
    (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        "upn",
    ),
];

/// (local name, wire name) pairs for local-to-wire conversion.
pub static TO: &[(&str, &str)] = &[
    (
        "authenticationMethod",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
    ),
    ("commonName", "http://schemas.xmlsoap.org/claims/commonname"),
    (
        "denyOnlyPrimaryGroupSid",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarygroupsid",
    ),
    (
        "denyOnlyPrimarySid",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlyprimarysid",
    ),
    (
        "denyOnlySid",
        "http://schemas.xmlsoap.com/ws/2005/05/identity/claims/denyonlysid",
    ),
    (
        "emailAddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    ),
    (
        "givenName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    ),
    ("group", "http://schemas.xmlsoap.org/claims/group"),
    (
        "groupSid",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
    ),
    (
        "name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    ),
    (
        "nameId",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
    ),
    (
        "primaryGroupSid",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid",
    ),
    (
        "primarySid",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
    ),
    (
        "privatePersonalId",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier",
    ),
    (
        "role",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    ),
    (
        "surname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    ),
    (
        "upn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
    ),
    (
        "windowsAccountName",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
    ),
];
