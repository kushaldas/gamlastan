// Constants for the Deployment Profile for the Swedish eID Framework.
//
// Identifiers are taken from:
// - "Deployment Profile for the Swedish eID Framework" (this profile)
// - "Registry for Identifiers" [SC.Registry]
// - "Entity Categories for the Swedish eID Framework" [SC.EntCat]
// - "Attribute Specification for the Swedish eID Framework" [SC.Attributes]
// - Section 8 "Cryptographic Algorithms" of this profile

// ── XML namespaces ──────────────────────────────────────────────────────────

/// SAML 2.0 assertion namespace.
pub const NS_SAML_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SAML 2.0 protocol namespace.
pub const NS_SAML_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML 2.0 metadata namespace.
pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// Metadata UI extension namespace [SAML2MetaUI].
pub const NS_MDUI: &str = "urn:oasis:names:tc:SAML:metadata:ui";
/// Metadata entity-attributes extension namespace [SAML2MetaAttr].
pub const NS_MDATTR: &str = "urn:oasis:names:tc:SAML:metadata:attribute";
/// Metadata algorithm-support extension namespace [SAML2MetaAlgSupport].
pub const NS_ALG: &str = "urn:oasis:names:tc:SAML:metadata:algsupport";
/// Shibboleth metadata namespace (used for `<shibmd:Scope>`).
pub const NS_SHIBMD: &str = "urn:mace:shibboleth:metadata:1.0";
/// IdP discovery protocol namespace (`<idpdisc:DiscoveryResponse>`).
pub const NS_IDPDISCO: &str = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";
/// Principal Selection extension namespace [SC.Principal].
pub const NS_PSC: &str = "http://id.swedenconnect.se/authn/1.0/principal-selection/ns";
/// DSS-Ext namespace where the `SignMessage` element is defined [SC.DSS.Ext].
pub const NS_DSS_EXT: &str = "http://id.elegnamnden.se/csig/1.1/dss-ext/ns";
/// Signature Activation Protocol namespace where `SADRequest`/`SAD` live [SC.SAP].
pub const NS_SAP: &str = "http://id.elegnamnden.se/csig/1.1/sap/ns";
/// XML Digital Signature namespace.
pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

// ── Name identifier formats (section 3) ─────────────────────────────────────

/// Persistent NameID format — the profile default.
pub const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
/// Transient NameID format.
pub const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

// ── Subject confirmation methods (section 6.2) ──────────────────────────────

/// Bearer subject confirmation — used with the Web Browser SSO Profile.
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
/// Holder-of-key subject confirmation — used with the HoK Web Browser SSO Profile.
pub const CM_HOLDER_OF_KEY: &str = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

// ── Bindings (section 5.2) ──────────────────────────────────────────────────

/// HTTP-Redirect binding — used by SPs to send AuthnRequests.
pub const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/// HTTP-POST binding — used by IdPs to send Responses (and optionally requests).
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// Holder-of-key Web Browser SSO Profile binding [SAML2HokProf].
pub const BINDING_HOK_BROWSER: &str =
    "urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser";

// ── Levels of Assurance (section 3.1.1 of [SC.Registry]) ────────────────────

/// LoA 1.
pub const LOA1: &str = "http://id.elegnamnden.se/loa/1.0/loa1";
/// LoA 2.
pub const LOA2: &str = "http://id.elegnamnden.se/loa/1.0/loa2";
/// LoA 3.
pub const LOA3: &str = "http://id.elegnamnden.se/loa/1.0/loa3";
/// LoA 4.
pub const LOA4: &str = "http://id.elegnamnden.se/loa/1.0/loa4";
/// LoA 2 for non-residents.
pub const LOA2_NONRESIDENT: &str = "http://id.elegnamnden.se/loa/1.0/loa2-nonresident";
/// LoA 3 for non-residents.
pub const LOA3_NONRESIDENT: &str = "http://id.elegnamnden.se/loa/1.0/loa3-nonresident";
/// LoA 4 for non-residents.
pub const LOA4_NONRESIDENT: &str = "http://id.elegnamnden.se/loa/1.0/loa4-nonresident";
/// Uncertified ("self-declared") LoA 3.
pub const UNCERTIFIED_LOA3: &str = "http://id.swedenconnect.se/loa/1.0/uncertified-loa3";

// eIDAS authentication context URIs (notified, "nf", and non-notified variants).

/// eIDAS low (non-notified).
pub const EIDAS_LOW: &str = "http://id.elegnamnden.se/loa/1.0/eidas-low";
/// eIDAS substantial (non-notified).
pub const EIDAS_SUBSTANTIAL: &str = "http://id.elegnamnden.se/loa/1.0/eidas-sub";
/// eIDAS high (non-notified).
pub const EIDAS_HIGH: &str = "http://id.elegnamnden.se/loa/1.0/eidas-high";
/// eIDAS low (notified eID).
pub const EIDAS_NF_LOW: &str = "http://id.elegnamnden.se/loa/1.0/eidas-nf-low";
/// eIDAS substantial (notified eID).
pub const EIDAS_NF_SUBSTANTIAL: &str = "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub";
/// eIDAS high (notified eID).
pub const EIDAS_NF_HIGH: &str = "http://id.elegnamnden.se/loa/1.0/eidas-nf-high";

// ── Entity categories (section 2.1, [SC.EntCat]) ────────────────────────────

/// Entity-category attribute name [EntCat / RFC8409].
pub const ENTITY_CATEGORY_ATTR: &str = "http://macedir.org/entity-category";
/// Entity-category-support attribute name [EntCat / RFC8409].
pub const ENTITY_CATEGORY_SUPPORT_ATTR: &str = "http://macedir.org/entity-category-support";
/// Assurance-certification attribute name [SAML2IAP].
pub const ASSURANCE_CERTIFICATION_ATTR: &str =
    "urn:oasis:names:tc:SAML:attribute:assurance-certification";

// Service entity categories (attribute-release / level-of-assurance combinations).

/// Service entity category: LoA 2 with personal identity number.
pub const EC_LOA2_PNR: &str = "http://id.elegnamnden.se/ec/1.0/loa2-pnr";
/// Service entity category: LoA 3 with personal identity number.
pub const EC_LOA3_PNR: &str = "http://id.elegnamnden.se/ec/1.0/loa3-pnr";
/// Service entity category: LoA 4 with personal identity number.
pub const EC_LOA4_PNR: &str = "http://id.elegnamnden.se/ec/1.0/loa4-pnr";
/// Service entity category: eIDAS natural person.
pub const EC_EIDAS_NATURALPERSON: &str = "http://id.elegnamnden.se/ec/1.0/eidas-naturalperson";
/// Service entity category: LoA 3 with name.
pub const EC_LOA3_NAME: &str = "http://id.swedenconnect.se/ec/1.0/loa3-name";
/// Service entity category: LoA 3 with organizational identity.
pub const EC_LOA3_ORGID: &str = "http://id.swedenconnect.se/ec/1.0/loa3-orgid";

// Service type entity categories.

/// Service type entity category: signature service [section 2.1.4].
pub const ST_SIGSERVICE: &str = "http://id.elegnamnden.se/st/1.0/sigservice";
/// Service type entity category: public sector SP.
pub const ST_PUBLIC_SECTOR_SP: &str = "http://id.elegnamnden.se/st/1.0/public-sector-sp";
/// Service type entity category: private sector SP.
pub const ST_PRIVATE_SECTOR_SP: &str = "http://id.elegnamnden.se/st/1.0/private-sector-sp";

// Service property entity categories.

/// Service property entity category: SCAL2 / SAP support [section 2.1.3].
pub const SPROP_SCAL2: &str = "http://id.elegnamnden.se/sprop/1.0/scal2";

// ── Status codes (section 6.4, section 3.1.4 of [SC.Registry]) ───────────────

/// Standard top-level status: success.
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// Standard top-level status: requester error.
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
/// Standard top-level status: responder error.
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
/// Standard top-level status: version mismatch.
pub const STATUS_VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
/// Second-level status: no requested authn context supported.
pub const STATUS_NO_AUTHN_CONTEXT: &str = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
/// Second-level status: principal not known / does not match `PrincipalSelection`.
pub const STATUS_UNKNOWN_PRINCIPAL: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

/// Sweden Connect second-level status: user cancelled the operation.
pub const STATUS_CANCEL: &str = "http://id.elegnamnden.se/status/1.0/cancel";
/// Sweden Connect second-level status: determined fraud.
pub const STATUS_FRAUD: &str = "http://id.elegnamnden.se/status/1.0/fraud";
/// Sweden Connect second-level status: suspected fraud.
pub const STATUS_POSSIBLE_FRAUD: &str = "http://id.elegnamnden.se/status/1.0/possibleFraud";

// ── Attributes (section 4, [SC.Attributes]) ─────────────────────────────────

/// Attribute name format used throughout the framework (URI).
pub const ATTRNAME_FORMAT_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

/// Swedish personal identity number (personnummer / samordningsnummer).
pub const ATTR_PERSONAL_IDENTITY_NUMBER: &str = "urn:oid:1.2.752.29.4.13";
/// Surname.
pub const ATTR_SN: &str = "urn:oid:2.5.4.4";
/// Given name.
pub const ATTR_GIVEN_NAME: &str = "urn:oid:2.5.4.42";
/// Display name.
pub const ATTR_DISPLAY_NAME: &str = "urn:oid:2.16.840.1.113730.3.1.241";
/// Country.
pub const ATTR_C: &str = "urn:oid:2.5.4.6";
/// E-mail address.
pub const ATTR_MAIL: &str = "urn:oid:0.9.2342.19200300.100.1.3";
/// Organization name.
pub const ATTR_O: &str = "urn:oid:2.5.4.10";
/// Date of birth.
pub const ATTR_DATE_OF_BIRTH: &str = "urn:oid:1.3.6.1.5.5.7.9.1";
/// eIDAS provisional identifier (prid).
pub const ATTR_PRID: &str = "urn:oid:1.2.752.201.3.4";
/// eIDAS prid persistence.
pub const ATTR_PRID_PERSISTENCE: &str = "urn:oid:1.2.752.201.3.5";
/// eIDAS person identifier (mapped).
pub const ATTR_EIDAS_PERSON_IDENTIFIER: &str = "urn:oid:1.2.752.201.3.7";
/// Transaction identifier.
pub const ATTR_TRANSACTION_IDENTIFIER: &str = "urn:oid:1.2.752.201.3.2";
/// Authentication context parameters.
pub const ATTR_AUTH_CONTEXT_PARAMS: &str = "urn:oid:1.2.752.201.3.3";
/// Sign message digest attribute (section 3.2.4 of [SC.Attributes]).
pub const ATTR_SIGN_MESSAGE_DIGEST: &str = "urn:oasis:names:tc:SAML:attribute:signMessageDigest";
/// Signature Activation Data (SAD) attribute.
pub const ATTR_SAD: &str = "urn:oid:1.2.752.201.3.12";

// ── Cryptographic algorithm URIs (section 8) ────────────────────────────────

/// Mandatory digest algorithm: SHA-256.
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// Optional digest algorithm: SHA-384.
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
/// Optional digest algorithm: SHA-512.
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
/// Broken digest algorithm: SHA-1 — MUST NOT be used.
pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// Mandatory signature algorithm: RSA-SHA256.
pub const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// Mandatory signature algorithm: ECDSA-SHA256.
pub const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// Optional signature algorithm: RSA-SHA384.
pub const SIG_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
/// Optional signature algorithm: RSA-SHA512.
pub const SIG_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
/// Optional signature algorithm: ECDSA-SHA384.
pub const SIG_ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
/// Optional signature algorithm: ECDSA-SHA512.
pub const SIG_ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

/// Mandatory block encryption: AES-128-CBC.
pub const ENC_AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
/// Mandatory block encryption: AES-192-CBC.
pub const ENC_AES192_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
/// Mandatory block encryption: AES-256-CBC.
pub const ENC_AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
/// Optional block encryption: AES-128-GCM.
pub const ENC_AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
/// Optional block encryption: AES-192-GCM.
pub const ENC_AES192_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
/// Optional block encryption: AES-256-GCM.
pub const ENC_AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

/// Mandatory key transport: RSA-OAEP-MGF1P.
pub const KEYTRANSPORT_RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
/// Broken key transport: RSA PKCS#1 v1.5 — SHOULD NOT be used.
pub const KEYTRANSPORT_RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

/// Mandatory signature algorithms (section 8.2). A conformant sender MUST be
/// able to fall back to one of these when no algorithm intersection exists.
pub const MANDATORY_SIGNATURE_ALGORITHMS: &[&str] = &[SIG_RSA_SHA256, SIG_ECDSA_SHA256];

/// Signature algorithms explicitly permitted by the profile (section 8.2).
pub const ALLOWED_SIGNATURE_ALGORITHMS: &[&str] = &[
    SIG_RSA_SHA256,
    SIG_ECDSA_SHA256,
    SIG_RSA_SHA384,
    SIG_RSA_SHA512,
    SIG_ECDSA_SHA384,
    SIG_ECDSA_SHA512,
];

/// Digest algorithms explicitly permitted by the profile (section 8.1).
pub const ALLOWED_DIGEST_ALGORITHMS: &[&str] = &[DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512];

/// Mandatory block-encryption algorithms (section 8.3).
pub const MANDATORY_BLOCK_ENCRYPTION_ALGORITHMS: &[&str] =
    &[ENC_AES128_CBC, ENC_AES192_CBC, ENC_AES256_CBC];

/// Block-encryption algorithms explicitly permitted by the profile (section 8.3).
pub const ALLOWED_BLOCK_ENCRYPTION_ALGORITHMS: &[&str] = &[
    ENC_AES128_CBC,
    ENC_AES192_CBC,
    ENC_AES256_CBC,
    ENC_AES128_GCM,
    ENC_AES192_GCM,
    ENC_AES256_GCM,
];

/// Key-transport algorithms explicitly permitted by the profile (section 8.4).
pub const ALLOWED_KEY_TRANSPORT_ALGORITHMS: &[&str] = &[KEYTRANSPORT_RSA_OAEP_MGF1P];

/// Returns `true` if `uri` is one of the mandatory signature algorithms.
pub fn is_mandatory_signature_algorithm(uri: &str) -> bool {
    MANDATORY_SIGNATURE_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is one of the signature algorithms permitted by
/// section 8.2 of the profile.
pub fn is_allowed_signature_algorithm(uri: &str) -> bool {
    ALLOWED_SIGNATURE_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is one of the digest algorithms permitted by
/// section 8.1 of the profile.
pub fn is_allowed_digest_algorithm(uri: &str) -> bool {
    ALLOWED_DIGEST_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is one of the block-encryption algorithms permitted
/// by section 8.3 of the profile.
pub fn is_allowed_block_encryption_algorithm(uri: &str) -> bool {
    ALLOWED_BLOCK_ENCRYPTION_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is one of the key-transport algorithms permitted by
/// section 8.4 of the profile.
pub fn is_allowed_key_transport_algorithm(uri: &str) -> bool {
    ALLOWED_KEY_TRANSPORT_ALGORITHMS.contains(&uri)
}

/// Returns `true` if `uri` is an algorithm explicitly called out as broken by
/// this profile (SHA-1 digest or RSA PKCS#1 v1.5 key transport).
pub fn is_broken_algorithm(uri: &str) -> bool {
    uri == DIGEST_SHA1 || uri == KEYTRANSPORT_RSA_1_5
}
