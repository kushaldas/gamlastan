# Changelog

All notable changes to this repository will be documented in this file.

The project is still pre-1.0, so minor releases may include behavior changes
where needed to correct protocol handling.

## [0.8.0] - 2026-08-03

### Added

- Attack-corpus regression suite (`crates/gamlastan/tests/attack_corpus.rs` plus
  `tests/fixtures/attacks/`) replaying known-malicious SAML payloads against the
  real parse and signature-verification pipeline: DTD/XXE/entity-expansion,
  comment- and CDATA-truncation, processing-instruction injection, smuggled
  `AuthnRequest`-in-`Response`, HMAC `SignatureMethod`, and DigestValue/URI
  signature-wrapping vectors, with a legitimate-response positive control to
  prove the hardening does not over-block.
- `xml::parse_secure_metadata`: a metadata-tolerant secure parse entry point.
  It keeps every `parse_secure` guard (DTD/entity rejection, resource caps, and
  CDATA rejection) but allows XML comments and processing instructions, which
  real federation metadata aggregates (eduGAIN, InCommon) legitimately carry and
  which never invalidate an enveloped metadata signature.
- `xml::SecureParseConfig` gains `forbid_comments`, `forbid_pis`, and
  `forbid_cdata` policy flags (all default `true`) with matching
  `with_forbid_*` builders.

### Changed

- Raised the declared minimum supported Rust version from 1.75 to 1.88 to match
  the resolved Actix, bergshamra, kryptering, and time dependency graph.
- The example IdP now honors `IsPassive`, `ForceAuthn`, RequestedAuthnContext
  comparison, and requested NameID format, returning signed SAML protocol errors
  when a request cannot be satisfied. Reused sessions preserve their original
  authentication context, instant, and session index.
- The example IdP loads trusted SP metadata with `parse_secure_metadata`, so
  legitimate federation comments remain compatible with the hardened parser.
- **Breaking (operational):** the default MDQ fetch body cap dropped from
  200 MiB to 10 MiB per response, with at most 8 response bodies buffered
  concurrently. Per-entity MDQ lookups are unaffected. Deployments fetching
  large federation *aggregates* (e.g. eduGAIN, on the order of 100 MiB) through
  `ReqwestFetcher` must now opt in deliberately with
  `ReqwestFetcher::with_limits(timeout, max_body_bytes, max_concurrent_fetches)`
  or `from_client_with_limits`; the previous 200 MiB-per-request default sized
  every consumer for the worst case. Dynamically fetched MDQ metadata is also
  cached with a 1024-entry bound by default (`MdqClient::with_cache_capacity`;
  oldest fetch evicted first, zero disables caching).
- Upgraded the XML-security/crypto stack: `bergshamra` 0.7.0 → 0.8.0 and the
  direct `kryptering` dependency 0.4 → 0.5, features still mirroring bergshamra
  (`legacy`, `post-quantum`, `pkcs11`) so the shared `Signer` / `Pkcs11Signer`
  types resolve to a single instance with no version or feature drift. `uppsala`
  stays at 0.9. `Key::to_signing_key` and `sign::from_uri` now return `Result`,
  handled at the two crypto call sites.
- Metadata parsing (MDQ verify, SPID and mdui/algsupport extensions, `KeyInfo`
  extraction, Sweden Connect entity attributes) now uses `parse_secure_metadata`
  and gathers full element text (deep concatenation) instead of the first text
  node, so an allowed comment can never truncate a signed value.

### Security

- SPID and example IdP pending authentication state is TTL-bounded, capacity-
  bounded, and atomically consumed only after all terminal validation succeeds.
- The ready Actix SP binds each AuthnRequest to the initiating browser:
  `/saml/login` sets a five-minute `__Host-gamlastan_authn_state` cookie
  (Secure, HttpOnly, SameSite=None) and the ACS consumes an outstanding request
  ID only when the presenting browser holds the state it was issued with, so a
  response solicited in one browser cannot be injected into another.
  **Deployment note:** the cookie is `Secure`, so solicited logins require the
  SP to be served over HTTPS — including local development; over plain HTTP the
  cookie is never stored and every solicited response is rejected at the ACS
  with "InResponseTo does not match". Custom `RequestIdTracker` implementations
  must override `store_bound`/`consume_bound`; the defaults fail closed for the
  ready ACS flow.
- `InMemoryRequestIdTracker` is capacity-bounded (default 1024 outstanding IDs,
  configurable via `with_limits`), evicting the oldest live entry at capacity.
  The login endpoint is unauthenticated, so unbounded correlation state was a
  memory-growth vector (ADR 0041).
- Actix SLO verifies every signature representation supplied with a message; a
  valid Redirect signature can no longer mask an invalid enveloped XML-DSig.
- The SPID ACS now parses network-supplied responses exclusively through the
  secure XML boundary before typed deserialization.
- `parse_secure` now rejects XML comments, processing instructions, and CDATA
  sections anywhere in a document. Comments and CDATA both split an element's
  text into multiple nodes while canonicalizing to the same signed bytes, so a
  first-text-node reader could see a different value than the signature covered
  (the comment- and CDATA-truncation authentication-bypass class,
  CVE-2017-11427). Refusing them before any field text is extracted closes the
  bypass at the parse choke point.
- `ResponseRef::from_xml` rejects smuggled protocol *request* elements
  (`AuthnRequest`, `LogoutRequest`, `ArtifactResolve`, `AttributeQuery`,
  `AuthnQuery`, `AuthzDecisionQuery`, `AssertionIDRequest`,
  `ManageNameIDRequest`, `NameIDMappingRequest`) as direct children of a
  `<samlp:Response>` — a classic signature-wrapping / request-smuggling vector.
- XML-DSig verification rejects HMAC-based `SignatureMethod` algorithms outright
  (`SamlVerifier::set_reject_hmac_signatures`, default on): SAML IdPs sign with
  asymmetric keys, so a legitimate response is never HMAC-signed, and refusing
  HMAC closes a symmetric key-confusion class as defence in depth on top of
  `trusted_keys_only`. The detection list is kept a superset of the DSig
  backend's HMAC URIs (including `hmac-ripemd160`) so the two cannot drift. The
  `ds:Object` (E91) and HMAC structural pre-scans parse comment-tolerantly so
  comment-bearing federation metadata is not rejected during verification.

## [0.7.0] - 2026-07-06

### Added

- `profiles::sso::idp` response/assertion signing helpers: `signature_template`
  (build an empty enveloped `<ds:Signature>` template for a reference ID, with
  exclusive c14n, the enveloped-signature transform, a SHA-256 digest and the
  signing certificate in `<ds:KeyInfo>`), `sign_response_xml` (splice + sign a
  serialized `Response` - assertion, response envelope, or both, inner-to-outer),
  and `create_signed_response` (one call: `create_response` + serialize + sign).
  The signature is anchored after each element's `<saml:Issuer>`, per the SAML
  schema ordering, so callers no longer hand-roll the template and splice. See
  ADR 0033.
- Guarded PySAML2 MD5 EPTID compatibility for stock PySAML2 cutovers:
  `idp::eptid::EptidDigest::Pysaml2Md5Legacy`, `EptidOptions`, and fallible
  constructors. SHA-256 remains the default; legacy MD5 requires
  `allow_legacy_md5 = true`. See ADR 0036.
- Expanded docs.rs-facing module documentation and examples across the public
  library surface, including attribute maps, bindings, crypto, IdP helpers,
  metadata, profiles, PySAML2 compatibility, security defaults, and XML parsing.
- Security hardening documentation covering signature reference binding,
  request/response correlation, trusted SP boundaries, metadata key extraction,
  attribute-release matching, and `KeyInfo` certificate extraction.

### Changed

- `SwedenConnect` `build_authn_request` now carries the `SignMessage` /
  `SADRequest` / `PrincipalSelection` extensions on the typed request's
  `AuthnRequest::extensions` field, so serializing the request emits the
  `<saml2p:Extensions>` block in the schema-correct position (after
  `<saml:Issuer>`). The `SwedenConnectAuthnRequest::extensions_xml` field is
  removed: callers no longer splice a separate extensions string into the
  serialized XML - they just serialize and sign the request.
- `xml::SecureParseConfig` and `parse_secure_with_config`, exposing uppsala's
  parser hardening knobs (`max_depth`, `max_entity_expansion`, parse-time DTD
  rejection, and entity-declaration rejection) while keeping `parse_secure`
  fail-closed for SAML by default.
- Crypto hardening knobs for the bergshamra 0.7 stack:
  `SamlVerifier::set_require_reference_digests`,
  `SamlVerifier::set_allow_raw_inline_keyinfo_with_trust_anchors`, and
  `SamlEncryptor` / `SamlDecryptor` PBKDF2 iteration caps.
- Ready Actix IdP handlers can resolve trusted SP metadata dynamically while
  keeping the same fail-closed trust requirements as statically configured SPs.
  See ADR 0034.

### Security

- XML-DSig verification now binds verified reference IDs to the exact SAML
  object being consumed across ACS, MDQ, Sweden Connect, SPID, and example
  flows. A valid signature elsewhere in the document no longer authenticates a
  different Response or Assertion. See ADR 0028.
- Solicited SAML response processors now require present, matching
  `InResponseTo` values and reject dangling `InResponseTo` on otherwise
  unsolicited flows. This covers artifact resolution, assertion query,
  ManageNameID, NameIDMapping, Sweden Connect, and logout response handling. See
  ADR 0029.
- Ready IdP and federation helper boundaries now require the peer to resolve to
  trusted metadata before issuing assertions, destroying sessions, resolving
  artifacts, or accepting dynamically fetched entities. See ADR 0030 and
  ADR 0034.
- Metadata key extraction and input validation now fail closed for malformed
  trust-anchor fragments, self-closing `X509Data`, namespace-confused X.509
  lookalikes, duplicate Assertion IDs in SPID responses, and unsafe RelayState
  handling. See ADR 0031.
- Attribute release decisions now match on trusted SAML attribute `Name` values,
  never on SP-supplied `FriendlyName`, unless PySAML2 compatibility is
  explicitly enabled with `ReleasePolicy::allow_friendly_name_release_matching`.
  See ADR 0032.
- `SecurityConfig::require_signed_assertions`, SAML `WantAssertionsSigned`, and
  Sweden Connect `want_assertions_signed` now require the consumed Assertion's
  own verified signature. A verified Response signature no longer satisfies that
  direct assertion-signature policy. The Actix ACS helper now verifies all
  enveloped signatures so double-signed Responses still collect both Response
  and Assertion reference IDs, and Sweden Connect `verify_and_process_response`
  verifies decrypted assertion signatures after decryption. See ADR 0037.
- `parse_secure` now rejects `<!DOCTYPE>` at Uppsala parse time instead of
  parsing a bounded DTD and rejecting the resulting document afterward.
- Uppsala 0.9 includes the 0.8 reserved namespace-binding hardening, so illegal
  `xml` / `xmlns` namespace bindings are rejected by the parser instead of
  being accepted into a non-idempotent DOM.
- XML-DSig verification now keeps bergshamra 0.7's local reference-digest
  requirement enabled by default and continues to reject raw inline signing keys
  when trust anchors are configured. The default HMAC truncation floor follows
  bergshamra's hardened 160-bit policy.
- Lockfile-only `anyhow` update to 1.0.103 clears RUSTSEC-2026-0190 from
  `cargo audit --deny warnings`.

## [0.6.0] - 2026-06-28

### Added

- `idp::entity_category`: owned, runtime-constructible entity categories.
  `OwnedEntityCategoryRule` / `OwnedEntityCategoryPolicy` (with `new` /
  `with_rule` / `with_conflicts` / `with_only_required` / `extend_from_static`
  builders), `EntityCategoryRule::as_owned` / `EntityCategoryPolicy::as_owned`,
  and `releasable_attributes_owned`. Callers (including language bindings) can
  now define their own entity categories at runtime and mix them with the
  shipped policies, with identical matching semantics. The shipped `&'static`
  policies are unchanged. `PolicyEntry::with_owned_entity_categories` accepts
  them; `with_entity_categories` keeps its signature. See ADR 0026.
- Metadata extension accessors: `EntityDescriptor::registration_authority()`
  (`mdrpi:RegistrationInfo`), `entity_categories()` and
  `entity_attribute_values()` (`mdattr:EntityAttributes`), backed by the new
  `metadata::types::md_extensions::MdExtensions` (fail-soft, `parse_secure`).
- MDUI and algorithm-support metadata extensions: `MdExtensions` now also parses
  `mdui:UIInfo` (`UiInfo` / `LocalizedText` / `UiLogo`: display names,
  descriptions, information/privacy URLs, keywords, logos) and
  `alg:SigningMethod` / `alg:DigestMethod` (`signing_methods` / `digest_methods`
  / `supported_algorithms()`). `EntityDescriptor` exposes `sp_ui_info()` /
  `idp_ui_info()` (role descriptor first, then entity-level Extensions) and
  `supported_algorithms()` (aggregated across the entity and SSO roles,
  de-duplicated). Used by IdPs to display an SP's name/logo on consent screens
  and to negotiate signing/digest algorithms.
- `idp::policy::ReleasePolicy` registration-authority-based selection:
  `set_registration_authority` / `with_registration_authority` /
  `register_sp_metadata`, resolving SP entity ID > registration authority >
  default (pysaml2 `Policy.get` precedence). See ADR 0027.

### Security

- Added `gamlastan::xml::parse_secure`, a hardened parse entry point for all
  attacker-controlled XML. It is a drop-in replacement for `uppsala::parse`
  that, on top of uppsala 0.5's default resource limits, **rejects any document
  carrying a DTD (`<!DOCTYPE …>`)** so that no DTD-bearing document is accepted
  past the parse boundary — removing the XXE / entity-smuggling entry point from
  downstream SAML handling. All inbound and remote-derived parse sites were
  migrated to it: SP/IdP Actix handlers, SOAP/PAOS envelope unwrap, ECP envelope
  parsing, Sweden Connect response validation/decryption and decrypted
  assertions, IdP-discovery and PEFIM extension parsing, SPID and Sweden Connect
  metadata extensions, `KeyInfo` X.509 extraction, the standalone `ds:Object`
  signature guard, and the MDQ verifier. See ADR 0024.
- Inbound XML is now bounded by uppsala 0.5's fail-closed default limits —
  element-nesting depth (128), entity-expansion byte budget (1 MiB), and
  entity-nesting depth (256) — defeating deep-nesting stack exhaustion and
  billion-laughs / quadratic entity amplification before assertion validation
  runs. uppsala 0.5 also sanitizes serializer output (comments, PIs, CDATA,
  names, encoding, control characters). See ADR 0023.

### Changed

- Upgraded the XML/crypto stack: `uppsala` 0.4 → 0.5, `bergshamra` 0.5.1 → 0.6.0,
  and the direct `kryptering` dependency 0.3 → 0.4 with features mirroring
  bergshamra (`legacy`, `post-quantum`, `pkcs11`) so the shared `Signer` /
  `Pkcs11Signer` types resolve to a single instance with no version or feature
  drift. All are consumed from crates.io. See ADR 0023.
- Migrated `spid-sp-test` and `example-idp` off the unmaintained `rustls-pemfile`
  crate (RUSTSEC-2025-0134) to the `PemObject` API in `rustls-pki-types`, and
  dropped the `rustls-pemfile` dependency.
- IdP response builders now take a `ResponseTimes { issue_instant, authn_instant }`
  value instead of a single `now: DateTime<Utc>`. Affects
  `profiles::sso::idp::{create_response, create_unsolicited_response}` and
  `profiles::swedenconnect::idp::create_response`. Fresh-login callers use
  `ResponseTimes::at(now)` to preserve the previous behaviour.
  `gamlastan_actix::idp::AuthnCallbackResult` gains
  `authn_instant: Option<DateTime<Utc>>` (`None` means "authenticated now"), so
  a callback reusing a session reports its real authentication time. Breaking
  API change. See ADR 0025 and issue #15.

### Fixed

- IdP response construction no longer forces `AuthnStatement/@AuthnInstant` to
  equal the document issue time. The previous single-`now` builders conflated
  *when the principal authenticated* with *when the response was generated*,
  which over-reported authentication freshness to SPs that rely on it (e.g. via
  `RequestedAuthnContext` / `ForceAuthn` or a max-age policy) whenever an
  existing SSO session was reused. The two instants are now independent. See
  ADR 0025 and issue #15.
- Cleared all `cargo audit` findings: `quinn-proto` 0.11.14 → 0.11.15
  (RUSTSEC-2026-0185, remote memory exhaustion), `rand` 0.8.5 → 0.8.6 and
  0.9.2 → 0.9.4 (RUSTSEC-2026-0097), and `crypto-bigint` off the yanked 0.7.3.

## [0.5.0] - 2026-06-21

### Security

- `gamlastan-actix` ACS processing now verifies SAML Response / Assertion
  XML signatures with trusted IdP metadata keys before profile validation or
  claim extraction. Signature markup alone no longer satisfies signed-assertion
  requirements; verified XML-DSig reference IDs are bound to the parsed Response
  or Assertion used for authentication. Added regression coverage for tampered
  signed responses, signature wrapping, and hostile inline `KeyInfo`. See
  ADR 0016.
- Web SSO assertion validation now fails closed when required bearer controls
  are missing: no `Conditions` means the assertion expiry and audience checks
  fail, and bearer `SubjectConfirmationData` without `NotOnOrAfter` fails. See
  ADR 0017.
- SOAP unwrap now validates the SOAP 1.1 namespace, rejects duplicate Header /
  Body elements, and requires exactly one Body element child, closing an
  element-smuggling / wrapping confusion path. See ADR 0018.
- `gamlastan-actix` SP SLO handling now requires trusted signed LogoutRequest
  and LogoutResponse messages, verifies Redirect or XML signatures against IdP
  metadata keys, validates Issuer and Destination, and requires LogoutResponse
  `InResponseTo` to match an outstanding SP-issued LogoutRequest. See ADR 0019.
- XML Signature `ds:Object` rejection is now namespace-aware and shared by the
  verifier and security helper, so alternate XMLDSig prefixes no longer bypass
  SAML errata E91 enforcement. See ADR 0020.
- HTTP Redirect and POST bindings now reject duplicate or ambiguous
  security-sensitive parameters before decoding: duplicate `SAMLRequest`,
  `SAMLResponse`, `RelayState`, Redirect `SigAlg`, Redirect `Signature`, mixed
  request/response parameters, and Redirect `Signature` without `SigAlg`. POST
  decoding now also fails closed on invalid UTF-8 bodies and malformed
  `RelayState` URL encoding. See ADR 0021.
- Generic SP response processing now rejects opaque encrypted-only responses
  and rejects `require_encrypted_assertions` in the generic processor, which
  cannot decrypt or prove encrypted-assertion provenance. See ADR 0022.

### Changed

- `profiles::sso::sp::process_response_with_verified_signatures()` was added
  for callers that perform XML-DSig verification outside the generic SP
  processor and need to pass verified Response / Assertion IDs into validation.
- `SecurityConfig::strict()` and the ready-to-use Actix SP paths are stricter
  about signed messages, SSO bearer validity, and SLO trust/correlation.

### Fixed

- Metadata KeyDescriptor certificate extraction now handles real-world
  `KeyInfo` fragments that rely on inherited XMLDSig namespace declarations.
  The test fixture coverage includes `edugain-v2.xml`.
- POST binding `RelayState` decoding now treats `+` as a form-encoded space and
  returns URL decoding errors instead of falling back to malformed raw values.

### Documentation

- Added ADRs `0016` through `0022` documenting the security decisions from the
  SAML security audit.

### Upgrade Notes

- Direct callers of `profiles::sso::sp::process_response()` that require signed
  assertions or signed responses must either disable those requirements for a
  trusted unsigned deployment or verify the exact XML response with
  `SamlVerifier` and call `process_response_with_verified_signatures()`.
- IdP metadata used by `gamlastan-actix` SP ACS/SLO handlers must contain usable
  signing certificates for signed incoming messages.
- Tests or adapters that previously accepted duplicate SAML binding parameters,
  malformed POST bodies, malformed `RelayState`, missing Web SSO audience /
  expiry controls, unsigned SLO messages, or opaque encrypted-only generic SP
  responses must be updated to expect rejection.

## [0.4.1] - 2026-06-10

### Changed

- `idp::entity_category`: REFEDS Access categories (personalized / pseudonymous
  / anonymous) now use a conflict-aware matcher. `EntityCategoryRule` gained a
  `conflicts` field (the `no_aggregation` flag was removed), mirroring pysaml2's
  `EntityCategoryMatcher` on the `ft-typing` / `ft-refeds_ec` branches: a rule
  matches only when every required category is present and no conflicting
  category is. The three REFEDS Access rules are mutually exclusive yet combine
  with non-conflicting categories (R&S, CoCo, ESI), and are now active by
  default in the `SWAMID` policy. See ADR 0014.

### Added

- `idp::policy`: subject-id / pairwise-id mutual exclusion (pysaml2 PR #987).
  New `SubjectIdReq` (parsed from the SP's `subject-id:req` metadata entity
  attribute) and `prefer_pairwise_over_subject_id()`; `ReleasePolicy::filter()`
  and `restrict()` take a `subject_id_req` argument and drop `subject-id` when
  the requirement is `any` and both `subject-id` and `pairwise-id` would
  otherwise be released. See ADR 0015.

## [0.4.0] - 2026-06-10

### Added

- `idp` module: IdP-side server infrastructure closing the pysaml2 parity
  gaps in IdP attribute handling:
  - `idp::policy::ReleasePolicy` — per-SP attribute release policy engine
    (regex value restrictions, lifetime, NameID format, attribute NameFormat,
    sign targets incl. on-demand, `fail_on_missing_requested`, filtering
    against SP `AttributeConsumingService` required/optional attributes).
  - `idp::entity_category` — shipped entity-category release policies
    (eduGAIN CoCo v1, REFEDS R&S, InCommon R&S, SWAMID incl. CoCo v2/ESI,
    AT eGov PVP2, and opt-in REFEDS personalized/pseudonymous/anonymous
    no-aggregation rules).
  - `idp::ident::IdentDb` — identity database with transient/persistent
    NameID generation honoring `NameIDPolicy` (E14 AllowCreate, E78 stable
    persistent IDs), pluggable `IdentityStore` backend, and server-side
    ManageNameID (NewID/Terminate) and NameIDMapping semantics.
  - `idp::eptid::Eptid` — deterministic eduPersonTargetedID generation
    (SHA-256 based; values intentionally differ from pysaml2's MD5 scheme).
  - `idp::authn_broker::AuthnBroker` — RequestedAuthnContext matching with
    exact/minimum/maximum/better comparison semantics.
  - `idp::assertion_store` — issued-assertion store plus
    `create_assertion_id_request_response()` and
    `create_authn_query_response()` to serve AssertionIDRequest and
    AuthnQuery from stored assertions.
- `attribute_map` module: bidirectional wire <-> local attribute name
  conversion with shipped maps generated from pysaml2's curated collection
  (`saml_uri` with eduPerson/SCHAC/eIDAS/voPerson catalogs, `basic`,
  `shibboleth_uri`, `adfs_v1x`, `adfs_v20`), `allow_unknown_attributes`
  pass-through semantics, and eduPersonTargetedID helpers.
- `AttributeValue::NameId` / `AttributeValueRef::NameId` variants:
  NameID-valued attribute values (EPTID) now parse and serialize as
  structured `saml:NameID` elements instead of raw XML.
- `Assertion.advice` (`Advice` / `AdviceRef`): `saml:Advice` with
  AssertionIDRef/AssertionURIRef references, embedded assertions, and
  embedded encrypted assertions, fully round-tripped.
- Per-request certificate encryption (PEFIM flow):
  `crypto::encryptor::{SamlEncryptor::for_certificate,
  encrypted_data_template_for_cert, CertEncryptionOptions}` and
  `profiles::sso::idp::{encrypt_assertion_to_cert,
  encrypt_response_assertions_to_cert, add_encrypted_advice,
  assertion_to_self_contained_xml}` — encrypt assertions toward a
  certificate supplied in the AuthnRequest (e.g. `pefim:SPCertEnc`) with
  AES-256-GCM + RSA-OAEP defaults.

  Upgrade notes:

  - `Assertion`/`AssertionRef` gained an `advice` field and
    `AttributeValue`/`AttributeValueRef` gained a `NameId` variant; code
    using struct literals or exhaustive matches must add the new
    field/arm.
  - `ProfileError` gained `Crypto` and `Xml` variants.

### Changed

- Discovery Service return URL validation in `profiles::idp_discovery` now
  preserves any query string registered in metadata
  `idpdisc:DiscoveryResponse` endpoints. A caller-supplied `return` URL may
  extend the registered query string, but it may no longer replace it.

  Upgrade notes:

  - If your registered DiscoveryResponse endpoint includes fixed query
    parameters, ensure your discovery service preserves those parameters when
    echoing the `return` URL.
  - Tests and mocks that previously used the same path with different query
    values will now fail validation and should be updated.

- `profiles::logout::SpLogoutOrchestrator` now treats
  `urn:oasis:names:tc:SAML:2.0:status:PartialLogout` as a terminal non-success
  outcome for orchestration state and `progress()` accounting.

  Upgrade notes:

  - `LogoutResponseOutcome` still exposes the wire-level response as
    `success: true` and `partial: true` when the top-level SAML status is
    `Success` with `PartialLogout`.
  - `successful_logouts` now counts only fully successful participants. If you
    previously treated partial logout as a success in orchestration metrics,
    update your code to inspect `outcome.partial` or `failed_participants`.

### Fixed

- ECP envelope parsing in `profiles::sso::ecp` now verifies the SOAP 1.1
  namespace on the `Envelope`, `Header`, `Body`, and `Fault` elements
  (previously only local names were checked) and rejects SOAP Bodies with
  more than one child element, closing an element-smuggling vector.
- `profiles::logout::SpLogoutOrchestrator::handle_response()` now rejects
  LogoutResponses without an `Issuer`; previously the issuer check was
  skipped when the element was absent, allowing spoofed responses to be
  correlated solely by `InResponseTo`.
- Phase-1 ECP parsing in `profiles::sso::ecp` now rejects envelopes that omit
  the mandatory `ecp:Request` header and returns the explicit
  `ProfileError::EcpMissingRequestHeader` error variant.

  Upgrade notes:

  - Callers that pattern-match ECP parse errors should handle
    `ProfileError::EcpMissingRequestHeader` explicitly.
  - ECP phase-1 fixtures and integration tests must include both
    `paos:Request` and `ecp:Request` headers.

### Documentation

- Added ADRs `0005` through `0007` covering discovery return URL matching,
  ECP phase-1 header requirements, and partial logout accounting.

## [0.3.0] - 2026-06-10

Initial curated changelog baseline for the current workspace release.
Earlier `v0.3.0` changes were published before this file existed; consult the
Git history and GitHub release notes for the full change set.

## [0.2.0] - 2026-06-09

Historical release recorded before changelog adoption.

## [0.1.0] - 2026-06-08

Historical release recorded before changelog adoption.

[0.8.0]: https://github.com/kushaldas/gamlastan/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kushaldas/gamlastan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kushaldas/gamlastan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kushaldas/gamlastan/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kushaldas/gamlastan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kushaldas/gamlastan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.3.0
[0.2.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.2.0
[0.1.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.1.0
