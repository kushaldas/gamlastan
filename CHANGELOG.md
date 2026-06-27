# Changelog

All notable changes to this repository will be documented in this file.

The project is still pre-1.0, so minor releases may include behavior changes
where needed to correct protocol handling.

## [Unreleased]

## [0.6.0] - 2026-06-27

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

### Fixed

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

[Unreleased]: https://github.com/kushaldas/gamlastan/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/kushaldas/gamlastan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kushaldas/gamlastan/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kushaldas/gamlastan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kushaldas/gamlastan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.3.0
[0.2.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.2.0
[0.1.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.1.0
