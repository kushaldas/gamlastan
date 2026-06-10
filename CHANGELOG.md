# Changelog

All notable changes to this repository will be documented in this file.

The project is still pre-1.0, so minor releases may include behavior changes
where needed to correct protocol handling.

## [Unreleased]

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

[Unreleased]: https://github.com/kushaldas/gamlastan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.3.0
[0.2.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.2.0
[0.1.0]: https://github.com/kushaldas/gamlastan/releases/tag/v0.1.0
