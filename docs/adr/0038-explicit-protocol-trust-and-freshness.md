# ADR 0038 - Explicit protocol trust and freshness

- **Status:** Accepted
- **Date:** 2026-08-02
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan/src/profiles/sso/{idp,sp}.rs`, `crates/gamlastan/src/profiles/logout.rs`, `crates/gamlastan/src/security/validation.rs`, `crates/gamlastan/src/idp/assertion_store.rs`

## Context

Several low-level profile APIs accepted protocol data without receiving the
trusted context needed to validate it. IdP AuthnRequest processing could accept
an ACS URL without SP metadata, replay protection was optional, logout helpers
did not require signature provenance or an expected issuer, and assertion age
and stored AuthnStatement lifetime were not consistently enforced.

Persistent NameID uniqueness also compared a persistent identifier with itself
as the “principal”. That check could never detect reassignment. The SP library
cannot derive an IdP's independent local account identifier from a SAML
response.

## Decision

1. `process_authn_request` requires trusted `SpSsoDescriptor` metadata and an
   explicit `request_signature_verified` proof. Explicit ACS selection matches
   both URL and binding. Metadata `AuthnRequestsSigned` is enforced.
2. SP response profile entrypoints require a `ReplayCache`; missing replay state
   is a validation failure in lower-level validator use.
3. Assertion `IssueInstant` is checked against `max_assertion_age_seconds`.
4. AuthnQuery responses only reuse assertions whose Conditions and session
   lifetime are currently valid.
5. Logout request/response processing requires explicit signature provenance,
   expected issuer matching, and correlation.
6. Persistent-ID uniqueness is opt-in because it requires an application store
   and independent local principal. When enabled without both, validation fails
   closed. Built-in defaults do not pretend to enforce an invariant they cannot
   observe.

## Consequences

- These profile APIs intentionally break callers that omitted trust, replay, or
  signature context; callers must migrate rather than silently retain unsafe
  behavior.
- Valid metadata-selected ACS endpoints, signed requests, one-time responses,
  current assertions, and authenticated logout messages remain supported.
- Distributed deployments should implement `ReplayCache` over shared storage.
- Applications that know the IdP-local principal may explicitly enable E78
  enforcement with `with_persistent_id_store(store, principal)`.

