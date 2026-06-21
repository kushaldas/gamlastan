# ADR 0008 — IdP-side server infrastructure as a `gamlastan::idp` module

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Core (§2.7 statements, §3.3 queries, §3.6 NameID management), SAML V2.0 Profiles (§5 attribute, §6 AssertionIDRequest/AuthnQuery); pysaml2 `Server`/`Policy`/`IdentDB`/`AuthnBroker`/`Eptid`
- **Implementation:** `crates/gamlastan/src/idp/`

## Context

gamlastan already produced IdP-side *messages* (`profiles::sso::idp::create_response`,
the Sweden Connect IdP path, error responses). What it lacked was the IdP-side
*server infrastructure* that pysaml2's `Server` class provides around message
construction: deciding **which attributes to release to which SP**, generating
and remembering **NameIDs**, matching a **RequestedAuthnContext** to a configured
authentication method, and answering **back-channel queries** (AssertionIDRequest,
AuthnQuery) from previously issued assertions.

These are cohesive, IdP-only concerns. The question was where they should live and
how stateful they should be, given that gamlastan is a library (no ambient process,
no mandated database) used both in single-instance binaries (`example-idp`) and,
prospectively, in multi-instance deployments.

## Decision

Add a single `gamlastan::idp` module grouping the IdP server-side concerns, one
file per concern, each ported from its pysaml2 counterpart but re-expressed in
idiomatic Rust:

| File | pysaml2 analogue | Responsibility |
| --- | --- | --- |
| `policy.rs` | `Policy` | Per-SP attribute **release policy** engine: filter / restrict / value-regex / NameFormat / lifetime / `fail_on_missing_requested` / `SignTargets` |
| `entity_category.rs` | `entity_category.*` | Shipped **federation release rules** keyed on `mdattr:EntityAttributes` category URIs |
| `ident.rs` | `IdentDB` | **Identity database**: transient/persistent NameID generation, find/match/remove, ManageNameID + NameIDMapping server side |
| `eptid.rs` | `Eptid` / `EptidShelve` | Deterministic **eduPersonTargetedID** generation with caching |
| `authn_broker.rs` | `AuthnBroker` | **RequestedAuthnContext → method** matching (exact/minimum/maximum/better) |
| `assertion_store.rs` | session DB | **Issued-assertion store** serving AssertionIDRequest and AuthnQuery |

Two cross-cutting design choices apply across the module.

### 1. State is pluggable behind a `Send + Sync` trait; in-memory is the default

`ident`, `eptid`, and `assertion_store` all persist state. Rather than hard-wire a
backend, each defines a small trait (`IdentityStore`, `AssertionStore`) with an
`InMemory*` implementation shipped for single-instance deployments and tests. A
deployment that needs to scale horizontally implements the trait over Redis/SQL
without touching the policy or message-construction logic.

- ➕ Single-instance and test use is zero-config; multi-instance is a backend swap.
- ➕ Keeps gamlastan dependency-free of any particular datastore.
- ➖ The in-memory stores use `Mutex<HashMap<…>>` — correct, but not the final word
  on contention; that is the integrator's concern once they supply a real backend.

### 2. Ported from pysaml2 semantics deliberately, with two principled divergences

The release-policy filter pipeline (`filter` → `restrict` →
`filter_on_attributes` → `filter_on_demands` → `filter_on_wire_representation` →
`filter_attribute_value_assertions`) and the entity-category rule modifiers
(`only_required`, `no_aggregation`) reproduce pysaml2 behaviour so existing
federation deployments get the release decisions they expect. Two divergences are
intentional:

- **EPTID uses SHA-256, not MD5.** pysaml2 hashes the targeted-ID with MD5;
  gamlastan refuses MD5 on principle and uses SHA-256. **Consequence:** the
  generated EPTID values differ between the two stacks for the same secret — they
  are *stable within gamlastan* but not interchangeable with a pysaml2 deployment.
  Migrators must **import previously issued values into the store**, not recompute
  them. Documented at the top of `eptid.rs`.
- **Value restrictions use Rust `regex` with Python `re.match` anchoring.**
  pysaml2 restricts attribute values with `re.match` (anchored at the start, not
  the end). gamlastan adds the `regex` crate and reproduces that anchoring
  explicitly (`test_regex_is_anchored_like_python_match`) so ported policies match
  the same values.

## Consequences

- gamlastan can now run as a policy-driven IdP, not just emit IdP messages: an
  integrator wires a `ReleasePolicy`, an `IdentDb`, an `AuthnBroker`, and an
  `AssertionStore` and gets release decisions, NameID lifecycle, authn-context
  matching, and back-channel query answers.
- Attribute matching in `policy.rs` is on **local (friendly) names**, resolved
  through the converter set from ADR 0009, so policies can be written against
  human names while the wire carries `urn:oid:…`.
- A new `regex` runtime dependency (used only by the policy engine).
- The module is **additive**: it introduces no breaking change to existing
  message-construction APIs.

## Alternatives considered

- **One file / one giant `idp.rs`.** Rejected: six independent concerns; the split
  keeps each testable and matches the pysaml2 mental model contributors arrive with.
- **A separate `gamlastan-idp` crate.** Deferred: the module depends only on
  `gamlastan` internals (core types, crypto digest, attribute_map, metadata). An
  in-crate module avoids a second public surface and version to keep in lockstep;
  it can be extracted if external consumers ever need it standalone.
- **Mandate a concrete datastore (e.g. SQLite).** Rejected: forces a dependency and
  a schema on every consumer, including tests and the in-process example IdP. The
  trait keeps the choice with the deployment.
- **Keep pysaml2's MD5 EPTID for bit-for-bit parity.** Rejected: shipping MD5 in a
  security library is not acceptable; the migration-by-import path covers the one
  scenario (cutover from pysaml2) where the difference matters.

## Validation

- `cargo test -p gamlastan` — 592 unit tests passing, including the
  `idp::policy::tests` suite (defaults, `filter_on_attributes` required/optional,
  `filter_on_demands`, value-regex restrictions, Python-`match` anchoring,
  CoCo `only_required`) and the eptid/ident/authn_broker/assertion_store tests.
- `cargo clippy -p gamlastan` (gated on `-D warnings`) — clean.

