# ADR 0001 — Sweden Connect Deployment Profile as a layered profile module

- **Status:** Accepted
- **Date:** 2026-06-08
- **Deciders:** gamlastan maintainers
- **Spec:** [Deployment Profile for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html), v1.9 (mirrored at `specs/deployment_profile_for_th_swedish_eid_framework.md`)
- **Implementation:** `crates/gamlastan/src/profiles/swedenconnect/`

## Context

We need to support the Swedish eID Framework's deployment profile (Sweden
Connect / DIGG). The profile is normatively a **restriction and extension** of
the SAML V2.0 Web Browser SSO Profile and the Holder-of-key Web Browser SSO
Profile, plus framework-specific identifiers (Levels of Assurance, entity
categories, status codes), metadata extensions (`mdui:UIInfo`,
`mdattr:EntityAttributes`, `shibmd:Scope`, `idpdisc:DiscoveryResponse`), and
two `AuthnRequest` extensions used for "Authentication for Signature"
(`csig:SignMessage`, `sap:SADRequest`) together with `psc:PrincipalSelection`.

gamlastan already implements the underlying machinery the profile builds on:

- `profiles::sso::{sp,idp}` — Web Browser SSO request/response handling,
- `security::{config,validation}` — the 32-check `AssertionValidator`, replay
  cache, clock-skew/errata defences,
- `crypto::{SamlSigner,SamlVerifier,SamlEncryptor,SamlDecryptor}` — XML-DSig and
  XML-Encryption,
- `metadata::types` — `EntityDescriptor`, role descriptors, and a generic
  `Extensions { raw_xml }` container (with a typed precedent in
  `metadata::types::spid`).

The question was **how** to add Sweden Connect: extend the core SAML types, or
add a self-contained profile layer on top of the existing building blocks.

## Decision

Implement Sweden Connect as a **self-contained `profiles::swedenconnect`
module** that configures and wraps the existing Web Browser SSO functions,
rather than modifying core protocol/metadata types.

Module layout (one concern per file):

| File | Spec | Responsibility |
| --- | --- | --- |
| `constants.rs` | §2, §3, §6.4, §8 | LoA URIs, entity categories, status codes, attribute OIDs, namespaces, algorithm URIs |
| `config.rs` | §6.1, §6.3.5 | `SwedenConnectConfig` → profile-correct `SecurityConfig` |
| `authn_context.rs` | §5.3.1, §6.3.4 | `LevelOfAssurance`, exact `RequestedAuthnContext`, LoA matching |
| `principal_selection.rs` | §5.3.3, §2.1.3 | `psc:PrincipalSelection` / `psc:RequestedPrincipalSelection` |
| `sign_message.rs` | §7.1 | `csig:SignMessage`, `sap:SADRequest` |
| `metadata.rs` | §2.1 | `mdui:UIInfo`, `mdattr:EntityAttributes`, `shibmd:Scope`, `idpdisc:DiscoveryResponse` builders + readers |
| `request.rs` | §5 | SP-side `build_authn_request` applying every §5 constraint |
| `response.rs` | §6 | SP-side `verify_and_process_response` (recommended), `process_response` + `decrypt_response` (low-level) |
| `idp.rs` | §6, §6.4 | IdP-side response/error construction |
| `error.rs` | §6.4 | `SwedenConnectError` + SAML status mapping |
| `xmlutil.rs` | — | private XML-escaping helpers for hand-written extension fragments |

The "extension point" remains plain function composition over the dual-typed
SAML structs; there is no profile trait/registry.

## Consequences and the decisions inside the decision

### 1. Layer, don't fork the core types

**Chosen.** Reuse `SecurityConfig`, `AssertionValidator`, the crypto wrappers,
and `sso::{sp,idp}` verbatim; encode the profile as constraints + new extension
types. The security-critical machinery (signature, encryption, replay,
audience, errata E78/E90/E91/E93) is shared and unchanged.

- ➕ No destabilisation of the ~450-test crate; the profile is additive.
- ➕ Errata fixes and crypto improvements flow in for free.
- ➖ A few small pieces of orchestration are re-expressed in the profile layer
  (see #3).

### 2. `AuthnRequest` extensions returned as a serialized block

The core `AuthnRequest` type has **no generic `<saml2p:Extensions>` field**, and
adding one would ripple through every constructor (the whole test suite builds
`AuthnRequest` literals) and the serializer/deserializer.

**Decision:** `build_authn_request` returns
`SwedenConnectAuthnRequest { request, extensions_xml: Option<String> }`. The
`SignMessage` / `SADRequest` / `PrincipalSelection` elements are serialized into
a `<saml2p:Extensions>` string that the caller splices into the serialized
request (after `<saml2:Issuer>`) before signing.

- ➕ Keeps the core type and its serializer untouched and stable.
- ➕ Extensions are still produced as correct, namespaced XML.
- ➖ Callers using these extensions must perform a string splice rather than
  getting a single serialized document. Documented on the return type.
- ↪ **Revisitable:** if/when several profiles need request extensions, promote
  `extensions: Option<Extensions>` onto the core `AuthnRequest` and wire
  serialization once; this module would then drop the splice.

### 3. Profile-layer signing/encryption enforcement; validator driven directly

While implementing response processing we found two properties of the existing
validator:

- `SecurityConfig::require_encrypted_assertions` is **not enforced** anywhere in
  `security::validation`.
- Validator "check 4" fails for **any** signed response unless
  `ValidationParams::response_signature_verified` is `Some(true)`, and
  `sso::sp::process_response` hard-codes it to `None`.

**Decision:** `swedenconnect::response::process_response` calls
`AssertionValidator` directly (threading `response_signature_verified`) instead
of delegating to `sso::sp::process_response`, and enforces the profile's
signed-response / encrypted-assertion mandates at the profile layer via explicit
inputs:

- `response_signature_verified: bool` — caller verified the `<Response>`
  signature with `SamlVerifier` against the IdP metadata key (§6.3.1),
- `assertion_was_encrypted: bool` — set by `decrypt_response` after handling
  `<saml2:EncryptedAssertion>` (§6.1).

This keeps verification/decryption (which need keys) at the edges and makes the
profile checks unit-testable with plaintext fixtures.

- ➕ Faithful to §6.1/§6.3.1; correct handling of genuinely-signed responses.
- ➖ Small duplication of NameID/attribute extraction that mirrors `sso::sp`.
- ↪ A future cleanup could thread `response_signature_verified` through
  `sso::sp::process_response` and let this module delegate again.

### 4. Hand-written XML for extension fragments

Extension/metadata fragments are emitted as strings (matching the existing
`Extensions { raw_xml }` representation and the `metadata::types::spid`
precedent) with local escaping helpers (`xmlutil`), rather than as new
`SamlSerialize` implementations.

- ➕ Consistent with how metadata extensions are already represented.
- ➕ No new entries in the typed serializer for opaque extension elements.
- ➖ Manual escaping; mitigated by `xmlutil` + unit tests.

### 5. Strict-by-default deployment configuration

`SwedenConnectConfig::security_config()` clamps clock skew to **≤ 60 s** (§6.3.5,
tightened from 3–5 min in v1.9), and forces `require_signed_responses`,
`require_encrypted_assertions`, `verify_destination`, and `verify_recipient` on.
Unsolicited responses are rejected unless `accept_unsolicited` is explicitly set
(§6.1).

### 6. Pre-publication security hardening (differential review, 2026-06-08)

A security-focused differential review of the new module surfaced gaps where the
profile *advertised* a guarantee that was only partially enforced. Because
**nothing in this module is published yet — there are no external consumers and
no production handler wires it** — we fixed these directly, including breaking
changes to the (unreleased) profile API, rather than carrying compatibility
shims.

| ID | Issue | Fix |
| --- | --- | --- |
| H-1 | A response mixing a cleartext `<saml2:Assertion>` with an `<saml2:EncryptedAssertion>` was accepted, and since assertion signatures are not required, the unsigned cleartext assertion could become authoritative (an XML Signature Wrapping vector). | `decrypt_response` now rejects any response carrying a cleartext assertion (`SwedenConnectError::CleartextAssertion`); §6.1 requires the *entire* assertion encrypted. |
| M-1 / M-3 | The split `decrypt_response` + `process_response` trusted caller-supplied `response_signature_verified` / `assertion_was_encrypted` booleans, with nothing binding the signature-verified bytes to the processed assertion; the response-signature E91 `ds:Object` scan was also skipped on this path. | Added **`verify_and_process_response`** as the recommended entry point: it verifies the enveloped signature over the exact bytes with `SamlVerifier` (default config enforces trusted-keys-only, XML-Signature-Wrapping reference-position checks, and E91), then decrypts, then processes — establishing the facts instead of trusting them. The low-level functions remain, documented as such. |
| M-2 | Replay protection was optional (`Option<&dyn ReplayCache>`), silently a no-op when `None`, despite §6.3.5's MUST. | `SwedenConnectResponseParams::replay_cache` is now a required `&dyn ReplayCache`. |
| L-1 | "Exactly one assertion" (§6.2) was not enforced; identity/attributes were drawn from the first/all assertions. | `process_response` rejects `assertions.len() != 1` (`SwedenConnectError::AssertionCount`). |
| L-2 | `SignMessage` with an encrypted body double-escaped the raw `<xenc:EncryptedData>` element into inert text. | Encrypted bodies are emitted verbatim; only Base64 cleartext is escaped. |
| INFO-1 | The shared validator binds the *assertion* Issuer value but only the *response* Issuer *format*, not its value. | `process_response` binds the response-level `<saml2:Issuer>` value to the expected IdP (`MissingResponseIssuer` / `ResponseIssuerMismatch`). |
| INFO-2 | When no request was expected (unsolicited, or a solicited response whose `InResponseTo` matched no tracked request), a dangling `InResponseTo` was accepted unchecked. | `process_response` rejects a dangling `InResponseTo` on the response or any `SubjectConfirmationData` (`UnexpectedInResponseTo`). |

INFO-1 and INFO-2 are enforced at the **profile layer** rather than by editing
the shared 32-check `AssertionValidator`, consistent with decision #1 (the shared
security machinery stays unchanged) and decision #3 (profile-specific mandates
are enforced in `swedenconnect::response`). They harden the Sweden Connect path
without altering base Web Browser SSO behaviour or its test suite.

## Scope boundaries

Recorded so the profile's coverage is unambiguous:

- **Holder-of-key Web Browser SSO** — supported at the metadata/constant and
  `SubjectConfirmation` method level (`CM_HOLDER_OF_KEY`, `BINDING_HOK_BROWSER`).
  The mutual-TLS transport requirement (§5.2/§6.1) is a deployment concern
  outside a SAML library.
- **DSS / SAP** — only the SAML authentication-phase pieces are modelled
  (`SignMessage`, `SADRequest` request extensions; `signMessageDigest` response
  attribute). The DSS `SignRequest`/`SignResponse` envelope and full SAD
  signature verification belong to separate protocol specs ([SC.DSS.Ext],
  [SC.SAP]) and are out of scope.
- **Algorithm enforcement** — §8 algorithm URIs and `is_broken_algorithm`
  helpers are provided; negotiating the metadata `alg:SigningMethod` /
  `md:EncryptionMethod` intersection is left to the calling deployment.
- **Metadata fetch/IOP** — periodic signed metadata consumption (§2,
  [SAML2MetaIOP]) reuses the existing `metadata::cache`; not re-implemented here.

## Validation

- `cargo check`, `cargo clippy -p gamlastan` / `-p gamlastan-actix` (gated on
  `-D warnings`) — clean. (The full `--workspace --all-targets` clippy is
  memory-hungry on smaller machines; package-scoped runs cover the changed code.)
- `cargo test -p gamlastan` — 460 unit + 1 doc passing, including **43**
  swedenconnect tests covering LoA matching, request constraints, response
  processing (unsolicited/signing/encryption/LoA/structure), metadata
  round-trips, extension serialization, and the §6 security hardening above
  (cleartext-assertion rejection, exactly-one-assertion, response-Issuer
  binding, dangling-`InResponseTo` rejection, encrypted `SignMessage` body).

## Alternatives considered

- **Extend core protocol/metadata types** with Sweden Connect fields/extensions.
  Rejected: large blast radius across constructors, serializer, and tests for a
  single national profile, with no benefit to the generic SAML core.
- **Delegate response processing wholesale to `sso::sp::process_response`.**
  Rejected: it cannot thread the response-signature-verified flag, so it fails
  on genuinely signed responses (see #3).
- **A separate `gamlastan-swedenconnect` crate.** Deferred: the profile is a
  thin layer that depends only on `gamlastan` internals; an in-crate module
  avoids a public-API surface and a second version to keep in lockstep. Can be
  extracted later if external consumers need it independently.
