# ADR 0002 — Metadata Query Protocol (MDQ) client as a separate async crate

- **Status:** Accepted
- **Date:** 2026-06-08
- **Deciders:** gamlastan maintainers
- **Spec:** [Metadata Query Protocol](https://datatracker.ietf.org/doc/html/draft-young-md-query) (`draft-young-md-query`) and its [SAML profile](https://datatracker.ietf.org/doc/html/draft-young-md-query-saml) (`draft-young-md-query-saml`); SAML V2.0 Metadata Interoperability Profile ([SAML2MetaIOP])
- **Implementation:** `crates/gamlastan-mdq/`

## Context

Service Providers and Identity Providers in a federation must resolve peer
metadata by `entityID`. Loading every entity at startup (as `example-idp`'s
`SP_METADATA_PATH` directory does) does not scale to federations with thousands
of entities. The **Metadata Query Protocol (MDQ)** solves this: a client
requests `server_url + transform(entityID)` from an MDQ server and receives a
single, federation-signed `<EntityDescriptor>` (or an `<EntitiesDescriptor>`
aggregate) on demand, cached per the document's `validUntil`/`cacheDuration`.

The defining property of MDQ — and the source of all its security requirements —
is that **the MDQ server is an untrusted intermediary** (typically a CDN or
shared cache). Transport security (TLS) is *not* the authenticity anchor;
authenticity comes from a **federation signature** over each metadata document,
verified by the consumer against a pre-configured trust anchor.

gamlastan already provides the pure building blocks MDQ needs:

- `xml::{uppsala, parse_saml}` and `metadata::types::{EntityDescriptorRef,
  EntitiesDescriptorRef}` — zero-copy parsing,
- `metadata::cache::{MetadataCache, CachedMetadata}` — the E94-aware cache that
  honours `validUntil`/`cacheDuration`,
- `metadata::MetadataSigningProfile::validate_signature_profile` and
  `crypto::SamlVerifier` — XML-DSig profile checks and enveloped-signature
  verification (E91 `ds:Object` rejection, XML-Signature-Wrapping reference
  checks via bergshamra `strict_verification`).

What was missing was the **on-demand, networked** layer: the entityID→URL
transform, the HTTP transport, the verify-then-cache orchestration, and the
two operational shapes (dynamic per-entity vs. a single static entity). The
question was **where** that layer lives and **how** it is structured.

## Decision

Implement MDQ as a **separate crate, `gamlastan-mdq`**, that is a thin async
layer over gamlastan's pure metadata/crypto building blocks — not as an in-crate
module like `profiles::swedenconnect` (ADR 0001).

Module layout (one concern per file):

| File | Responsibility |
| --- | --- |
| `lib.rs` | crate docs, public re-exports, `#![forbid(unsafe_code)]` |
| `client.rs` | `MdqClient<F>`: dynamic queries, static file/URL modes, caching, trust material, clock injection |
| `verify.rs` | `parse_verify_select`: parse → verify (if certs) → select entity → role-gate → **entityID binding** |
| `transform.rs` | `MdqTransform` (`UrlEncoded`/`Sha1`), `request_path`, `parse_xs_duration` |
| `fetch.rs` | `MetadataFetcher` trait + default `ReqwestFetcher` (size cap, redirect bound) |
| `error.rs` | `MdqError` |

The builder is plain function composition over the existing dual-typed SAML
structs; there is no plugin/registry machinery.

## Consequences and the decisions inside the decision

### 1. A separate `gamlastan-mdq` crate, not an in-crate module

**Chosen.** MDQ needs `async` and a real HTTP/TLS stack (`reqwest`, `tokio` in
tests). The `gamlastan` core is a synchronous, allocation-light, zero-copy
library; pulling an async runtime and a TLS client into it would force that
dependency weight onto every consumer (including `spid-sp-test` and the pure
parsing paths) and blur the crate's "pure SAML logic" boundary.

- ➕ Network/async/TLS dependencies stay isolated; the core remains sync and
  light. `gamlastan-mdq` depends only on `gamlastan` + `reqwest`/`chrono`/
  `bytes`/`base64`/`thiserror`/`log`.
- ➕ Mirrors the existing split where framework/runtime concerns live outside the
  core (`gamlastan-actix`).
- ➖ One more workspace crate and version to keep in lockstep.
- ↪ This is the *opposite* call to ADR 0001's "in-crate module" decision —
  justified because Sweden Connect added no new dependency, whereas MDQ adds an
  async transport stack.

### 2. Pluggable transport via a `MetadataFetcher` trait

`MdqClient<F = ReqwestFetcher>` is generic over a fetcher that deals only in raw
bytes (`fn fetch(&self, url) -> impl Future<Output = Result<Bytes, MdqError>> +
Send`). Production uses `ReqwestFetcher`; the test suite injects a deterministic
`MockFetcher`.

- ➕ The entire verify/select/cache pipeline is testable without a network, with
  signed fixtures and a controllable clock — the suite never opens a socket.
- ➕ Callers can supply their own transport (custom TLS roots, proxies, mTLS).
- ➖ A generic parameter on the public type; defaulted to `ReqwestFetcher` so the
  common case stays `MdqClient::new(url)`.

### 3. Two request transforms; URL-encoded is the default

`MdqTransform::UrlEncoded` (percent-encode the raw entityID) is the default and
matches most MDQ servers; `MdqTransform::Sha1` (`"{sha1}" + hex(sha1(entityID))`)
covers pyFF/thiss.io deployments. `request_path` percent-encodes the whole
identifier as a **single path segment** (RFC 3986 unreserved set only), so an
entityID can never alter the host or inject extra path segments. SHA-1 here is a
spec-mandated *identifier transform*, not a security primitive.

### 4. Dynamic and static modes in one type

- **Dynamic** (`MdqClient::new`): query per entityID, verify, cache.
- **Static** (`into_static_file` / `into_static_url`): serve one configured
  entity. URL-backed static metadata that fails its initial fetch is **not** a
  construction error — the client is returned and retries lazily with
  exponential backoff (`RETRY_BASE` 5 s → `RETRY_MAX` 120 s) on the next `get`.

This lets a deployment treat "a single peer from a file", "a single peer from a
URL", and "any peer from an MDQ server" uniformly through one `get(entity_id)`
API. In static mode the per-call `entity_id` argument is advisory (logged on
mismatch); the configured entity is what is served — but the *loaded* metadata
is bound to the configured entityID (see #7).

### 5. Caching delegated to `gamlastan::metadata::cache`

The client does not reimplement cache freshness. It builds `CachedMetadata` from
the document's `cacheDuration`/`validUntil` (falling back to a configurable TTL,
default 1 h) and asks `CachedMetadata::should_refresh(now)` — which already
encodes E94 (expired `validUntil` ⇒ refetch). Only `xs:duration` parsing lives
here (`parse_xs_duration`), because the cache consumes a `std::time::Duration`.
A child entity's own hints take precedence over an enclosing aggregate's.

### 6. Trust is the federation signature, with rollover

`Trust` holds **zero or more** federation signing certs. With ≥1 cert
configured, every fetched document must carry a valid enveloped signature
(profile-checked, then verified against the trust anchor); multiple certs
support key rollover. The clock is injectable (`with_clock`) so verification and
cache behaviour are deterministic under test.

### 7. Pre-publication security hardening (differential review, 2026-06-08)

A security-focused differential review of the new crate ran before any consumer
wired it. Because **nothing here is published yet — there are no external
consumers and no production handler depends on it** — the findings were fixed
directly, including a breaking change to the default trust posture, rather than
carrying compatibility shims.

| ID | Issue | Fix |
| --- | --- | --- |
| H-1 | The single-`<EntityDescriptor>` path (the common MDQ response) verified the signature but **never compared the returned `entityID` to the requested one**. An untrusted server could answer a query for entity A with B's *validly federation-signed* metadata; it passed signature + role checks and was cached under A's key, letting the app trust B's signing key/endpoints as A's (IdP impersonation across the federation). | `finish` now binds request to response: `entity.entity_id != requested ⇒ MdqError::EntityIdMismatch`, on **both** the single-entity and aggregate paths (and at static load time). The signature attests provenance, not that it answers *this* query. |
| M-1 | **Fail-open default:** a client with no certs silently accepted unverified metadata (warn-once only) — i.e. no authenticity at all under the MDQ threat model — which is the default state of `MdqClient::new`. | A no-cert client now returns `MdqError::VerificationNotConfigured`; the insecure mode is an explicit `allow_unverified()` opt-in. With certs configured, documents are always verified regardless. |
| M-2 | `parse_xs_duration` used `Duration::from_secs_f64`, which **panics on overflow**; a crafted `cacheDuration` (e.g. `P10000000000000000000Y`) is finite-but-huge and passed the prior guards — an unauthenticated DoS in `allow_unverified` mode. | Use the fallible `Duration::try_from_secs_f64(...).map_err(BadDuration)`. |
| M-3 | `ReqwestFetcher` buffered the entire body (`resp.bytes()`) with no size cap (memory-exhaustion DoS from a hostile server) and followed reqwest's default redirect chain. | Enforce an 8 MiB cap (advertised `Content-Length` pre-check **and** chunk-by-chunk streaming enforcement) and bound redirects to 2. |
| INFO-1 | The `MetadataSigningProfile` profile pre-check is substring-based, not DOM-based. | Left as-is: it is a *pre-check*, not the security boundary. Cryptographic verification is `SamlVerifier::verify_enveloped` with bergshamra `strict_verification` (XML-Signature-Wrapping reference-position checks) + E91 `ds:Object` rejection. Recorded here as the relied-upon control. Hardening lives in `gamlastan`, out of this crate's scope. |

The entityID-binding (H-1) and fail-closed default (M-1) are the two controls
that make a consumer safe against an untrusted MDQ server; both are now enforced
by the library rather than left to each caller.

## Scope boundaries

Recorded so the crate's coverage is unambiguous:

- **Client only.** This crate *consumes* MDQ; it does not implement an MDQ
  *server*, metadata aggregation, or metadata *publishing* (the `example-idp`
  `/metadata` endpoint and `MetadataSigningProfile` cover the producer side).
- **Signature profile / C14N** belong to `gamlastan`/`bergshamra`; this crate
  selects and invokes them but does not re-implement DSig.
- **Cache is in-memory and per-client.** No persistent/shared cache and no
  negative caching; a cache miss refetches.
- **TLS is transport only.** Certificate validation of the MDQ *server* is
  reqwest/rustls' concern and is deliberately *not* the metadata authenticity
  anchor — the federation signature is. Running `allow_unverified()` discards
  authenticity entirely and is for local testing only.
- **No metadata-driven discovery** (e.g. `mdq` `Link:` headers, entity
  enumeration); resolution is by explicit `entityID`.

## Validation

- `cargo clippy -p gamlastan-mdq --all-targets` (gated on `-D warnings`) — clean.
- `cargo fmt -p gamlastan-mdq -- --check` — clean.
- `cargo test -p gamlastan-mdq` — **26 integration + 6 transform unit + 2 doc**
  passing. Coverage includes: URL-encoded/SHA-1 transforms; dynamic caching and
  `cacheDuration`/`validUntil`/fallback-TTL expiry; aggregate child selection
  and not-found; role gating; signed-verifies / tampered-rejected /
  unsigned-with-cert-rejected; static file/URL modes with lazy retry and
  backoff doubling; and the #7 hardening: **signed-but-substituted entity
  rejected**, unsigned entityID mismatch rejected, unverified-without-opt-in
  rejected, static-file entityID mismatch rejected, and `xs:duration` overflow
  rejected (not panicking).
- `cargo build --workspace` — clean.

## Alternatives considered

- **An in-crate `metadata::mdq` module** (as ADR 0001 did for Sweden Connect).
  Rejected: it would impose `reqwest` + an async runtime on the synchronous core
  and every consumer of it (see #1).
- **A blocking/synchronous client.** Rejected: the intended consumers
  (`gamlastan-actix`, the `translateid` proxy) are async; a blocking client would
  force `spawn_blocking` at every call site.
- **Caller-managed caching** (return parsed metadata, let the app cache).
  Rejected: E94 freshness and `validUntil`/`cacheDuration` semantics are easy to
  get wrong; the cache already exists in `gamlastan` and is reused here (#5).
- **TLS-only trust** (rely on the MDQ server's certificate). Rejected: it
  contradicts the MDQ threat model — the server is an untrusted intermediary;
  the federation signature is the anchor (#6, #7/H-1).
