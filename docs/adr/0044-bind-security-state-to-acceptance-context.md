# ADR 0044 - Bind security state to its acceptance context

- **Status:** Accepted
- **Date:** 2026-09-03
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan/src/xml/deserialize.rs`, `crates/gamlastan/src/security/validation.rs`, `crates/gamlastan/src/bindings/traits.rs`, `crates/gamlastan/src/profiles/session.rs`, `crates/gamlastan/src/profiles/logout.rs`, `crates/gamlastan-actix/src/config.rs`, `crates/gamlastan-actix/src/idp.rs`, `crates/gamlastan-actix/src/sp.rs`, `../pygamlastan`

## Context

Authentication of a SAML message does not by itself authorize every state
transition that message can name. Artifacts belong to a particular resolver,
logout requests belong to an issuer and validity window, IdP sessions contain
SP-specific participant identifiers, and successful SLO must terminate the
local application session. Likewise, a signed unsolicited response can still
cause login CSRF when no browser initiated the authentication.

Several state lifetimes also differed from the protocol acceptance lifetime.
Assertion replay entries expired at the raw `NotOnOrAfter` even though clock
skew kept the assertion acceptable, and LogoutRequests had no shared freshness
or replay boundary. Metadata split-text protection additionally rescanned wide
sibling lists before signature verification, permitting quadratic CPU work.

ADR 0029 intentionally preserved unsolicited responses, and ADR 0030 allowed a
generic transport-authenticated bypass for ready IdP handlers. Those choices do
not provide enough context to prevent login CSRF or to bind an authenticated
transport peer to a claimed SAML issuer.

## Decision

1. Scan metadata child lists once while preserving structural comments and
   processing instructions and rejecting either when it separates meaningful
   text.
2. Retain assertion replay IDs until `NotOnOrAfter` plus the accepted clock
   skew, using checked time arithmetic.
3. Extend `ArtifactStore` with recipient-aware store and atomic
   requester-aware consume operations. Legacy stores remain source compatible
   but the new operations fail closed until implemented. The ready IdP uses
   only requester-aware resolution.
4. Resolve IdP logout targets through the authenticated SP participant. Match
   the full participant NameID, including qualifiers and `SPProvidedID`, plus
   any supplied SessionIndex. Encrypted NameIDs require a custom decrypting
   handler rather than returning false success.
5. Add stateful LogoutRequest validation that bounds `IssueInstant`, applies a
   maximum age and clock skew, and atomically reserves an issuer-scoped replay
   key before session mutation. Ready SP and IdP configurations use dedicated
   logout replay caches with a five-minute default maximum age. The older
   stateless validator remains for compatibility layers that already provide
   equivalent outer controls.
6. Require ready Actix SP users to register an infallible `SloCallback`. Invoke
   it only after trust, freshness, replay, destination, and correlation checks,
   and before returning protocol success. This callback is the application
   boundary that invalidates its server-side session.
7. Supersede ADR 0029 while retaining its solicited-response and dangling-
   correlation requirements. Reject unsolicited Web SSO by default.
   `SecurityConfig` provides an explicit
   `allow_unsolicited_responses` opt-in, and the core profile returns
   `UnsolicitedNotAllowed`.
8. Supersede ADR 0030 while retaining its metadata trust, signature, issuer, and
   destination requirements. Ready destructive IdP handlers always require a
   signature bound to trusted SP metadata. A transport-only deployment must use
   a custom handler that maps the authenticated transport identity to an entity
   ID; the generic bypass is removed.
9. The PySAML2 compatibility layer retains its public shapes and existing
   logout replay controls. It reads PySAML2's `allow_unsolicited` setting and
   maps missing correlation to `UnsolicitedResponse`; deployments that
   intentionally use IdP-initiated SSO opt in with that established setting.

## Consequences

- Replays cannot re-enter during accepted skew, and one trusted peer cannot
  reserve another peer's logout ID.
- A trusted SP can resolve only artifacts issued for it and can terminate only
  sessions in which it is the exactly matched participant.
- Custom artifact stores must migrate issuance to `store_for_recipient` and
  implement requester-aware atomic consumption. Custom session stores using
  participant-specific pseudonyms should override participant lookup.
- Ready SP SLO configuration without a local invalidation callback now fails
  closed instead of reporting a logout it did not perform.
- Unsolicited SSO and transport-only ready-handler operation become explicit
  compatibility decisions rather than implicit defaults.
- The new public configuration and participant fields can require updates to
  exhaustive pre-1.0 Rust struct literals. Constructor/default users inherit
  the secure behavior.

## Validation

Regression coverage exercises wide comment-bearing metadata, replay during
clock skew, issuer-scoped LogoutRequest replay and freshness, exact participant
and SessionIndex matching, fail-closed legacy artifact stores, unsolicited SSO
default denial and explicit opt-in, and PySAML2 `allow_unsolicited` behavior.
