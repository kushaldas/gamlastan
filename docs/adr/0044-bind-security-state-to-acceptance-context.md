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
2. Retain assertion replay IDs until the earlier of `NotOnOrAfter` plus the
   accepted clock skew and the bounded assertion-age window, using checked time
   arithmetic. Do not retain entries whose acceptance deadline is already due.
3. Extend `ArtifactStore` with recipient-aware store and atomic
   requester-aware consume operations. Legacy stores remain source compatible
   but the new operations fail closed until implemented. The ready IdP uses
   only requester-aware resolution.
4. Resolve IdP logout targets through the authenticated SP participant. Match
   the full participant NameID, including qualifiers and `SPProvidedID`, plus
   any supplied SessionIndex. Treat omitted NameID Format as the explicit SAML
   `unspecified` format. Encrypted NameIDs require a custom decrypting handler
   rather than returning false success. Recheck that participant match and
   remove the current session record in one store transaction or lock; legacy
   custom stores fail closed until they implement the compound operation.
5. Add stateful LogoutRequest validation that bounds `IssueInstant`, applies a
   maximum age and clock skew, and atomically reserves an issuer-scoped replay
   key before session mutation. Ready SP and IdP configurations use dedicated
   logout replay caches with a five-minute default maximum age. The older
   stateless validator remains for compatibility layers that already provide
   equivalent outer controls.
6. Require ready Actix SP users to register an async, fallible `SloCallback`.
   Invoke it only after trust, freshness, replay, destination, and correlation
   checks, and return protocol success only after it returns `Ok(())`. Replay
   and correlation reservations remain terminal on callback failure, preventing
   reuse at the cost of protocol retry liveness. Applications should make
   invalidation durable and idempotent before returning success.
7. Bind outgoing SP LogoutRequest IDs to the same short-lived, host-only
   browser nonce used for AuthnRequest correlation. Atomically consume a
   LogoutResponse correlation only when the returning browser presents that
   nonce, so one browser cannot terminate another browser's local session.
   Obtain the outgoing NameID and SessionIndex values from a fallible
   application callback bound to that authenticated local session, and require
   `SpSigningContext` to sign the Redirect LogoutRequest before reserving its
   correlation state.
8. Supersede ADR 0029 while retaining its solicited-response and dangling-
   correlation requirements. Reject unsolicited Web SSO by default.
   `SecurityConfig` provides an explicit
   `allow_unsolicited_responses` opt-in, and the core profile returns
   `UnsolicitedNotAllowed`.
9. Supersede ADR 0030 while retaining its metadata trust, signature, issuer, and
   destination requirements. Ready destructive IdP handlers always require an
   HTTP-Redirect or enveloped XML signature bound to trusted SP metadata and
   verify every signature representation present. A transport-only deployment
   must use a custom handler that maps the authenticated transport identity to
   an entity ID; the generic bypass is removed.
10. The PySAML2 compatibility layer retains its public shapes and existing
   logout replay controls. It reads PySAML2's `allow_unsolicited` setting and
   maps missing correlation to `UnsolicitedResponse`; deployments that
   intentionally use IdP-initiated SSO opt in with that established setting.

## Consequences

- Replays cannot re-enter during accepted skew, and one trusted peer cannot
  reserve another peer's logout ID.
- A trusted SP can resolve only artifacts issued for it and can terminate only
  sessions in which it is the exactly matched participant at the instant of
  atomic removal.
- Custom artifact stores must migrate issuance to `store_for_recipient` and
  implement requester-aware atomic consumption. Custom session stores used by
  ready IdP SLO must implement atomic participant-bound removal.
- Ready SP SLO configuration without a local invalidation callback, or with a
  callback that returns an error, now fails closed instead of reporting a
  logout it did not perform. A failed callback does not make the authenticated
  SLO message reusable.
- SP-initiated logout correlation is accepted only from its initiating browser.
- Ready SP-initiated logout fails closed without an authenticated-session
  callback and signing context; the IdP receives a signed Redirect request
  rather than application-authenticated arbitrary query parameters.
- Unsolicited SSO and transport-only ready-handler operation become explicit
  compatibility decisions rather than implicit defaults.
- The new public configuration and participant fields can require updates to
  exhaustive pre-1.0 Rust struct literals. Constructor/default users inherit
  the secure behavior.

## Validation

Regression coverage exercises wide comment-bearing metadata, replay during
clock skew, issuer-scoped LogoutRequest replay and freshness, exact participant
and SessionIndex matching, fail-closed legacy artifact stores, unsolicited SSO
default denial and explicit opt-in, async SLO callback success and failure,
browser-bound LogoutResponse correlation, Redirect-only and mixed-signature
IdP SLO, omitted/explicit unspecified NameID equivalence, bounded replay-cache
retention, atomic participant-bound session removal, signed SP-initiated
LogoutRequests, and PySAML2 `allow_unsolicited` behavior.
