# ADR 0040 - Ready handlers bind browser and signing state

- **Status:** Accepted
- **Date:** 2026-08-02
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan-actix/src/{config,sp,idp}.rs`, `example-idp/src/main.rs`

## Context

The ready SP tracked AuthnRequest IDs in a process-global set. Possession of any
outstanding ID could therefore correlate a response in a different browser.
The ready IdP could issue an unsigned Response/Assertion when signing was
configured but its signing context was absent, and it did not authenticate
AuthnRequests according to partner metadata before profile processing.

The example IdP also reused sessions for `ForceAuthn`, reset AuthnInstant when
reusing a session, and used the general XML parser at its network boundary.

## Decision

1. AuthnRequest IDs are bound to random browser state in a five-minute Secure,
   HttpOnly, SameSite=None `__Host-` cookie. The browser nonce is reused during
   its lifetime so concurrent login tabs work; each request ID remains atomic
   and one-time.
2. `RequestIdTracker` exposes bound store/consume operations. Legacy custom
   trackers fail closed for ready ACS use until they implement bound consumption.
3. The ready IdP verifies Redirect and/or enveloped AuthnRequest signatures with
   the issuing SP's metadata keys and passes explicit provenance to the core
   profile.
4. If response or assertion signing is enabled but no `IdpSigningContext` is
   registered, issuance fails as a configuration error.
5. The example IdP uses secure parsing, honors `ForceAuthn`, and preserves the
   original authentication instant and session index when reusing a session.

## Consequences

- Cross-browser response injection no longer succeeds with a globally pending
  request ID.
- Cross-site HTTP-POST SAML remains supported; production ACS endpoints must be
  HTTPS because the state cookie is Secure.
- Custom trackers require a small source migration but cannot silently claim
  browser binding they do not provide.
