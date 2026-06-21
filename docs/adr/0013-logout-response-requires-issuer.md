# ADR 0013 — LogoutResponse without an Issuer is rejected

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Core §3.2.2 (StatusResponseType `Issuer`), §3.7 (LogoutResponse); SAML V2.0 Profiles §4.4 (Single Logout)
- **Implementation:** `crates/gamlastan/src/profiles/logout.rs`

## Context

The SP-side logout orchestrator's `handle_response()` correlated an incoming
`LogoutResponse` to its pending target and then checked that the response's
`Issuer` matched the target entity — but only *if an Issuer was present*:

```rust
if let Some(issuer) = &response.issuer {
    if issuer.value != target.entity_id { /* reject */ }
}
```

A response with **no Issuer** skipped the check entirely and was accepted. The only
remaining binding between the response and a particular responder was
`InResponseTo`, which is not a secret: an attacker who can observe or guess the
request ID could forge a LogoutResponse with no Issuer and have it accepted as
though it came from the real IdP. The PR #7 review flagged this as a
responder-identity gap.

## Decision

Treat a missing `Issuer` on a `LogoutResponse` as an error, not a skipped check.

`handle_response()` now requires the `Issuer` (it is the only responder-identity
signal here and is required by the protocol schema) and then enforces the
value match:

```rust
let issuer = response.issuer.as_ref()
    .ok_or_else(|| ProfileError::Other("LogoutResponse has no Issuer".to_string()))?;
if issuer.value != target.entity_id { /* reject */ }
```

## Consequences

- A LogoutResponse can no longer be accepted on `InResponseTo` correlation alone; it
  must positively identify the responder, and that identity must match the target.
- Strictly a tightening: well-formed responses from a conformant IdP (which always
  include an Issuer) are unaffected.
- Pairs with the ECP envelope hardening of ADR 0012; both close
  responder/parser-trust gaps surfaced by the same PR #7 review.

## Alternatives considered

- **Keep the `if let Some` skip and rely on `InResponseTo`.** Rejected:
  `InResponseTo` is not an authenticity signal; this is the spoofing vector.
- **Require a verified signature instead of just a present Issuer.** Out of scope
  here — signature verification is a separate concern layered by the caller; this
  change fixes the unconditional acceptance, the minimal correct step.

## Validation

- Added `test_orchestrator_rejects_missing_issuer` (a success LogoutResponse with
  `issuer = None` is rejected).
- `cargo test -p gamlastan test_orchestrator` — passing.

