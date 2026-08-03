# ADR 0042 - Complete inbound protocol validation

- **Status:** Accepted
- **Date:** 2026-08-03
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan-actix/src/sp.rs`, `example-idp/src/main.rs`, `spid-sp-test/src/main.rs`

## Context

An inbound SAML exchange can carry security-relevant intent and authentication
evidence in more than one place. An AuthnRequest may require passive operation,
a particular NameID format, or an AuthnContext comparison. A Redirect-bound
logout message can also contain an enveloped XML signature. Treating one valid
field or signature as permission to ignore the others creates inconsistent
interpretations of the same message.

Browser-mediated flows also span several requests. Removing correlation state
before terminal validation turns ordinary validation failures into destructive
state changes, while retaining abandoned state without bounds permits memory
growth driven by untrusted clients.

## Decision

1. Ready and example handlers validate every security-relevant representation
   that is present. In particular, Actix SLO verifies both the Redirect
   signature and XML-DSig when a message supplies both; either failure rejects
   the message.
2. The example IdP honors `ForceAuthn`, `IsPassive`, RequestedAuthnContext and
   its comparison, and requested NameID format. Unsupported intent produces a
   SAML protocol error rather than an interactive fallback with different
   semantics.
3. Multi-step authentication correlation is non-consuming during recoverable
   checks and atomically consumed only at the terminal success boundary.
   Pending state has a five-minute TTL and a 1024-entry capacity bound.
4. Network protocol messages use `parse_secure`; federation metadata and
   metadata-derived KeyInfo fragments use `parse_secure_metadata`. Both reject
   DTDs and entities, while the metadata policy permits structural comments and
   processing instructions used by real aggregates.

## Consequences

- A valid signature in one representation cannot conceal a corrupted second
  representation.
- Passive and context-constrained requests either receive a conforming response
  or an explicit SAML error and never silently prompt for incompatible login.
- Concurrent submissions and validation failures cannot reuse or prematurely
  destroy live correlation state; abandoned state remains bounded.
- Comment-bearing federation metadata remains interoperable without weakening
  the stricter protocol-message parse boundary.
