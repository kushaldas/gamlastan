# ADR 0012 — ECP envelope parsing verifies the SOAP 1.1 namespace and rejects multi-element Bodies

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Profiles §4.2 (ECP), SAML V2.0 Bindings §3.2 (SOAP); SOAP 1.1 envelope
- **Implementation:** `crates/gamlastan/src/profiles/sso/ecp.rs`

## Context

A differential security review of the ECP profile (PR #7 review) flagged that
`parse_envelope()` matched the SOAP envelope structure by **local element name
only**: `Envelope`, `Header`, `Body`, `Fault` were accepted regardless of their
namespace, and the `Body` handler iterated *all* child elements, keeping the last
one it saw as the SAML message.

Two concrete weaknesses followed:

- **No namespace binding.** An element named `Envelope` in any namespace (or none)
  was accepted as a SOAP envelope, so the parser did not actually enforce the SOAP
  1.1 binding it claims to implement.
- **Element smuggling.** The SOAP binding requires *exactly one* element in the
  Body. Accepting extras lets an attacker place a decoy first element and the real
  (or a second, conflicting) SAML message after it — a classic
  parser-differential / XML-signature-wrapping setup where a verifier and the
  business logic disagree on which element is "the message".

## Decision

Make the ECP phase-2 envelope parser enforce the SOAP 1.1 structure it depends on.

- The root element must match `{http://schemas.xmlsoap.org/soap/envelope/}Envelope`
  (`matches_name_ns(SOAP11_NS, "Envelope")`); a non-SOAP namespace is rejected with
  an error naming the offending `{namespace}local`.
- `Header`, `Body`, and `Fault` are likewise matched **namespace-qualified** against
  `SOAP11_NS`.
- The `Body` must contain **exactly one** element. A `Fault` child still short-circuits
  to a fault error; otherwise the *second* element child triggers
  `"SOAP Body must contain exactly one element"`.

## Consequences

- Envelopes that are not genuine SOAP 1.1 fail fast instead of being parsed on the
  strength of a coincidental local name.
- The Body-smuggling vector is closed: a single SAML message is the only accepted
  shape.
- Scope is limited to the ECP envelope parser; other SOAP-body extraction paths are
  unchanged (cf. ADR 0006, which tightened ECP *phase-1* header requirements).
- This complements the equivalent IdP-side responder-identity fix in ADR 0013; both
  came from the same PR #7 review.

## Alternatives considered

- **Keep local-name matching for leniency toward non-conformant peers.** Rejected:
  the profile parser should enforce the profile; a lenient SOAP-body extractor, if
  ever needed, belongs in a different, clearly-named API.
- **Accept multiple Body children and pick the SAML one by name.** Rejected: "pick
  the one that looks right" is exactly the parser-differential that enables
  signature wrapping. The binding says one element; enforce one element.

## Validation

- Added `test_parse_envelope_rejects_non_soap_namespace` (an `Envelope` in
  `urn:not-soap`) and `test_parse_envelope_rejects_multiple_body_children` (a decoy
  + real `samlp:Response` in one Body).
- `cargo test -p gamlastan` — passing.

## Publication status

Unreleased.
