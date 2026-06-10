# ADR 0006 — ECP phase-1 parsing requires the `ecp:Request` header

- **Status:** Accepted
- **Date:** 2026-06-10
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Profiles, section 4.2.4.2; PAOS/ECP phase-1 envelope requirements
- **Implementation:** `crates/gamlastan/src/profiles/sso/ecp.rs`, `crates/gamlastan/src/profiles/error.rs`

## Context

The ECP profile's phase-1 envelope from the SP to the client carries two
mandatory header blocks:

- `paos:Request`, which identifies the `responseConsumerURL`, and
- `ecp:Request`, which carries the SP issuer plus ECP-specific semantics such
  as `IsPassive`, `ProviderName`, and `IDPList`.

The initial parser enforced only the PAOS header. If `ecp:Request` was absent,
`parse_ecp_authn_request_envelope()` still returned an `EcpRequest` with empty
optional fields. That meant a non-compliant envelope was silently accepted and
important profile semantics were dropped instead of being surfaced as an error.

## Decision

Require `ecp:Request` when parsing a phase-1 ECP envelope.

`parse_ecp_authn_request_envelope()` now returns a dedicated
`ProfileError::EcpMissingRequestHeader` when the PAOS header is present but the
mandatory ECP header is absent.

This keeps the parser aligned with the profile boundary it claims to implement.
If a caller needs a looser SOAP-body extractor, that should be a different API,
not the ECP profile parser.

## Consequences

- Non-compliant phase-1 ECP envelopes now fail fast instead of degrading to a
  best-effort parse.
- Callers receive a precise error that distinguishes a missing PAOS header from
  a missing `ecp:Request` header.
- The stricter behavior is limited to the phase-1 ECP parser; the generic IdP
  SOAP-body extraction path remains unchanged.

## Alternatives considered

- **Keep best-effort parsing and fill missing fields with `None`.** Rejected
  because it hides a protocol violation and discards required semantics.
- **Reuse `MissingPaosHeader` for both cases.** Rejected because the two wire
  errors are operationally different and easier to debug when reported
  separately.

## Validation

- Added `test_parse_phase1_missing_ecp_request`.
- Re-ran `cargo test -p gamlastan test_parse_phase1_missing`.
