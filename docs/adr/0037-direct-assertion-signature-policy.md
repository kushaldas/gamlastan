# ADR 0037 - Direct assertion-signature policy

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** gamlastan maintainers
- **Supersedes in part:** [0016](0016-acs-signature-verification-before-claims.md), [0028](0028-signature-binding-to-consumed-object.md)
- **Implementation:** `crates/gamlastan/src/security/validation.rs`, `crates/gamlastan-actix/src/sp.rs`, `crates/gamlastan/src/profiles/swedenconnect/response.rs`

## Context

A focused security review found a signature-policy mixup in the SP-side
assertion validator. `SecurityConfig::require_signed_assertions`,
SAML metadata `WantAssertionsSigned`, and the Sweden Connect
`want_assertions_signed` option are direct assertion-signature policies: the
consumed `<saml:Assertion>` should carry its own verified `<ds:Signature>`.

The implementation accepted either the consumed Assertion ID or the enclosing
Response ID in `ValidationParams::verified_signed_ids`. That preserved
response-envelope integrity when the Response signature was trusted, so it was
not an unauthenticated identity-forgery bug. But it allowed a response-only
signature to satisfy a policy that explicitly asks for assertion-level
signatures. It also meant callers using `SamlVerifier::verify_enveloped` could
miss an assertion signature when a Response was signed at both levels, because
the Response signature appears first in document order.

Sweden Connect has an additional wrinkle: assertion-level signatures are inside
the encrypted assertion plaintext, so they cannot be collected from the outer
Response XML before decryption.

## Decision

1. Treat `SecurityConfig::require_signed_assertions` as a direct assertion
   requirement. Check 6 now passes only when the consumed assertion carries
   signature markup and its own Assertion ID appears in `verified_signed_ids`.
   A verified Response ID no longer satisfies this check.

2. Treat assertion signature markup as meaningful. If an assertion carries
   `<ds:Signature>` markup, the assertion ID must be among the verified IDs;
   the validator does not ignore that unverified signature merely because the
   Response envelope was signed.

3. Keep response-envelope signing available as its own policy. Deployments that
   accept signed Responses with unsigned Assertions set
   `require_signed_assertions = false` and
   `require_signed_responses = true`.

4. Make the Actix ACS helper verify every enveloped signature with
   `SamlVerifier::verify_all_enveloped` and collect all valid reference IDs.
   This preserves valid double-signed Responses where the Response signature
   appears before the Assertion signature.

5. Make the Sweden Connect secure entrypoint verify all visible outer Response
   signatures, then verify decrypted assertion signatures after decryption when
   the decrypted assertion carries signature markup. `WantAssertionsSigned`
   still maps to the shared direct assertion-signature policy, and an unsigned
   decrypted assertion is rejected by the validator when that option is enabled.

## Consequences

- A response-only signature no longer satisfies direct assertion-signature
  requirements.
- Double-signed Responses continue to work through the ready Actix ACS handler
  because the helper now collects both Response and Assertion reference IDs.
- Sweden Connect callers using `verify_and_process_response` get response
  signature verification, decryption, decrypted assertion-signature
  verification, and semantic validation in one path.
- Low-level callers of `process_response_with_verified_signatures` or
  Sweden Connect `process_response` must pass verified IDs from every signature
  they intend to satisfy. Passing only the Response ID is correct only when
  assertion signatures are not required and no assertion-level signature markup
  needs to be trusted.

## Validation

- `test_response_signature_does_not_satisfy_required_assertion_signature`
- `test_required_assertion_signature_accepts_direct_verified_assertion_id`
- `test_acs_response_signature_does_not_satisfy_assertion_signature_requirement`
- `test_verify_all_enveloped_collects_response_and_assertion_signatures`
- `test_want_assertions_signed_rejects_response_only_signature`
- `test_want_assertions_signed_accepts_direct_assertion_signature`
- `cargo test -p gamlastan assertion_signature -- --nocapture`
- `cargo test -p gamlastan-actix assertion_signature -- --nocapture`
- `cargo test -p gamlastan want_assertions_signed -- --nocapture`
