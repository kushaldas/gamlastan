# ADR 0019 - SP SLO requires trust and correlation

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Single Logout Profile, HTTP Redirect Binding, XML Signature
- **Implementation:** `crates/gamlastan-actix/src/sp.rs`

## Context

The ready-to-use Actix SP SLO handler parsed incoming LogoutRequest and
LogoutResponse messages and applied only limited profile checks. It did not
verify signatures, require a trusted issuer, validate Destination, or correlate
LogoutResponse messages to an outstanding LogoutRequest.

That allows spoofed logout requests, spoofed logout responses, or completion of
an SLO flow that did not come from the configured IdP.

## Decision

The Actix SP SLO handler now fails closed for incoming SLO messages:

1. Incoming SLO messages must be signed.
2. HTTP Redirect signatures are verified over the preserved original signature
   input.
3. XML signatures are verified against trusted IdP metadata certificates and
   must reference the parsed LogoutRequest or LogoutResponse ID.
4. The Issuer must match the configured IdP entity ID.
5. Destination must match the SP SLO URL when destination verification is
   enabled.
6. SP-initiated LogoutRequest IDs are stored in the request ID tracker.
7. LogoutResponse messages must carry InResponseTo matching and consuming an
   outstanding stored request ID.
8. Non-success LogoutResponse status is rejected.

The same metadata verifier builder now adds both trusted certificate anchors
and certificate-derived verification keys so it can support enveloped XML-DSig
and Redirect binding signatures.

## Consequences

- Unsigned SLO messages are rejected by the ready-to-use SP handler.
- LogoutResponse messages cannot complete an SLO flow unless they match a
  LogoutRequest ID issued by this SP.
- Missing or mismatched Issuer and Destination values fail before the handler
  acts on the logout message.
- Deployments using the ready-to-use handler must publish IdP signing
  certificates in metadata for signed SLO verification.

## Validation

- `test_slo_unsigned_message_is_rejected_before_metadata_key_lookup`
- `test_slo_common_rejects_issuer_and_destination_mismatch`
- `test_slo_logout_response_requires_matching_in_response_to`
- `cargo test -p gamlastan-actix`

