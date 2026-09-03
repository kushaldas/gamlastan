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
6. SP-initiated logout obtains its full NameID and SessionIndex values from an
   application callback bound to the authenticated local session.
7. SP-initiated Redirect LogoutRequests require `SpSigningContext` and are
   signed before their IDs are stored in the request ID tracker.
8. LogoutResponse messages must carry InResponseTo matching and consuming an
   outstanding stored request ID.
9. Non-success LogoutResponse status is rejected.

The same metadata verifier builder now adds both trusted certificate anchors
and certificate-derived verification keys so it can support enveloped XML-DSig
and Redirect binding signatures.

## Consequences

- Unsigned SLO messages are rejected by the ready-to-use SP handler.
- LogoutResponse messages cannot complete an SLO flow unless they match a
  LogoutRequest ID issued by this SP.
- Caller-supplied query parameters cannot choose the subject of a signed
  SP-initiated LogoutRequest.
- Missing authenticated-session or signing callbacks fail before a request ID
  is reserved or a LogoutRequest is emitted.
- Missing or mismatched Issuer and Destination values fail before the handler
  acts on the logout message.
- Deployments using the ready-to-use handler must publish IdP signing
  certificates in metadata for signed SLO verification.

## Validation

- `test_slo_unsigned_message_is_rejected_before_metadata_key_lookup`
- `test_slo_common_rejects_issuer_and_destination_mismatch`
- `test_slo_logout_response_requires_matching_in_response_to`
- `sp_logout_requires_signing_and_authenticated_session_callbacks`
- `sp_logout_binds_request_id_to_emitted_browser_cookie`
- `cargo test -p gamlastan-actix`
