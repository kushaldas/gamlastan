# ADR 0021 - Bindings reject duplicate SAML parameters

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 HTTP Redirect Binding, SAML 2.0 HTTP POST Binding
- **Implementation:** `crates/gamlastan/src/bindings/redirect.rs`, `crates/gamlastan/src/bindings/post.rs`

## Context

HTTP frameworks may collapse duplicate query or form parameters by returning
the first value, the last value, or a list depending on the API. SAML Redirect
signature verification is especially sensitive because the signature is over
exact URL-encoded parameter bytes. If duplicate SAML parameters are accepted,
one layer can verify one value while another layer consumes a different value.

The same ambiguity exists for POST binding form fields when the request body
contains more than one `SAMLRequest`, `SAMLResponse`, or `RelayState` field.

## Decision

Redirect decoding now inspects the raw query string before decoding the SAML
message. POST decoding inspects the raw URL-encoded form body before decoding
the SAML message. Both paths decode only parameter names for counting and leave
values untouched for later binding-specific processing.

The decoders reject:

1. Duplicate `SAMLRequest` or `SAMLResponse` parameters.
2. Requests containing both `SAMLRequest` and `SAMLResponse`.
3. Duplicate `RelayState`.
4. Duplicate Redirect signing parameters `SigAlg` or `Signature`.
5. Redirect requests with `Signature` but no `SigAlg`.

Redirect signature input is rebuilt from the single accepted raw parameters in
the SAML-specified order: message parameter, optional `RelayState`, then
`SigAlg`.

## Consequences

- Ambiguous SAML binding requests fail before XML parsing or decompression.
- Percent-encoded parameter names are counted by decoded name, so encoded
  duplicate names do not bypass the check.
- Framework adapters do not need a new multi-value parameter API.

## Validation

- `test_redirect_decode_rejects_duplicate_saml_message_param`
- `test_redirect_decode_rejects_encoded_duplicate_param_name`
- `test_post_decode_rejects_duplicate_saml_message_param`
- `test_post_decode_rejects_encoded_duplicate_param_name`
- `cargo test -p gamlastan`
