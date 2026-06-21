# ADR 0016 - Verify ACS signatures before consuming claims

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Web Browser SSO Profile, XML Signature, SAML metadata key descriptors
- **Implementation:** `crates/gamlastan-actix/src/sp.rs`, `crates/gamlastan/src/profiles/sso/sp.rs`, `crates/gamlastan/src/security/validation.rs`

## Context

The ready-to-use Actix Assertion Consumer Service (ACS) handler parsed a SAML
Response and passed it to SP profile validation without first performing XML
Signature verification.

The lower-level validator tracked whether the response had signature markup,
but assertion-level validation treated `assertion.has_signature` as a passing
condition. That meant a forged assertion with a syntactically present but
invalid `ds:Signature` element could satisfy `require_signed_assertions` if the
other issuer, audience, recipient, and time checks were shaped correctly.

This is the same failure class as many historical SAML signature validation
bugs: the application consumes identity data from an XML object that was not
cryptographically verified, or it treats signature presence as signature trust.

## Decision

The ACS handler verifies signatures before profile validation and before any
authentication result is constructed.

1. The Actix ACS handler parses the incoming XML, then checks whether the
   Response or any Assertion carries signature markup.

2. If signatures are required by `SecurityConfig` and no signature is present,
   ACS rejects the message before claim extraction.

3. If signature markup is present, ACS builds a `SamlVerifier` from IdP signing
   certificates extracted from IdP metadata. Metadata without a usable signing
   certificate is a configuration error for signed ACS responses.

4. ACS verifies the exact XML string received by the endpoint. The verifier
   uses trusted metadata keys rather than attacker-controlled inline `KeyInfo`.

5. ACS converts verified XML-DSig references into signed SAML object IDs. Those
   IDs are passed into `process_response_with_verified_signatures`.

6. The shared validator accepts assertion signature requirements only when the
   verified ID set contains either the assertion ID or the enclosing response
   ID. Signature markup alone is a failure.

The original `process_response` API remains available, but it passes an empty
verified-ID set. Secure high-level callers that perform XML-DSig verification
should use `process_response_with_verified_signatures`.

## Consequences

- The ready-to-use Actix ACS path no longer accepts forged assertion signature
  markup as proof of authentication.
- ACS fails closed if a signed response is received but no trusted IdP signing
  certificate can be extracted from metadata.
- The validator now binds cryptographic verification to the parsed Response or
  Assertion object that supplies the user's identity and attributes.
- Existing direct calls to `process_response` that rely on signed assertions
  without supplying verified IDs now fail validation. Callers must verify the
  XML and pass the verified reference IDs through the new API.
- Sweden Connect response processing passes the externally verified response ID
  into the shared validator to preserve its existing profile-level guarantee.

## Alternatives considered

- **Keep accepting `has_signature` as sufficient.** Rejected: this is the
  vulnerability. Signature markup is attacker-controlled XML until verified.
- **Verify signatures inside the generic validator.** Rejected for now: the
  validator works over parsed SAML structs, while XML-DSig verification must
  operate on the exact XML bytes/string and trusted key material supplied by the
  binding or integration layer.
- **Trust inline `KeyInfo` from the response.** Rejected: SAML deployments must
  verify with trusted metadata keys, not attacker-provided keys.
- **Require only response-level signatures.** Rejected: deployments commonly
  use assertion signatures, response signatures, or both. The policy should
  support either, but both must be cryptographically verified when used.

## Validation

- `test_process_response_rejects_unverified_assertion_signature_markup` verifies
  that assertion signature markup alone fails and the same response passes only
  when the assertion ID is supplied as a verified reference.
- `cargo test -p gamlastan -p gamlastan-actix` passed.
- `cargo test --workspace` passed.

## Publication status

Unreleased.
