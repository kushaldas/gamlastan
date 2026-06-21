# ADR 0022 - Generic SP processing rejects opaque encrypted assertions

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Web Browser SSO Profile, SAML 2.0 XML Encryption
- **Implementation:** `crates/gamlastan/src/profiles/sso/sp.rs`

## Context

The generic SP `process_response` API validates plaintext `Assertion` values
and extracts identity from them. It does not decrypt `EncryptedAssertion`
elements. The previous behavior allowed responses containing only encrypted
assertions to pass the initial assertion-presence check and later fail with a
less accurate validation or extraction error.

The `require_encrypted_assertions` security option was also misleading in this
generic API. The function cannot prove that a plaintext assertion originally
came from an encrypted assertion, and opaque encrypted markup alone is not
validated identity data.

## Decision

The generic SP processor now fails closed when:

1. A response contains encrypted assertions but no plaintext assertions.
2. `require_encrypted_assertions` is enabled for this generic processor.

The error messages explain that callers must decrypt assertions before
processing and must use a profile/API that tracks encrypted provenance when
encryption is a policy requirement.

## Consequences

- Encrypted markup is never treated as a usable assertion by the generic SP
  processor.
- Operators receive a clear configuration error instead of a misleading
  assertion validation result.
- Profile-specific code, such as Sweden Connect processing, remains the right
  place to decrypt and track whether encryption was used.

## Validation

- `test_process_response_rejects_encrypted_only_response`
- `test_process_response_rejects_require_encrypted_assertions_without_provenance`
- `cargo test -p gamlastan`
