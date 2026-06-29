# ADR 0031 - Fail-closed metadata key extraction and input validation

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** gamlastan maintainers
- **Spec:** XML Signature / XML Encryption KeyInfo, SAML Errata E46 / E90 / E91, CWE-345 / CWE-347 / CWE-693 / CWE-20 / CWE-601
- **Implementation:** `crates/gamlastan/src/metadata/types/key_descriptor.rs`, `crates/gamlastan/src/security/relay_state.rs`, `crates/gamlastan/src/bindings/relay_state.rs`, `crates/gamlastan/src/security/validation.rs`, `crates/gamlastan/src/security/signature.rs`, `crates/gamlastan/src/crypto/verifier.rs`

## Context

The security review (`report.md`, findings 2, 14, 15, 16) found several
validation helpers that **failed open**: when an input could not be fully
inspected, or was structurally unusual, the code returned the "safe to proceed"
answer rather than rejecting.

- **KeyInfo X509 extraction (2)** accepted any element whose local name was
  `X509Certificate` regardless of namespace or position, and fell back to a
  namespace-blind raw-string scan when the fragment did not parse standalone. A
  metadata author could smuggle attacker DER through an `<evil:X509Certificate>`
  lookalike and have it promoted to a trusted signing key.
- **RelayState sanitizers (14)** checked dangerous URI schemes with
  `starts_with` on a non-normalized string, so leading whitespace or an embedded
  control character (`java\tscript:`) bypassed them.
- **AudienceRestriction (15)** treated `Conditions` with an **empty** restriction
  list as "unconstrained" (pass), letting an assertion that named no SP be
  consumed by any SP.
- **E91 `contains_ds_object` (16)** returned `false` (the same value as "no
  object found") when the XML failed to parse, so a parser differential could
  bypass the hardening check.

## Decision

Each of these helpers now fails closed:

- **KeyInfo:** a candidate `<X509Certificate>` is honoured only when it is in
  the XML Signature namespace (or unqualified — common but non-conformant) and
  nested under an `<X509Data>` ancestor. The unparseable-fragment fallback
  anchors trust to the `<KeyInfo>` root's prefix (which the deserializer
  guarantees is XMLDSig): the `<X509Certificate>` and its enclosing `<X509Data>`
  must use that same prefix, and neither may rebind it to a foreign namespace
  inline. This rejects both inline and **ancestor-declared** foreign-namespace
  lookalikes, closing the residual gap noted in the first remediation pass. It is
  documented in depth, with accepted/rejected examples and the (now much
  narrower) residual-limitation analysis, in
  [`docs/keyinfo-certificate-extraction.md`](../keyinfo-certificate-extraction.md).
- **RelayState:** all control characters (C0/C1, TAB/CR/LF, DEL) are rejected
  outright, and the value is whitespace-trimmed before dangerous-scheme parsing,
  in both the security and binding-layer sanitizers.
- **AudienceRestriction:** for SP-side validation, `Conditions` with no
  `AudienceRestriction` binding this SP fails check 11.
- **E91:** `contains_ds_object` returns `Result<bool, _>`; the verifier and the
  assertion validator both treat a parse error as a rejection.

## Consequences

- Foreign-namespace certificate lookalikes and loose `X509Certificate` elements
  are no longer promoted to trust anchors; legacy unqualified and ancestor-
  namespace KeyInfo (e.g. real eduGAIN metadata) still work.
- Obfuscated dangerous RelayState schemes are rejected before reaching the
  application callback.
- An assertion with no audience binding is rejected by the SP validator.
- A signature fragment that cannot be parsed for the E91 check is rejected
  rather than waved through.

## Validation

- `test_x509_certificates_der_rejects_foreign_namespace_lookalike`,
  `test_x509_certificates_der_requires_x509data_ancestor`,
  `test_x509_certificates_der_fragment_requires_x509data`,
  `test_x509_certificates_der_fragment_rejects_inherited_foreign_prefix`,
  `test_x509_certificates_der_fragment_rejects_inline_rebound_prefix`,
  `test_x509_certificates_der_fragment_accepts_matching_prefix`
- `test_relay_state_leading_whitespace_scheme`,
  `test_relay_state_embedded_control_char_scheme`
- `test_conditions_without_audience_restriction_rejected`
- `test_unparseable_xml_fails_closed`
- `cargo test -p gamlastan`
