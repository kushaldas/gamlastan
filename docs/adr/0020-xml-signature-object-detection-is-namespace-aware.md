# ADR 0020 - XML Signature Object detection is namespace aware

- **Status:** Accepted
- **Date:** 2026-06-21
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Errata E91, XML Signature
- **Implementation:** `crates/gamlastan/src/security/signature.rs`, `crates/gamlastan/src/crypto/verifier.rs`

## Context

SAML Errata E91 requires SAML signatures to reject `ds:Object` elements.
The previous guard used string matching for a small set of prefixes and tag
spellings. That could be bypassed by changing the XML Signature prefix, by
using a default namespace shape that did not match the string checks, or by
placing an unrelated element named `Object` outside the XML Signature namespace.

## Decision

`contains_ds_object` now parses the signature XML and compares expanded XML
names. It rejects any element whose local name is `Object` and whose namespace
URI is `http://www.w3.org/2000/09/xmldsig#`, independent of the chosen prefix.

Malformed XML is not classified as containing a `ds:Object` by this helper. The
main XML signature verifier still receives the same input and remains
responsible for rejecting malformed signed XML.

## Consequences

- Prefix changes no longer bypass E91 enforcement.
- Non-XMLDSig elements named `Object` are not rejected by this specific guard.
- The verifier uses the same helper, so the standalone security helper and
  cryptographic verification path have one shared interpretation.

## Validation

- `test_dsig_object_with_unusual_prefix`
- `test_ignores_non_dsig_object`
- `cargo test -p gamlastan`
