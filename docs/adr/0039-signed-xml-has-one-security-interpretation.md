# ADR 0039 - Signed XML has one security interpretation

- **Status:** Accepted
- **Date:** 2026-08-02
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan/src/xml/deserialize.rs`, `crates/gamlastan/src/metadata/types/key_descriptor.rs`, `crates/gamlastan/src/crypto/{verifier,decryptor}.rs`, `crates/gamlastan/src/profiles/swedenconnect/response.rs`

## Context

Signature verification and semantic readers must interpret XML identically.
Comments or processing instructions can split element text, and inherited
namespace prefixes can be rebound on an intermediate wrapper around a
certificate. Algorithms hidden inside encrypted plaintext are invisible to an
outer-document policy scan.

The transitive RustCrypto `rsa` dependency is also affected by
RUSTSEC-2023-0071 for PKCS#1 v1.5 decryption, with no fixed upstream release.

## Decision

1. General SAML parsing continues to reject comments, PIs, and CDATA.
2. Metadata parsing permits structural comments/PIs used by federation feeds,
   but rejects either node when it splits meaningful direct element text.
3. KeyInfo fragment extraction rejects rebinding of the expected XML-DSig
   prefix on any intermediate start tag, not only X509Data/certificate tags.
4. Redirect and enveloped SAML verification reject HMAC algorithms by default.
5. `SamlDecryptor` prohibits XML Encryption RSA-PKCS#1 v1.5 key transport before
   invoking the vulnerable dependency; RSA-OAEP remains supported.
6. Sweden Connect algorithm policy is applied to each decrypted assertion
   plaintext before parsing, signature verification, or claim consumption.

## Consequences

- Federation comments between elements remain interoperable; comments embedded
  in a value are rejected instead of ambiguously concatenated or truncated.
- Malformed or namespace-ambiguous KeyInfo fragments yield no trust anchors.
- Legacy RSA1_5 encrypted assertions and SAML HMAC signatures are rejected.
- The RustSec advisory remains documented in audit configuration only because
  the vulnerable padding mode is unreachable through the public decryptor.

