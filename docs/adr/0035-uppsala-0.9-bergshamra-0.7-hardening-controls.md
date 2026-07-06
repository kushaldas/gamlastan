# ADR 0035 - Adopt uppsala 0.9 and bergshamra 0.7 hardening controls

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** gamlastan maintainers
- **Supersedes in part:** [0023](0023-uppsala-0.5-bergshamra-0.6-dependency-stack.md), [0024](0024-reject-dtd-at-saml-parse-boundary.md)
- **Implementation:** workspace `Cargo.toml`, `crates/gamlastan/src/xml/deserialize.rs`, `crates/gamlastan/src/crypto`

## Context

`uppsala` 0.9.0 and `bergshamra` 0.7.0 are security-hardening releases. The
Uppsala release adds parse-time DTD/entity rejection, pull-parser parity with
the DOM parser, reserved namespace-binding enforcement from the 0.8 line,
XPath/XSD/XSLT hardening, output caps for XSLT, and encoding-declaration
normalization for byte parsing. The bergshamra release tracks Uppsala 0.9 and
adds DSig local reference-digest enforcement, duplicate ID rejection, safer
detached-reference resolution, stricter inline-KeyInfo trust anchor behavior,
and XML Encryption PBKDF2 iteration caps.

gamlastan's SAML processing path uses Uppsala for DOM parsing and bergshamra for
XML-DSig and XML-Enc. It does not run XSLT, XSD validation, or public XPath
evaluation as part of SAML message processing.

## Decision

1. Bump the workspace XML stack to published crates:
   `uppsala = 0.9.0` and all direct `bergshamra*` crates to `0.7.0`. Keep the
   bergshamra family on one minor version to avoid duplicate XML-security crates
   in the lockfile.

2. Replace `parse_secure`'s post-parse DTD inspection with Uppsala's parse-time
   controls. `parse_secure` now uses `SecureParseConfig::default()`:

   - `max_depth = uppsala::parser::DEFAULT_MAX_DEPTH`
   - `max_entity_expansion = uppsala::parser::DEFAULT_MAX_ENTITY_EXPANSION`
   - `forbid_dtd = true`
   - `forbid_entities = true`

   Expose `parse_secure_with_config` for callers that need to tune these parser
   caps while staying on the hardened parse surface.

3. Keep bergshamra 0.7's DSig fail-closed defaults and expose the SAML-relevant
   compatibility switches on `SamlVerifier`:

   - `set_require_reference_digests(bool)` defaults to `true`.
   - `set_allow_raw_inline_keyinfo_with_trust_anchors(bool)` defaults to
     `false`.
   - `set_hmac_min_out_len(usize)` remains available, with the default raised to
     160 bits to match bergshamra's hardened default.

4. Expose the XML Encryption PBKDF2 work-factor cap on both `SamlDecryptor` and
   `SamlEncryptor` via `set_max_pbkdf2_iterations(u32)`, defaulting to
   bergshamra's `DEFAULT_MAX_PBKDF2_ITERATIONS`.

5. Do not wrap Uppsala's pull parser, XPath/XSD/XSLT knobs, or bergshamra's
   detached-reference URL-map/base-directory controls in the SAML convenience
   wrappers. They are not part of gamlastan's SAML message-processing path.
   Callers that deliberately use those lower-level APIs can access Uppsala via
   `gamlastan::xml::uppsala` or depend on bergshamra directly.

## Consequences

- DTD-bearing SAML input is rejected before Uppsala parses the DTD internal
  subset, closing the residual bounded-work gap documented in ADR 0024.
- SAML signature verification requires local digest coverage by default, so a
  valid `SignatureValue` cannot be mistaken for payload integrity when reference
  bytes were not verified.
- Raw inline signing keys remain rejected when trust anchors are configured,
  unless a caller explicitly opts into the compatibility escape hatch.
- XML-controlled PBKDF2 parameters can no longer select an unbounded CPU work
  factor through gamlastan's encryption/decryption wrappers.

## Validation

- `cargo update -p uppsala -p bergshamra -p bergshamra-core -p bergshamra-dsig -p bergshamra-enc -p bergshamra-c14n -p bergshamra-crypto -p bergshamra-keys`
- `cargo outdated --depth 1` reports only `rand 0.8.6 -> 0.10.2` as a direct
  semver-major candidate; that is outside this XML/security stack update.
- `cargo audit --deny warnings`
- `cargo fmt --all`
- `cargo check --workspace`
- `cargo test --workspace`
