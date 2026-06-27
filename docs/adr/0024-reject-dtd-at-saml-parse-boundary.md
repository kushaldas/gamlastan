# ADR 0024 - Reject DTDs at the SAML parse boundary

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** gamlastan maintainers
- **Spec:** SAML 2.0 Core §1.3.1 (no constraint requires DTDs; SAML schemas are
  XSD), SAML Security and Privacy Considerations, OWASP XXE Prevention
- **Implementation:** `crates/gamlastan/src/xml/deserialize.rs` (`parse_secure`)

## Context

uppsala does **not** resolve external `SYSTEM`/`PUBLIC` entities, so the classic
XXE file-read vector is already absent, and uppsala 0.5 bounds internal-entity
expansion to a 1 MiB byte budget (see
[0023](0023-uppsala-0.5-bergshamra-0.6-dependency-stack.md)). However, uppsala
still *parses* an internal DTD subset and *expands* internal entities up to that
budget. Legitimate SAML never carries a DTD: SAML grammar is defined by XSD, and
protocol messages, assertions, and metadata are DTD-free. A `<!DOCTYPE …>` in an
inbound message is therefore always either a probe or an attack (entity
expansion, entity-based obfuscation of signed content, XXE attempts against
less-strict downstream parsers).

Before this change every inbound parse site called `uppsala::parse` directly,
accepting documents with a DTD as long as expansion stayed within budget.

## Decision

Add a single hardened entry point, `gamlastan::xml::parse_secure`, used for all
attacker-controlled XML. It is a drop-in replacement for `uppsala::parse` (same
`Result<Document, uppsala::XmlError>` return type, so existing `?` / `map_err`
handling is unchanged) and:

1. inherits uppsala 0.5's resource limits via `uppsala::parse`, then
2. **rejects any document whose `doctype` is present**, returning a
   well-formedness error.

Refusing DTDs outright closes the internal-entity-expansion surface entirely —
defense in depth over uppsala's expansion budget — and removes the XXE entry
point as a matter of policy rather than relying on a downstream parser's
configuration.

The following inbound / remote-derived parse sites were migrated to
`parse_secure`: SP and IdP actix handlers (`gamlastan-actix` `sp.rs`, `idp.rs`),
SOAP/PAOS envelope unwrap (`bindings/soap.rs`), ECP envelope parsing
(`profiles/sso/ecp.rs`), Sweden Connect response validation / decryption and
decrypted assertions (`profiles/swedenconnect/response.rs`), IdP-discovery and
PEFIM extension parsing, SPID and Sweden Connect metadata-extension parsing,
`KeyInfo` X.509 extraction (`metadata/types/key_descriptor.rs`), the standalone
`ds:Object` signature guard (`security/signature.rs`), and the MDQ verifier
(`gamlastan-mdq` `verify.rs`).

Trusted XML the library produces itself (serialize-then-reparse round trips,
unit-test fixtures) may continue to call `uppsala::parse` directly.

## Consequences

- Any inbound SAML message or remote metadata document carrying a DTD is
  rejected before deserialization, regardless of whether its entities would have
  fit the expansion budget.
- No legitimate SAML payload is affected — SAML is DTD-free by design; the only
  DTDs in the codebase are `<!DOCTYPE html>` in HTML *output* templates, which
  do not flow through `parse_secure`.
- New parse sites for untrusted XML should use `parse_secure`; this is the single
  documented choke point for inbound XML hardening.

## Validation

- `parse_secure_tests::rejects_doctype_declaration` (entity-bearing DTD)
- `parse_secure_tests::rejects_internal_subset_without_entities`
- `parse_secure_tests::accepts_well_formed_saml_without_dtd`
- `cargo test --workspace` — full suite green.
