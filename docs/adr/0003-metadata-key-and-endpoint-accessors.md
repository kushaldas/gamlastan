# ADR 0003 — Metadata accessors for X.509 certs and SSO endpoints

- **Status:** Accepted
- **Date:** 2026-06-09
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Metadata ([saml-metadata-2.0-os] §2.4.1.1 KeyDescriptor,
  §2.4.3 IDPSSODescriptor; erratum E62 key-use semantics, E69 KeyInfo opacity)
- **Implementation:** `crates/gamlastan/src/metadata/types/key_descriptor.rs`,
  `crates/gamlastan/src/metadata/types/idp.rs`
- **Related:** [ADR 0002 — MDQ client](0002-mdq-metadata-query-client.md)

## Context

A consumer that resolves an IdP's `<EntityDescriptor>` — whether from a local
file, an `<EntitiesDescriptor>` aggregate, or [MDQ](0002-mdq-metadata-query-client.md) —
needs two concrete things out of it to actually drive Web Browser SSO:

1. **Where to send the AuthnRequest** — the IdP's `SingleSignOnService`
   endpoint for a particular binding (e.g. HTTP-Redirect).
2. **What key verifies the Response** — the IdP's signing certificate(s).

gamlastan modelled the metadata faithfully but stopped at the data: a
`KeyDescriptor` carries its `<ds:KeyInfo>` as an **opaque XML string**
(`key_info_xml`, deliberately so per erratum E69), and `IdpSsoDescriptor`
exposes `single_sign_on_services: Vec<Endpoint>` and
`sso_base.base.key_descriptors: Vec<KeyDescriptor>` as plain fields. So every
consumer had to (a) re-parse the KeyInfo XML to pull out the
`<ds:X509Certificate>` base64, decode it, and (b) hand-roll the
binding/`use="signing"` filtering.

The first consumer to need this was tunnelbana's MDQ-backed SAML backend, but
the operations are **generic SAML metadata concerns**, not proxy-specific. The
decision was where they belong.

## Decision

Put the extraction in gamlastan, on the metadata types themselves, so every
consumer reuses one correct implementation rather than re-parsing KeyInfo XML.

- **`KeyDescriptor::x509_certificates_der(&self) -> Vec<Vec<u8>>`** — parses the
  opaque `key_info_xml` on demand (via `uppsala`), returns the DER of every
  `<X509Certificate>` it finds, in document order, with whitespace stripped and
  base64 decoded. Matching is by **local name** (`X509Certificate`) so any
  namespace prefix — or a prefix-less default namespace — works. Malformed or
  empty KeyInfo yields an empty vec rather than an error: a descriptor simply
  has no usable certs.

- **`IdpSsoDescriptor::single_sign_on_service(&self, binding) -> Option<&Endpoint>`**
  — the first `SingleSignOnService` advertised for the given binding URI.

- **`IdpSsoDescriptor::signing_certificates_der(&self) -> Vec<Vec<u8>>`** —
  collects DER certs across the descriptor's key descriptors that **can sign**
  (`use="signing"` or no `use`, per E62), reusing `can_sign()` and
  `KeyDescriptor::x509_certificates_der`. `use="encryption"` descriptors are
  skipped.

These are read-only, allocation-on-demand accessors with no new dependencies
(`uppsala` and `base64` are already gamlastan dependencies) and no change to the
metadata types' representation.

## Alternatives considered

- **Parse `key_info_xml` into a typed `KeyInfo` on deserialize.** Rejected:
  E69 makes KeyInfo intentionally opaque (it can carry arbitrary key-resolution
  material), and most callers never need the certs. On-demand extraction keeps
  the hot path zero-copy and the type honest.
- **Leave extraction to each consumer.** Rejected — that is exactly the
  duplication (and the XML-parsing footguns) this ADR removes; the next SP/RP
  would reinvent it.
- **Return parsed certificates / `Key`s instead of DER.** Rejected for these
  accessors: DER is the lowest-common-denominator the crypto layer
  (`loader::load_x509_cert_der`, `KeysManager::add_trusted_cert`) already
  consumes, and it lets the caller decide the trust policy.

## Consequences

**Positive**

- One correct, tested KeyInfo/endpoint extraction; consumers (the tunnelbana SAML
  backend, future RPs, metadata tooling) call an accessor instead of re-parsing XML.
- No representational change, no new dependencies, no cost unless called.

**Negative / accepted trade-offs**

- `x509_certificates_der` re-parses the KeyInfo fragment on each call; callers
  that need it repeatedly should cache the result. Acceptable — it is small and
  called once per metadata resolution in practice.
- Local-name matching ignores the namespace; a (non-conformant) document using
  `X509Certificate` in a foreign namespace would still match. Considered
  acceptable: such a document is already malformed, and the certs are only ever
  used as *candidate* verification keys, gated by signature verification.

## References

- `crates/gamlastan/src/metadata/types/key_descriptor.rs` —
  `x509_certificates_der`, `x509_certificates_der_from_key_info`, tests
- `crates/gamlastan/src/metadata/types/idp.rs` — `single_sign_on_service`,
  `signing_certificates_der`
- Consumer: tunnelbana `crates/tunnelbana-plugins/src/saml2_backend.rs` (MDQ path)
