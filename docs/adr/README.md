# Architecture Decision Records

This directory holds Architecture Decision Records (ADRs) — short documents
capturing a significant decision, its context, and its consequences.

Each ADR is `NNNN-kebab-title.md` with a monotonically increasing number. A
record is **Accepted** once merged; supersede it with a new ADR rather than
rewriting history (mark the old one `Superseded by NNNN`).

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-sweden-connect-deployment-profile.md) | Sweden Connect Deployment Profile as a layered profile module | Accepted |
| [0002](0002-mdq-metadata-query-client.md) | Metadata Query Protocol (MDQ) client as a separate async crate | Accepted |
| [0003](0003-metadata-key-and-endpoint-accessors.md) | Metadata accessors for X.509 certs and SSO endpoints | Accepted |
| [0004](0004-hsm-pkcs11-signing.md) | HSM / PKCS#11-backed signing | Accepted |
| [0005](0005-discovery-return-url-matching.md) | Discovery return URL matching preserves registered query | Accepted |
| [0006](0006-ecp-phase1-header-requirements.md) | ECP phase-1 parsing requires the `ecp:Request` header | Accepted |
| [0007](0007-partial-logout-accounting.md) | Partial logout is terminal but not counted as success | Accepted |
| [0008](0008-idp-server-infrastructure.md) | IdP-side server infrastructure as a `gamlastan::idp` module | Accepted |
| [0009](0009-attribute-name-conversion.md) | Attribute name conversion with code-generated shipped maps | Accepted |
| [0010](0010-core-assertion-type-extensions.md) | Core assertion type extensions: NameID-valued attributes and `saml:Advice` | Accepted |
| [0011](0011-per-request-certificate-encryption.md) | Per-request certificate encryption (PEFIM) | Accepted |
| [0012](0012-ecp-soap-envelope-hardening.md) | ECP envelope parsing verifies the SOAP 1.1 namespace and rejects multi-element Bodies | Accepted |
| [0013](0013-logout-response-requires-issuer.md) | LogoutResponse without an Issuer is rejected | Accepted |
| [0014](0014-entity-category-conflict-matcher.md) | Conflict-aware entity-category matcher for REFEDS Access | Accepted |
| [0015](0015-subject-id-pairwise-id-mutual-exclusion.md) | Prefer pairwise-id when subject-id:req is any | Accepted |
| [0016](0016-acs-signature-verification-before-claims.md) | Verify ACS signatures before consuming claims | Accepted |
| [0017](0017-web-sso-requires-audience-and-expiry.md) | Web SSO requires audience and bearer expiry | Accepted |
| [0018](0018-soap-body-single-child-enforcement.md) | Enforce a single SOAP Body child | Accepted |
| [0019](0019-sp-slo-requires-trust-and-correlation.md) | SP SLO requires trust and correlation | Accepted |
| [0020](0020-xml-signature-object-detection-is-namespace-aware.md) | XML Signature `ds:Object` detection is namespace aware | Accepted |
| [0021](0021-bindings-reject-duplicate-saml-parameters.md) | Bindings reject duplicate SAML parameters | Accepted |
| [0022](0022-generic-sp-processing-rejects-opaque-encrypted-assertions.md) | Generic SP processing rejects opaque encrypted assertions | Accepted |
| [0023](0023-uppsala-0.5-bergshamra-0.6-dependency-stack.md) | Adopt uppsala 0.5, local bergshamra 0.6, and kryptering 0.4 | Accepted |
| [0024](0024-reject-dtd-at-saml-parse-boundary.md) | Reject DTDs at the SAML parse boundary | Accepted |
