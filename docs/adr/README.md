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
