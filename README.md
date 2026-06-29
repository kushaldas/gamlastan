# gamlastan

A comprehensive Rust SAML 2.0 library built on zero-copy XML parsing. The
library implements the full SAML 2.0 specification with errata corrections and
passes the Italian SPID (Sistema Pubblico di Identita Digitale) conformance
test suite (263/263 tests).

The plan is to become Rust equivalent of
[pysaml2](https://https://github.com/IdentityPython/pysaml2) project. We will
not be 100% compatible, but will try to close the gap. We thank the amazing
maintainers of the `pysaml2` project for maintaining the stack for the community.

## Workspace Structure

| Crate | Description |
|-------|-------------|
| `gamlastan` | Core SAML 2.0 library: types, XML, crypto, metadata, bindings, security, profiles |
| `gamlastan-actix` | actix-web integration (extractors, responders, handlers, middleware) |
| `gamlastan-mdq` | Metadata Query Protocol (MDQ) client: fetch entity metadata on demand, verify, and cache |

The `gamlastan` crate contains the following modules:

| Module | Description |
|--------|-------------|
| `core` | Core SAML 2.0 types (Issuer, NameID, Assertions, StatusCode, Conditions, etc.) |
| `xml` | XML serialization/deserialization via [uppsala](https://github.com/kushaldas/uppsala) |
| `crypto` | Cryptographic operations (signing, verification) via [bergshamra](https://github.com/kushaldas/bergshamra) |
| `metadata` | SAML metadata types, SPID extensions, caching, and validation |
| `bindings` | HTTP Redirect, POST, Artifact, SOAP, PAOS bindings and RelayState handling |
| `security` | 32-check assertion validator, replay cache, clock skew handling |
| `profiles` | Web Browser SSO (SP + IdP), SLO, ECP, artifact resolution, name ID management, Sweden Connect deployment profile |

## Deployment Profiles

In addition to the core SAML 2.0 profiles, gamlastan ships national deployment
profiles that layer restrictions and extensions on Web Browser SSO:

| Profile | Module | Description |
|---------|--------|-------------|
| Italian SPID | (built into `core`, `metadata`, `security`) | Italian public digital identity system; validated by the SPID conformance suite (see below) |
| Sweden Connect | `profiles::swedenconnect` | [Deployment Profile for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html) (Sweden Connect / DIGG) |

The `swedenconnect` module implements the Swedish eID Framework as a restriction
and extension of Web Browser SSO, covering:

- **Levels of Assurance** -- the `LevelOfAssurance` enum, exact-comparison
  `RequestedAuthnContext` building, and the section 6.3.4 LoA matching check.
- **Deployment configuration** -- `SwedenConnectConfig` yields a profile-correct
  `SecurityConfig` (<= 1 minute clock skew, signed + encrypted responses,
  Destination/Recipient checks).
- **Metadata extensions** -- `mdui:UIInfo`, `mdattr:EntityAttributes` (entity
  categories + assurance certification), `shibmd:Scope`, and
  `idpdisc:DiscoveryResponse`.
- **Principal selection** -- the `psc:PrincipalSelection` request extension and
  `psc:RequestedPrincipalSelection` metadata extension.
- **Authentication for Signature** -- the `csig:SignMessage` and `sap:SADRequest`
  request extensions (section 7).
- **SP-side request/response** -- AuthnRequest construction (section 5) and
  Response processing: decrypt, signature verification, LoA match, structural
  checks (section 6).
- **IdP-side responses** -- Response and error construction (sections 6 and 6.4).

The ordinary Web Browser SSO profile is fully covered. Holder-of-key is supported
at the metadata/constant and `SubjectConfirmation`-method level; the mutual-TLS
transport requirement is a deployment concern outside the library. The DSS/SAP
`SignRequest`/`SignResponse` envelope and SAD verification are out of scope.

## Security

gamlastan is built to fail closed against the SAML attack classes catalogued in
[`samlattacks.md`](samlattacks.md). The enforced controls — signature binding
against XML Signature Wrapping, request correlation, ready-handler trust
boundaries, and fail-closed key extraction and input validation — are documented
in [`docs/security-hardening.md`](docs/security-hardening.md), with the rationale
for each decision captured in the [Architecture Decision Records](docs/adr/).

## License

BSD-2-Clause
