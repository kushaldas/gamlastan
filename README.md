# gamlastan

A comprehensive Rust SAML 2.0 library built on zero-copy XML parsing. The
library implements the full SAML 2.0 specification with errata corrections and
passes the Italian SPID (Sistema Pubblico di Identita Digitale) conformance
test suite (263/263 tests).

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
| `xml` | XML serialization/deserialization via [uppsala](../../uppsala) |
| `crypto` | Cryptographic operations (signing, verification) via [bergshamra](../../bergshamra) |
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

## Dependencies

gamlastan depends on two sibling libraries via path dependencies:

- **[uppsala](https://github.com/kushaldas/uppsala)** -- Zero-copy XML parser (pure Rust)
- **[bergshamra](https://github.com/kushaldas/bergshamra)** -- XML security: DSig signing/verification,
  XML Encryption, C14N canonicalization, key management (pure Rust)


## Prerequisites

- **Rust** 1.75 or later
- **[just](https://github.com/casey/just)** command runner
- **Docker** (needed for SPID conformance testing and E2E IdP testing)

## Building

```sh
just build
```

## Running Tests

### All tests

Run the full test suite across all workspace crates (457 unit tests + 3 doctests):

```sh
just test
```

With full output (no capture):

```sh
just test-verbose
```

### Per-crate tests

```sh
just test-gamlastan  # gamlastan library (417 tests + 1 doc test)
just test-actix      # gamlastan-actix (37 tests + 2 doc tests)
```

### Filtered tests

Run only tests matching a pattern:

```sh
just test-filter <PATTERN>
```

For example, to run all tests with "issuer" in the name:

```sh
just test-filter issuer
```

### Full CI check

Run formatting check, clippy lints, and the full test suite in sequence:

```sh
just check
```

This runs `fmt-check`, then `clippy` (with `-D warnings`), then `test`. All
three must pass.

## Code Quality

Check for lint warnings (fails on any warning):

```sh
just clippy
```

Format all code:

```sh
just fmt
```

Check formatting without modifying files:

```sh
just fmt-check
```

## Documentation

Build API documentation for all crates:

```sh
just doc
```

Build and open in browser:

```sh
just doc-open
```

## SPID Conformance Testing

The `spid-sp-test` binary crate is a fully SPID-compliant Service Provider that
is tested against the [spid_sp_test](https://github.com/italia/spid-sp-test)
Python tool. The tool acts as its own IdP: it fetches the SP's metadata and
login endpoint, generates signed SAML responses for each test case, and POSTs
them to the SP's Assertion Consumer Service.

All of this runs inside a single Docker container.

### What is tested

The conformance suite validates three areas:

| Area | Tests | What it checks |
|------|-------|----------------|
| Metadata | 210 | XML structure, signing, required SPID elements, certificate properties |
| AuthnRequest | 152 | Request format, signing, required attributes, NameIDPolicy, bindings |
| Response | 263 | Signature verification, assertion validation, attribute handling, error detection |

### Building the Docker image

The Docker build context must be the **parent directory** of this workspace
because the Rust build needs access to the `uppsala` and `bergshamra` path
dependencies.

```sh
cd /home/kdas/code/xml
docker build -f saml/spid-sp-test/Dockerfile -t spid-sp-test .
```

Or using docker compose:

```sh
cd /home/kdas/code/xml
docker compose -f saml/spid-sp-test/docker-compose.yml up --build
```

### What the Docker image contains

The image is built in two stages:

1. **Build stage** (debian:13) -- Installs Rust, compiles the `spid-sp-test`
   binary in release mode.
2. **Production stage** (debian:13-slim) -- Contains the compiled SP binary,
   `xmlsec1` (used by the Python tool for signing), and the `spid_sp_test`
   Python tool installed via `uv`.

### Running the tests

Run the full conformance suite (metadata + AuthnRequest + response):

```sh
docker run --rm --name spid-sp spid-sp-test
```

The entrypoint script:

1. Starts the SP on `https://localhost:8080` inside the container
2. Waits up to 30 seconds for the SP to become ready
3. Runs the full `spid_sp_test` suite against it
4. Reports results and exits with the test tool's exit code

### Running specific tests

You can pass custom arguments to `spid_sp_test` by appending them to the
`docker run` command. The entrypoint will use your arguments instead of the
default full suite.

Metadata + AuthnRequest only (no response tests):

```sh
docker run --rm spid-sp-test \
    --metadata-url https://localhost:8080/metadata \
    --authn-url https://localhost:8080/login \
    --extra \
    -pr spid-sp-public \
    -d INFO
```

Full suite including response tests (the default):

```sh
docker run --rm spid-sp-test \
    --metadata-url https://localhost:8080/metadata \
    --authn-url https://localhost:8080/login \
    --extra \
    -pr spid-sp-public \
    -tr \
    -d INFO
```

A single response test (e.g., test number 1):

```sh
docker run --rm spid-sp-test \
    --metadata-url https://localhost:8080/metadata \
    --authn-url https://localhost:8080/login \
    --extra \
    -pr spid-sp-public \
    -tr \
    -tn 1 \
    -d INFO
```

### Environment variables

The following environment variables can be overridden at runtime:

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level for the SP binary (`debug`, `info`, `warn`, `error`) |
| `SP_HOST` | `localhost` | Hostname the SP listens on |
| `SP_PORT` | `8080` | Port the SP listens on |
| `IDP_ENTITY_ID` | `https://localhost:8443` | Entity ID of the IdP in SAML metadata |
| `IDP_BASE_URL` | `https://localhost:8443` | Base URL for IdP endpoint resolution |
| `CERT_DIR` | `/app/certs` | Directory containing certificates |
| `REQUESTS_CA_BUNDLE` | `/app/certs/rootCA.pem` | CA bundle for Python `requests` TLS verification |

### Certificates

The Docker image ships with several certificates:

| File | Purpose |
|------|---------|
| `sp-key.pem` / `sp-cert.pem` | SAML signing keypair (RSA 2048, SHA-256) for the SP |
| `idp-cert.pem` | IdP certificate (from AgID test infrastructure, CN=agid.gov.it) |
| `tls-cert.pem` / `tls-key.pem` | TLS certificate for localhost (generated with mkcert) |
| `rootCA.pem` | mkcert root CA -- trusted by Python `requests` via `REQUESTS_CA_BUNDLE` |

The TLS certificates are self-signed via [mkcert](https://github.com/FiloSottile/mkcert).
The `rootCA.pem` file is set as `REQUESTS_CA_BUNDLE` so the Python test tool
trusts the SP's HTTPS endpoint.

### Expected output

A successful run ends with output like:

```
spid_sp_test --metadata-url https://localhost:8080/metadata ...

[INFO] Metadata validation: 210/210 PASSED
[INFO] AuthnRequest validation: 152/152 PASSED
[INFO] Response validation: 263/263 PASSED, 0 failures, 0 warnings

=== Tests complete (exit code: 0) ===
```

## End-to-End IdP Testing

The `example-idp` binary crate is a fully functional SAML 2.0 Identity Provider
that can be tested against a real Service Provider. The docker-compose setup
pairs it with a Django SP ([dsamlrp](../../learning/dsamlrp)) that uses
`django-allauth` with `python3-saml` as the SAML backend.

### Architecture

Two services communicate via standard SAML Web Browser SSO (SP-initiated):

| Service | Port | Description |
|---------|------|-------------|
| `idp` (example-idp) | 9443 | Rust IdP built on gamlastan + gamlastan-actix |
| `sp` (dsamlrp) | 8443 | Django SP using django-allauth + python3-saml |

### SSO flow

```
Browser                    SP (:8443)                       IdP (:9443)
  |                           |                                |
  | GET /accounts/saml/       |                                |
  |   sunet/login/            |                                |
  |-------------------------->|                                |
  |                           |                                |
  | 302 Redirect              |                                |
  |   SAMLRequest (deflate+   |                                |
  |   base64 in query string) |                                |
  |<--------------------------|                                |
  |                                                            |
  | GET /sso?SAMLRequest=...&RelayState=...                    |
  |----------------------------------------------------------->|
  |                                                            |
  | HTML login form (alice/hunter2 or bob/hunter2)             |
  |<-----------------------------------------------------------|
  |                                                            |
  | POST /sso (username + password + pending_id)               |
  |----------------------------------------------------------->|
  |                                                            |
  | HTML auto-submit form with signed SAMLResponse             |
  |   (HTTP-POST binding, both Assertion + Response signed)    |
  |<-----------------------------------------------------------|
  |                                                            |
  | POST /accounts/saml/sunet/acs/                             |
  |   (SAMLResponse + RelayState)                              |
  |-------------------------->|                                |
  |                           |                                |
  | 302 to landing page       |                                |
  |   (Django session created)|                                |
  |<--------------------------|                                |
```

### IdP endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metadata` | GET | Signed `EntityDescriptor` with `IDPSSODescriptor`, `KeyDescriptor`, SSO + SLO endpoints |
| `/sso` | GET | Receives AuthnRequest via HTTP-Redirect binding, shows login form |
| `/sso` | POST | Authenticates user, returns signed SAML Response via HTTP-POST binding |
| `/slo` | GET/POST | Single Logout endpoint (stub) |

### Test users

| Username | Password | Email | Name |
|----------|----------|-------|------|
| `alice` | `hunter2` | alice@example.com | Alice Smith |
| `bob` | `hunter2` | bob@example.com | Bob Jones |

Attributes are sent using OID-format names (`urn:oid:0.9.2342.19200300.100.1.1`
for uid, etc.) to match the SP's `attribute_mapping` configuration.

### Running with docker compose

```sh
cd /home/kdas/code/xml/saml/example-idp
docker compose up --build
```

Then open `https://localhost:8443/accounts/saml/sunet/login/` in a browser.

### Running locally (without Docker)

```sh
# Terminal 1: Run the IdP
cd example-idp && cargo run
# Starts on https://localhost:9443

# Terminal 2: Run the Django SP
cd /home/kdas/code/learning/dsamlrp && just dev
# Starts on https://localhost:8443

# Terminal 3: Smoke test
curl -k https://localhost:9443/metadata   # verify signed metadata XML
```

Then open `https://localhost:8443/accounts/saml/sunet/login/` in a browser.

### Certificates

| File | Purpose |
|------|---------|
| `certs/idp-key.pem` / `certs/idp-cert.pem` | SAML signing keypair (RSA 2048, self-signed, CN=Example IdP) |
| `certs/tls-key.pem` / `certs/tls-cert.pem` | TLS certificate for localhost (generated with mkcert) |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level for the IdP binary |
| `IDP_HOST` | `localhost` | Hostname the IdP listens on |
| `IDP_PORT` | `9443` | Port the IdP listens on |
| `CERT_DIR` | `/app/certs` (Docker) or `certs` (local) | Directory containing certificates |

## Clean

Remove all build artifacts:

```sh
just clean
```

## License

BSD-2-Clause
