# example-idp

A minimal, fully functional SAML 2.0 Identity Provider built on `gamlastan` and
`gamlastan-actix`. It exists to exercise the library end to end against a real
Service Provider -- specifically the Django SP (`dsamlrp`) that uses
`django-allauth` with `python3-saml` as its SAML backend.

This is a **test/demo binary**, not a production IdP. It keeps users, sessions,
and pending requests in memory, ships a hardcoded test-user table, and uses
self-signed certificates.

## What it does

It implements the IdP side of the SAML V2.0 Web Browser SSO Profile
(SP-initiated):

1. Receives an `AuthnRequest` from a trusted SP (HTTP-Redirect or HTTP-POST
   binding).
2. Validates the request: the issuer must match one of the configured trusted
   SP entity IDs, and the signature is checked against that SP's metadata
   certificate.
3. If the user has no session, shows a login form; on success it creates an
   in-memory session and sets an `idp_session` cookie.
4. Builds a signed SAML `Response` (Response and/or Assertion signed) and
   returns it to the SP's Assertion Consumer Service via the HTTP-POST binding.

Attributes are emitted using OID-format names
(`urn:oid:0.9.2342.19200300.100.1.1` for uid, etc.) to match the SP's
`attribute_mapping` configuration. The `NameID` uses the email-address format.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page listing endpoints and test users |
| `/metadata` | GET | Signed `EntityDescriptor` with `IDPSSODescriptor`, `KeyDescriptor`, SSO + SLO endpoints |
| `/sso` | GET | Receives `AuthnRequest` via HTTP-Redirect, shows login form |
| `/sso` | POST | Receives `AuthnRequest` via HTTP-POST, or handles login form submission |
| `/slo` | GET/POST | Single Logout endpoint (stub) |

## Test users

| Username | Password | Email | Name |
|----------|----------|-------|------|
| `alice` | `hunter2` | alice@example.com | Alice Smith |
| `bob` | `hunter2` | bob@example.com | Bob Jones |

## Trusted Service Providers

The IdP needs each trusted SP's metadata so it can verify incoming
`AuthnRequest` signatures and resolve the Assertion Consumer Service. Point
`SP_METADATA_PATH` at either:

- a **single metadata file** -- the one trusted SP, or
- a **directory** -- every `*.xml` file inside it is loaded as one trusted SP.

The directory form lets the IdP serve more than one SP at a time. Each incoming
`AuthnRequest` is matched to a trusted SP by its issuer entity ID; an unknown
issuer is rejected as untrusted. Each SP's signed-request policy is honoured
independently (its metadata `AuthnRequestsSigned`, plus the global
`ALLOW_UNSIGNED_AUTHN_REQUESTS` override). Duplicate entity IDs across files are
rejected at startup.

## Running locally (without Docker)

```sh
# Terminal 1: run the IdP (from the workspace root)
# single SP:
SP_METADATA_PATH=/path/to/sp-metadata.xml cargo run -p example-idp
# or multiple SPs (a directory of *.xml files):
SP_METADATA_PATH=./sp_metadata cargo run -p example-idp
# Starts on https://localhost:9443

# Terminal 2: run the Django SP
cd /home/kdas/code/learning/dsamlrp && just dev
# Starts on https://localhost:8443

# Terminal 3: smoke test
curl -k https://localhost:9443/metadata   # verify signed metadata XML
```

Then open `https://localhost:8443/accounts/saml/sunet/login/` in a browser and
log in as `alice` / `hunter2`.

For local interop where the SP cannot sign its requests, you can relax the
signature requirement (insecure -- testing only):

```sh
ALLOW_UNSIGNED_AUTHN_REQUESTS=true SP_METADATA_PATH=/path/to/sp-metadata.xml \
    cargo run -p example-idp
```

Note: if the SP's metadata sets `AuthnRequestsSigned="true"`, signed requests
are required regardless of this override.

## Running with Docker

The Docker build context is the **project root directory** (`uppsala` and
`bergshamra` are pulled from crates.io, so no sibling source trees are needed).

The IdP validates incoming `AuthnRequest`s against trusted SP metadata, so it
needs that metadata mounted into the container. Place one `*.xml` file per
trusted SP in a local `./sp_metadata` directory -- it is mounted read-only at
`/app/sp_metadata`, and `SP_METADATA_PATH` defaults to that directory (so every
file is loaded):

```sh
mkdir -p sp_metadata
cp /path/to/sp-a-metadata.xml sp_metadata/sp-a.xml
cp /path/to/sp-b-metadata.xml sp_metadata/sp-b.xml   # add as many as you need
```

Build the image from the project root:

```sh
cd /home/kdas/code/xml/saml
docker build -f example-idp/Dockerfile -t example-idp .
```

Run the image, mounting the metadata directory:

```sh
docker run --rm -p 9443:9443 \
    -v ./sp_metadata:/app/sp_metadata:ro \
    example-idp
```

Or run the full IdP + SP pair via docker compose (from this directory):

```sh
docker compose up --build
# then open: https://localhost:8443/accounts/saml/sunet/login/
```

The compose file builds the IdP from source and pairs it with the `dsamlsp`
image. It mounts `./sp_metadata` into the IdP container and sets
`SP_METADATA_PATH=/app/sp_metadata`, so make sure that directory contains at
least one SP `*.xml` file before running. Because SAML flows are
browser-mediated (HTTP-Redirect +
HTTP-POST), both containers simply expose ports to `localhost`; no
container-to-container networking is required. `init-sp.sh` runs the SP's
migrations, sets the Django site domain, and starts gunicorn with TLS on port
8443.

## SSO flow

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

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SP_METADATA_PATH` | (required) | Trusted SP metadata: a single XML file, or a directory of `*.xml` files (one per SP) |
| `IDP_HOST` | `localhost` | Hostname the IdP listens on |
| `IDP_PORT` | `9443` | Port the IdP listens on |
| `CERT_DIR` | `example-idp/certs` | Directory containing the signing + TLS certificates |
| `ALLOW_UNSIGNED_AUTHN_REQUESTS` | `false` | Accept unsigned `AuthnRequest`s (insecure; ignored if SP metadata requires signing) |
| `RUST_LOG` | `info` | Log level for the IdP binary (`debug`, `info`, `warn`, `error`) |

## Certificates

| File | Purpose |
|------|---------|
| `certs/idp-key.pem` / `certs/idp-cert.pem` | SAML signing keypair (RSA 2048, self-signed, CN=Example IdP) |
| `certs/tls-key.pem` / `certs/tls-cert.pem` | TLS certificate for localhost (generated with mkcert) |

## Tests

```sh
cargo test -p example-idp
```

The unit tests cover SP-metadata loading (signed-request policy resolution) and
`AuthnRequest` validation (rejecting untrusted SPs and unsigned requests when
signing is required).
```
