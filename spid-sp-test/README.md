# spid-sp-test

A SPID-compliant SAML 2.0 **Service Provider (SP)** used to verify the
[`gamlastan`](../crates/gamlastan) / [`gamlastan-actix`](../crates/gamlastan-actix)
stack against the official Italian [SPID](https://www.spid.gov.it/) conformance
suite, [`spid_sp_test`](https://github.com/italia/spid-sp-test).

SPID is one of the strictest SAML 2.0 profiles in production (SHA-256 only,
mandatory signed `AuthnRequest`s, specific metadata extensions and
`AttributeConsumingService` rules). Passing its checks is strong evidence the
library's metadata generation, request signing, and response validation are
correct.

This is a binary crate (`publish = false`) — it is a test fixture, not a
shipped library.

## What it does

The binary starts a real HTTPS Service Provider exposing the SAML endpoints,
then the Python `spid_sp_test` tool crawls and grades them:

| Route        | Method   | Role                                                        |
|--------------|----------|------------------------------------------------------------|
| `/`          | GET      | Landing page                                               |
| `/metadata`  | GET      | SP SAML metadata (`EntityDescriptor`)                      |
| `/login`     | GET      | Builds and sends a signed `AuthnRequest`                   |
| `/acs`       | POST     | Assertion Consumer Service — receives and validates `Response` |
| `/slo`       | GET/POST | Single Logout                                              |

Security posture (set in `src/main.rs`): signed assertions required, 3-minute
clock skew, 5-minute max assertion age, and `ds:Object` rejection (errata E91).

## Layout

```
spid-sp-test/
├── src/main.rs          # the actix-web SP
├── certs/               # SAML signing certs + keys (test-only)
│   ├── sp-cert.pem      #   SP signing certificate
│   ├── sp-key.pem       #   SP signing private key
│   ├── idp-cert.pem     #   AgID TEST IdP certificate (public)
│   ├── tls-cert.pem     #   localhost TLS cert (mkcert)
│   └── tls-key.pem      #   localhost TLS key (mkcert)
├── docker/
│   ├── entrypoint.sh    # starts SP, waits, runs spid_sp_test
│   ├── tls-*.pem        # container TLS certs (mkcert)
│   └── rootCA.pem       # mkcert root CA (so Python trusts the SP)
├── Dockerfile
└── docker-compose.yml
```

> **Note:** the certificates under `certs/` and `docker/` are throwaway
> test/localhost keys (self-signed SP cert + mkcert dev certs). They are **not**
> production secrets and must never be reused outside this test harness.

## Running with Docker (recommended)

The image builds the SP, installs `spid_sp_test` via `uv`, starts the SP, and
runs the conformance suite against it. The build context is the project root
directory; `uppsala` and `bergshamra` are pulled from crates.io, so no sibling
source trees are required.

Run these from the **project root directory**:

```sh
# Build
docker build -f spid-sp-test/Dockerfile -t spid-sp-test .

# Run the default suite (metadata + AuthnRequest + response tests)
docker run --rm spid-sp-test
```

Or via compose:

```sh
docker compose -f spid-sp-test/docker-compose.yml up --build
```

The container exits with `spid_sp_test`'s exit code, so it can gate CI.

### Passing custom test arguments

Any arguments after the image name are forwarded to `spid_sp_test`, overriding
the default suite:

```sh
docker run --rm spid-sp-test \
    --metadata-url https://localhost:8080/metadata \
    --authn-url    https://localhost:8080/login \
    --extra -pr spid-sp-public -tr -d INFO
```

### Configuration (environment variables)

| Variable             | Default                  | Purpose                                  |
|----------------------|--------------------------|------------------------------------------|
| `SP_HOST`            | `localhost`              | Host the SP advertises                   |
| `SP_PORT`            | `8080`                   | Port the SP listens on (HTTPS)           |
| `IDP_BASE_URL`       | `https://localhost:8443` | IdP base URL                             |
| `IDP_ENTITY_ID`      | `https://localhost:8443` | IdP entity ID                            |
| `CERT_DIR`           | `/app/certs` (`spid-sp-test/certs` locally) | Directory holding certs |
| `RUST_LOG`           | `info`                   | Log filter                               |
| `REQUESTS_CA_BUNDLE` | `/app/certs/rootCA.pem`  | Lets Python trust the SP's mkcert TLS    |

## Running locally (without Docker)

You need the Python `spid_sp_test` tool and the certs in place. Run the SP from
the **project root directory** so the default `CERT_DIR=spid-sp-test/certs`
resolves:

```sh
# 1. Start the SP (HTTPS on :8080)
cargo run --release -p spid-sp-test

# 2. In another shell, run the conformance tool
uv tool run spid_sp_test \
    --metadata-url https://localhost:8080/metadata \
    --authn-url    https://localhost:8080/login \
    --extra -pr spid-sp-public -tr -d INFO
```

A quick smoke check without the Python tool:

```sh
curl -sk https://localhost:8080/metadata | head
```

## Optional: browser-based validator

The commented-out `idp` service in `docker-compose.yml` runs
[`italia/spid-saml-check`](https://github.com/italia/spid-saml-check), a
browser UI validator on `https://localhost:8443`. Uncomment it to drive the SP
interactively instead of via the CLI.
