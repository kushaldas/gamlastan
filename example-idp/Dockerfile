# Build context: the project root directory (uppsala and bergshamra come from crates.io)
#
# Run these from the project root directory:
#
# Build:
#   docker build -f example-idp/Dockerfile -t example-idp .
#
# Or via docker compose (from the example-idp directory):
#   docker compose up --build

##### Build stage: compile the Rust IdP binary
FROM debian:13 AS build
RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH=/root/.cargo/bin:$PATH

# Copy the workspace (uppsala + bergshamra are pulled from crates.io).
# All workspace member manifests must be present for cargo to resolve.
COPY Cargo.toml Cargo.lock /src/saml/
COPY crates/ /src/saml/crates/
COPY spid-sp-test/ /src/saml/spid-sp-test/
COPY example-idp/ /src/saml/example-idp/

# Build only the example-idp binary in release mode
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/saml/target \
    cd /src/saml && cargo build --release -p example-idp \
    && cp /src/saml/target/release/example-idp /example-idp

##### Runtime image: IdP binary + certs
FROM debian:13-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built IdP binary
COPY --from=build /example-idp /app/example-idp

# Copy SAML signing + TLS certs
COPY example-idp/certs/ /app/certs/

WORKDIR /app

ENV RUST_LOG=info
ENV CERT_DIR=/app/certs
ENV IDP_HOST=localhost
ENV IDP_PORT=9443
# The IdP validates incoming AuthnRequests against trusted SP metadata.
# Mount a local directory (e.g. ./sp_metadata) at /app/sp_metadata; every
# *.xml file inside it is loaded as one trusted SP, so the IdP can serve
# multiple Service Providers:
#   docker run -v ./sp_metadata:/app/sp_metadata:ro example-idp
ENV SP_METADATA_PATH=/app/sp_metadata

EXPOSE 9443

CMD ["/app/example-idp"]
