# Build context: the project root directory (uppsala and bergshamra come from crates.io)
#
# Run these from the project root directory:
#
# Build:
#   docker build -f spid-sp-test/Dockerfile -t spid-sp-test .
#
# Or via docker compose:
#   docker compose -f spid-sp-test/docker-compose.yml up --build

##### Build stage: compile the Rust SP binary
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

# Build only the spid-sp-test binary in release mode
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/saml/target \
    cd /src/saml && cargo build --release -p spid-sp-test \
    && cp /src/saml/target/release/spid-sp-test /spid-sp-test

##### Production image: SP binary + spid_sp_test Python tool
FROM debian:13-slim

RUN apt-get update && apt-get install -y \
    xmlsec1 ca-certificates curl python3 python3-venv \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install uv for Python package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH=/root/.local/bin:$PATH

# Create venv and install spid_sp_test
RUN uv venv /opt/spid-venv && \
    uv pip install --python /opt/spid-venv/bin/python spid_sp_test
ENV PATH=/opt/spid-venv/bin:$PATH

# Copy the built SP binary
COPY --from=build /spid-sp-test /app/spid-sp-test

# Copy SAML signing certs
COPY spid-sp-test/certs/sp-key.pem /app/certs/sp-key.pem
COPY spid-sp-test/certs/sp-cert.pem /app/certs/sp-cert.pem
COPY spid-sp-test/certs/idp-cert.pem /app/certs/idp-cert.pem

# Copy TLS certs (localhost) + mkcert root CA
COPY spid-sp-test/docker/tls-cert.pem /app/certs/tls-cert.pem
COPY spid-sp-test/docker/tls-key.pem /app/certs/tls-key.pem
COPY spid-sp-test/docker/rootCA.pem /app/certs/rootCA.pem

# Copy entrypoint
COPY spid-sp-test/docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /app

# Default environment
ENV RUST_LOG=info
ENV CERT_DIR=/app/certs
# This makes Python 'requests' trust our mkcert TLS certs
ENV REQUESTS_CA_BUNDLE=/app/certs/rootCA.pem

ENTRYPOINT ["/app/entrypoint.sh"]
