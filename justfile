# gamlastan - SAML 2.0 library for Rust


# Default recipe: build and test
default:
    @just --list

# Build all workspace crates
build:
    cargo build --workspace

# Ensure the eduGAIN metadata fixture exists for tests that parse real metadata.
_ensure-edugain:
    @if [ ! -f edugain-v2.xml ]; then \
        echo 'Downloading edugain-v2.xml...'; \
        if command -v curl >/dev/null 2>&1; then \
            curl -fsSL --output edugain-v2.xml https://mds.edugain.org/edugain-v2.xml; \
        elif command -v wget >/dev/null 2>&1; then \
            wget -qO edugain-v2.xml https://mds.edugain.org/edugain-v2.xml; \
        else \
            echo 'Neither curl nor wget is available to download edugain-v2.xml.' >&2; \
            exit 1; \
        fi; \
    fi

# Run all tests
test: _ensure-edugain
    cargo test --workspace

# Run tests with output
test-verbose: _ensure-edugain
    cargo test --workspace -- --nocapture

# Run clippy with all targets
clippy:
    cargo clippy --all-targets -- -D warnings

# Format all code
fmt:
    cargo fmt --all

# Check formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Full check: fmt, clippy, test
check: fmt-check clippy test

# Build documentation
doc:
    cargo doc --workspace --no-deps

# Open documentation in browser
doc-open:
    cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
    cargo clean

# Run gamlastan library tests
test-gamlastan: _ensure-edugain
    cargo test -p gamlastan

# Run gamlastan-actix tests
test-actix:
    cargo test -p gamlastan-actix

# Run gamlastan-mdq tests
test-mdq: _ensure-edugain
    cargo test -p gamlastan-mdq

# Run tests matching a pattern
test-filter PATTERN: _ensure-edugain
    cargo test --workspace -- {{PATTERN}}

# Check compilation without producing binaries (faster)
check-compile:
    cargo check --workspace --all-targets

# Install the system packages needed by `just test-hsm` (Debian/Ubuntu).
# SoftHSM2 provides the PKCS#11 token, OpenSC provides pkcs11-tool, and
# OpenSSL mints the key pair + self-signed cert that gets imported.
install-hsm-deps:
    sudo apt-get update
    sudo apt-get install -y softhsm2 opensc openssl

# Provision a throwaway SoftHSM2 token and run the HSM (PKCS#11) signing test.
#
# Everything lives in a temp dir wiped on exit: a private SOFTHSM2_CONF, the
# token, an RSA key pair imported under the label the test looks for, and the
# matching self-signed certificate. The private key is generated in software
# and imported (standard SoftHSM test provisioning); the signing operation
# under test runs entirely on the token. Run `just install-hsm-deps` first.
test-hsm:
    #!/usr/bin/env bash
    set -euo pipefail
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    export SOFTHSM2_CONF="$WORK/softhsm2.conf"
    mkdir -p "$WORK/tokens"
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > "$SOFTHSM2_CONF"
    MODULE="$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so 2>/dev/null | head -n1 || true)"
    [ -n "$MODULE" ] || { echo 'libsofthsm2.so not found — run `just install-hsm-deps`' >&2; exit 1; }
    echo "Using PKCS#11 module: $MODULE"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
        -days 365 -subj '/CN=gamlastan-hsm-test' >/dev/null 2>&1
    openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -out "$WORK/key.p8.pem"
    softhsm2-util --init-token --free --label saml --so-pin 0000 --pin 1234 >/dev/null
    softhsm2-util --import "$WORK/key.p8.pem" --token saml \
        --label saml-signing-key --id a1b2 --pin 1234 >/dev/null
    GAMLASTAN_PKCS11_MODULE="$MODULE" \
    GAMLASTAN_PKCS11_PIN=1234 \
    GAMLASTAN_PKCS11_LABEL=saml-signing-key \
    GAMLASTAN_PKCS11_CERT="$WORK/cert.pem" \
        cargo test -p gamlastan --test hsm_signing -- --ignored --nocapture
