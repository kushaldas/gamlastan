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
