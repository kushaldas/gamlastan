# gamlastan - SAML 2.0 library for Rust


# Default recipe: build and test
default:
    @just --list

# Build all workspace crates
build:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Run tests with output
test-verbose:
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
test-gamlastan:
    cargo test -p gamlastan

# Run gamlastan-actix tests
test-actix:
    cargo test -p gamlastan-actix

# Run tests matching a pattern
test-filter PATTERN:
    cargo test --workspace -- {{PATTERN}}

# Check compilation without producing binaries (faster)
check-compile:
    cargo check --workspace --all-targets
