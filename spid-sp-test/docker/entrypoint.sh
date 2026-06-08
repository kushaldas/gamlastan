#!/bin/bash
set -e

echo "=== SPID SP Test Container ==="
echo "REQUESTS_CA_BUNDLE=${REQUESTS_CA_BUNDLE}"
echo "CERT_DIR=${CERT_DIR}"

# Default env vars (can be overridden via docker-compose or docker run)
: "${SP_HOST:=localhost}"
: "${SP_PORT:=8080}"
: "${IDP_BASE_URL:=https://localhost:8443}"
: "${IDP_ENTITY_ID:=https://localhost:8443}"

export SP_HOST SP_PORT IDP_BASE_URL IDP_ENTITY_ID

echo "SP will listen on https://${SP_HOST}:${SP_PORT}"
echo "IdP base URL: ${IDP_BASE_URL}"
echo "IdP entity ID: ${IDP_ENTITY_ID}"

# Start the SP in the background
echo "Starting SP..."
/app/spid-sp-test &
SP_PID=$!

# Wait for SP to be ready (up to 30 seconds)
echo "Waiting for SP to start..."
for i in $(seq 1 30); do
    if curl -sk "https://${SP_HOST}:${SP_PORT}/metadata" > /dev/null 2>&1; then
        echo "SP is ready!"
        break
    fi
    if ! kill -0 $SP_PID 2>/dev/null; then
        echo "ERROR: SP process died"
        exit 1
    fi
    sleep 1
done

# Verify SP is actually responding
if ! curl -sk "https://${SP_HOST}:${SP_PORT}/metadata" > /dev/null 2>&1; then
    echo "ERROR: SP did not become ready within 30 seconds"
    exit 1
fi

SP_URL="https://${SP_HOST}:${SP_PORT}"

# Run spid_sp_test with provided arguments, or the default full test suite
if [ $# -gt 0 ]; then
    echo "Running: spid_sp_test $@"
    spid_sp_test "$@"
    EXIT_CODE=$?
else
    echo "=== Running SPID SP tests (metadata + authn request + response) ==="
    echo "Metadata URL: ${SP_URL}/metadata"
    echo "AuthnRequest URL: ${SP_URL}/login"
    echo ""

    spid_sp_test \
        --metadata-url "${SP_URL}/metadata" \
        --authn-url "${SP_URL}/login" \
        --extra \
        -pr spid-sp-public \
        -tr \
        -d INFO
    EXIT_CODE=$?
fi

echo ""
echo "=== Tests complete (exit code: ${EXIT_CODE}) ==="

# Keep the SP alive briefly so logs can be captured
kill $SP_PID 2>/dev/null || true
exit $EXIT_CODE
