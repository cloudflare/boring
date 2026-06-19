#!/usr/bin/env bash
# Generates the certificates used by `boring/src/ssl/test/verify.rs` for the
# `rsa_key_usage_mismatch` test.
#
# The resulting leaf certificate has an RSA key and a keyUsage extension that
# only asserts keyEncipherment (no digitalSignature). When BoringSSL enforces
# RSA keyUsage, an ECDHE-RSA cipher suite therefore fails with
# KEY_USAGE_BIT_INCORRECT. When enforcement is relaxed, the handshake succeeds.
set -euo pipefail

cd "$(dirname "$0")"
NAME=rsa-key-usage-relaxed

# CA key and self-signed certificate. The CA key is deleted at the end; only
# the CA certificate is needed by the test.
openssl genrsa -out "${NAME}-ca-key.pem" 2048
openssl req -new -x509 \
    -key "${NAME}-ca-key.pem" \
    -out "${NAME}-ca.pem" \
    -days 3650 \
    -subj "/CN=Relax RSA Key Usage Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# Leaf key and certificate request.
openssl genrsa -out "${NAME}-key.pem" 2048
openssl req -new \
    -key "${NAME}-key.pem" \
    -out "${NAME}.csr" \
    -subj "/CN=localhost"

# Leaf certificate with keyUsage=keyEncipherment only. The missing
# digitalSignature bit is what triggers the RSA keyUsage check failure.
openssl x509 -req \
    -in "${NAME}.csr" \
    -CA "${NAME}-ca.pem" \
    -CAkey "${NAME}-ca-key.pem" \
    -CAcreateserial \
    -out "${NAME}.pem" \
    -days 365 \
    -extfile <(printf '%s\n' \
        'keyUsage=critical,keyEncipherment' \
        'extendedKeyUsage=serverAuth' \
        'subjectAltName=DNS:localhost')

rm -f "${NAME}.csr" "${NAME}.srl" "${NAME}-ca-key.pem"
