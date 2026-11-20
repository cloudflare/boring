#!/usr/bin/env bash
# Generates the certificates used by `boring/src/x509/tests/path_len.rs`.
#
# The chain models a CA key rollover, where Int2 re-keys itself by issuing a
# self-issued (same subject and issuer name, different key) certificate:
#
#   Root
#    └─ Int2      (old key, pathlen 1 or 0)
#        └─ Rollover  (Int2 name, new key, signed by old key, pathlen 1 or 0)
#            └─ Int1
#                └─ Leaf
#
# RFC 5280 says self-issued intermediates do not count towards the path length,
# but their own pathLenConstraint still applies. BoringSSL only enforces the
# latter since ed00cfde0.
#
# The *-pathlen0 variants are reissued from the same key and name as their
# pathlen 1 counterparts, so the rest of the chain is shared.
#
# CA keys are committed so the chain can be reissued (e.g. to extend validity)
# without changing key identifiers. Missing keys are generated. The leaf key is
# discarded.
set -euo pipefail

cd "$(dirname "$0")"
NAME=path-len-rollover
DAYS=7300

ROOT_SUBJ="/CN=Path Len Rollover Test Root"
INT2_SUBJ="/CN=Path Len Rollover Test Int2"
INT1_SUBJ="/CN=Path Len Rollover Test Int1"
LEAF_SUBJ="/CN=localhost"

for key in root int2 int2-new int1; do
    if [[ ! -f "${NAME}-${key}.key" ]]; then
        openssl genrsa -traditional -out "${NAME}-${key}.key" 2048
    fi
done
openssl genrsa -out "${NAME}-leaf-key.pem" 2048

# issue OUT KEY SUBJECT CA_CERT CA_KEY EXTENSION...
issue() {
    local out=$1 key=$2 subj=$3 ca_cert=$4 ca_key=$5
    shift 5
    openssl req -new -key "${key}" -subj "${subj}" -out "${NAME}.csr"
    openssl x509 -req \
        -in "${NAME}.csr" \
        -CA "${ca_cert}" \
        -CAkey "${ca_key}" \
        -CAserial "${NAME}.srl" \
        -CAcreateserial \
        -out "${out}" \
        -days "${DAYS}" \
        -extfile <(printf '%s\n' "$@" \
            'subjectKeyIdentifier=hash' \
            'authorityKeyIdentifier=keyid:always')
}

CA_KEY_USAGE='keyUsage=critical,keyCertSign,cRLSign'

# Self-signed root.
openssl req -new -x509 \
    -key "${NAME}-root.key" \
    -out "${NAME}-root.pem" \
    -days "${DAYS}" \
    -subj "${ROOT_SUBJ}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "${CA_KEY_USAGE}" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always"

# Int2 with its old key, issued by Root.
for pathlen in 1 0; do
    suffix=$([[ ${pathlen} == 0 ]] && echo "-pathlen0" || true)
    issue "${NAME}-int2${suffix}.pem" "${NAME}-int2.key" "${INT2_SUBJ}" \
        "${NAME}-root.pem" "${NAME}-root.key" \
        "basicConstraints=critical,CA:TRUE,pathlen:${pathlen}" "${CA_KEY_USAGE}"
done

# Rollover: Int2's name and new key, signed by Int2's old key.
for pathlen in 1 0; do
    suffix=$([[ ${pathlen} == 0 ]] && echo "-pathlen0" || true)
    issue "${NAME}-rollover${suffix}.pem" "${NAME}-int2-new.key" "${INT2_SUBJ}" \
        "${NAME}-int2.pem" "${NAME}-int2.key" \
        "basicConstraints=critical,CA:TRUE,pathlen:${pathlen}" "${CA_KEY_USAGE}"
done

# Int1, issued by Int2's new key (i.e. by Rollover).
issue "${NAME}-int1.pem" "${NAME}-int1.key" "${INT1_SUBJ}" \
    "${NAME}-rollover.pem" "${NAME}-int2-new.key" \
    "basicConstraints=critical,CA:TRUE" "${CA_KEY_USAGE}"

# Leaf, issued by Int1.
issue "${NAME}-leaf.pem" "${NAME}-leaf-key.pem" "${LEAF_SUBJ}" \
    "${NAME}-int1.pem" "${NAME}-int1.key" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:localhost"

rm -f "${NAME}.csr" "${NAME}.srl" "${NAME}-leaf-key.pem"
