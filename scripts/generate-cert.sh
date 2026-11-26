#!/usr/bin/env bash
# Generates the self-signed localhost certificate used by the tokio-boring tests.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd -- "${script_dir}/.." && pwd)"
certificate="${workspace_root}/tokio-boring/tests/cert.pem"
private_key="${workspace_root}/tokio-boring/tests/key.pem"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Required command not found: openssl" >&2
  exit 1
fi

# Keep the checked-in key stable when renewing the certificate. If the fixture
# is absent, create a replacement test key that subsequent runs will reuse.
if [[ ! -f "${private_key}" ]]; then
  openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${private_key}"
  chmod 0644 "${private_key}"
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/boring-test-certificate.XXXXXX")"
trap 'rm -rf "${temporary_dir}"' EXIT
touch "${temporary_dir}/index.txt"
printf '1000\n' >"${temporary_dir}/serial"

cat >"${temporary_dir}/openssl.cnf" <<EOF
[ ca ]
default_ca = test_ca

[ test_ca ]
database = ${temporary_dir}/index.txt
new_certs_dir = ${temporary_dir}
serial = ${temporary_dir}/serial
default_md = sha256
policy = test_policy
x509_extensions = test_extensions
unique_subject = no

[ test_policy ]
countryName = supplied
stateOrProvinceName = supplied
organizationName = supplied
commonName = supplied

[ test_extensions ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = CA:true
subjectAltName = DNS:localhost
EOF

openssl req -new \
  -key "${private_key}" \
  -out "${temporary_dir}/request.pem" \
  -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost"

# Fixed validity and serial values make renewal reproducible. RSA PKCS#1 v1.5
# signatures are deterministic, so an unchanged key produces an unchanged PEM.
openssl ca -selfsign -batch -notext -quiet \
  -config "${temporary_dir}/openssl.cnf" \
  -keyfile "${private_key}" \
  -in "${temporary_dir}/request.pem" \
  -out "${certificate}" \
  -startdate 20261126000000Z \
  -enddate 20361123000000Z
chmod 0644 "${certificate}"
