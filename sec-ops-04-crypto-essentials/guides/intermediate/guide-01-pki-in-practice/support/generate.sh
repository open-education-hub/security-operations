#!/usr/bin/env bash
# generate.sh — Regenerate all PKI support files for guide-01-pki-in-practice
#
# This script pre-builds the complete 3-tier PKI so instructors can:
#   a) Distribute a ready-to-use PKI to students who want to skip the build steps
#   b) Verify the expected output during live sessions
#   c) Reset the PKI to a known-good state
#
# Usage: bash generate.sh
# NOTE: Running inside Docker (ubuntu:22.04) is recommended to match the guide.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating PKI support files for guide-01-pki-in-practice ==="

# Clean any previous run
rm -rf pki
mkdir -p pki/{root-ca,intermediate-ca}/{certs,crl,newcerts,private,csr}
chmod 700 pki/root-ca/private pki/intermediate-ca/private

# Initialise database files
echo 1000 > pki/root-ca/serial
echo 1000 > pki/intermediate-ca/serial
touch pki/root-ca/index.txt
touch pki/intermediate-ca/index.txt
echo 1000 > pki/root-ca/crlnumber
echo 1000 > pki/intermediate-ca/crlnumber

echo "[+] PKI directory structure initialised"

# ── Root CA OpenSSL config ────────────────────────────────────────────────────
cat > pki/root-ca/openssl.cnf << 'CONFEOF'
[ca]
default_ca = CA_default

[CA_default]
dir               = REPLACE_WITH_ABSOLUTE_PATH/root-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/root-ca.key.pem
certificate       = $dir/certs/root-ca.crt.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/root-ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 365
default_md        = sha256
preserve          = no
policy            = policy_strict
default_days      = 3650

[policy_strict]
countryName            = match
stateOrProvinceName    = optional
organizationName       = match
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[req]
default_bits       = 4096
distinguished_name = req_distinguished_name
string_mask        = utf8only
default_md         = sha256
x509_extensions    = v3_ca

[req_distinguished_name]
countryName                    = Country Name (2 letter code)
countryName_default            = US
organizationName               = Organization Name
organizationName_default       = SOC Training PKI
commonName                     = Common Name

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true
keyUsage               = critical,digitalSignature,keyCertSign,cRLSign

[v3_intermediate_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,digitalSignature,keyCertSign,cRLSign

[crl_ext]
authorityKeyIdentifier = keyid:always

[usr_cert]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical,digitalSignature,nonRepudiation,keyEncipherment
extendedKeyUsage       = clientAuth,emailProtection

[server_cert]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
CONFEOF

# ── Intermediate CA OpenSSL config ───────────────────────────────────────────
cat > pki/intermediate-ca/openssl.cnf << 'CONFEOF'
[ca]
default_ca = CA_default

[CA_default]
dir               = REPLACE_WITH_ABSOLUTE_PATH/intermediate-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/intermediate-ca.key.pem
certificate       = $dir/certs/intermediate-ca.crt.pem
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate-ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_loose
default_days      = 375

[policy_loose]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
string_mask        = utf8only
default_md         = sha256

[req_distinguished_name]
countryName                    = Country Name
countryName_default            = US
organizationName               = Organization Name
organizationName_default       = SOC Training Corp
commonName                     = Common Name

[server_cert]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth

[client_cert]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical,digitalSignature,nonRepudiation
extendedKeyUsage       = clientAuth

[crl_ext]
authorityKeyIdentifier = keyid:always
CONFEOF

# Patch config files with the actual absolute path to the PKI directory
PKI_ABS="$SCRIPT_DIR/pki"
sed -i "s|REPLACE_WITH_ABSOLUTE_PATH|$PKI_ABS|g" \
  pki/root-ca/openssl.cnf \
  pki/intermediate-ca/openssl.cnf

echo "[+] OpenSSL configuration files created and path-patched"

# ── Root CA key and self-signed certificate ───────────────────────────────────
openssl genrsa -out pki/root-ca/private/root-ca.key.pem 4096 2>/dev/null
chmod 400 pki/root-ca/private/root-ca.key.pem

openssl req -config pki/root-ca/openssl.cnf \
  -key pki/root-ca/private/root-ca.key.pem \
  -new -x509 -days 7300 \
  -extensions v3_ca \
  -out pki/root-ca/certs/root-ca.crt.pem \
  -subj "/C=US/O=SOC Training PKI/CN=SOC Training Root CA" 2>/dev/null
chmod 444 pki/root-ca/certs/root-ca.crt.pem
echo "[+] Root CA certificate created (4096-bit RSA, 20-year validity)"

# ── Intermediate CA ───────────────────────────────────────────────────────────
openssl genrsa -out pki/intermediate-ca/private/intermediate-ca.key.pem 2048 2>/dev/null
chmod 400 pki/intermediate-ca/private/intermediate-ca.key.pem

openssl req -config pki/root-ca/openssl.cnf \
  -key pki/intermediate-ca/private/intermediate-ca.key.pem \
  -new -sha256 \
  -out pki/intermediate-ca/csr/intermediate-ca.csr.pem \
  -subj "/C=US/O=SOC Training PKI/CN=SOC Training Intermediate CA" 2>/dev/null

openssl ca -config pki/root-ca/openssl.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 \
  -notext -md sha256 \
  -in pki/intermediate-ca/csr/intermediate-ca.csr.pem \
  -out pki/intermediate-ca/certs/intermediate-ca.crt.pem \
  -batch 2>/dev/null
chmod 444 pki/intermediate-ca/certs/intermediate-ca.crt.pem

openssl verify -CAfile pki/root-ca/certs/root-ca.crt.pem \
  pki/intermediate-ca/certs/intermediate-ca.crt.pem 2>/dev/null && \
  echo "[+] Intermediate CA created and verified against Root CA"

# Create the CA chain bundle
cat pki/intermediate-ca/certs/intermediate-ca.crt.pem \
    pki/root-ca/certs/root-ca.crt.pem \
    > pki/intermediate-ca/certs/ca-chain.crt.pem
echo "[+] CA chain bundle created (intermediate + root)"

# ── Server certificate (api.internal.corp) ────────────────────────────────────
openssl genrsa -out pki/intermediate-ca/private/api-server.key.pem 2048 2>/dev/null
chmod 400 pki/intermediate-ca/private/api-server.key.pem

openssl req -new -sha256 \
  -key pki/intermediate-ca/private/api-server.key.pem \
  -out pki/intermediate-ca/csr/api-server.csr.pem \
  -subj "/C=US/O=SOC Training Corp/CN=api.internal.corp" 2>/dev/null

openssl ca -config pki/intermediate-ca/openssl.cnf \
  -extensions server_cert \
  -days 375 \
  -notext -md sha256 \
  -in pki/intermediate-ca/csr/api-server.csr.pem \
  -out pki/intermediate-ca/certs/api-server.crt.pem \
  -batch 2>/dev/null
echo "[+] Server certificate issued for api.internal.corp"

# ── Client certificates (alice and bob) ──────────────────────────────────────
for analyst in alice bob; do
  openssl genrsa -out "pki/intermediate-ca/private/$analyst.key.pem" 2048 2>/dev/null
  chmod 400 "pki/intermediate-ca/private/$analyst.key.pem"

  openssl req -new -sha256 \
    -key "pki/intermediate-ca/private/$analyst.key.pem" \
    -out "pki/intermediate-ca/csr/$analyst.csr.pem" \
    -subj "/C=US/O=SOC Training Corp/OU=SOC Analysts/CN=$analyst@corp.local" 2>/dev/null

  openssl ca -config pki/intermediate-ca/openssl.cnf \
    -extensions client_cert \
    -days 365 -notext -md sha256 \
    -in "pki/intermediate-ca/csr/$analyst.csr.pem" \
    -out "pki/intermediate-ca/certs/$analyst.crt.pem" \
    -batch 2>/dev/null
  echo "[+] Client certificate issued for $analyst"
done

# Create PKCS#12 bundle for alice
openssl pkcs12 -export \
  -inkey pki/intermediate-ca/private/alice.key.pem \
  -in pki/intermediate-ca/certs/alice.crt.pem \
  -certfile pki/intermediate-ca/certs/ca-chain.crt.pem \
  -out pki/alice.p12 \
  -passout pass:alice_password 2>/dev/null
echo "[+] PKCS#12 bundle created for alice (password: alice_password)"

# ── Certificate Revocation: revoke bob ───────────────────────────────────────
openssl ca -config pki/intermediate-ca/openssl.cnf \
  -revoke pki/intermediate-ca/certs/bob.crt.pem \
  -crl_reason keyCompromise \
  -batch 2>/dev/null
echo "[+] Bob's certificate revoked (keyCompromise)"

openssl ca -config pki/intermediate-ca/openssl.cnf \
  -gencrl \
  -out pki/intermediate-ca/crl/intermediate-ca.crl.pem 2>/dev/null
echo "[+] CRL generated"

echo ""
echo "=== Generation complete ==="
echo ""
echo "PKI structure:"
find pki -type f | sort
echo ""
echo "Notes:"
echo "  Config files use absolute paths — re-run generate.sh if you move the directory."
echo "  Alice PKCS#12 import password: alice_password"
echo "  Bob's certificate is revoked (to demonstrate CRL in Part 7)."
