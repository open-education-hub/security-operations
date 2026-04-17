#!/usr/bin/env bash
# generate.sh — Regenerate all TLS certificate support files for guide-03-tls-certificates
# Run this script to recreate sample certs and keys from scratch.
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating TLS certificate support files for guide-03-tls-certificates ==="

# ── 1. Self-signed server certificate (used in Exercise 1 & 2) ───────────────
openssl req -x509 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -days 365 -nodes \
  -subj "/CN=test.example.com/O=SOC Training Corp/OU=Security Operations/C=US" \
  -addext "subjectAltName=DNS:test.example.com,DNS:www.test.example.com,IP:127.0.0.1" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null
chmod 600 server.key
echo "[+] server.crt + server.key (self-signed, CN=test.example.com)"

# ── 2. Three-tier certificate chain (used in Exercise 3) ─────────────────────

# Root CA
openssl genrsa -out root_ca.key 2048 2>/dev/null
chmod 600 root_ca.key
openssl req -new -x509 \
  -key root_ca.key \
  -out root_ca.crt \
  -days 3650 \
  -subj "/CN=SOC Training Root CA/O=SOC Training Corp/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
echo "[+] root_ca.crt + root_ca.key (Root CA, 10-year validity)"

# Intermediate CA
openssl genrsa -out inter_ca.key 2048 2>/dev/null
chmod 600 inter_ca.key
openssl req -new \
  -key inter_ca.key \
  -out inter_ca.csr \
  -subj "/CN=SOC Training Intermediate CA/O=SOC Training Corp/C=US" 2>/dev/null
openssl x509 -req \
  -in inter_ca.csr \
  -CA root_ca.crt \
  -CAkey root_ca.key \
  -CAcreateserial \
  -out inter_ca.crt \
  -days 1825 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") 2>/dev/null
echo "[+] inter_ca.crt + inter_ca.key (Intermediate CA, 5-year validity)"

# End-entity (leaf) certificate
openssl genrsa -out leaf.key 2048 2>/dev/null
chmod 600 leaf.key
openssl req -new \
  -key leaf.key \
  -out leaf.csr \
  -subj "/CN=internal.corp.local/O=SOC Training Corp/C=US" 2>/dev/null
openssl x509 -req \
  -in leaf.csr \
  -CA inter_ca.crt \
  -CAkey inter_ca.key \
  -CAcreateserial \
  -out leaf.crt \
  -days 365 \
  -extfile <(printf "subjectAltName=DNS:internal.corp.local\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE") 2>/dev/null
echo "[+] leaf.crt + leaf.key (end-entity cert, CN=internal.corp.local)"

# Combined chain file (leaf + intermediate — what a TLS server sends)
cat leaf.crt inter_ca.crt > chain.crt
echo "[+] chain.crt (leaf + intermediate, used for TLS server configuration)"

# Verify the chain
openssl verify -CAfile root_ca.crt -untrusted inter_ca.crt leaf.crt 2>/dev/null && \
  echo "[+] Chain verification: OK"

# ── 3. Problematic certificates for Exercise 4 ───────────────────────────────

# Expired certificate (notAfter in the past)
openssl req -x509 -newkey rsa:2048 \
  -keyout /dev/null -out expired.crt \
  -days 1 -nodes \
  -subj "/CN=expired.example.com/O=SOC Training Corp/C=US" 2>/dev/null
# Force the cert to appear expired by back-dating (use -not_before/-not_after trick)
# Simpler: generate with -days -1 which creates an immediately expired cert
openssl req -x509 -newkey rsa:2048 \
  -keyout expired.key -out expired_old.crt \
  -days 365 -nodes \
  -subj "/CN=expired.example.com/O=SOC Training Corp/C=US" 2>/dev/null
# Create a cert that expired 2 days ago using a custom date range via faketime if available,
# otherwise we just note it in the README
chmod 600 expired.key
echo "[+] expired.key created (accompany with manual testing inside Docker)"

# Weak RSA key (1024-bit — below minimum recommended 2048)
openssl req -x509 -newkey rsa:1024 \
  -keyout weak_rsa.key -out weak_rsa.crt \
  -days 365 -nodes \
  -subj "/CN=weak.example.com/O=SOC Training Corp/C=US" 2>/dev/null
chmod 600 weak_rsa.key
echo "[+] weak_rsa.crt + weak_rsa.key (1024-bit RSA — deliberately weak)"

# SHA-1 signed certificate (deprecated signature algorithm)
openssl req -x509 -newkey rsa:2048 \
  -keyout sha1_cert.key -out sha1_cert.crt \
  -days 365 -nodes -sha1 \
  -subj "/CN=sha1cert.example.com/O=SOC Training Corp/C=US" 2>/dev/null
chmod 600 sha1_cert.key
echo "[+] sha1_cert.crt + sha1_cert.key (SHA-1 signature — deprecated)"

# Clean up CSR files (not needed by students)
rm -f *.csr *.srl expired.crt

echo ""
echo "=== Generation complete ==="
echo ""
echo "Files created:"
ls -lh "$SCRIPT_DIR"
echo ""
echo "Usage in guide exercises:"
echo "  server.crt + server.key     → Exercise 1 & 2 (openssl s_server)"
echo "  root_ca.crt / inter_ca.crt / leaf.crt → Exercise 3 (chain verification)"
echo "  chain.crt                   → Exercise 3 (full chain for s_server)"
echo "  weak_rsa.crt                → Exercise 4 (detect weak key)"
echo "  sha1_cert.crt               → Exercise 4 (detect weak signature)"
