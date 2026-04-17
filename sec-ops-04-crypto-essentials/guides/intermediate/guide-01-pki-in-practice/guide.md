# Guide 01 (Intermediate): Setting Up a Basic PKI with OpenSSL

> **Level:** Intermediate
> **Time:** 60 minutes
> **Prerequisites:** Reading sections 7, 8; Basic guides completed
> **Tools:** Docker, OpenSSL

---

## Learning Objectives

* Build a complete 3-tier PKI from scratch: Root CA → Intermediate CA → End-entity certificates
* Understand the purpose of each tier in the hierarchy
* Issue client certificates for mutual TLS (mTLS)
* Implement certificate revocation (CRL)
* Understand how enterprise internal PKI works
* Connect the PKI concepts to SOC monitoring and incident response

---

## Background: Why a 3-Tier PKI?

```text
Root CA (offline, air-gapped)
  ├── kept in physical safe or HSM
  ├── only used to sign intermediate CA certs
  └── Intermediate CA 1 (operational)
        ├── used daily to sign end-entity certs
        ├── can be revoked and replaced without touching Root CA
        └── End-entity certificates (servers, users, devices)
```

**Why not use the Root CA directly?**

* If the root private key is compromised, the entire PKI must be rebuilt
* Keeping the root offline dramatically reduces attack surface
* Intermediate CAs can be purpose-specific (web servers, VPN clients, code signing)

---

## Setup

```console
docker run --rm -it --name pki-guide ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl ca-certificates python3 tree 2>/dev/null | tail -3
mkdir -p /pki && cd /pki
```

---

## Part 1: Initialize the PKI Directory Structure

```bash
# Create OpenSSL CA directory structure
mkdir -p {root-ca,intermediate-ca}/{certs,crl,newcerts,private,csr}
chmod 700 root-ca/private intermediate-ca/private

# Initialize serial number and index files
echo 1000 > root-ca/serial
echo 1000 > intermediate-ca/serial
touch root-ca/index.txt
touch intermediate-ca/index.txt
echo 1000 > root-ca/crlnumber
echo 1000 > intermediate-ca/crlnumber

echo "PKI directory structure:"
tree /pki 2>/dev/null || find /pki -type d | sort
```

---

## Part 2: Configure OpenSSL for Each CA

```bash
# Root CA configuration
cat > /pki/root-ca/openssl.cnf << 'EOF'
[ca]
default_ca = CA_default

[CA_default]
dir               = /pki/root-ca
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
EOF

echo "Root CA config created"
```

```bash
# Intermediate CA configuration (similar, slightly different policies)
cat > /pki/intermediate-ca/openssl.cnf << 'EOF'
[ca]
default_ca = CA_default

[CA_default]
dir               = /pki/intermediate-ca
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
EOF

echo "Intermediate CA config created"
```

---

## Part 3: Create the Root CA

```bash
echo "=== STEP 1: Creating Root CA ==="
echo "(In production, this would be done on an air-gapped machine)"

# Generate Root CA private key (4096-bit RSA — highest security)
openssl genrsa -out /pki/root-ca/private/root-ca.key.pem 4096 2>/dev/null
chmod 400 /pki/root-ca/private/root-ca.key.pem
echo "✓ Root CA private key generated (4096-bit RSA)"

# Create self-signed Root CA certificate
openssl req -config /pki/root-ca/openssl.cnf \
  -key /pki/root-ca/private/root-ca.key.pem \
  -new -x509 -days 7300 \
  -extensions v3_ca \
  -out /pki/root-ca/certs/root-ca.crt.pem \
  -subj "/C=US/O=SOC Training PKI/CN=SOC Training Root CA" 2>/dev/null

chmod 444 /pki/root-ca/certs/root-ca.crt.pem
echo "✓ Root CA certificate created (valid 20 years)"
echo ""

openssl x509 -noout -text -in /pki/root-ca/certs/root-ca.crt.pem | \
  grep -E "Subject:|Issuer:|Not Before|Not After|Basic Constraints|Key Usage" | \
  sed 's/^[[:space:]]*/  /'
```

---

## Part 4: Create the Intermediate CA

```bash
echo "=== STEP 2: Creating Intermediate CA ==="

# Generate Intermediate CA private key (2048-bit)
openssl genrsa -out /pki/intermediate-ca/private/intermediate-ca.key.pem 2048 2>/dev/null
chmod 400 /pki/intermediate-ca/private/intermediate-ca.key.pem
echo "✓ Intermediate CA key generated"

# Create CSR (Certificate Signing Request)
openssl req -config /pki/root-ca/openssl.cnf \
  -key /pki/intermediate-ca/private/intermediate-ca.key.pem \
  -new -sha256 \
  -out /pki/intermediate-ca/csr/intermediate-ca.csr.pem \
  -subj "/C=US/O=SOC Training PKI/CN=SOC Training Intermediate CA" 2>/dev/null
echo "✓ Intermediate CA CSR created"

# Root CA signs the Intermediate CA certificate
openssl ca -config /pki/root-ca/openssl.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 \
  -notext \
  -md sha256 \
  -in /pki/intermediate-ca/csr/intermediate-ca.csr.pem \
  -out /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
  -batch 2>/dev/null
chmod 444 /pki/intermediate-ca/certs/intermediate-ca.crt.pem
echo "✓ Intermediate CA certificate signed by Root CA"

# Verify intermediate cert was signed correctly
openssl verify -CAfile /pki/root-ca/certs/root-ca.crt.pem \
  /pki/intermediate-ca/certs/intermediate-ca.crt.pem && echo "✓ Intermediate CA chain verified"

# Create CA certificate chain file (Intermediate + Root)
cat /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
    /pki/root-ca/certs/root-ca.crt.pem > /pki/intermediate-ca/certs/ca-chain.crt.pem
echo "✓ CA chain file created"
```

---

## Part 5: Issue Server Certificates

```bash
echo "=== STEP 3: Issuing Server Certificates ==="

# Issue certificate for internal web server
SERVER_COMMON="api.internal.corp"

openssl genrsa -out /pki/intermediate-ca/private/api-server.key.pem 2048 2>/dev/null
chmod 400 /pki/intermediate-ca/private/api-server.key.pem

# Create CSR with SANs
openssl req -new -sha256 \
  -key /pki/intermediate-ca/private/api-server.key.pem \
  -out /pki/intermediate-ca/csr/api-server.csr.pem \
  -subj "/C=US/O=SOC Training Corp/CN=$SERVER_COMMON" \
  -addext "subjectAltName=DNS:api.internal.corp,DNS:api,IP:10.0.0.10" 2>/dev/null

# Intermediate CA signs the server certificate
openssl ca -config /pki/intermediate-ca/openssl.cnf \
  -extensions server_cert \
  -days 375 \
  -notext -md sha256 \
  -in /pki/intermediate-ca/csr/api-server.csr.pem \
  -out /pki/intermediate-ca/certs/api-server.crt.pem \
  -batch \
  -extfile <(echo -e "[ext]\nsubjectAltName=DNS:api.internal.corp,DNS:api,IP:10.0.0.10\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null

echo "✓ Server certificate issued for $SERVER_COMMON"
openssl x509 -noout -text -in /pki/intermediate-ca/certs/api-server.crt.pem | \
  grep -E "Subject:|SAN|Not Before|Not After" | sed 's/^[[:space:]]*/  /'

# Verify against full chain
openssl verify \
  -CAfile /pki/root-ca/certs/root-ca.crt.pem \
  -untrusted /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
  /pki/intermediate-ca/certs/api-server.crt.pem && echo "✓ Server cert chain verified"
```

---

## Part 6: Issue Client Certificates (for mTLS)

```bash
echo "=== STEP 4: Issuing Client Certificates (mTLS) ==="

# Issue certificate for analyst "alice"
for analyst in alice bob; do
  openssl genrsa -out /pki/intermediate-ca/private/$analyst.key.pem 2048 2>/dev/null

  openssl req -new -sha256 \
    -key /pki/intermediate-ca/private/$analyst.key.pem \
    -out /pki/intermediate-ca/csr/$analyst.csr.pem \
    -subj "/C=US/O=SOC Training Corp/OU=SOC Analysts/CN=$analyst@corp.local" 2>/dev/null

  openssl ca -config /pki/intermediate-ca/openssl.cnf \
    -extensions client_cert \
    -days 365 -notext -md sha256 \
    -in /pki/intermediate-ca/csr/$analyst.csr.pem \
    -out /pki/intermediate-ca/certs/$analyst.crt.pem \
    -batch 2>/dev/null

  echo "✓ Client certificate issued for $analyst"
done

# Create PKCS#12 bundle for analyst (contains cert + key for import into browser/OS)
openssl pkcs12 -export \
  -inkey /pki/intermediate-ca/private/alice.key.pem \
  -in /pki/intermediate-ca/certs/alice.crt.pem \
  -certfile /pki/intermediate-ca/certs/ca-chain.crt.pem \
  -out /pki/alice.p12 \
  -passout pass:alice_password 2>/dev/null

echo "✓ PKCS#12 bundle created for alice (alice.p12)"
echo "  Import this file into Windows, macOS, or Firefox for mTLS authentication"
```

---

## Part 7: Certificate Revocation

```bash
echo "=== STEP 5: Certificate Revocation ==="

# Scenario: Bob's laptop was compromised — revoke his certificate
echo "Scenario: Bob's private key was leaked in a breach"
echo "Revoking bob's certificate..."

openssl ca -config /pki/intermediate-ca/openssl.cnf \
  -revoke /pki/intermediate-ca/certs/bob.crt.pem \
  -crl_reason keyCompromise \
  -batch 2>/dev/null && echo "✓ Bob's certificate revoked"

# Generate CRL (Certificate Revocation List)
openssl ca -config /pki/intermediate-ca/openssl.cnf \
  -gencrl \
  -out /pki/intermediate-ca/crl/intermediate-ca.crl.pem 2>/dev/null

echo "✓ CRL generated"
echo ""
echo "CRL contents:"
openssl crl -in /pki/intermediate-ca/crl/intermediate-ca.crl.pem -text -noout | \
  grep -E "Last Update|Next Update|Serial Number|Reason"

# Verify bob's cert is revoked
echo ""
echo "Verifying bob's certificate against CRL:"
openssl verify \
  -CAfile /pki/root-ca/certs/root-ca.crt.pem \
  -untrusted /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
  -crl_check_all \
  -CRLfile /pki/intermediate-ca/crl/intermediate-ca.crl.pem \
  /pki/intermediate-ca/certs/bob.crt.pem 2>&1 || echo "✗ Bob's certificate is REVOKED"

# Verify alice's cert is still valid
echo ""
echo "Verifying alice's certificate (not revoked):"
openssl verify \
  -CAfile /pki/root-ca/certs/root-ca.crt.pem \
  -untrusted /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
  /pki/intermediate-ca/certs/alice.crt.pem && echo "✓ Alice's certificate is valid"
```

---

## Part 8: Inventory the PKI

```bash
echo "=== PKI Inventory ==="

echo ""
echo "Certificate Database (index.txt):"
echo "Format: Status | Expiry | Serial | Subject"
cat /pki/intermediate-ca/index.txt

echo ""
echo "Issued certificates:"
for cert in /pki/intermediate-ca/newcerts/*.pem; do
  if [ -f "$cert" ]; then
    SUBJECT=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null | sed 's/subject=//')
    EXPIRY=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | sed 's/notAfter=//')
    STATUS="VALID"
    openssl verify -CAfile /pki/root-ca/certs/root-ca.crt.pem \
      -untrusted /pki/intermediate-ca/certs/intermediate-ca.crt.pem \
      -crl_check_all \
      -CRLfile /pki/intermediate-ca/crl/intermediate-ca.crl.pem \
      "$cert" 2>/dev/null | grep -q "OK" || STATUS="REVOKED"
    echo "  [$STATUS] $SUBJECT | Expires: $EXPIRY"
  fi
done
```

---

## Part 9: Test mTLS with the PKI

```bash
echo "=== Testing Mutual TLS (mTLS) ==="

# Start server requiring client certificate authentication
openssl s_server \
  -cert /pki/intermediate-ca/certs/api-server.crt.pem \
  -key /pki/intermediate-ca/private/api-server.key.pem \
  -CAfile /pki/intermediate-ca/certs/ca-chain.crt.pem \
  -Verify 1 \
  -port 8443 -www -quiet 2>/dev/null &
SRVPID=$!
sleep 1

echo "Server started with client certificate requirement"
echo ""

# Connect as alice (valid certificate)
echo "Alice connecting with valid client cert:"
echo | openssl s_client \
  -connect localhost:8443 \
  -CAfile /pki/intermediate-ca/certs/ca-chain.crt.pem \
  -cert /pki/intermediate-ca/certs/alice.crt.pem \
  -key /pki/intermediate-ca/private/alice.key.pem \
  -servername api.internal.corp 2>&1 | grep -E "Verify|Cipher|Server certificate CN|peer certificate"

echo ""
echo "Connecting WITHOUT a client certificate:"
echo | openssl s_client \
  -connect localhost:8443 \
  -CAfile /pki/intermediate-ca/certs/ca-chain.crt.pem \
  -servername api.internal.corp 2>&1 | grep -E "Verify|alert|handshake failure" | head -5

kill $SRVPID 2>/dev/null || true
```

---

## Summary

```bash
echo "=== PKI Summary ==="
echo ""
echo "PKI tier structure:"
echo "  Root CA     → Signed intermediate CA cert"
echo "                4096-bit RSA, valid 20 years, kept offline"
echo "  Intermediate → Signed server and client certs"
echo "                2048-bit RSA, valid 10 years, used operationally"
echo "  End-entity  → Servers, users, devices"
echo "                2048-bit RSA, valid 1 year max"
echo ""
echo "Key management:"
echo "  Root CA private key: /pki/root-ca/private/ (protect with HSM in production)"
echo "  Intermediate CA key: /pki/intermediate-ca/private/"
echo "  Certificate database: /pki/intermediate-ca/index.txt"
echo "  CRL: /pki/intermediate-ca/crl/"
echo ""
echo "SOC operational relevance:"
echo "  - Internal PKI powers VPN, mTLS, 802.1X (network access control)"
echo "  - Certificate expiry monitoring → alert before certs expire (cert outages)"
echo "  - CRL/OCSP monitoring → detect revocation issues"
echo "  - Audit trail: who issued which cert, when, for what purpose"
```

---

## Self-Check Questions

1. Why is the Root CA kept offline while the Intermediate CA is used operationally?
1. A server's certificate expires tomorrow. What is the operational impact? What should you do?
1. An analyst's laptop is stolen with her client certificate on it. What immediate actions should you take?
1. What is `pathlen:0` in the `basicConstraints` extension and why does it matter?
1. Explain why having a 3-tier PKI provides better security than issuing all certificates from the root CA.
