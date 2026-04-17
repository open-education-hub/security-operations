# Guide 03: Examining TLS Certificates from Websites

> **Level:** Basic
> **Time:** 30 minutes
> **Prerequisites:** Reading sections 7, 8, 9.1 (Certificates, PKI, TLS)
> **Tools:** Docker, OpenSSL s_client, tshark

---

## Learning Objectives

* Use `openssl s_client` to inspect TLS connections and certificates
* Read and interpret X.509 certificate fields
* Verify certificate chains manually
* Identify security issues in TLS configurations
* Practice the certificate analysis a SOC analyst performs

---

## Setup

```console
docker run --rm -it --name tls-guide ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl ca-certificates python3 2>/dev/null | tail -3
mkdir -p /guide && cd /guide
```

---

## Exercise 1: Connecting to a Website and Inspecting the Certificate

```console
# Connect to a public HTTPS server and examine its certificate
# Note: This requires outbound internet access from the container
# If no internet: use the local demo server setup below

echo | openssl s_client \
  -connect google.com:443 \
  -servername google.com \
  2>/dev/null | head -60
```

If no internet access, create a local test server:

```bash
# Local test server (no internet needed)
openssl req -x509 -newkey rsa:2048 -keyout /tmp/test.key -out /tmp/test.crt \
  -days 365 -nodes \
  -subj "/CN=test.example.com/O=Test Corp/OU=SOC Training/C=US" \
  -addext "subjectAltName=DNS:test.example.com,DNS:www.test.example.com" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null

openssl s_server -cert /tmp/test.crt -key /tmp/test.key -port 8443 -www -quiet 2>/dev/null &
sleep 1

echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt \
  -servername test.example.com 2>&1 | head -60
```

---

## Exercise 2: Certificate Field Breakdown

Let's parse every important field of the certificate.

```console
# Extract certificate from connection and display all fields
echo | openssl s_client \
  -connect localhost:8443 \
  -CAfile /tmp/test.crt \
  -servername test.example.com 2>/dev/null | \
  openssl x509 -noout -text
```

**Understanding key fields:**

```bash
# Field-by-field extraction
CERT_CMD="openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt -servername test.example.com"

echo "=== CERTIFICATE FIELD ANALYSIS ==="
echo ""

echo "1. VERSION"
echo $CERT_CMD | bash 2>/dev/null | openssl x509 -noout -text | grep "Version:"
echo "   X.509 Version 3 is required for SANs and extensions"
echo ""

echo "2. SERIAL NUMBER"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -serial
echo "   Unique identifier; used in CRL/OCSP revocation checks"
echo ""

echo "3. SUBJECT (Identity)"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -subject
echo "   CN = Common Name, O = Organization, C = Country"
echo ""

echo "4. ISSUER (Who signed it?)"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -issuer
echo "   Self-signed = Issuer equals Subject (WARNING in production!)"
echo ""

echo "5. VALIDITY PERIOD"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -dates
echo ""

echo "6. SUBJECT ALTERNATIVE NAMES (SANs)"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -text | grep -A3 "Subject Alternative Name"
echo "   SANs are the authoritative list of valid hostnames"
echo ""

echo "7. PUBLIC KEY"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -text | grep -E "Public Key Algorithm|Public-Key:"
echo ""

echo "8. SIGNATURE ALGORITHM"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -text | grep "Signature Algorithm" | head -2
echo "   sha256WithRSAEncryption = GOOD"
echo "   md5WithRSAEncryption    = BAD (broken)"
echo "   sha1WithRSAEncryption   = BAD (deprecated)"
echo ""

echo "9. CERTIFICATE FINGERPRINT (SHA-256)"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256
echo "   Used for certificate pinning"
```

---

## Exercise 3: Certificate Chain Validation

```bash
# Create a proper CA → Intermediate → End-entity chain for practice
echo "=== Building a 3-level Certificate Chain ==="

# Root CA
openssl genrsa -out root_ca.key 2048 2>/dev/null
openssl req -new -x509 -key root_ca.key -out root_ca.crt -days 3650 \
  -subj "/CN=Training Root CA/O=SOC Lab/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
echo "Created Root CA"

# Intermediate CA
openssl genrsa -out inter_ca.key 2048 2>/dev/null
openssl req -new -key inter_ca.key -out inter_ca.csr \
  -subj "/CN=Training Intermediate CA/O=SOC Lab/C=US" 2>/dev/null
openssl x509 -req -in inter_ca.csr -CA root_ca.crt -CAkey root_ca.key \
  -CAcreateserial -out inter_ca.crt -days 1825 \
  -extfile <(echo -e "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") 2>/dev/null
echo "Created Intermediate CA"

# End-entity certificate
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
  -subj "/CN=internal.corp.local/O=Corp/C=US" 2>/dev/null
openssl x509 -req -in server.csr -CA inter_ca.crt -CAkey inter_ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(echo -e "subjectAltName=DNS:internal.corp.local\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE") 2>/dev/null
echo "Created End-entity Certificate"

# Create certificate chain file (server + intermediate)
cat server.crt inter_ca.crt > chain.crt
echo ""
echo "Certificate chain created!"
```

```bash
# Verify the chain
echo "=== Verifying Certificate Chain ==="
echo ""

echo "Step 1: Verify end-entity cert against intermediate"
openssl verify -CAfile inter_ca.crt server.crt && echo "✓ Verified"

echo ""
echo "Step 2: Verify intermediate cert against root"
openssl verify -CAfile root_ca.crt inter_ca.crt && echo "✓ Verified"

echo ""
echo "Step 3: Verify full chain in one step"
openssl verify -CAfile root_ca.crt -untrusted inter_ca.crt server.crt && echo "✓ Full chain verified"

echo ""
echo "Certificate chain summary:"
for cert in root_ca.crt inter_ca.crt server.crt; do
  echo ""
  echo "--- $cert ---"
  openssl x509 -in "$cert" -noout -subject -issuer -dates | sed 's/subject=/Subject: /' | sed 's/issuer=/Issuer:  /'
done
```

---

## Exercise 4: Detecting Certificate Issues

```bash
# Create certificates with various problems for practice
echo "=== Creating Problematic Certificates ==="

# Problem 1: Expired certificate
openssl req -x509 -newkey rsa:2048 -keyout /tmp/expired.key -out /tmp/expired.crt \
  -days -1 -nodes \
  -subj "/CN=expired.example.com" 2>/dev/null
echo "Created: expired.crt (expired 1 day ago)"

# Problem 2: Weak RSA key
openssl req -x509 -newkey rsa:1024 -keyout /tmp/weak.key -out /tmp/weak.crt \
  -days 365 -nodes \
  -subj "/CN=weak.example.com" 2>/dev/null
echo "Created: weak.crt (1024-bit RSA — too weak)"

# Problem 3: SHA-1 signature (deprecated)
openssl req -x509 -newkey rsa:2048 -keyout /tmp/sha1.key -out /tmp/sha1.crt \
  -days 365 -nodes -sha1 \
  -subj "/CN=sha1cert.example.com" 2>/dev/null
echo "Created: sha1.crt (SHA-1 signature — deprecated)"
```

```bash
python3 << 'PYEOF'
import subprocess
import re
from datetime import datetime

cert_files = {
    "expired.crt": "/tmp/expired.crt",
    "weak_key.crt": "/tmp/weak.crt",
    "sha1_sig.crt": "/tmp/sha1.crt",
    "good.crt": "/tmp/test.crt",
}

def analyze_cert(name, path):
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-text", "-in", path],
        capture_output=True, text=True
    )
    text = result.stdout + result.stderr

    issues = []

    # Check expiry
    not_after = re.search(r'Not After\s*:\s*(.+)', text)
    if not_after:
        try:
            exp = datetime.strptime(not_after.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            if exp < datetime.utcnow():
                issues.append(f"EXPIRED ({exp.strftime('%Y-%m-%d')})")
        except:
            pass

    # Check key size
    key_size = re.search(r'Public-Key:\s*\((\d+)', text)
    if key_size and int(key_size.group(1)) < 2048:
        issues.append(f"WEAK KEY ({key_size.group(1)}-bit RSA)")

    # Check signature algorithm
    if "sha1WithRSA" in text or "md5WithRSA" in text:
        algo = "SHA-1" if "sha1" in text else "MD5"
        issues.append(f"WEAK SIGNATURE ({algo})")

    # Check if self-signed
    subject = re.search(r'Subject:\s*(.+)', text)
    issuer = re.search(r'Issuer:\s*(.+)', text)
    if subject and issuer and subject.group(1).strip() == issuer.group(1).strip():
        issues.append("SELF-SIGNED")

    status = "ISSUES FOUND" if issues else "OK"
    print(f"\n{name}:")
    print(f"  Status: {status}")
    for issue in issues:
        print(f"  ⚠ {issue}")
    if not issues:
        print("  ✓ No obvious issues")

for name, path in cert_files.items():
    analyze_cert(name, path)
PYEOF
```

---

## Exercise 5: TLS Protocol Version and Cipher Suite Inspection

```bash
# Start servers with different TLS configurations
echo "=== Testing TLS Configurations ==="

# TLS 1.3 only server (best)
openssl s_server -cert /tmp/test.crt -key /tmp/test.key -port 8443 -www -quiet \
  -no_tls1 -no_tls1_1 -no_tls1_2 2>/dev/null &
TLS13_PID=$!
sleep 0.5

echo "Connecting to TLS 1.3 server:"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt \
  -tls1_3 2>&1 | grep -E "Protocol|Cipher"

kill $TLS13_PID 2>/dev/null || true
sleep 0.3

# TLS 1.2 server (acceptable)
openssl s_server -cert /tmp/test.crt -key /tmp/test.key -port 8443 -www -quiet \
  -no_tls1 -no_tls1_1 2>/dev/null &
TLS12_PID=$!
sleep 0.5

echo ""
echo "Connecting to TLS 1.2 server:"
echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt \
  -tls1_2 2>&1 | grep -E "Protocol|Cipher"

kill $TLS12_PID 2>/dev/null || true
```

```bash
# Check what cipher suites a server supports
echo ""
echo "=== Cipher Suite Enumeration ==="
echo "Testing which TLS 1.3 ciphers the server accepts:"

for cipher in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  openssl s_server -cert /tmp/test.crt -key /tmp/test.key -port 8443 -www -quiet 2>/dev/null &
  SRV_PID=$!
  sleep 0.3

  RESULT=$(echo | openssl s_client -connect localhost:8443 -CAfile /tmp/test.crt \
    -ciphersuites "$cipher" 2>&1 | grep "Cipher :" | awk '{print $NF}')

  kill $SRV_PID 2>/dev/null || true
  sleep 0.2

  if [ -n "$RESULT" ]; then
    echo "  ✓ $cipher — Supported"
  else
    echo "  ✗ $cipher — Not accepted"
  fi
done
```

---

## Exercise 6: Certificate Transparency Lookup

Certificate Transparency (CT) logs record all certificates issued by public CAs.
SOC analysts use CT to detect rogue certificates.

```bash
python3 << 'PYEOF'
print("Certificate Transparency (CT) Log Analysis")
print("=" * 50)
print()
print("SOC use cases for CT logs:")
print()
print("1. Monitor for new certificates for your domain:")
print("   → Detect unauthorized certificate issuance (e.g., attacker gets cert for your domain)")
print("   Tool: https://crt.sh/?q=%.yourdomain.com")
print()
print("2. Phishing detection:")
print("   → Monitor for look-alike domains: 'arnazon.com', 'paypa1.com'")
print("   → New cert issued for 'secure-login-bank.com' targeting your bank customers")
print()
print("3. Subdomain discovery (recon):")
print("   → crt.sh reveals all subdomains with public certificates")
print("   → Useful for attack surface mapping")
print()
print("Example crt.sh API query (requires internet):")
print("  curl 'https://crt.sh/?q=%.github.com&output=json' | python3 -m json.tool | head -40")
print()
print("Example monitoring setup:")
print("  Daily: query CT logs for *.yourdomain.com")
print("  Alert: if new certificate found that you didn't issue")
print("  Action: investigate — may be legitimate (DevOps forgot to notify SOC)")
print("          or malicious (attacker compromised domain validation)")
PYEOF
```

---

## Summary: Certificate Analysis Checklist

```bash
cat << 'EOF'
=== SOC Certificate Analysis Checklist ===

When examining a certificate:

□ 1. Is the CN/SAN correct for the connection?
     (Connecting to api.company.com but cert says CN=company.com only?)

□ 2. Is the certificate expired?
     (Check Not After date)

□ 3. Is the issuer a trusted CA or self-signed?
     (Self-signed on public internet = suspicious)

□ 4. Is the certificate newly issued?
     (Check Not Before — cert issued today is suspicious for established service)

□ 5. What is the signature algorithm?
     (sha256WithRSA = OK; sha1WithRSA = BAD; md5WithRSA = VERY BAD)

□ 6. What is the public key size?
     (RSA < 2048 bits = WEAK; ECC P-256 = OK)

□ 7. Is the certificate chain complete?
     (Server should send intermediate certs, not just the end-entity cert)

□ 8. What CA issued it?
     (Is this CA normally trusted? Let's Encrypt is free and used by both
      legitimate sites AND malware infrastructure)

□ 9. Does the cert appear in CT logs?
     (Required for public trust since 2018)

□ 10. Is revocation status checked?
      (OCSP stapling configured?)
EOF
```

---

## Quick Reference

```bash
# Connect and show full TLS info
echo | openssl s_client -connect HOST:443 -servername HOST

# Show only certificate details
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | \
  openssl x509 -noout -text

# Show expiry date
echo | openssl s_client -connect HOST:443 2>/dev/null | \
  openssl x509 -noout -dates

# Check if certificate is expired
echo | openssl s_client -connect HOST:443 2>/dev/null | \
  openssl x509 -noout -checkend 0
# Exit code 0 = valid, 1 = expired

# Check if cert expires in next 30 days
echo | openssl s_client -connect HOST:443 2>/dev/null | \
  openssl x509 -noout -checkend 2592000

# Show SANs only
echo | openssl s_client -connect HOST:443 2>/dev/null | \
  openssl x509 -noout -text | grep -A3 "Subject Alternative"

# Verify cert against a CA bundle
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt server.crt
```
