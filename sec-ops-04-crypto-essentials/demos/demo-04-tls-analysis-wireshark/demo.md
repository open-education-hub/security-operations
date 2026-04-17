# Demo 04: Analyzing TLS in Wireshark

> **Duration:** ~30 minutes
> **Difficulty:** Intermediate
> **Tools:** Docker, Wireshark, OpenSSL, tshark, tcpdump
> **Concepts:** TLS handshake, cipher suites, JA3 fingerprinting, certificate inspection, SNI

---

## Overview

This demo captures and analyzes a real TLS 1.3 handshake.
You will:

1. Generate a TLS PCAP using OpenSSL's s_server / s_client
1. Analyze the handshake with `tshark` (Wireshark command-line)
1. Identify cipher suites, SNI, and certificate details
1. Understand what is visible vs. encrypted in TLS 1.3
1. Compute a JA3 fingerprint manually
1. Practice the analysis that SOC analysts use for threat detection

---

## Part A: Capture a TLS Handshake (Docker)

### Step 1: Start the Environment

```console
# This docker-compose starts a server + client + analyzer
docker-compose up
```

Or manually:

```console
docker run --rm -it --name tls-demo ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl tshark tcpdump python3 2>/dev/null | tail -3
```

### Step 2: Create a Self-Signed Certificate

```bash
mkdir -p /demo && cd /demo

# Generate server key and self-signed certificate
openssl req -x509 -newkey rsa:2048 \
  -keyout server_key.pem \
  -out server_cert.pem \
  -days 365 -nodes \
  -subj "/CN=demo.internal/O=SOC Training Lab/C=US" \
  -addext "subjectAltName=DNS:demo.internal"

echo "Certificate created:"
openssl x509 -in server_cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|Public Key Algorithm|Public-Key:"
```

### Step 3: Capture TLS Handshake

```bash
# Terminal 1: Start OpenSSL TLS server
openssl s_server \
  -cert server_cert.pem \
  -key server_key.pem \
  -port 8443 \
  -tls1_3 \
  -www &

SERVER_PID=$!
sleep 1

# Terminal 2: Start packet capture
tcpdump -i lo -w /demo/tls_handshake.pcap port 8443 &
TCPDUMP_PID=$!
sleep 0.5

# Terminal 3: Connect as TLS client
echo "Connecting with TLS 1.3..."
openssl s_client \
  -connect localhost:8443 \
  -tls1_3 \
  -CAfile server_cert.pem \
  -servername demo.internal \
  < /dev/null 2>&1 | head -40

sleep 1
kill $TCPDUMP_PID $SERVER_PID 2>/dev/null || true
echo "Capture saved: /demo/tls_handshake.pcap"
```

---

## Part B: Analyze the PCAP with tshark

### Step 4: Overview of Captured Packets

```bash
echo "=== PCAP Summary ==="
tshark -r /demo/tls_handshake.pcap -q -z io,phs 2>/dev/null | head -20

echo ""
echo "=== All TLS Packets ==="
tshark -r /demo/tls_handshake.pcap \
  -Y "tls" \
  -T fields \
  -e frame.number \
  -e frame.len \
  -e ip.src \
  -e ip.dst \
  -e tls.record.content_type \
  -e tls.handshake.type \
  2>/dev/null | head -20
```

**TLS handshake types:**

* 1 = ClientHello
* 2 = ServerHello
* 11 = Certificate
* 13 = CertificateRequest
* 14 = ServerHelloDone
* 15 = CertificateVerify
* 20 = Finished

### Step 5: Extract ClientHello Details

```console
echo "=== ClientHello Details ==="
tshark -r /demo/tls_handshake.pcap \
  -Y "tls.handshake.type == 1" \
  -V 2>/dev/null | grep -E "TLS|Version|Cipher|Extension|SNI|Supported Groups" | head -30
```

What to look for:

* `TLS 1.3 (0x0304)` — protocol version
* Cipher suites offered by client
* Extensions: SNI (server_name), supported_groups, supported_versions
* key_share: the ECDH public key for key exchange

### Step 6: Extract SNI (Server Name Indication)

```console
echo "=== SNI (Server Name Indication) ==="
echo "This reveals which domain the client is connecting to — VISIBLE in plaintext!"
echo ""
tshark -r /demo/tls_handshake.pcap \
  -Y "tls.handshake.extensions_server_name" \
  -T fields \
  -e tls.handshake.extensions_server_name \
  2>/dev/null
```

**SOC significance:** Even in TLS 1.3, the SNI is sent in plaintext in the ClientHello.
This means:

* Firewalls can block specific domains
* SOC tools can log which HTTPS domains are visited
* Malware C2 domains are visible in the SNI field

### Step 7: Inspect the Server Certificate

```bash
echo "=== Server Certificate Information ==="
tshark -r /demo/tls_handshake.pcap \
  -Y "tls.handshake.certificate" \
  -V 2>/dev/null | grep -E "Subject:|Issuer:|Not Before|Not After|Algorithm|Serial" | head -20

# Also extract the certificate directly
echo ""
echo "=== Extract Certificate with OpenSSL ==="
openssl s_client \
  -connect localhost:8443 \
  -CAfile server_cert.pem \
  -showcerts \
  < /dev/null 2>&1 | openssl x509 -noout -text | \
  grep -E "Issuer:|Subject:|Not Before|Not After|Public Key|Signature Alg|SAN" | \
  head -15
```

### Step 8: Check What's Encrypted in TLS 1.3

```bash
echo "=== TLS 1.3: What is visible vs. encrypted? ==="
echo ""
echo "VISIBLE (plaintext):"
echo "  ✓ ClientHello: TLS version, cipher suite list, SNI, key_share"
echo "  ✓ ServerHello: chosen cipher suite, server key_share"
echo "  ✓ IP addresses and port numbers"
echo "  ✓ Packet sizes and timing"
echo "  ✗ Application data: ENCRYPTED"
echo "  ✗ Certificate: ENCRYPTED in TLS 1.3 (was visible in TLS 1.2!)"
echo "  ✗ Session resumption tickets: ENCRYPTED"
echo ""
echo "VISIBLE in TLS 1.2 but ENCRYPTED in TLS 1.3:"
echo "  Certificate details (CN, SAN, issuer)"
echo "  ClientHello random, session ID"

echo ""
echo "Verifying what tshark can see in our capture..."
tshark -r /demo/tls_handshake.pcap \
  -Y "tls" -T fields \
  -e tls.record.content_type \
  -e tls.handshake.type \
  -e tls.app_data_proto \
  2>/dev/null | sort | uniq -c | sort -rn | head -10
```

### Step 9: TLS Cipher Suite Analysis

```bash
echo "=== Cipher Suite Analysis ==="

# Check what cipher was negotiated
openssl s_client \
  -connect localhost:8443 \
  -CAfile server_cert.pem \
  < /dev/null 2>&1 | grep -E "Cipher|Protocol|Session-ID"

echo ""
echo "Strong cipher suites (TLS 1.3 only suites):"
echo "  TLS_AES_128_GCM_SHA256       - AES-128 + GCM + SHA-256"
echo "  TLS_AES_256_GCM_SHA384       - AES-256 + GCM + SHA-384"
echo "  TLS_CHACHA20_POLY1305_SHA256 - ChaCha20 + Poly1305 + SHA-256"
echo ""
echo "Weak/deprecated cipher suites (should NEVER appear):"
echo "  TLS_RSA_WITH_RC4_128_MD5     - RC4 (broken) + MD5 (broken)"
echo "  TLS_RSA_EXPORT_WITH_DES40    - Export-grade (40-bit) DES (trivially broken)"
echo "  TLS_NULL_WITH_NULL_NULL      - NO encryption at all"
```

---

## Part C: JA3 Fingerprinting

JA3 is a TLS client fingerprinting method used in threat detection.
It creates an MD5 hash of specific TLS ClientHello fields to identify client implementations — including malware.

### Step 10: Understanding JA3

```bash
cat << 'EOF'
JA3 fingerprint = MD5 of:
  SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

Example breakdown:
  SSLVersion: 771 (TLS 1.2 = 0x0303)
  Ciphers: 49195,49199,52393,...
  Extensions: 0,23,65281,10,11,...
  EllipticCurves: 29,23,24,...
  EllipticCurvePointFormats: 0

JA3 = MD5("771,49195-49199-52393,0-23-65281,29-23-24,0")
EOF
```

```bash
python3 << 'PYEOF'
import hashlib

# Example JA3 computation (simplified)
# These values represent a typical Chrome browser ClientHello
ssl_version = "771"  # TLS 1.2 = 0x0303 (TLS 1.3 still uses 0x0303 in legacy version field)
ciphers = "4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-49162-49172-49161-49171-157-156-61-60-53-47-255"
extensions = "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21"
elliptic_curves = "29-23-24-25"
elliptic_curve_formats = "0"

ja3_string = f"{ssl_version},{ciphers},{extensions},{elliptic_curves},{elliptic_curve_formats}"
ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

print(f"JA3 raw string: {ja3_string[:60]}...")
print(f"JA3 hash: {ja3_hash}")
print()
print("Known JA3 fingerprints (examples):")
known_ja3 = {
    "7dc465e8f114a23f3609b2b4a2e2dade": "Curl / wget (varies by version)",
    "37a6d67a8a1c5d4f7f0c2e3b89c5c7d6": "Cobalt Strike default",
    "6734f37431670b3ab4292b8f60f29984": "Python requests library",
}
for h, name in known_ja3.items():
    print(f"  {h}  →  {name}")
print()
print("In practice: query threat intel APIs with JA3 hash to identify malware families")
PYEOF
```

---

## Part D: SOC Use Cases

### Step 11: Identifying Suspicious TLS Traffic

```bash
cat << 'EOF'
=== SOC TLS Analysis Checklist ===

When analyzing TLS traffic for threats, check:

1. CERTIFICATE ANALYSIS

   □ Is the certificate self-signed? (no trusted CA)
   □ Certificate validity period very short (<7 days)?
   □ Domain registered <30 days ago?
   □ Certificate CN doesn't match SNI?
   □ Unknown or unusual CA issuer?
   □ Certificate missing SAN extension?

2. PROTOCOL/CIPHER ANALYSIS
   □ TLS 1.0 or 1.1 in use? (deprecated)
   □ Weak cipher suite (RC4, DES, NULL, EXPORT)?
   □ Cipher suite inconsistent with claimed client type?

3. BEHAVIORAL ANALYSIS
   □ Regular connection interval (beaconing pattern)?
   □ Connection to newly registered domain?
   □ Large data upload to unusual external IP?
   □ Connection at unusual time (3am when user is offline)?
   □ High connection frequency to single IP?

4. JA3 FINGERPRINT ANALYSIS
   □ JA3 hash matches known malware in threat intel?
   □ JA3 inconsistent with expected user-agent?

5. FLOW METADATA
   □ Total bytes sent >> bytes received? (exfiltration pattern)
   □ Connection duration anomalous?
   □ Port unusual for service?
EOF
```

```bash
# Simulate analyzing multiple TLS connections
python3 << 'PYEOF'
import random
from datetime import datetime, timedelta

connections = [
    {"host": "api.github.com",     "cert_days": 365, "ja3": "6781...", "bytes_out": 1200,  "bytes_in": 85000, "tls_ver": "1.3"},
    {"host": "192.168.43.17",      "cert_days": 1,   "ja3": "c9e4...", "bytes_out": 45000, "bytes_in": 200,   "tls_ver": "1.2"},
    {"host": "login.microsoftonline.com", "cert_days": 180, "ja3": "7dc4...", "bytes_out": 2100, "bytes_in": 15000, "tls_ver": "1.3"},
    {"host": "xn--80aswg.xn--j1amh", "cert_days": 3, "ja3": "a5b2...", "bytes_out": 98000, "bytes_in": 100, "tls_ver": "1.2"},
]

print(f"{'Host':<35} {'Cert':>6} {'TLS':>5} {'Out KB':>8} {'In KB':>7} {'Risk'}")
print("-" * 80)
for c in connections:
    risk_flags = []
    if c["cert_days"] < 7: risk_flags.append("short cert")
    if c["bytes_out"] > c["bytes_in"] * 5: risk_flags.append("high upload")
    if c["tls_ver"] in ["1.0","1.1"]: risk_flags.append("old TLS")
    if not c["host"][0].isalpha(): risk_flags.append("IP/IDN host")

    risk = "HIGH ⚠" if len(risk_flags) >= 2 else ("MEDIUM" if risk_flags else "OK ✓")
    flags = ", ".join(risk_flags) if risk_flags else ""
    print(f"{c['host']:<35} {c['cert_days']:>6}d {c['tls_ver']:>5} {c['bytes_out']//1024:>7}K {c['bytes_in']//1024:>6}K  {risk} {flags}")

PYEOF
```

---

## Summary

```bash
echo "=== DEMO 04 SUMMARY ==="
echo ""
echo "What you can see in TLS traffic (without decryption):"
echo "  ✓ SNI (target domain)"
echo "  ✓ Certificate details (via TLS 1.2 or direct inspection)"
echo "  ✓ TLS version and cipher suite negotiated"
echo "  ✓ JA3/JA3S fingerprints"
echo "  ✓ IP addresses, ports, flow metadata"
echo "  ✓ Packet sizes and timing patterns"
echo ""
echo "What you CANNOT see (genuinely encrypted):"
echo "  ✗ Application payload (HTTP headers, body)"
echo "  ✗ URLs after the domain name"
echo "  ✗ API calls, credentials, data"
echo ""
echo "SOC tools that analyze TLS metadata:"
echo "  - Zeek (network security monitor): extracts TLS fields automatically"
echo "  - Suricata: JA3 rules, certificate matching"
echo "  - SIEM correlation: beaconing detection, DGA detection"
echo "  - TLS inspection proxy: full decryption (enterprise only)"
```

---

## Wireshark Filters Reference

```text
# Show all TLS traffic
tls

# Filter by TLS version
tls.record.version == 0x0303  # TLS 1.2/1.3

# Show only ClientHello
tls.handshake.type == 1

# Show only ServerHello
tls.handshake.type == 2

# Show certificates
tls.handshake.type == 11

# Filter by SNI
tls.handshake.extensions_server_name contains "example.com"

# Show cipher suite
tls.handshake.ciphersuites

# Show application data (encrypted)
tls.record.content_type == 23
```
