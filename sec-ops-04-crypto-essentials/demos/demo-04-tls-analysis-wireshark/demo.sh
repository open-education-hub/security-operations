#!/bin/bash
# Demo 04: TLS Analysis — capture and inspect a TLS handshake
set -e

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'

banner() { echo -e "\n${CYAN}════════════════════════════════════════════${RESET}\n${BOLD}${CYAN}  $1${RESET}\n${CYAN}════════════════════════════════════════════${RESET}"; }

mkdir -p /demo && cd /demo

banner "DEMO 04: TLS Handshake Analysis"
echo -e "${YELLOW}Capturing and analyzing TLS 1.3 traffic${RESET}"

banner "Step 1: Create Self-Signed Server Certificate"
openssl req -x509 -newkey rsa:2048 \
  -keyout server_key.pem \
  -out server_cert.pem \
  -days 365 -nodes \
  -subj "/CN=soc-training.internal/O=SOC Lab/C=US" 2>/dev/null

echo -e "${GREEN}✓ Certificate generated${RESET}"
echo ""
echo "Certificate details:"
openssl x509 -in server_cert.pem -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|Public Key Alg" | sed 's/^[[:space:]]*/  /'

banner "Step 2: Capture TLS Handshake"
# Start server in background
openssl s_server \
  -cert server_cert.pem -key server_key.pem \
  -port 8443 -www \
  -quiet 2>/dev/null &
SERVER_PID=$!

sleep 1

# Capture with tcpdump if available
if command -v tcpdump &>/dev/null; then
  tcpdump -i lo -w /demo/tls_handshake.pcap port 8443 2>/dev/null &
  TCPDUMP_PID=$!
  sleep 0.3
fi

echo "Making TLS connection to server..."
CLIENT_OUT=$(openssl s_client \
  -connect localhost:8443 \
  -CAfile server_cert.pem \
  -servername soc-training.internal \
  < /dev/null 2>&1)

sleep 0.5
[ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null || true
kill "$SERVER_PID" 2>/dev/null || true

echo -e "${GREEN}✓ Connection established and captured${RESET}"

banner "Step 3: Analyze TLS Handshake Details"
echo "$CLIENT_OUT" | grep -E "Protocol|Cipher|Server certificate|subject|issuer|Verification|TLSv" | head -20

banner "Step 4: Certificate Chain Analysis"
echo "Server certificate details:"
echo "$CLIENT_OUT" | openssl x509 -noout -text 2>/dev/null | \
  grep -E "Subject:|Issuer:|Not Before|Not After|Public.Key.Alg|Public-Key:" | \
  sed 's/^[[:space:]]*/  /' || true

echo ""
echo "Checking certificate with openssl x509 directly:"
openssl x509 -in server_cert.pem -noout -text | \
  grep -E "Subject:|Not Before|Not After|Public-Key:|Signature Alg" | \
  sed 's/^[[:space:]]*/  /'

banner "Step 5: Analyze PCAP with tshark (if available)"
if command -v tshark &>/dev/null && [ -f /demo/tls_handshake.pcap ]; then
  echo "TLS packets in capture:"
  tshark -r /demo/tls_handshake.pcap \
    -Y "tls" \
    -T fields \
    -e frame.number \
    -e ip.src \
    -e tls.handshake.type \
    2>/dev/null | head -15
else
  echo "(tshark not available or no pcap — showing OpenSSL output analysis)"
fi

banner "Step 6: JA3 Fingerprint Computation"
python3 << 'PYEOF'
import hashlib

print("JA3 fingerprint = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)")
print()

# Representative TLS 1.3 ClientHello fields (simplified example)
ssl_version = "771"
ciphers = "4866-4867-4865-49196-49200-49195-49199"
extensions = "0-23-65281-10-11-35-16-5-13-51-45-43"
elliptic_curves = "29-23-24"
ecpf = "0"

ja3_str = f"{ssl_version},{ciphers},{extensions},{elliptic_curves},{ecpf}"
ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
print(f"Input string: {ja3_str}")
print(f"JA3 hash: {ja3_hash}")
print()
print("SOC use case: query this hash against threat intel to identify")
print("known malware C2 clients, pentest tools, and vulnerability scanners.")
PYEOF

banner "Step 7: What SOC Analysts Can See"
cat << 'EOF'

  VISIBLE (no decryption needed):
  ─────────────────────────────────────────────────────
  ✓ SNI: target domain name in ClientHello
  ✓ TLS version negotiated
  ✓ Cipher suite list (client) + chosen suite (server)
  ✓ Certificate Subject, Issuer, SAN, validity dates
  ✓ Certificate fingerprint (SHA-256)
  ✓ JA3 / JA3S fingerprint
  ✓ IP addresses and ports
  ✓ Packet sizes and timing
  ✓ Flow metadata (total bytes, duration)

  ENCRYPTED (cannot see without keys):
  ─────────────────────────────────────────────────────
  ✗ HTTP headers (method, path, cookies, auth tokens)
  ✗ Request/response body
  ✗ API calls and credentials
  ✗ Certificate (encrypted in TLS 1.3!)

  RED FLAGS to watch for:
  ─────────────────────────────────────────────────────
  ⚠ Self-signed certificate on public host
  ⚠ Certificate valid < 7 days
  ⚠ TLS 1.0 or 1.1 in use
  ⚠ Beaconing: regular connection every N seconds
  ⚠ Large outbound transfer to unknown external IP
  ⚠ JA3 matches known malware family
  ⚠ Domain registered < 30 days
EOF

echo ""
echo -e "${GREEN}Demo 04 complete!${RESET}"
