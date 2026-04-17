#!/bin/bash
# Demo 01: Symmetric Encryption with OpenSSL (AES-256)
# Run inside Docker: docker run --rm -it ubuntu:22.04 bash
# Then: apt-get update -q && apt-get install -y openssl xxd python3 && bash demo.sh

set -e

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  $1${RESET}"
    echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
}

step() {
    echo ""
    echo -e "${GREEN}▶ $1${RESET}"
}

mkdir -p /demo && cd /demo

banner "DEMO 01: AES-256 Symmetric Encryption"
echo -e "${YELLOW}Demonstrating: AES-CBC, AES-GCM, ECB weakness, key derivation${RESET}"

# ── Step 1: Create plaintext ──────────────────────────────
banner "Step 1: Create Sample Sensitive File"

cat > secret_report.txt << 'EOF'
INCIDENT REPORT - CONFIDENTIAL
Date: 2024-01-15  |  Incident ID: IR-2024-0042

Summary: Suspicious outbound connections from workstation WS-042.
Destination: 185.220.101.47:443 (Known Tor exit node)
Duration: 3 hours 42 minutes | Data transferred: ~2.3 GB

Action required: Isolate workstation, preserve forensic image.
EOF

echo -e "Plaintext file contents:"
cat secret_report.txt
echo -e "\n${GREEN}Size: $(wc -c < secret_report.txt) bytes${RESET}"

# ── Step 2: AES-256-CBC ───────────────────────────────────
banner "Step 2: AES-256-CBC Encryption"

step "Encrypting with AES-256-CBC (password-based key derivation)..."
openssl enc -aes-256-cbc \
  -pbkdf2 -iter 100000 \
  -in secret_report.txt \
  -out report_cbc.enc \
  -pass pass:SecretPass123!

echo -e "${GREEN}✓ Encrypted: report_cbc.enc ($(wc -c < report_cbc.enc) bytes)${RESET}"
echo ""
echo "First 64 bytes of ciphertext (hex):"
xxd report_cbc.enc | head -4

step "Decrypting..."
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter 100000 \
  -in report_cbc.enc \
  -out report_decrypted.txt \
  -pass pass:SecretPass123!

echo -e "${GREEN}✓ Decryption successful!${RESET}"
diff secret_report.txt report_decrypted.txt && echo -e "${GREEN}✓ Files are identical${RESET}"

step "Testing wrong password..."
openssl enc -d -aes-256-cbc \
  -pbkdf2 -iter 100000 \
  -in report_cbc.enc \
  -out /dev/null \
  -pass pass:WRONGPASSWORD 2>&1 | head -3 || true
echo -e "${RED}✗ Wrong password correctly rejected${RESET}"

# ── Step 3: AES-256-GCM ───────────────────────────────────
banner "Step 3: AES-256-GCM (Authenticated Encryption — Recommended)"

KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 12)

echo "Random 256-bit key: ${KEY:0:16}...${KEY: -8} (keep secret!)"
echo "Random 96-bit nonce: $IV"

openssl enc -aes-256-gcm -K "$KEY" -iv "$IV" \
  -in secret_report.txt -out report_gcm.enc

echo -e "${GREEN}✓ AES-GCM encrypted: $(wc -c < report_gcm.enc) bytes${RESET}"

openssl enc -d -aes-256-gcm -K "$KEY" -iv "$IV" \
  -in report_gcm.enc -out report_gcm_dec.txt

diff secret_report.txt report_gcm_dec.txt && \
  echo -e "${GREEN}✓ GCM decryption verified — content integrity confirmed${RESET}"

# ── Step 4: ECB Mode Danger ───────────────────────────────
banner "Step 4: WHY ECB MODE IS DANGEROUS"

python3 -c "
data = b'IDENTICAL_BLOCK!' * 6  # 6 x 16-byte identical blocks
with open('repeated_data.bin', 'wb') as f:
    f.write(data)
print(f'Input: 6 IDENTICAL 16-byte blocks ({len(data)} bytes total)')
"

ECB_KEY=$(openssl rand -hex 32)

openssl enc -aes-256-ecb -K "$ECB_KEY" -nosalt \
  -in repeated_data.bin -out repeated_ecb.enc

echo ""
echo -e "${RED}ECB ciphertext — REPEATING PATTERN VISIBLE:${RESET}"
xxd repeated_ecb.enc | head -7

# CBC for comparison
CBC_KEY=$(openssl rand -hex 32)
CBC_IV=$(openssl rand -hex 16)

openssl enc -aes-256-cbc -K "$CBC_KEY" -iv "$CBC_IV" -nosalt \
  -in repeated_data.bin -out repeated_cbc.enc

echo ""
echo -e "${GREEN}CBC ciphertext — NO PATTERN (identical blocks → different ciphertext):${RESET}"
xxd repeated_cbc.enc | head -7

echo ""
echo -e "${YELLOW}⚠  ECB: same input block → same output block (NEVER USE!)${RESET}"
echo -e "${GREEN}✓  CBC: same input block → different output block (safe when used correctly)${RESET}"

# ── Summary ───────────────────────────────────────────────
banner "Summary"

echo -e "${BOLD}Files created:${RESET}"
ls -lh /demo/*.{txt,enc,bin} 2>/dev/null

echo ""
echo -e "${BOLD}Key takeaways:${RESET}"
echo "  1. AES-256 with a strong password is unbreakable by brute force"
echo "  2. CBC needs a unique random IV every time"
echo "  3. GCM = encryption + authentication (preferred for new applications)"
echo "  4. ECB leaks block patterns — NEVER use with real data"
echo "  5. PBKDF2 (100,000+ iterations) slows password-based key derivation"
echo ""
echo -e "${GREEN}Demo complete!${RESET}"
