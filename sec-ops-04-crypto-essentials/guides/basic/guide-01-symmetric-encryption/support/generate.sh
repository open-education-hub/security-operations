#!/usr/bin/env bash
# generate.sh — Regenerate all support artifacts for guide-01-symmetric-encryption
# Run this script to recreate sample files from scratch.
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating support files for guide-01-symmetric-encryption ==="

# ── 1. Plaintext configuration file ──────────────────────────────────────────
cat > db_config.env << 'EOF'
DB_HOST=internal-db.corp.local
DB_PORT=5432
DB_NAME=incident_tracker
DB_USER=soc_analyst
DB_PASSWORD=Tr0ub4dor&3_secure_pw
DB_SSL_MODE=require
EOF
echo "[+] db_config.env created"

# ── 2. AES-256-CBC encrypted file (password-based, PBKDF2) ───────────────────
PASSPHRASE="ThisIsAVeryLongAndSecurePassphrase2024!"
openssl enc -aes-256-cbc \
  -pbkdf2 \
  -iter 600000 \
  -in db_config.env \
  -out db_config.enc \
  -pass pass:"$PASSPHRASE"
echo "[+] db_config.enc created (AES-256-CBC, PBKDF2, passphrase in README)"

# ── 3. AES-256-CBC encrypted file (explicit random key + IV) ─────────────────
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
openssl enc -aes-256-cbc \
  -K "$KEY" \
  -iv "$IV" \
  -nosalt \
  -in db_config.env \
  -out db_config_raw_key.enc
# Save the key material (instructors will distribute separately to students)
printf "KEY=%s\nIV=%s\n" "$KEY" "$IV" > db_config_raw_key.key
chmod 600 db_config_raw_key.key
echo "[+] db_config_raw_key.enc + db_config_raw_key.key created (keep key confidential)"

# ── 4. AES-256-GCM encrypted file (via Python cryptography library) ──────────
# NOTE: `openssl enc` does not support AEAD modes (GCM) from the command line.
# The guide exercises create GCM ciphertexts inside Docker containers where
# Python's `cryptography` package is available.  This script uses the same
# library so the artifacts are bit-for-bit compatible with the guide commands.
python3 - <<'PYEOF'
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key   = os.urandom(32)
nonce = os.urandom(12)
pt    = open("db_config.env", "rb").read()
ct    = AESGCM(key).encrypt(nonce, pt, None)
open("db_config_gcm.enc", "wb").write(ct)
open("db_config_gcm.key", "w").write(f"KEY={key.hex()}\nNONCE={nonce.hex()}\n")
print(f"[+] db_config_gcm.enc created ({len(ct)} bytes, AES-256-GCM)")
PYEOF
chmod 600 db_config_gcm.key

# ── 5. Sample "evidence bundle" plaintext files ───────────────────────────────
mkdir -p sample_evidence
echo "Packet capture from IR-2024-042: 18,432 packets, duration 4m32s" > sample_evidence/network_summary.txt
printf "PID  PPID  CMD\n1234  1  svchost.exe\n5678  1234  powershell.exe -NoProfile -EncodedCommand\n9012  5678  cmd.exe /c whoami\n" > sample_evidence/processes.txt
echo "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run: C:\\Users\\Public\\svcupdate.exe" > sample_evidence/registry.txt
echo "[+] sample_evidence/ directory created"

echo ""
echo "=== Generation complete ==="
echo ""
echo "Files created:"
ls -lh "$SCRIPT_DIR"
echo ""
echo "Notes:"
echo "  db_config.enc        — decrypt with: openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in db_config.enc -out out.env -pass pass:'ThisIsAVeryLongAndSecurePassphrase2024!'"
echo "  db_config_raw_key.enc — decrypt with the KEY and IV from db_config_raw_key.key"
echo "  db_config_gcm.enc    — decrypt with the KEY and NONCE from db_config_gcm.key"
