#!/usr/bin/env bash
# generate.sh — Regenerate all challenge artifacts for drill-01-cipher-identification
#
# Creates pre-generated challenge data so the drill can be run without the
# inline Python setup script (useful for offline or pre-staged environments).
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating challenge artifacts for drill-01-cipher-identification ==="

# ── Artifact 1: MD5-hashed passwords (simulated database backup) ─────────────
python3 -c "
import hashlib
passwords = ['admin123', 'Summer2024!', 'P@ssword']
lines = ['# /var/db/users.bak — excerpt from password database backup']
lines.append('# username : algorithm : hash')
usernames = ['admin', 'jsmith', 'bwilson']
for u, p in zip(usernames, passwords):
    h = hashlib.md5(p.encode()).hexdigest()
    lines.append(f'{u}:\$1\${h}')
open('artifact_01_password_db.txt', 'w').write('\n'.join(lines) + '\n')
print('[+] artifact_01_password_db.txt — MD5 password hashes')
"

# ── Artifact 2: Base64-encoded config (looks like encryption, is not) ────────
python3 -c "
import base64
data = b'SECRET CONFIGURATION: API_KEY=xK9mP3qR7sT2'
b64 = base64.b64encode(data).decode()
open('artifact_02_encoded_config.txt', 'w').write(b64 + '\n')
print(f'[+] artifact_02_encoded_config.txt — Base64-encoded string')
print(f'    Content: {b64}')
"

# ── Artifact 3: OpenSSL AES-CBC encrypted file (Salted__ header) ─────────────
echo "This is a sample configuration file with credentials." > /tmp/plaintext_for_drill.txt
openssl enc -aes-256-cbc \
  -pbkdf2 \
  -iter 100000 \
  -in /tmp/plaintext_for_drill.txt \
  -out artifact_03_encrypted_config.enc \
  -pass pass:"SomeRandomPassphrase!" 2>/dev/null
# Save hex dump of the header for student inspection
python3 -c "
data = open('artifact_03_encrypted_config.enc', 'rb').read()
lines = []
for i in range(0, min(32, len(data)), 16):
    chunk = data[i:i+16]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    asc_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    lines.append(f'{i:08x}:  {hex_str:<47}  {asc_str}')
open('artifact_03_header_hexdump.txt', 'w').write('\n'.join(lines) + '\n')
print('[+] artifact_03_encrypted_config.enc + artifact_03_header_hexdump.txt')
"

# ── Artifact 4: Hash lengths for identification exercise ─────────────────────
python3 -c "
import hashlib
# These are real hashes of empty string — algorithm identifiable by length alone
hashes = {
    'File A hash (MD5)':    hashlib.md5(b'').hexdigest(),
    'File B hash (SHA-1)':  hashlib.sha1(b'').hexdigest(),
    'File C hash (SHA-256)':hashlib.sha256(b'').hexdigest(),
    'File D hash (SHA-512)':hashlib.sha512(b'').hexdigest(),
}
lines = ['# Threat intelligence report — file hashes (algorithm labels removed)']
lines.append('# Students must identify the algorithm from hash length alone')
lines.append('')
for name, h in hashes.items():
    # Show the hash but not the algorithm label
    display_name = name.split(' (')[0]
    lines.append(f'{display_name} ({len(h)} hex chars): {h}')
open('artifact_04_threat_intel_hashes.txt', 'w').write('\n'.join(lines) + '\n')
print('[+] artifact_04_threat_intel_hashes.txt — hashes with unlabelled algorithms')
"

# ── Bonus: Mystery Base64 string (C2 traffic simulation) ─────────────────────
python3 -c "
import base64
msg = b'hello world from malware'
b64 = base64.b64encode(msg).decode()
open('artifact_05_mystery_c2.txt', 'w').write(b64 + '\n')
print(f'[+] artifact_05_mystery_c2.txt — mystery encoded C2 string')
print(f'    Value: {b64}')
"

# ── Instructor answer key ─────────────────────────────────────────────────────
python3 -c "
import hashlib, base64
answers = [
    ('Artifact 1', 'MD5 (128-bit)', '32 hex chars per hash; also recognisable by \$1\$ prefix (Linux MD5 crypt)'),
    ('Artifact 2', 'Base64 ENCODING (not encryption)', 'Ends with =; charset is A-Za-z0-9+/=; decode directly without a key'),
    ('Artifact 3 Q5', 'OpenSSL (openssl enc)', 'Salted__ magic bytes 53 61 6c 74 65 64 5f 5f are the OpenSSL header'),
    ('Artifact 3 Q6', 'Salt prevents rainbow tables; random per encryption', '8-byte salt follows the Salted__ header'),
    ('Artifact 4 - File A', 'MD5 — 32 hex chars = 128 bits', 'd41d8cd98f00b204e9800998ecf8427e'),
    ('Artifact 4 - File B', 'SHA-1 — 40 hex chars = 160 bits', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
    ('Artifact 4 - File C', 'SHA-256 — 64 hex chars = 256 bits', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ('Artifact 4 - File D', 'SHA-512 — 128 hex chars = 512 bits', 'cf83e1357eef...'),
    ('Bonus', 'Base64', base64.b64decode('aGVsbG8gd29ybGQgZnJvbSBtYWx3YXJl').decode()),
]
lines = ['# INSTRUCTOR ANSWER KEY — drill-01-cipher-identification', '']
for item, answer, note in answers:
    lines.append(f'{item}:')
    lines.append(f'  Answer: {answer}')
    lines.append(f'  Note:   {note}')
    lines.append('')
open('INSTRUCTOR_ANSWERS.txt', 'w').write('\n'.join(lines))
print('[+] INSTRUCTOR_ANSWERS.txt created')
"

echo ""
echo "=== Generation complete ==="
echo ""
echo "Files created:"
ls -lh "$SCRIPT_DIR"
echo ""
echo "Distribute to students (without INSTRUCTOR_ANSWERS.txt):"
echo "  artifact_01_password_db.txt        — Artifact 1"
echo "  artifact_02_encoded_config.txt     — Artifact 2"
echo "  artifact_03_encrypted_config.enc   — Artifact 3"
echo "  artifact_03_header_hexdump.txt     — Artifact 3 (hex view)"
echo "  artifact_04_threat_intel_hashes.txt — Artifact 4"
echo "  artifact_05_mystery_c2.txt         — Bonus"
