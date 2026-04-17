#!/usr/bin/env bash
# generate.sh — Regenerate all support artifacts for guide-02-hashing-practice
# Run this script to recreate sample files and checksums from scratch.
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating support files for guide-02-hashing-practice ==="

# ── 1. Sample report files ────────────────────────────────────────────────────
echo "Malware analysis report - sample 001" > report_001.txt
echo "Malware analysis report - sample 002" > report_002.txt
cp report_001.txt report_001_copy.txt
echo "[+] report_001.txt, report_002.txt, report_001_copy.txt created"

# ── 2. Software release files for integrity demonstration ─────────────────────
mkdir -p release_v3.0

cat > release_v3.0/soc_monitor.py << 'PYEOF'
#!/usr/bin/env python3
# SOC Monitor v3.0 — official release build 20240115
# Monitors endpoint telemetry and forwards events to SIEM
import sys, socket, logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def main():
    logging.info("Starting SOC monitoring agent v3.0")
    logging.info(f"Hostname: {socket.gethostname()}")
    logging.info("Agent running — forwarding telemetry to siem.corp.local:514")

if __name__ == '__main__':
    main()
PYEOF

cat > release_v3.0/config.yaml << 'YAMLEOF'
version: "3.0"
log_level: INFO
siem_endpoint: siem.corp.local
siem_port: 514
output: /var/log/soc_monitor.log
heartbeat_interval_sec: 60
YAMLEOF

cat > release_v3.0/README.txt << 'TXTEOF'
SOC Monitor v3.0
================
Install: python3 soc_monitor.py --install
Requires: Python 3.8+
Support: soc-tools@corp.local
TXTEOF

echo "[+] release_v3.0/ directory created"

# ── 3. Create legitimate SHA256SUMS manifest (before tampering) ───────────────
cd release_v3.0
sha256sum soc_monitor.py config.yaml README.txt > ../SHA256SUMS
cd ..
echo "[+] SHA256SUMS manifest created"

# ── 4. Security tool file with its checksum (for tamper-detection exercise) ───
cat > security_tool_v2.1.sh << 'EOF'
#!/bin/bash
# Security Analysis Tool v2.1 - OFFICIAL RELEASE
# Build: 20240115-a7f3c1
echo "Installing SOC analysis tools..."
echo "This is the legitimate, vendor-signed software."
EOF
sha256sum security_tool_v2.1.sh > security_tool_v2.1.sh.sha256
echo "[+] security_tool_v2.1.sh + .sha256 created"

# ── 5. Pre-computed hash values for reference ─────────────────────────────────
python3 -c "
import hashlib
files = {
    'report_001.txt': open('report_001.txt', 'rb').read(),
    'report_002.txt': open('report_002.txt', 'rb').read(),
    'security_tool_v2.1.sh': open('security_tool_v2.1.sh', 'rb').read(),
}
lines = ['# Pre-computed hashes — reference for instructors', '# algorithm  filename  hash']
for name, data in files.items():
    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
        h = hashlib.new(algo, data).hexdigest()
        lines.append(f'{algo.upper():<8}  {name:<30}  {h}')
    lines.append('')
open('known_hashes.txt', 'w').write('\n'.join(lines))
print('[+] known_hashes.txt created (instructor reference)')
"

echo ""
echo "=== Generation complete ==="
echo ""
echo "Files created:"
ls -lh "$SCRIPT_DIR"
echo ""
echo "Guide exercises use:"
echo "  report_001.txt + report_002.txt + report_001_copy.txt  → Exercise 1 (hash comparison)"
echo "  security_tool_v2.1.sh + .sha256                       → Exercise 3 (tamper detection)"
echo "  release_v3.0/ + SHA256SUMS                            → Exercise 4 (multi-file checksum)"
echo "  known_hashes.txt                                       → Instructor reference"
