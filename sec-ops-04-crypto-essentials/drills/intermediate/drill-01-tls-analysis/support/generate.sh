#!/usr/bin/env bash
# generate.sh — Regenerate TLS connection log for drill-01-tls-analysis
#
# Pre-generates tls_connections.json so students can run the analysis tasks
# without the inline Python setup script.
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating TLS connection log for drill-01-tls-analysis ==="

python3 - << 'PYEOF'
import json

connections = [
    {
        "time": "08:14:32", "src": "10.0.5.117", "dst": "52.96.21.43", "port": 443,
        "tls_ver": "TLS 1.3", "sni": "outlook.office365.com",
        "cert_cn": "*.office365.com", "cert_issuer": "DigiCert Inc",
        "cert_valid_days": 365, "cert_age_days": 120,
        "bytes_out": 2840, "bytes_in": 128400, "duration": 8.2,
        "ja3": "7dc465e8f114a23f3609b2b4a2e2dade"
    },
    {
        "time": "08:32:11", "src": "10.0.5.117", "dst": "172.217.18.46", "port": 443,
        "tls_ver": "TLS 1.3", "sni": "accounts.google.com",
        "cert_cn": "*.google.com", "cert_issuer": "GTS CA 1C3",
        "cert_valid_days": 90, "cert_age_days": 45,
        "bytes_out": 1200, "bytes_in": 8900, "duration": 3.1,
        "ja3": "7dc465e8f114a23f3609b2b4a2e2dade"
    },
    {
        "time": "09:00:01", "src": "10.0.5.117", "dst": "185.220.101.47", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "updates.telemetry-cdn.net",
        "cert_cn": "updates.telemetry-cdn.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 2,
        "bytes_out": 843, "bytes_in": 212, "duration": 1.2,
        "ja3": "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a"
    },
    {
        "time": "09:01:01", "src": "10.0.5.117", "dst": "185.220.101.47", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "updates.telemetry-cdn.net",
        "cert_cn": "updates.telemetry-cdn.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 2,
        "bytes_out": 843, "bytes_in": 212, "duration": 1.2,
        "ja3": "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a"
    },
    {
        "time": "09:02:01", "src": "10.0.5.117", "dst": "185.220.101.47", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "updates.telemetry-cdn.net",
        "cert_cn": "updates.telemetry-cdn.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 2,
        "bytes_out": 843, "bytes_in": 212, "duration": 1.2,
        "ja3": "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a"
    },
    {
        "time": "09:03:01", "src": "10.0.5.117", "dst": "185.220.101.47", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "updates.telemetry-cdn.net",
        "cert_cn": "updates.telemetry-cdn.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 2,
        "bytes_out": 843, "bytes_in": 212, "duration": 1.2,
        "ja3": "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a"
    },
    {
        "time": "09:15:44", "src": "10.0.5.117", "dst": "13.107.42.14", "port": 443,
        "tls_ver": "TLS 1.3", "sni": "teams.microsoft.com",
        "cert_cn": "*.teams.microsoft.com", "cert_issuer": "DigiCert Inc",
        "cert_valid_days": 365, "cert_age_days": 90,
        "bytes_out": 45000, "bytes_in": 210000, "duration": 182.4,
        "ja3": "7dc465e8f114a23f3609b2b4a2e2dade"
    },
    {
        "time": "11:42:08", "src": "10.0.5.117", "dst": "91.198.174.222", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "secure-files.dropbox-storage.net",
        "cert_cn": "secure-files.dropbox-storage.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 1,
        "bytes_out": 2847293, "bytes_in": 4820, "duration": 287.3,
        "ja3": "a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c"
    },
    {
        "time": "14:02:19", "src": "10.0.5.117", "dst": "10.0.1.15", "port": 8443,
        "tls_ver": "TLS 1.0", "sni": "legacy-app.internal",
        "cert_cn": "legacy-app.internal", "cert_issuer": "legacy-app.internal",
        "cert_valid_days": 3650, "cert_age_days": 2100,
        "bytes_out": 8400, "bytes_in": 42000, "duration": 12.1,
        "ja3": "7dc465e8f114a23f3609b2b4a2e2dade"
    },
]

with open('tls_connections.json', 'w') as f:
    json.dump(connections, f, indent=2)

print(f'[+] tls_connections.json created ({len(connections)} connections)')
PYEOF

# ── Threat intelligence JA3 reference ────────────────────────────────────────
python3 - << 'PYEOF'
import json

threat_intel_ja3 = {
    "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a": {
        "family": "Cobalt Strike Beacon (default profile)",
        "severity": "CRITICAL",
        "references": ["https://github.com/salesforce/ja3", "Cobalt Strike default JA3 profile"]
    },
    "a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c": {
        "family": "Custom C2 implant (APT29 TTP - simulated)",
        "severity": "CRITICAL",
        "references": ["Simulated for training purposes"]
    },
    "7dc465e8f114a23f3609b2b4a2e2dade": {
        "family": "Common browser client (Firefox/Chrome variant)",
        "severity": "BENIGN",
        "references": []
    },
}

with open('threat_intel_ja3.json', 'w') as f:
    json.dump(threat_intel_ja3, f, indent=2)
print('[+] threat_intel_ja3.json created (simulated JA3 threat intel database)')
PYEOF

# ── Instructor answer key ─────────────────────────────────────────────────────
cat > INSTRUCTOR_ANSWERS.txt << 'ANS'
# INSTRUCTOR ANSWERS — drill-01-tls-analysis
# DO NOT distribute to students

== Task 1: Initial Triage ==
Suspicious connections (initial review):
  1. 185.220.101.47 — multiple connections, tiny uniform payloads, odd domain
  2. 91.198.174.222 — very high upload (2.7 MB out, 4.8 KB in) — exfiltration pattern
  3. 10.0.1.15:8443 — TLS 1.0, self-signed cert, very old (5.7 years)

== Task 2: Beaconing ==
  IP: 185.220.101.47 (updates.telemetry-cdn.net)
  Interval: exactly 60 seconds (09:00:01, 09:01:01, 09:02:01, 09:03:01)
  Tool: Cobalt Strike Beacon default check-in interval is 60s
  Pattern: uniform byte count (843 out / 212 in) — highly regular = beaconing

== Task 3: Certificate Analysis ==
  SUSPICIOUS:
  - updates.telemetry-cdn.net: cert issued 2 days ago (brand new), Let's Encrypt, matches unknown domain
  - secure-files.dropbox-storage.net: cert issued 1 day ago, Let's Encrypt, typosquat of Dropbox
  - legacy-app.internal: self-signed, 5.7 years old, TLS 1.0

  WHY new LE cert is suspicious: Attackers register domains and immediately get free LE certs.
  A cert being 1-2 days old on an unknown domain is a strong indicator of fresh infrastructure.

== Task 4: Data Volume ==
  Suspicious: secure-files.dropbox-storage.net
  Upload: 2.7 MB out vs 4.8 KB in → ratio 590:1
  This indicates data exfiltration — large upload to an external destination.

== Task 5: TLS Version ==
  TLS 1.0 on legacy-app.internal — deprecated since 2020, vulnerable to POODLE/BEAST

== Task 6: JA3 ==
  c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a = Cobalt Strike Beacon
    → Matches beaconing connections to 185.220.101.47
  a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c = APT29-associated custom C2
    → Matches the exfiltration connection to 91.198.174.222

== Summary / Incident Report ==
  WS-117 (10.0.5.117) is compromised with Cobalt Strike Beacon.
  The beacon started at 09:00:01 with 60s intervals to C2 at 185.220.101.47.
  At 11:42:08 the attacker exfiltrated ~2.7 MB to 91.198.174.222.
  
  IOCs:
    IPs: 185.220.101.47, 91.198.174.222
    Domains: updates.telemetry-cdn.net, secure-files.dropbox-storage.net
    JA3: c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a, a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c
  
  Immediate actions:
    1. Isolate WS-117 from network immediately
    2. Block IPs 185.220.101.47 and 91.198.174.222 at perimeter firewall
    3. Check all other workstations for same JA3 hashes
ANS
echo "[+] INSTRUCTOR_ANSWERS.txt created"

echo ""
echo "=== Generation complete ==="
ls -lh "$SCRIPT_DIR"
