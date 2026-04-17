# Drill 01 (Intermediate): TLS Traffic Analysis

> **Level:** Intermediate
> **Time:** 45–60 minutes
> **Tools:** Docker, tshark, OpenSSL, Python
> **Prerequisites:** Demo 04, Guide 03

---

## Scenario

Your SIEM has flagged unusual TLS traffic patterns from a workstation (WS-117, 10.0.5.117).
The workstation is used by a financial analyst.
You have been given simulated TLS connection metadata and must analyze it for threats.

**No internet access is required.** All analysis is performed on simulated data.

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl python3 tshark 2>/dev/null | tail -3
mkdir -p /drill && cd /drill
```

Generate the challenge data:

```bash
python3 << 'SETUP_EOF'
import json, hashlib, random
from datetime import datetime, timedelta

# Simulated TLS connection log from network sensor
# Format: timestamp, src_ip, dst_ip, dst_port, tls_version, sni, cert_subject,
#         cert_issuer, cert_days_valid, cert_not_before_ago_days,
#         bytes_sent, bytes_recv, duration_sec, ja3_hash

connections = [
    # Normal business traffic
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
    # SUSPICIOUS: beaconing (regular intervals)
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
    # More normal traffic
    {
        "time": "09:15:44", "src": "10.0.5.117", "dst": "13.107.42.14", "port": 443,
        "tls_ver": "TLS 1.3", "sni": "teams.microsoft.com",
        "cert_cn": "*.teams.microsoft.com", "cert_issuer": "DigiCert Inc",
        "cert_valid_days": 365, "cert_age_days": 90,
        "bytes_out": 45000, "bytes_in": 210000, "duration": 182.4,
        "ja3": "7dc465e8f114a23f3609b2b4a2e2dade"
    },
    # SUSPICIOUS: large data exfiltration
    {
        "time": "11:42:08", "src": "10.0.5.117", "dst": "91.198.174.222", "port": 443,
        "tls_ver": "TLS 1.2", "sni": "secure-files.dropbox-storage.net",
        "cert_cn": "secure-files.dropbox-storage.net", "cert_issuer": "Let's Encrypt",
        "cert_valid_days": 90, "cert_age_days": 1,
        "bytes_out": 2847293, "bytes_in": 4820, "duration": 287.3,
        "ja3": "a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c"
    },
    # SUSPICIOUS: old TLS version with weak cipher note
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

print("Generated tls_connections.json with", len(connections), "TLS connections")
print("Begin your analysis...")
SETUP_EOF
```

---

## Task 1: Initial Triage

Read and display the connection log:

```bash
python3 << 'EOF'
import json

with open('tls_connections.json') as f:
    conns = json.load(f)

print(f"{'Time':>10} {'Destination':>22} {'SNI':<38} {'TLS':>7} {'Out KB':>8} {'In KB':>8}")
print("-" * 100)
for c in conns:
    print(f"{c['time']:>10} {c['dst']:>22}:{c['port']:<5} {c['sni']:<38} {c['tls_ver']:>7} "
          f"{c['bytes_out']//1024:>7}K {c['bytes_in']//1024:>7}K")
EOF
```

**Question 1:** Without deeper analysis, which connections stand out as potentially suspicious based on initial review?
List them and explain why.

---

## Task 2: Beaconing Detection

```bash
python3 << 'EOF'
import json
from collections import defaultdict

with open('tls_connections.json') as f:
    conns = json.load(f)

# Group by destination
by_dest = defaultdict(list)
for c in conns:
    by_dest[c['dst']].append(c)

print("=== Beaconing Analysis ===")
print()
for dst, cs in sorted(by_dest.items(), key=lambda x: -len(x[1])):
    if len(cs) > 1:
        print(f"Destination: {dst} ({cs[0]['sni']}) — {len(cs)} connections")
        times = [c['time'] for c in cs]
        for t in times:
            print(f"  {t}")
        if len(cs) >= 2:
            # Calculate intervals
            from datetime import datetime
            time_objs = [datetime.strptime(t, "%H:%M:%S") for t in times]
            intervals = [(time_objs[i+1] - time_objs[i]).seconds for i in range(len(time_objs)-1)]
            print(f"  Intervals (seconds): {intervals}")
            if len(set(intervals)) == 1:
                print(f"  *** BEACONING DETECTED: perfectly regular {intervals[0]}s interval ***")
        print()
EOF
```

**Question 2:** Which connection shows a beaconing pattern?
What is the interval?
What malware tool commonly uses regular-interval beaconing?

---

## Task 3: Certificate Analysis

```bash
python3 << 'EOF'
import json
from datetime import datetime

with open('tls_connections.json') as f:
    conns = json.load(f)

print("=== Certificate Analysis ===")
print()
print(f"{'SNI':<40} {'Issuer':<20} {'Age':>8} {'Valid':>8} {'Risk'}")
print("-" * 95)

for c in conns:
    risks = []
    if c['cert_age_days'] < 7:
        risks.append(f"new cert ({c['cert_age_days']}d)")
    if c['cert_valid_days'] <= 1:
        risks.append("expired!")
    if c['cert_cn'] == c['cert_issuer']:
        risks.append("self-signed")
    if c['cert_issuer'] == "Let's Encrypt" and c['cert_age_days'] < 5:
        risks.append("fresh LE cert")

    risk_str = ", ".join(risks) if risks else "OK"
    print(f"{c['sni']:<40} {c['cert_issuer']:<20} {c['cert_age_days']:>7}d {c['cert_valid_days']:>7}d  {risk_str}")
EOF
```

**Question 3:** Which certificate(s) are suspicious?
Why is a brand-new Let's Encrypt certificate on an unknown domain suspicious?

---

## Task 4: Data Volume Analysis

```bash
python3 << 'EOF'
import json

with open('tls_connections.json') as f:
    conns = json.load(f)

print("=== Data Volume Analysis ===")
print()
print(f"{'Time':>10} {'SNI':<40} {'Out':>10} {'In':>10} {'Ratio':>8} {'Flag'}")
print("-" * 88)

for c in conns:
    out_kb = c['bytes_out'] / 1024
    in_kb = c['bytes_in'] / 1024
    ratio = c['bytes_out'] / max(c['bytes_in'], 1)
    flag = "*** SUSPICIOUS UPLOAD ***" if ratio > 10 and out_kb > 100 else ""
    print(f"{c['time']:>10} {c['sni']:<40} {out_kb:>9.1f}K {in_kb:>9.1f}K {ratio:>7.1f}x  {flag}")
EOF
```

**Question 4:** Which connection has an anomalous outbound/inbound ratio?
What does a high upload-to-download ratio suggest in a security context?

---

## Task 5: TLS Version Audit

```bash
python3 << 'EOF'
import json

with open('tls_connections.json') as f:
    conns = json.load(f)

print("=== TLS Version Audit ===")
version_counts = {}
for c in conns:
    ver = c['tls_ver']
    version_counts[ver] = version_counts.get(ver, 0) + 1

for ver, count in sorted(version_counts.items()):
    status = {
        "TLS 1.0": "DEPRECATED — do not use",
        "TLS 1.1": "DEPRECATED — do not use",
        "TLS 1.2": "Acceptable (if strong ciphers)",
        "TLS 1.3": "Recommended",
    }.get(ver, "Unknown")
    print(f"  {ver}: {count} connections — {status}")

print()
old_tls = [c for c in conns if c['tls_ver'] in ('TLS 1.0', 'TLS 1.1')]
for c in old_tls:
    print(f"  ⚠ Old TLS: {c['sni']} ({c['dst']}) — {c['tls_ver']}")
EOF
```

---

## Task 6: JA3 Fingerprint Analysis

```bash
python3 << 'EOF'
import json
from collections import Counter

with open('tls_connections.json') as f:
    conns = json.load(f)

# Simulated threat intel JA3 database
threat_intel_ja3 = {
    "c9e4e0bd0b45f4f4e5b4e4b2f9d87b3a": "Cobalt Strike Beacon (default)",
    "a5b2f81c3d7e4f2b8a9c1e4d6f8b0a2c": "Custom C2 implant (APT29 TTP)",
    "7dc465e8f114a23f3609b2b4a2e2dade": "Common browser (Firefox/Chrome variant)",
}

print("=== JA3 Fingerprint Analysis ===")
print()
ja3_counts = Counter(c['ja3'] for c in conns)
for ja3, count in ja3_counts.items():
    intel = threat_intel_ja3.get(ja3, "Unknown — not in threat intel")
    alert = " *** MALWARE ***" if ja3 in threat_intel_ja3 and "browser" not in threat_intel_ja3[ja3].lower() else ""
    print(f"  JA3: {ja3}")
    print(f"       Count: {count} | Intel: {intel}{alert}")

    if ja3 in threat_intel_ja3 and "browser" not in threat_intel_ja3[ja3].lower():
        matching_conns = [c for c in conns if c['ja3'] == ja3]
        for c in matching_conns:
            print(f"       Connection: {c['time']} → {c['sni']} ({c['dst']})")
    print()
EOF
```

**Question 5:** Which JA3 hashes match known malware?
What tool is identified?

---

## Task 7: Incident Report

Write a brief incident report covering:

1. **Summary:** What happened on WS-117?
1. **Indicators of Compromise (IOCs):** List all suspicious IPs, domains, and hashes
1. **Timeline:** Reconstruct the likely attack timeline
1. **Risk Assessment:** What data may have been exfiltrated?
1. **Immediate Recommendations:** Top 3 actions to take right now

---

**Time limit:** 60 minutes

**Pass criteria:** Complete Tasks 1-6 with correct findings, plus a coherent incident report
