# Solution: Threat Hunting with STIX IOCs

**Drill:** Intermediate Drill 02 — Threat Hunting

**Session:** 13 — Advanced Topics in Security Operations

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
GHOST ANCHOR Threat Hunt — Ironclad Shipping Co.
Intermediate Drill 02 Solution
"""

import json
import re
from datetime import datetime, timezone
from collections import defaultdict

# ─── Task 1: Extract IOCs from STIX Bundle ────────────────────────────────────
with open("/data/ghost_anchor_report.json") as f:
    bundle_raw = json.load(f)

objects = bundle_raw.get("objects", [])
indicators = [o for o in objects if o.get("type") == "indicator"]

def extract_ioc_value(pattern):
    """Extract the literal value from a STIX pattern string."""
    m = re.search(r"= '([^']+)'", pattern)
    return m.group(1) if m else None

def classify_ioc(pattern):
    if "[ipv4-addr:" in pattern:
        return "ipv4"
    if "[domain-name:" in pattern:
        return "domain"
    if "[url:" in pattern:
        return "url"
    if "[file:hashes" in pattern:
        return "hash"
    return "other"

# Build lookup dicts
ioc_lookup = defaultdict(dict)  # { type: { value: indicator } }
for ind in indicators:
    ioc_type = classify_ioc(ind.get("pattern",""))
    ioc_val  = extract_ioc_value(ind.get("pattern",""))
    if ioc_val:
        ioc_lookup[ioc_type][ioc_val] = ind

print("IOC summary:")
for itype, items in ioc_lookup.items():
    print(f"  {itype:10s}: {len(items)} indicators")
    for val in items:
        print(f"    {val}")

# ─── Task 2: Hunt in Proxy Logs ───────────────────────────────────────────────
with open("/data/proxy_logs.json") as f:
    proxy_logs = json.load(f)

proxy_hits = []
for entry in proxy_logs:
    matched_ioc = None
    indicator   = None

    # Check destination IP
    dest_ip = entry.get("dest_ip","")
    if dest_ip in ioc_lookup["ipv4"]:
        matched_ioc = dest_ip
        indicator   = ioc_lookup["ipv4"][dest_ip]

    # Check destination hostname
    dest_host = entry.get("dest_host","").lower()
    if not matched_ioc:
        for domain, ind in ioc_lookup["domain"].items():
            if domain.lower() in dest_host:
                matched_ioc = domain
                indicator   = ind
                break

    # Check URL
    url = entry.get("url","")
    if not matched_ioc:
        for url_ioc, ind in ioc_lookup["url"].items():
            if url_ioc.lower() in url.lower():
                matched_ioc = url_ioc
                indicator   = ind
                break

    if matched_ioc:
        proxy_hits.append({
            "timestamp":    entry["timestamp"],
            "src_ip":       entry.get("src_ip"),
            "dest_host":    entry.get("dest_host"),
            "dest_ip":      dest_ip,
            "matched_ioc":  matched_ioc,
            "indicator":    indicator.get("name"),
            "source":       "proxy"
        })

print(f"\nProxy log hits: {len(proxy_hits)}")
affected_internal_ips = set(h["src_ip"] for h in proxy_hits)
print(f"Affected internal hosts (by IP): {sorted(affected_internal_ips)}")
for h in proxy_hits:
    print(f"  {h['timestamp']} | {h['src_ip']} → {h['dest_host']} | IOC: {h['matched_ioc']}")

# ─── Task 3: Hunt in DNS Logs ─────────────────────────────────────────────────
with open("/data/dns_logs.json") as f:
    dns_logs = json.load(f)

dns_hits = []
for entry in dns_logs:
    matched_ioc = None
    indicator   = None

    query = entry.get("query_name","").lower()
    for domain, ind in ioc_lookup["domain"].items():
        if domain.lower() in query:
            matched_ioc = domain
            indicator   = ind
            break

    if not matched_ioc:
        resp_ip = entry.get("response_ip","")
        if resp_ip in ioc_lookup["ipv4"]:
            matched_ioc = resp_ip
            indicator   = ioc_lookup["ipv4"][resp_ip]

    if matched_ioc:
        dns_hits.append({
            "timestamp":   entry["timestamp"],
            "client_ip":   entry.get("client_ip"),
            "query_name":  entry.get("query_name"),
            "response_ip": entry.get("response_ip"),
            "matched_ioc": matched_ioc,
            "indicator":   indicator.get("name"),
            "source":      "dns"
        })

print(f"\nDNS log hits: {len(dns_hits)}")
dns_clients = set(h["client_ip"] for h in dns_hits)

# Correlate proxy vs DNS
overlap = affected_internal_ips & dns_clients
print(f"Correlation — IPs in both proxy AND dns hits: {sorted(overlap)}")

# ─── Task 4: Hunt in Endpoint Events ─────────────────────────────────────────
with open("/data/endpoint_events.json") as f:
    endpoint_events = json.load(f)

endpoint_hits = []
for entry in endpoint_events:
    md5    = entry.get("md5","").lower()
    sha256 = entry.get("sha256","").lower()

    matched_ioc = None
    indicator   = None

    for h, ind in ioc_lookup["hash"].items():
        h_low = h.lower()
        if md5 == h_low or sha256 == h_low:
            matched_ioc = h
            indicator   = ind
            break

    if matched_ioc:
        endpoint_hits.append({
            "timestamp":   entry["timestamp"],
            "hostname":    entry.get("hostname"),
            "user":        entry.get("user"),
            "image":       entry.get("image"),
            "matched_ioc": matched_ioc,
            "indicator":   indicator.get("name"),
            "source":      "endpoint"
        })

print(f"\nEndpoint hits: {len(endpoint_hits)}")
for h in endpoint_hits:
    print(f"  {h['timestamp']} | {h['hostname']} ({h['user']}) | {h['image']} | IOC: {h['matched_ioc']}")

# ─── Task 5: Write Hunt Report ────────────────────────────────────────────────
all_hits = proxy_hits + dns_hits + endpoint_hits
all_hits.sort(key=lambda x: x["timestamp"])

affected_hosts_proxy_dns = sorted(affected_internal_ips | dns_clients)
affected_hosts_endpoint  = sorted(set(h["hostname"] for h in endpoint_hits))
all_affected = affected_hosts_proxy_dns + affected_hosts_endpoint

total_hits   = len(all_hits)
confirmed    = total_hits > 0

report = f"""# GHOST ANCHOR Threat Hunt Report — Ironclad Shipping Co.

**Date:** {datetime.now(timezone.utc).strftime("%Y-%m-%d")}
**Analyst:** SOC Threat Hunt Team
**Campaign:** GHOST ANCHOR — Supply Chain Intelligence

---

## 1. Executive Summary

Threat actor GHOST ANCHOR activity was **{"CONFIRMED" if confirmed else "NOT CONFIRMED"}** in Ironclad's environment.

- Total IOC hits across all data sources: **{total_hits}**
- Data sources searched: proxy logs, DNS logs, endpoint process events
- Affected internal hosts (network): **{len(affected_internal_ips)} IPs**
- Affected endpoints (hash match): **{len(affected_hosts_endpoint)} hosts**

{"**Immediate escalation recommended.** At least one internal host has made confirmed connections to GHOST ANCHOR C2 infrastructure AND has a matching malware hash on disk, indicating active compromise." if len(affected_internal_ips) > 0 and len(affected_hosts_endpoint) > 0 else "No confirmed active compromise. Some IOC matches require further investigation."}

---

## 2. IOC Hit Summary

| IOC Value | Type | Source | Affected Hosts |
|-----------|------|--------|---------------|
"""
seen_iocs = set()
for hit in all_hits:
    if hit["matched_ioc"] not in seen_iocs:
        seen_iocs.add(hit["matched_ioc"])
        hosts = hit.get("src_ip") or hit.get("client_ip") or hit.get("hostname") or "?"
        report += f"| `{hit['matched_ioc']}` | {hit['source']} | {hit['source']} | {hosts} |\n"

report += f"""
---

## 3. Timeline of Events

| Timestamp | Source | Host | IOC | Indicator Name |
|-----------|--------|------|-----|----------------|
"""
for hit in all_hits:
    host = hit.get("src_ip") or hit.get("client_ip") or hit.get("hostname") or "?"
    report += f"| {hit['timestamp']} | {hit['source']} | {host} | `{hit['matched_ioc']}` | {hit['indicator']} |\n"

report += f"""
---

## 4. Affected Hosts

### Network Contacts (proxy/DNS)
"""
for ip in sorted(affected_internal_ips | dns_clients):
    report += f"- Internal IP: `{ip}`\n"

report += "\n### Endpoint Matches (file hash)\n"
for h in endpoint_hits:
    report += f"- `{h['hostname']}` (user: {h['user']}) — matched `{h['matched_ioc']}`\n"

report += """
---

## 5. Recommended Actions

1. **Isolate affected endpoints immediately** — Any endpoint with a hash match (GHOST ANCHOR loader or RAT) should be network-isolated and submitted for forensic imaging before reimaging.

2. **Block IOC IPs and domains at perimeter** — Add all 8 GHOST ANCHOR indicators to the firewall blocklist and DNS RPZ (Response Policy Zone). Do not just block the matched IOCs — block the entire indicator set from the report.

3. **Revoke and reset credentials** — Any user account active on an affected endpoint should have credentials rotated. If the RAT was running, assume keylogging and credential theft occurred.

4. **Review outbound connections for data exfiltration** — Check `bytes_in` > 50KB in proxy logs for the affected IPs during the incident window. Large inbound responses to C2 may indicate staged payload delivery; large outbound responses may indicate data exfiltration.

5. **Deploy YARA/AV signatures** — Push updated signatures based on the file hashes in the GHOST ANCHOR report to all endpoints via EDR. Run a full scan on all machines in the same network segment as affected hosts.

6. **Notify CISO and Legal** — If customer or partner data was on affected systems, evaluate breach notification obligations under applicable regulations (GDPR, NIS2, etc.).
"""

with open("/tmp/hunt_report.md", "w") as f:
    f.write(report)

print("\nHunt report written to /tmp/hunt_report.md")
```

---

## Key Findings to Expect

The dataset is designed to show:

* **2 proxy hits** from internal IP `10.10.5.22` contacting `updates.microsooft-cdn.net`
* **2 DNS hits** from the same IP resolving the typosquatted domain
* **1 endpoint hit** on `WS-IRONCLAD-017` with an MD5 matching the GHOST ANCHOR loader hash
* Correlation: `WS-IRONCLAD-017` is in the same subnet as `10.10.5.22` (same host, different identifiers)

---

## Common Mistakes

1. **Only matching exact string equality** — Domain lookups should check if the log entry's hostname *contains* the IOC domain (to catch subdomains), not exact equality.
1. **Case sensitivity in hash matching** — Hash values should always be lowercased before comparison.
1. **Missing the typosquatting** — `microsooft-cdn.net` (double `o`) will not match `microsoft.com`. Read the IOC list carefully.
1. **Not correlating across data sources** — The most important finding is that the same internal host appears in proxy logs, DNS logs, AND has a malware hash — this turns a "suspicious" lead into a "confirmed compromise".
1. **Reporting only confirmed hits** — A threat hunt report should also state which IOCs had *no* hits, to document the scope of the search.

---

## Scoring Guide

| Criterion | Full marks if... |
|-----------|-----------------|
| Task 1 (15 pts) | All IOCs extracted; correct type classification; lookup dicts populated |
| Task 2 (20 pts) | All proxy hits found; affected IPs identified |
| Task 3 (20 pts) | All DNS hits found; overlap with proxy hits noted |
| Task 4 (20 pts) | Hash match found; hostname correlated with network findings |
| Task 5 (25 pts) | Report has all 5 sections; timeline is correct; ≥4 specific actions |
