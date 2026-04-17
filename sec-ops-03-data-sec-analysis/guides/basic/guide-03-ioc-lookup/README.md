# Guide 03: Looking Up IOCs Using VirusTotal and MISP

**Level:** Basic

**Time:** ~25 minutes

**Prerequisites:** Python 3.x installed; optional VirusTotal account (free)

## What You Will Learn

* How to use the VirusTotal web interface for manual IOC lookups
* How to use the VirusTotal API v3 with Python
* How to search MISP for known IOCs
* How to interpret results and assess threat confidence

## Part 1: VirusTotal Manual Lookup

### Step 1: Access VirusTotal

VirusTotal (https://www.virustotal.com) is free for basic lookups.
Create a free account to increase your daily quota and access graph relationships.

### Step 2: Look Up a File Hash

1. Go to VirusTotal
1. Click the **Search** tab
1. Paste a SHA256 hash: `44d88612fea8a8f36de82e1278abb02f3524ec74`
1. Review results:
   * **Detection ratio:** `70/72` means 70 of 72 AV engines detected it as malicious
   * **Community score:** Crowdsourced reputation
   * **Details tab:** File type, size, compilation timestamp
   * **Relations tab:** Related URLs, domains, and IPs the file contacts

### Step 3: Look Up a Domain

1. Enter: `malicious-c2.example.com` (or any domain from your threat intelligence)
1. Review:
   * **Vendors' results:** How many engines flag it as phishing/malware/spam
   * **Details tab:** Registrar, creation date, DNS records
   * **Relations tab:** IP resolutions, files communicating with this domain
   * **Historical DNS tab:** Past IP addresses (useful for pivoting)

### Step 4: Look Up an IP Address

1. Enter: `185.220.101.5`
1. Review:
   * **Detection:** Which security vendors flag this IP
   * **Details:** Country, ASN, owner (hosting provider)
   * **Relations:** Domains hosted on this IP, files connecting to it

### Key VirusTotal Reading Guide

| Detection Ratio | Interpretation |
|----------------|----------------|
| 60+ / 72 | Near-certain malware — high confidence |
| 20–59 / 72 | Likely malicious — investigate further |
| 5–19 / 72 | Suspicious — could be PUP or false positives |
| 1–4 / 72 | Potentially suspicious — verify context |
| 0 / 72 | Clean by all engines — may still be new/unknown malware |

> **Important:** A 0/72 result does not mean a file is safe. Brand-new malware (zero-day) will not be detected. Rely on behavioral analysis (sandbox detonation) for unknown files.

---

## Part 2: VirusTotal API

For automating IOC lookups, use the VirusTotal API v3.

### Setup

```console
# Install the requests library
pip install requests

# Set your API key as environment variable (never hardcode it!)
export VT_API_KEY="your_api_key_here"
```

### Hash Lookup Script

```python
#!/usr/bin/env python3
"""
vt_lookup.py — Simple VirusTotal IOC lookup tool
Usage: python3 vt_lookup.py <hash_or_ip_or_domain>
"""
import os
import sys
import requests

API_KEY = os.environ.get("VT_API_KEY", "")
BASE    = "https://www.virustotal.com/api/v3"

def lookup_file(sha256):
    """Look up a file hash."""
    r = requests.get(
        f"{BASE}/files/{sha256}",
        headers={"x-apikey": API_KEY},
        timeout=15
    )
    if r.status_code == 404:
        return {"status": "NOT_FOUND"}
    if r.status_code != 200:
        return {"error": r.status_code}

    d = r.json()["data"]["attributes"]
    stats = d["last_analysis_stats"]
    total = sum(stats.values())
    return {
        "type":      "file",
        "name":      d.get("meaningful_name", "unknown"),
        "malicious": stats["malicious"],
        "total":     total,
        "detection": f"{stats['malicious']}/{total}",
        "tags":      d.get("tags", []),
    }

def lookup_domain(domain):
    """Look up a domain."""
    r = requests.get(
        f"{BASE}/domains/{domain}",
        headers={"x-apikey": API_KEY},
        timeout=15
    )
    if r.status_code != 200:
        return {"error": r.status_code}

    d = r.json()["data"]["attributes"]
    stats = d.get("last_analysis_stats", {})
    return {
        "type":       "domain",
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "registrar":  d.get("registrar", "unknown"),
        "created":    d.get("creation_date", "unknown"),
        "categories": d.get("categories", {}),
    }

def lookup_ip(ip):
    """Look up an IP address."""
    r = requests.get(
        f"{BASE}/ip_addresses/{ip}",
        headers={"x-apikey": API_KEY},
        timeout=15
    )
    if r.status_code != 200:
        return {"error": r.status_code}

    d = r.json()["data"]["attributes"]
    stats = d.get("last_analysis_stats", {})
    return {
        "type":       "ip",
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "country":    d.get("country", "unknown"),
        "as_owner":   d.get("as_owner", "unknown"),
        "network":    d.get("network", "unknown"),
    }

def score(result):
    """Simple risk score: HIGH / MEDIUM / LOW / CLEAN."""
    m = result.get("malicious", 0)
    s = result.get("suspicious", 0)
    if m >= 10:   return "HIGH"
    if m >= 3:    return "MEDIUM"
    if m + s > 0: return "LOW"
    return "CLEAN"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 vt_lookup.py <value>")
        sys.exit(1)

    value = sys.argv[1]

    # Auto-detect type
    import re
    if re.match(r"^[0-9a-fA-F]{32,64}$", value):
        result = lookup_file(value)
    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
        result = lookup_ip(value)
    else:
        result = lookup_domain(value)

    result["risk"] = score(result)
    import json
    print(json.dumps(result, indent=2))
```

**Test it:**

```console
# File hash (EICAR test file)
python3 vt_lookup.py 44d88612fea8a8f36de82e1278abb02f3524ec74

# IP address
python3 vt_lookup.py 8.8.8.8

# Domain
python3 vt_lookup.py google.com
```

---

## Part 3: MISP Lookup

MISP provides community-contributed threat intelligence.
Lookups can be done via:

1. The web interface (manual)
1. The REST API
1. The `PyMISP` Python library

### MISP Web Interface Search

1. Log in to your MISP instance
1. Click **Event Actions** → **Search Attributes**
1. Enter the IOC value in the **Value** field
1. Click **Search**

Results show:

* Which events contain this IOC
* Tags (TLP level, threat actor, campaign)
* First and last seen dates
* Relationship to other IOCs

### MISP Python API

```python
#!/usr/bin/env python3
"""
misp_lookup.py — Query a MISP instance for an IOC
"""
import os
import sys

MISP_URL = os.getenv("MISP_URL", "https://misp.your-org.com")
MISP_KEY = os.getenv("MISP_KEY", "YOUR_API_KEY")

try:
    from pymisp import PyMISP
except ImportError:
    print("Install: pip install pymisp")
    sys.exit(1)

def search_misp(value):
    """Search MISP for an IOC and return formatted results."""
    misp = PyMISP(MISP_URL, MISP_KEY, False)
    results = misp.search(value=value, pythonify=True)

    if not results:
        print(f"[~] Not found in MISP: {value}")
        return

    print(f"[!] Found in {len(results)} MISP event(s):")
    for event in results:
        print(f"\n  Event: {event.info}")
        print(f"  Date:  {event.date}")
        print(f"  Threat Level: {event.threat_level_id}")

        matching_attrs = [a for a in event.attributes if a.value == value]
        for attr in matching_attrs:
            print(f"  IOC: [{attr.type}] {attr.value}")
            if attr.comment:
                print(f"       Comment: {attr.comment}")
            for tag in attr.tags:
                print(f"       Tag: {tag.name}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 misp_lookup.py <ioc_value>")
        sys.exit(1)
    search_misp(sys.argv[1])
```

---

## Part 4: Interpreting Results and Making Decisions

When both MISP and VirusTotal return results, combine them for a complete picture:

| Scenario | Interpretation | Action |
|----------|---------------|--------|
| High VT detections + MISP match | Almost certainly malicious, attribution available | Block immediately, open incident |
| High VT detections, no MISP | Malicious but novel/unattributed | Block, investigate, consider sharing to MISP |
| Low VT detections + MISP match | Targeted/rare malware, known to community | Block, high-priority investigation |
| 0 VT detections + no MISP match | Unknown — possible zero-day or false positive | Sandbox analysis required |
| 0 VT detections + no MISP match + unusual behavior | Suspicious — possible targeted attack | Investigate behavior, not just indicators |

### The Limitations of IOC-Based Detection

1. **Hash evasion:** Recompiling malware with minor changes produces a completely different hash. VT won't match it.
1. **IP rotation:** C2 operators change IPs regularly. A 3-week-old IP list may be completely outdated.
1. **False positives:** Shared hosting means a malicious VT-flagged IP might also host legitimate sites.
1. **False context:** An IP flagged in MISP as "associated with APT-X" in 2022 may be reassigned to a new legitimate owner in 2024.

> Always combine IOC-based lookups with behavioral analysis and context from your environment (asset inventory, user activity baseline).
