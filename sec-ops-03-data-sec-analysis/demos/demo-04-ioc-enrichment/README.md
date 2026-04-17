# Demo 04: Enriching Alerts with IOCs Using MISP and VirusTotal API

**Difficulty:** Intermediate

**Time:** ~45 minutes

**Prerequisites:** Python 3.x, optional VirusTotal API key (free), Docker

## Overview

This demo shows how to enrich security alerts with threat intelligence.
When a SIEM fires an alert containing an IP address, domain, or file hash, analysts need context: *Is this IP known to be malicious?
What malware family does this hash belong to?*

We will:

1. Run a local **MISP** instance populated with sample IOCs
1. Write a Python enrichment script that queries MISP and VirusTotal
1. Integrate enrichment into a simulated alert workflow
1. Build a Docker-based enrichment microservice

## Architecture

```text
  ┌──────────────────┐        ┌────────────────────────────┐
  │   Alert Source   │        │    Enrichment Service       │
  │   (simulated)    │──────▶ │                            │
  │                  │        │  1. Parse IOC from alert   │
  └──────────────────┘        │  2. Query MISP             │
                              │  3. Query VirusTotal API   │
  ┌──────────────────┐        │  4. Merge intelligence     │
  │      MISP        │◀──────▶│  5. Return enriched alert  │
  │  (local TI DB)   │        └────────────────────────────┘
  └──────────────────┘                    │
                                          ▼
  ┌──────────────────────────────────────────────────────────┐
  │              Enriched Alert Output                        │
  │  { "ip": "185.220.101.5",                                │
  │    "misp_events": 3,                                      │
  │    "misp_tags": ["Emotet", "TLP:GREEN"],                 │
  │    "vt_malicious": 45,                                    │
  │    "threat_score": "HIGH",                               │
  │    "recommended_action": "Block + Incident" }            │
  └──────────────────────────────────────────────────────────┘
```

## Step 1: Start MISP

```console
docker compose up -d

# MISP takes 3-5 minutes to initialize
docker compose logs -f misp | grep "MISP is ready"
```

Access MISP: http://localhost:80

* Login: `admin@admin.test` / `admin`
* You will be prompted to change the password on first login

### Load Sample IOCs

```console
# Load pre-built MISP event with sample IOCs
docker exec demo04-misp-populate python3 /populate/populate_misp.py
```

This creates MISP events containing:

* Known C2 IP addresses
* Malicious domain names
* Malware file hashes (Emotet, Cobalt Strike, Mimikatz)
* IOCs tagged with MITRE ATT&CK techniques

## Step 2: Review the Enrichment Script

Examine `scripts/enrich.py`.
It implements:

```python
def enrich_ioc(ioc_value, ioc_type):
    """
    Enrich an IOC against MISP and VirusTotal.
    Returns a combined intelligence report.
    """
    result = {
        "ioc": ioc_value,
        "type": ioc_type,
        "misp": query_misp(ioc_value, ioc_type),
        "virustotal": query_virustotal(ioc_value, ioc_type),
        "threat_score": calculate_threat_score(...)
    }
    return result
```

## Step 3: Run the Enrichment Script

```bash
# Install dependencies
pip install pymisp requests

# Test with a known malicious IP (pre-loaded in MISP)
python3 scripts/enrich.py --type ip --value 185.220.101.5

# Test with a domain
python3 scripts/enrich.py --type domain --value update-services.ru

# Test with a file hash (SHA256)
python3 scripts/enrich.py --type hash --value 44d88612fea8a8f36de82e1278abb02f3524ec74

# Process a batch of IOCs from a file
python3 scripts/enrich.py --batch scripts/sample_iocs.txt
```

Expected output:

```json
{
  "ioc": "185.220.101.5",
  "type": "ip-dst",
  "misp": {
    "found": true,
    "events": 2,
    "threat_actor": "Emotet Distribution Network",
    "tags": ["tlp:green", "misp-galaxy:threat-actor=\"Emotet\""],
    "first_seen": "2024-01-15",
    "last_seen": "2024-03-10"
  },
  "virustotal": {
    "malicious": 32,
    "suspicious": 5,
    "undetected": 53,
    "country": "DE",
    "as_owner": "Hetzner Online GmbH"
  },
  "threat_score": "HIGH",
  "confidence": 0.87,
  "recommended_action": "Block at firewall, open incident ticket"
}
```

## Step 4: Run Automated Alert Processing

The `alert-processor` container watches for simulated SIEM alerts and enriches them automatically:

```console
# Watch the alert processor output
docker compose logs -f alert-processor
```

You will see alerts being enriched in real time.
The processor:

1. Receives a raw alert: `{"alert": "Suspicious connection", "src_ip": "185.220.101.5"}`
1. Extracts the IOC: IP address `185.220.101.5`
1. Queries MISP → finds 2 matching events, Emotet attribution
1. Queries VirusTotal → 32/90 engines flag it as malicious
1. Outputs enriched alert with recommended action

## Step 5: VirusTotal API Configuration (Optional)

If you have a VirusTotal API key, configure it:

```console
export VT_API_KEY="your_api_key_here"
python3 scripts/enrich.py --type ip --value 8.8.8.8 --vt-key $VT_API_KEY
```

Without an API key, the script uses mock VT responses from a local cache.

## Step 6: Tear Down

```console
docker compose down -v
```

## Key Takeaways

1. **Enrichment adds context** — an IP address alone is noise; an IP tagged as Emotet C2 by MISP with 32/90 VT detections is actionable intelligence.
1. **MISP is a community resource** — in production, subscribe to external MISP feeds (Abuse.ch, URLhaus, CIRCL) to get community threat intelligence.
1. **Automate enrichment** — manually looking up every IOC is not scalable. Integrate enrichment into your alert pipeline so analysts get context before they even open a ticket.
1. **Score and prioritize** — not all IOC matches are equal. A hash matching 70/90 AV engines on VT is higher priority than a hash matching 2/90.
