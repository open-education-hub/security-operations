# Solution: Drill 01 (Advanced) — Full SOAR Deployment

## Key Architecture Decisions

### Workflow Architecture

```text
Splunk Detection Rules
       │ (webhook per rule type)
       ▼
Shuffle SOAR
  ├── Workflow 1: Phishing Response
  ├── Workflow 2: Brute Force/Credential Stuffing
  ├── Workflow 3: Malware Hash Enrichment
  └── Workflow 4: Daily Metrics Report
       │ (all workflows create cases)
       ▼
TheHive 5 (Case Management)
  └── Cortex (Automated IOC Analysis)
       │ (notifications)
       ▼
Slack SOC Channel
```

---

## Workflow 1: Phishing Email Response — Key Implementation Details

### Score calculation logic

```python
import json

# Inputs: $vt_url_check (VirusTotal), $abuseipdb_check, $exec (trigger)
vt_raw = $vt_url_check
vt_data = json.loads(vt_raw) if isinstance(vt_raw, str) else vt_raw

# VT score (0-100)
try:
    stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    vt_score = int(malicious / max(total, 1) * 100)
except:
    vt_score = 0

# AbuseIPDB score
try:
    abuse_raw = $abuseipdb_check
    abuse_data = json.loads(abuse_raw) if isinstance(abuse_raw, str) else abuse_raw
    abuse_score = abuse_data["data"]["abuseConfidenceScore"]
except:
    abuse_score = 0

# Composite score (weight VT more heavily for URLs)
composite = int(vt_score * 0.6 + abuse_score * 0.4)

# Determine routing
if composite >= 70:
    verdict = "MALICIOUS"
    severity = 3
    action = "quarantine_and_block"
elif composite >= 30:
    verdict = "SUSPICIOUS"
    severity = 2
    action = "quarantine_and_review"
else:
    verdict = "CLEAN"
    severity = 1
    action = "log_and_close"

return json.dumps({
    "composite_score": composite,
    "vt_score": vt_score,
    "abuse_score": abuse_score,
    "verdict": verdict,
    "thehive_severity": severity,
    "action": action
})
```

### TheHive alert creation (Workflow 1)

```text
title: "[PHISHING] $calculate_score.verdict: $exec.sender → $exec.recipient"
severity: $calculate_score.thehive_severity
description: |
  Automated phishing detection.
  Sender: $exec.sender
  URLs: $exec.urls
  VT Score: $calculate_score.vt_score%
  AbuseIPDB: $calculate_score.abuse_score%
  Composite: $calculate_score.composite_score%
  Action taken: $calculate_score.action
tags: ["phishing", "auto-enriched", "$calculate_score.verdict"]
```

---

## Workflow 2: Brute Force — Key Implementation Details

### IP loop and Splunk API query

```python
# Action: enrich_ips (loops over IP array)
# For each IP in $exec.source_ips array:

import json, requests

ip = "$exec_loop_ip"  # Loop variable in Shuffle

headers = {
    "Key": "your-abuseipdb-key",
    "Accept": "application/json"
}
resp = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    params={"ipAddress": ip, "maxAgeInDays": 90},
    headers=headers
)
data = resp.json()

result = {
    "ip": ip,
    "abuse_score": data["data"]["abuseConfidenceScore"],
    "total_reports": data["data"]["totalReports"],
    "is_tor": data["data"]["isTor"],
    "country": data["data"]["countryCode"]
}
return json.dumps(result)
```

### Splunk API context query

```python
# Action: query_splunk_context
# Check if source IPs hit other systems

import requests, base64, json

splunk_url = "http://splunk:8089"
auth = base64.b64encode(b"admin:Splunk2026Admin!").decode()

search_query = f"""
search index=soc_events
src_ip IN ({",".join([f'"{ip}"' for ip in ["91.108.4.1","91.108.4.2","91.108.4.3"]])})
earliest=-24h
| stats count by src_ip, dest_host, dest_port
| sort -count
"""

resp = requests.post(
    f"{splunk_url}/services/search/jobs",
    headers={"Authorization": f"Basic {auth}"},
    data={"search": search_query, "output_mode": "json", "exec_mode": "oneshot"}
)

results = resp.json().get("results", [])
return json.dumps({"context_hits": len(results), "details": results[:10]})
```

---

## Workflow 3: Malware Hash — Extended with MalwareBazaar

### Parallel enrichment (run simultaneously)

```text
[Webhook]
    │
    ├── [VirusTotal Hash Check] ────────┐
    └── [MalwareBazaar Check]  ─────── ┤
                                        │
                                [Wait for both to complete]
                                        │
                               [Calculate Combined Verdict]
```

### Combined verdict with both sources

```python
import json

# Parse VT
vt_raw = $vt_hash_check
vt_data = json.loads(vt_raw) if isinstance(vt_raw, str) else vt_raw

try:
    stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    vt_malicious = stats.get("malicious", 0)
    vt_total = sum(stats.values())
    vt_score = int(vt_malicious / max(vt_total, 1) * 100)
except:
    vt_score = 0

# Parse MalwareBazaar
mb_raw = $malwarebazaar_check
mb_data = json.loads(mb_raw) if isinstance(mb_raw, str) else mb_raw
mb_found = mb_data.get("query_status") == "ok"
mb_name = mb_data.get("data", [{}])[0].get("signature", "") if mb_found else ""

# Combined decision
if vt_score >= 50 or mb_found:
    verdict = "MALICIOUS"
    severity = 3
elif vt_score >= 10:
    verdict = "SUSPICIOUS"
    severity = 2
else:
    verdict = "CLEAN"
    severity = 1

return json.dumps({
    "verdict": verdict,
    "vt_score": vt_score,
    "mb_found": mb_found,
    "malware_name": mb_name,
    "thehive_severity": severity
})
```

---

## Workflow 4: Daily Metrics

### Complete metrics script

```python
import json
from datetime import datetime, timedelta

# Get data from previous actions
# Assume $get_thehive_stats returns TheHive stats

now = datetime.now()
yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")

# Simulate TheHive query result (in real workflow, from TheHive API)
stats = {
    "total_alerts": 127,
    "auto_closed": 82,
    "pending_review": 31,
    "escalated": 14,
    "by_type": {
        "phishing": 52,
        "brute_force": 28,
        "malware": 11,
        "other": 36
    }
}

automation_rate = round(stats["auto_closed"] / max(stats["total_alerts"], 1) * 100, 1)
analyst_queue = stats["total_alerts"] - stats["auto_closed"]

report = f"""📊 *Daily SOC Report* — {yesterday}

*Alert Volume*: {stats["total_alerts"]} alerts received
*Auto-resolved*: {stats["auto_closed"]} ({automation_rate}% automation rate)
*Analyst review queue*: {analyst_queue} alerts

*By Type*: Phishing {stats["by_type"]["phishing"]} | BruteForce {stats["by_type"]["brute_force"]} | Malware {stats["by_type"]["malware"]} | Other {stats["by_type"]["other"]}

*Escalated*: {stats["escalated"]} alerts escalated to L2
"""

return report
```

---

## Known Limitations in Lab Environment

1. **Splunk scheduler may not trigger in time** — For testing, always use "Run Now" in Splunk saved search or send directly to Shuffle webhook.

1. **VirusTotal rate limits** — Free tier: 4 req/min. Add `Wait: 15000ms` between VT calls.

1. **Slack interactive components** — Approval workflows require Slack App with interactive components. In lab, document the approval step as a manual action (analyst responds to Slack message).

1. **Container-to-container networking** — All containers must be on `soc-net`. Use container hostnames (e.g., `http://thehive:9000`) not `localhost`.

1. **TheHive first-start setup** — The first time TheHive starts, you must manually create the admin account via the web UI.

---

## Testing Verification

Examiner should verify:

* [ ] All 3 workflows exist in Shuffle UI
* [ ] Test webhook call produces execution in Shuffle
* [ ] TheHive has alerts/cases from workflow executions
* [ ] Slack webhook received notification (or mock demonstrated)
* [ ] Daily metrics workflow exists with schedule trigger
* [ ] Architecture diagram accurately reflects implementation
