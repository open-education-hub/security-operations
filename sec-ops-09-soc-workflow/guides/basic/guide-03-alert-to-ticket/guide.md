# Guide 03: Creating an Alert-to-Ticket Workflow in Splunk

**Level**: Basic

**Estimated time**: 45 minutes

**Prerequisites**: Access to Splunk (see Demo 03 for Docker setup); basic Splunk SPL knowledge

---

## Learning Objectives

After this guide, you will be able to:

* Configure Splunk to generate structured security alerts
* Create saved searches that fire on security conditions
* Automatically populate ticket fields from SIEM alert data
* Configure Splunk alert actions (webhook, email, script)
* Build an end-to-end alert-to-ticket pipeline without SOAR

---

## Section 1: Splunk Alert Architecture

Splunk generates security tickets through a pipeline:

```text
Log Sources → Splunk Indexer → Detection Rule (Search) → Alert Trigger
    → Alert Action (webhook / email / script) → Ticketing System
```

**Key Splunk concepts for alert-to-ticket:**

| Concept | Description |
|---------|-------------|
| **Index** | Storage partition for log data (e.g., `index=soc_events`) |
| **Sourcetype** | Log format identifier (e.g., `sourcetype=cisco:asa`) |
| **Saved Search** | A stored SPL query that can run on a schedule |
| **Alert** | A saved search with a trigger condition and action |
| **Lookup** | A reference table (e.g., asset criticality table) |
| **Field extraction** | Parsing structured fields from raw log text |

---

## Section 2: Configuring the Data Pipeline

### 2.1 Create the security events index

```console
# Via Splunk CLI
/opt/splunk/bin/splunk add index soc_events -maxTotalDataSizeMB 10000 -maxDataSize auto

# Or via Splunk Web:
# Settings → Indexes → New Index
# Index Name: soc_events
# Max size: 10 GB
```

### 2.2 Configure HEC for alert ingestion

HTTP Event Collector (HEC) allows direct event injection — useful for testing:

1. Settings → Data Inputs → HTTP Event Collector
1. Global Settings: Enable HEC, port 8088
1. New Token:
   * Name: `soc-alerts-hec`
   * Source type: `soc:alert`
   * Default index: `soc_events`

### 2.3 Create asset criticality lookup

Create `asset_criticality.csv` in `$SPLUNK_HOME/etc/apps/search/lookups/`:

```csv
hostname,ip_address,criticality,tier,owner,environment
dc01,10.0.0.10,critical,1,IT-Infra,production
dc02,10.0.0.11,critical,1,IT-Infra,production
payroll-srv,10.0.1.50,high,2,Finance,production
web01,10.0.2.10,high,2,WebOps,production
workstation-01,10.0.100.50,medium,3,alice@company.com,production
workstation-02,10.0.100.51,medium,3,bob@company.com,production
lab-vm-01,192.168.1.10,low,4,Security,lab
```

Define the lookup in `transforms.conf`:

```ini
[asset_criticality]
filename = asset_criticality.csv
case_sensitive_match = false
match_type = WILDCARD(hostname)
```

---

## Section 3: Detection Rule Examples

### 3.1 Brute Force Detection

```spl
index=soc_events sourcetype="windows:security" EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, dest_user, dest_host
| where count > 20
| lookup asset_criticality hostname as dest_host OUTPUT criticality, tier
| eval severity = case(
    criticality="critical" AND count>50, "P1",
    criticality="critical" AND count>20, "P2",
    criticality="high" AND count>50, "P2",
    count>100, "P2",
    true(), "P3"
  )
| table _time, src_ip, dest_user, dest_host, criticality, count, severity
```

**Alert settings**:

* Trigger when: Number of results > 0
* Schedule: Every 5 minutes
* Time range: Last 10 minutes

### 3.2 Phishing Indicator Detection

```spl
index=soc_events sourcetype="exchange:transport"
(subject="*urgent*" OR subject="*suspended*" OR subject="*verify*" OR subject="*password*")
NOT (from_domain IN ("company.com", "trusted-partner.com"))
| lookup asset_criticality hostname as recipient_host OUTPUT criticality
| eval alert_type = "phishing_indicator",
       ticket_title = "Phishing Indicator: " + from_address + " → " + recipient,
       ticket_body = "Sender: " + from_address + "\nRecipient: " + recipient + "\nSubject: " + subject + "\nTimestamp: " + _time
| table _time, from_address, recipient, subject, message_id, alert_type, ticket_title, ticket_body
```

### 3.3 Anomalous Authentication

```spl
index=soc_events sourcetype="windows:security" EventCode=4624 Logon_Type=10
| lookup asset_criticality hostname as ComputerName OUTPUT criticality, tier
| stats values(IpAddress) as source_ips, count by user, ComputerName, criticality
| where count > 1 OR mvcount(source_ips) > 2
| eval severity = if(criticality="critical" OR criticality="high", "P2", "P3"),
       alert_type = "anomalous_rdp_login"
| table user, ComputerName, source_ips, count, criticality, severity, alert_type
```

---

## Section 4: Alert Actions — Configuring Webhook Output

### 4.1 Webhook to SOAR

Configure a webhook alert action to forward to Shuffle SOAR:

1. In the saved search, click **Add Action** → **Webhook**
1. URL: `http://shuffle-backend:5001/api/v1/hooks/webhook_<id>`
1. The webhook sends Splunk result data as JSON

**Splunk webhook payload format:**

```json
{
  "result": {
    "_time": "1712413931",
    "severity": "P2",
    "alert_type": "brute_force",
    "src_ip": "185.220.101.50",
    "dest_user": "administrator",
    "dest_host": "dc01",
    "criticality": "critical",
    "count": "87"
  },
  "sid": "rt_scheduler__admin_search_1712413931",
  "results_link": "http://splunk:8000/...",
  "search_name": "Brute Force Detection",
  "owner": "admin",
  "app": "search"
}
```

### 4.2 Direct webhook to TheHive

If you don't have SOAR, webhook directly to TheHive via a Python receiver:

```python
#!/usr/bin/env python3
"""
splunk_to_thehive.py
Receives Splunk alert webhooks and creates TheHive alerts.
Run as: python3 splunk_to_thehive.py
Listens on: http://0.0.0.0:8585/alert
"""

from flask import Flask, request, jsonify
import requests
import json
import hashlib
from datetime import datetime

app = Flask(__name__)

THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "your-thehive-api-key"

SEVERITY_MAP = {"P1": 3, "P2": 3, "P3": 2, "P4": 1}

@app.route("/alert", methods=["POST"])
def receive_splunk_alert():
    """Receive Splunk webhook and create TheHive alert"""
    data = request.json

    if not data:
        return jsonify({"error": "No JSON body"}), 400

    result = data.get("result", {})
    search_name = data.get("search_name", "Unknown Alert")

    # Build TheHive alert
    severity_str = result.get("severity", "P3")
    severity_int = SEVERITY_MAP.get(severity_str, 2)

    source_ref = hashlib.md5(
        f"{search_name}{result.get('_time', '')}".encode()
    ).hexdigest()[:12]

    alert_payload = {
        "title": f"[{severity_str}] {search_name}",
        "description": build_description(result, search_name, data),
        "severity": severity_int,
        "tlp": 2,
        "pap": 2,
        "tags": [
            result.get("alert_type", "siem-alert"),
            f"severity:{severity_str}",
            "splunk-auto"
        ],
        "type": "external",
        "source": "splunk",
        "sourceRef": source_ref,
        "date": int(datetime.now().timestamp() * 1000)
    }

    # Create alert in TheHive
    resp = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers={
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        },
        json=alert_payload
    )

    if resp.status_code in [200, 201]:
        alert_id = resp.json().get("_id", "unknown")
        print(f"Created TheHive alert: {alert_id} for {search_name}")
        return jsonify({"status": "success", "alert_id": alert_id}), 201
    else:
        print(f"TheHive error: {resp.status_code} - {resp.text}")
        return jsonify({"error": "TheHive creation failed", "details": resp.text}), 500

def build_description(result, search_name, raw_data):
    """Build formatted alert description from Splunk result"""
    timestamp = result.get("_time", "Unknown")
    try:
        ts = datetime.fromtimestamp(float(timestamp)).isoformat()
    except (ValueError, TypeError):
        ts = timestamp

    lines = [
        f"## {search_name}",
        f"",
        f"**Detection Time**: {ts}",
        f"**Severity**: {result.get('severity', 'Unknown')}",
        f"**Alert Type**: {result.get('alert_type', 'Unknown')}",
        f"",
        f"## Affected Assets",
        f"**Source IP**: {result.get('src_ip', 'N/A')}",
        f"**Destination Host**: {result.get('dest_host', 'N/A')}",
        f"**User**: {result.get('dest_user', result.get('user', 'N/A'))}",
        f"**Asset Criticality**: {result.get('criticality', 'Unknown')}",
        f"",
        f"## Raw Event Data",
        f"```json",
        json.dumps(result, indent=2),
        f"```",
        f"",
        f"[View in Splunk]({raw_data.get('results_link', '#')})"
    ]
    return "\n".join(lines)

if __name__ == "__main__":
    print("Starting Splunk → TheHive bridge on port 8585")
    app.run(host="0.0.0.0", port=8585, debug=False)
```

**Install dependencies and run:**

```console
pip install flask requests
python3 splunk_to_thehive.py
```

**Configure Splunk webhook:**
URL: `http://your-server:8585/alert`

---

## Section 5: Building a Complete Alert-to-Ticket SPL Dashboard

### 5.1 Alert volume dashboard

```spl
| pivot soc_events soc_events count(soc_events) AS "Alert Count"
  SPLITROW _time AS _time
  SPLITCOL alert_type
  PERIOD auto
| timechart count by alert_type
```

### 5.2 SLA tracking dashboard

Track alerts by time-in-queue to identify SLA risk:

```spl
| inputlookup open_tickets.csv
| eval hours_open = round((now() - strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")) / 3600, 1)
| eval sla_target = case(
    severity="P1", 4,
    severity="P2", 8,
    severity="P3", 24,
    true(), 72
  )
| eval sla_percent = round(hours_open / sla_target * 100, 0)
| eval sla_status = case(
    sla_percent >= 100, "BREACHED",
    sla_percent >= 80, "AT RISK",
    true(), "OK"
  )
| table ticket_id, severity, assigned_to, hours_open, sla_target, sla_percent, sla_status
| sort - sla_percent
```

### 5.3 Severity classification automation

Auto-calculate severity using lookup:

```spl
index=soc_events
| lookup asset_criticality hostname as dest_host OUTPUT criticality, tier
| eval threat_severity = case(
    match(signature, "(?i)ransomware|cryptolocker|wannacry"), "critical",
    match(signature, "(?i)c2|command.*control|beacon|cobalt.*strike"), "critical",
    match(signature, "(?i)exploit|CVE-202[0-9]-[0-9]+"), "high",
    match(signature, "(?i)bruteforce|password.*spray|credential"), "high",
    match(signature, "(?i)policy|unauthorized.*access|suspicious"), "medium",
    true(), "low"
  )
| eval ticket_severity = case(
    (tier=1 OR tier=2) AND threat_severity="critical", "P1",
    tier=1 AND threat_severity="high", "P1",
    tier=2 AND threat_severity="critical", "P1",
    (tier=1 OR tier=2) AND threat_severity="high", "P2",
    tier=3 AND threat_severity="critical", "P2",
    true(), "P3"
  )
```

---

## Section 6: Alert Tuning — Reducing False Positives

Before automating ticket creation, tune detection rules to reduce FP rate.

### Identifying high-FP rules

```spl
index=soc_tickets
| stats count AS total_alerts, sum(eval(resolution="false_positive")) AS fps by rule_name
| eval fp_rate = round(fps / total_alerts * 100, 1)
| sort - fp_rate
| where total_alerts > 10
| table rule_name, total_alerts, fps, fp_rate
```

### Common tuning patterns

**1.
Add exclusions for known-good behavior:**

```spl
index=soc_events EventCode=4625
NOT (src_ip IN ("10.0.0.0/8", "172.16.0.0/12"))  /* Internal scanners */
NOT (dest_user IN ("svc_backup", "svc_monitor"))   /* Service accounts */
```

**2.
Raise thresholds for noisy rules:**

```spl
/* Before: fires on any 5 failures */
| where count > 5

/* After: fires on 20 failures in 5 min */
| bucket _time span=5m
| stats count by _time, src_ip, dest_user
| where count > 20
```

**3.
Add asset context filter:**

```spl
/* Only alert on Tier 1 and Tier 2 assets */
| lookup asset_criticality hostname as dest_host OUTPUT tier
| where tier <= 2
```

---

## Summary

You have configured:

1. A Splunk index and HEC for security event ingestion
1. Three detection rules with asset-aware severity calculation
1. Webhook alert actions to forward to SOAR or TheHive
1. A Python bridge for direct Splunk → TheHive integration
1. SPL dashboards for alert volume and SLA tracking
1. Tuning patterns to reduce false positive rate

This pipeline transforms raw logs into structured, severity-classified tickets — ready for analyst investigation or SOAR automation.
