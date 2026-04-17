# Demo 04: Integrating Alerts with TheHive Ticketing System

**Duration**: ~50 minutes

**Level**: Intermediate

**Prerequisites**: Docker installed; Demo 01 reviewed

---

## Overview

This demo walks through deploying TheHive 5 with Cortex and configuring it as a SOC case management platform.
You will:

1. Deploy TheHive + Cortex + Elasticsearch + Cassandra via Docker
1. Configure TheHive for SOC use (custom templates, severity levels)
1. Set up Cortex analyzers for automated IOC enrichment
1. Create a case via the TheHive API (simulating SOAR integration)
1. Run automated Cortex analyzers on observables
1. Build a Python script that creates TheHive alerts from raw alert data

---

## Part 1: Deploy the Stack

### 1.1 Create configuration files

```console
mkdir -p /opt/soc-lab/demo-04-ticketing-integration/config/thehive
mkdir -p /opt/soc-lab/demo-04-ticketing-integration/config/cortex
```

**config/thehive/application.conf:**

```hocon
play.http.secret.key = "SOCLabThehiveSecret2026Change"

db.janusgraph {
  storage {
    backend = cql
    hostname = ["cassandra"]
    cql {
      cluster-name = thehive
      keyspace = thehive
    }
  }
  index.search {
    backend = elasticsearch
    hostname = ["elasticsearch"]
    index-name = thehive
  }
}

storage {
  provider = localfs
  localfs.location = /opt/thehive/data
}

# Cortex integration
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule

cortex {
  servers = [
    {
      name = cortex1
      url = "http://cortex:9001"
      auth {
        type = bearer
        key = "your-cortex-api-key-here"
      }
      wsConfig {}
    }
  ]
  refreshDelay = 5 seconds
  maxRetryOnError = 3
  statusCheckInterval = 1 minute
}

# Initial admin user
auth.providers = [
  {name = local}
]
```

**config/cortex/application.conf:**

```hocon
play.http.secret.key = "SOCLabCortexSecret2026Change"

search {
  index = cortex
  uri = "http://elasticsearch:9200"
}

analyzer {
  urls = [
    "https://download.thehive-project.org/analyzers.json"
  ]
  fork-join-executor {
    parallelism-min = 2
    parallelism-factor = 2.0
    parallelism-max = 4
  }
}

responder {
  urls = [
    "https://download.thehive-project.org/responders.json"
  ]
}
```

### 1.2 Start the stack

```console
cd /opt/soc-lab/demo-04-ticketing-integration
docker compose up -d

# Monitor startup (Cassandra takes ~60s, Elasticsearch ~45s, TheHive ~90s)
docker compose logs -f thehive
```

**Health check:**

```console
# TheHive
curl -s http://localhost:9000/api/v1/status | python3 -m json.tool

# Cortex
curl -s http://localhost:9001/api/status | python3 -m json.tool
```

---

## Part 2: Initial TheHive Configuration

### 2.1 Create admin account

On first start, TheHive prompts you to create an admin:

1. Open `http://localhost:9000`
1. Click **Create admin account**
1. Email: `admin@soc-lab.local`
1. Password: `SOCAdmin2026!`

### 2.2 Create SOC organization

1. Login as admin
1. Navigate to **Admin** → **Organizations** → **Create Organization**
1. Name: `SOC Lab`
1. Description: `Security Operations Center - Lab Environment`

### 2.3 Create analyst users

```bash
# Create users via TheHive API
# First get an API key: Profile → API Key → Create

TH_URL="http://localhost:9000"
TH_KEY="your-admin-api-key"

# Create L1 analyst
curl -s -X POST "$TH_URL/api/v1/user" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "l1analyst@soc-lab.local",
    "name": "L1 Analyst",
    "password": "Analyst2026!",
    "profile": "analyst",
    "organisation": "SOC Lab"
  }'

# Create L2 analyst
curl -s -X POST "$TH_URL/api/v1/user" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "l2analyst@soc-lab.local",
    "name": "L2 Senior Analyst",
    "password": "SeniorAnalyst2026!",
    "profile": "analyst",
    "organisation": "SOC Lab"
  }'
```

### 2.4 Create case templates

Case templates standardize the tasks and fields for different incident types.

**Phishing Response Template (via API):**

```bash
curl -s -X POST "$TH_URL/api/v1/caseTemplate" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Email Response",
    "displayName": "Phishing Response",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["phishing", "email"],
    "description": "Standard phishing email investigation workflow",
    "tasks": [
      {
        "title": "1. Extract IOCs from email",
        "group": "Triage",
        "description": "Extract: sender, reply-to, URLs, attachments, headers"
      },
      {
        "title": "2. Enrich IOCs",
        "group": "Analysis",
        "description": "Run Cortex analyzers on all observables"
      },
      {
        "title": "3. Check if user clicked / opened attachment",
        "group": "Analysis",
        "description": "Query SIEM for user activity related to email IOCs"
      },
      {
        "title": "4. Quarantine email",
        "group": "Containment",
        "description": "Remove email from all mailboxes"
      },
      {
        "title": "5. Block malicious IOCs",
        "group": "Containment",
        "description": "Block domains/IPs/URLs at proxy/firewall"
      },
      {
        "title": "6. Notify affected user",
        "group": "Communication",
        "description": "Send notification to recipient about phishing attempt"
      },
      {
        "title": "7. Post-incident review",
        "group": "Closure",
        "description": "Document lessons learned and tuning recommendations"
      }
    ],
    "customFields": {}
  }'
```

---

## Part 3: Configure Cortex Analyzers

### 3.1 Create Cortex admin account

1. Open `http://localhost:9001`
1. Click **Update database** (first run)
1. Create admin: admin@soc-lab.local / CortexAdmin2026!

### 3.2 Create Cortex organization

1. Navigate to **Organizations** → **Add Organization**
1. Name: `SOC Lab`

### 3.3 Enable analyzers

1. Navigate to **Organizations** → **SOC Lab** → **Analyzers**
1. Enable the following (free tier, no API key required):
   * `FileInfo_8_0` — Extract metadata from files
   * `Yara_2_0` — YARA rule scanning
1. Enable (require free API keys):
   * `VirusTotal_GetUrl_3_1` — VT URL reputation
   * `VirusTotal_GetIP_3_1` — VT IP reputation
   * `AbuseIPDB_3_0` — IP abuse check
   * `URLScan_io_1_1` — URL sandbox

### 3.4 Configure VirusTotal analyzer

1. Click **VirusTotal_GetIP_3_1** → **Configure**
1. Enter:
   * `key`: `<your-vt-api-key>`
   * `polling_interval`: `60`
1. Click **Save**

### 3.5 Get Cortex API key for TheHive

1. In Cortex, navigate to **Users** → `admin` → **API Keys**
1. Click **Create**
1. Copy the key
1. Update `config/thehive/application.conf`:

   ```text
   key = "your-cortex-api-key-here"  ← Replace with actual key
```

1. Restart TheHive: `docker compose restart thehive`

---

## Part 4: Create Cases via API

### 4.1 Create a phishing case from alert data

```bash
TH_URL="http://localhost:9000"
TH_KEY="your-admin-api-key"

# Create a case using the phishing template
curl -s -X POST "$TH_URL/api/v1/case" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Phishing: attacker@evil-domain.xyz → alice@company.com",
    "description": "Phishing email detected by SIEM rule Phishing_Email_Detected.\n\nSender: attacker@evil-domain.xyz\nRecipient: alice@company.com\nSubject: URGENT: Account Suspended\nURL: http://evil-domain.xyz/login",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["phishing", "email", "auto-created"],
    "template": "Phishing Email Response"
  }' | python3 -m json.tool
```

Save the returned case ID (e.g., `~123456789`).

### 4.2 Add observables to the case

```bash
CASE_ID="~123456789"  # Replace with actual case ID

# Add sender email
curl -s -X POST "$TH_URL/api/v1/case/$CASE_ID/observable" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "mail",
    "data": "attacker@evil-domain.xyz",
    "message": "Phishing sender email",
    "tlp": 2,
    "ioc": true,
    "sighted": false,
    "tags": ["sender", "phishing"]
  }'

# Add malicious URL
curl -s -X POST "$TH_URL/api/v1/case/$CASE_ID/observable" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "url",
    "data": "http://evil-domain.xyz/login",
    "message": "Phishing URL from email body",
    "tlp": 2,
    "ioc": true,
    "sighted": true,
    "tags": ["phishing-url", "credential-harvest"]
  }'

# Add sender IP
curl -s -X POST "$TH_URL/api/v1/case/$CASE_ID/observable" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "185.220.101.50",
    "message": "Sending mail server IP from email headers",
    "tlp": 2,
    "ioc": true,
    "sighted": true,
    "tags": ["c2", "tor-exit"]
  }'
```

### 4.3 Run Cortex analyzers on observables

```bash
# Get observable IDs
curl -s "$TH_URL/api/v1/case/$CASE_ID/observable" \
  -H "Authorization: Bearer $TH_KEY" | python3 -m json.tool

# Run analyzer on IP observable (replace OBSERVABLE_ID)
OBSERVABLE_ID="~987654321"

curl -s -X POST "$TH_URL/api/v1/connector/cortex/job" \
  -H "Authorization: Bearer $TH_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "analyzerId": "AbuseIPDB_3_0",
    "observableId": "'$OBSERVABLE_ID'",
    "cortexId": "cortex1"
  }'
```

### 4.4 View analyzer results in TheHive

1. Open `http://localhost:9000`
1. Navigate to **Cases** → your case
1. Click **Observables** tab
1. Click on the IP observable → **Cortex Analysis Results**
1. Review the analyzer report

---

## Part 5: Python Integration Script

```python
#!/usr/bin/env python3
"""
thehive_integration.py
Creates TheHive cases and alerts from SIEM alert data.
Demonstrates how SOAR would interact with TheHive API.
"""

import requests
import json
import sys
from datetime import datetime

class TheHiveClient:
    def __init__(self, url, api_key):
        self.url = url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def create_alert(self, title, description, severity, tags, source_ref):
        """Create an alert in TheHive (pre-investigation state)"""
        payload = {
            "title": title,
            "description": description,
            "severity": severity,  # 1=Low, 2=Medium, 3=High, 4=Critical
            "tlp": 2,              # 0=White, 1=Green, 2=Amber, 3=Red
            "pap": 2,
            "tags": tags,
            "type": "external",
            "source": "siem-automation",
            "sourceRef": source_ref,
            "date": int(datetime.now().timestamp() * 1000)
        }
        resp = requests.post(
            f"{self.url}/api/v1/alert",
            headers=self.headers,
            json=payload
        )
        resp.raise_for_status()
        return resp.json()

    def promote_alert_to_case(self, alert_id):
        """Promote an alert to a full case for investigation"""
        resp = requests.post(
            f"{self.url}/api/v1/alert/{alert_id}/case",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()

    def create_case(self, title, description, severity, tags, template=None):
        """Create a case directly"""
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": 2,
            "pap": 2,
            "tags": tags
        }
        if template:
            payload["template"] = template
        resp = requests.post(
            f"{self.url}/api/v1/case",
            headers=self.headers,
            json=payload
        )
        resp.raise_for_status()
        return resp.json()

    def add_observable(self, case_id, data_type, data, message, is_ioc=True, tags=None):
        """Add an observable (IOC) to a case"""
        payload = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tlp": 2,
            "ioc": is_ioc,
            "sighted": is_ioc,
            "tags": tags or []
        }
        resp = requests.post(
            f"{self.url}/api/v1/case/{case_id}/observable",
            headers=self.headers,
            json=payload
        )
        resp.raise_for_status()
        return resp.json()

    def add_task_log(self, task_id, message):
        """Add a log entry to a task"""
        payload = {"message": message}
        resp = requests.post(
            f"{self.url}/api/v1/task/{task_id}/log",
            headers=self.headers,
            json=payload
        )
        resp.raise_for_status()
        return resp.json()

    def list_alerts(self, limit=10):
        """List recent alerts"""
        resp = requests.get(
            f"{self.url}/api/v1/alert?range=0-{limit}",
            headers=self.headers
        )
        resp.raise_for_status()
        return resp.json()

def process_siem_alert(alert_data, thehive_client):
    """
    Process a raw SIEM alert and create corresponding TheHive artifacts
    """
    print(f"Processing alert: {alert_data['alert_id']}")

    # Determine severity
    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = severity_map.get(alert_data.get("severity", "medium").lower(), 2)

    # Create alert in TheHive
    alert = thehive_client.create_alert(
        title=f"[{alert_data['alert_type'].upper()}] {alert_data['alert_id']}: {alert_data.get('summary', 'Security Alert')}",
        description=f"""
## SIEM Alert Details

**Alert ID**: {alert_data['alert_id']}
**Rule**: {alert_data.get('rule_name', 'N/A')}
**Source**: {alert_data.get('source_system', 'SIEM')}
**Timestamp**: {alert_data.get('timestamp', 'N/A')}

## Affected Assets

**Host**: {alert_data.get('host', 'Unknown')}
**User**: {alert_data.get('user', 'Unknown')}
**Source IP**: {alert_data.get('src_ip', 'Unknown')}

## Raw Event
```

{json.dumps(alert_data.get('raw_event', {}), indent=2)}

```text
        """,
        severity=severity,
        tags=[
            alert_data.get("alert_type", "unknown"),
            "siem-auto-created",
            alert_data.get("source_system", "siem")
        ],
        source_ref=alert_data["alert_id"]
    )

    print(f"  Created TheHive alert: {alert['_id']}")

    # Add observables if present
    iocs = alert_data.get("iocs", {})

    for ip in iocs.get("ips", []):
        try:
            thehive_client.add_observable(
                case_id=alert["_id"],
                data_type="ip",
                data=ip,
                message="IP from SIEM alert",
                tags=["siem-extracted"]
            )
            print(f"  Added IP observable: {ip}")
        except Exception as e:
            print(f"  Warning: Could not add IP {ip}: {e}")

    for domain in iocs.get("domains", []):
        try:
            thehive_client.add_observable(
                case_id=alert["_id"],
                data_type="domain",
                data=domain,
                message="Domain from SIEM alert",
                tags=["siem-extracted"]
            )
            print(f"  Added domain observable: {domain}")
        except Exception as e:
            print(f"  Warning: Could not add domain {domain}: {e}")

    return alert

if __name__ == "__main__":
    # Configure TheHive connection
    client = TheHiveClient(
        url="http://localhost:9000",
        api_key="your-thehive-api-key"
    )

    # Example SIEM alert data
    siem_alert = {
        "alert_id": "SPL-2026-TEST-001",
        "alert_type": "phishing",
        "severity": "high",
        "rule_name": "Phishing_Email_Detected",
        "source_system": "splunk",
        "timestamp": "2026-04-06T14:32:11Z",
        "summary": "Phishing email from known malicious sender",
        "host": "mail-gateway-01",
        "user": "alice@company.com",
        "src_ip": "185.220.101.50",
        "iocs": {
            "ips": ["185.220.101.50", "45.153.160.2"],
            "domains": ["evil-domain.xyz", "phish-site.evil"],
            "urls": ["http://evil-domain.xyz/login"],
            "hashes": []
        },
        "raw_event": {
            "sender": "attacker@evil-domain.xyz",
            "recipient": "alice@company.com",
            "subject": "URGENT: Account Suspended"
        }
    }

    # Process the alert
    result = process_siem_alert(siem_alert, client)
    print(f"\nAlert created successfully!")
    print(f"TheHive Alert ID: {result['_id']}")
    print(f"View at: http://localhost:9000/alerts/{result['_id'].lstrip('~')}")
```

Run the script:

```console
python3 thehive_integration.py
```

---

## Part 6: TheHive Dashboard Configuration

### Configure dashboards for SOC visibility

1. Navigate to **Dashboards** → **Add Dashboard**
1. Name: `SOC Operations Overview`
1. Add widgets:
   * **Alert Volume** (last 7 days): Bar chart by alert type
   * **Open Cases by Severity**: Donut chart
   * **SLA Status**: Cases by age vs. severity
   * **Analyst Workload**: Cases per assignee

---

## Verification Checklist

* [ ] TheHive accessible at `http://localhost:9000`
* [ ] Cortex accessible at `http://localhost:9001`
* [ ] Both services show "green" status
* [ ] Cortex is linked to TheHive (check Admin → Cortex)
* [ ] At least one Cortex analyzer is enabled
* [ ] Case created via API with observables
* [ ] Cortex analyzer ran on at least one observable
* [ ] Analyzer results visible in TheHive case

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| Cassandra connection refused | Cassandra not ready | Wait 60s; check `docker logs cassandra` |
| 401 Unauthorized | Wrong API key | Regenerate key in TheHive UI |
| Cortex analyzer fails | Missing API key config | Configure analyzer in Cortex UI |
| Port 9200 conflict | Elasticsearch conflict | Change port in docker-compose.yml |
| OutOfMemoryError | Insufficient RAM | Increase JVM heap or host RAM |
