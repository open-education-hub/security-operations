# Demo 03 — Playbook Automation: Building a Credential Stuffing Response Playbook

## Overview

This demo builds a complete credential stuffing detection and response playbook using **Python and TheHive**.
We simulate the detection, implement automated enrichment, and walk through the full automated response workflow.

**Duration:** 45 minutes

**Difficulty:** Intermediate

**Tools:** Docker, TheHive, Python, mock API server

---

## Setup

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive-demo3
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1024m
    volumes:
      - thehive-data:/opt/thp/thehive/data
      - thehive-index:/opt/thp/thehive/index
    networks:
      - demo-net
    depends_on:
      - cassandra
      - elasticsearch

  cassandra:
    image: cassandra:4.1
    container_name: cassandra-demo3
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=128M
    volumes:
      - cassandra-data:/var/lib/cassandra
    networks:
      - demo-net

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.12
    container_name: elasticsearch-demo3
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - demo-net

  # Mock API server for demo integrations
  mock-api:
    image: python:3.11-slim
    container_name: mock-api
    command: python /app/mock_server.py
    volumes:
      - ./mock_server:/app
    ports:
      - "8080:8080"
    networks:
      - demo-net

networks:
  demo-net:
    driver: bridge

volumes:
  thehive-data:
  thehive-index:
  cassandra-data:
  elasticsearch-data:
```

### Mock API server

```python
# mock_server/mock_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, random

class MockAPIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = json.loads(self.rfile.read(content_length))

        response = {}

        if self.path == "/api/threat-intel/ip":
            ip = body.get("ip", "")
            # Simulate threat intel lookup
            known_bad = ["45.33.32.156", "192.168.0.0", "185.220.101.45"]
            response = {
                "ip": ip,
                "is_known_malicious": ip in known_bad,
                "feeds": ["AbuseIPDB", "AlienVault OTX"] if ip in known_bad else [],
                "country": "RU" if ip in known_bad else "US",
                "asn": "AS1234"
            }
        elif self.path == "/api/geo/ip":
            response = {
                "ip": body.get("ip"),
                "country": random.choice(["RU", "CN", "US", "DE", "BR"]),
                "city": random.choice(["Moscow", "Shanghai", "New York", "Berlin"])
            }
        elif self.path == "/api/waf/block":
            response = {
                "status": "blocked",
                "ip": body.get("ip"),
                "rule_id": f"BLOCK-{random.randint(10000, 99999)}"
            }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress logs

if __name__ == "__main__":
    print("Mock API server running on port 8080")
    HTTPServer(("0.0.0.0", 8080), MockAPIHandler).serve_forever()
```

```console
mkdir -p mock_server
# create mock_server/mock_server.py with the content above
docker compose up -d
```

---

## Part 1: Understand the Scenario (5 minutes)

**Context:** GlobalBank Corp's login portal is under credential stuffing attack.

**Detection rule fired:**

* 847 failed logins in 3 minutes
* 14 distinct source IPs
* Targeting 12 different accounts
* All from outside the EU (anomalous geo)

**Manual response without automation:**

1. Analyst reviews SIEM alert (2 min)
1. Analyst looks up each IP in threat intel (10 min)
1. Analyst checks geo for each IP (5 min)
1. Analyst creates TheHive case (5 min)
1. Analyst submits WAF block request (10 min per IP = 140 min!)
1. Total: ~160 minutes per attack

**With our playbook:**

* Total: ~45 seconds (mostly API latency)

---

## Part 2: The Automation Script (20 minutes)

Create the playbook as a Python script:

```python
# playbook_credential_stuffing.py
"""
Credential Stuffing Response Playbook
Automates: enrichment, case creation, IP blocking, notifications
"""

import requests
import json
import time
from datetime import datetime, timezone

# Configuration
THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"
MOCK_API_URL = "http://localhost:8080"

HEADERS_THEHIVE = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json"
}

def log_step(step_name, result=None, error=None):
    """Log automation steps with timestamp."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    status = "✓" if not error else "✗"
    print(f"[{ts}] {status} {step_name}")
    if result:
        print(f"         → {result}")
    if error:
        print(f"         → ERROR: {error}")

def enrich_ip(ip):
    """Check IP against threat intelligence."""
    try:
        r = requests.post(
            f"{MOCK_API_URL}/api/threat-intel/ip",
            json={"ip": ip}, timeout=5
        )
        intel = r.json()

        geo_r = requests.post(
            f"{MOCK_API_URL}/api/geo/ip",
            json={"ip": ip}, timeout=5
        )
        geo = geo_r.json()

        return {
            "ip": ip,
            "is_malicious": intel.get("is_known_malicious", False),
            "feeds": intel.get("feeds", []),
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown")
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def create_thehive_case(alert_data, enriched_ips):
    """Create a case in TheHive."""
    malicious_ips = [ip for ip in enriched_ips if ip.get("is_malicious")]

    description = f"""
## Credential Stuffing Attack — {alert_data['target_service']}

**Detected:** {datetime.now(timezone.utc).isoformat()}
**Source:** SIEM Rule CR-047

### Attack Statistics
- Failed logins: **{alert_data['failed_logins']}** in {alert_data['timeframe']}
- Distinct source IPs: **{len(alert_data['source_ips'])}**
- Targeted accounts: **{alert_data['targeted_accounts']}**
- Known malicious IPs: **{len(malicious_ips)}** / {len(alert_data['source_ips'])}

### Source IP Analysis
| IP | Country | Known Malicious | Feeds |
|----|---------|----------------|-------|
{chr(10).join(f"| {e['ip']} | {e.get('country','?')} | {'YES' if e.get('is_malicious') else 'No'} | {', '.join(e.get('feeds',[])) or '-'} |" for e in enriched_ips)}

### Initial Assessment
Pattern consistent with credential stuffing attack using distributed proxy network.
Automated blocking applied to {len(malicious_ips)} high-confidence malicious IPs.
    """

    case_data = {
        "title": f"Credential Stuffing — {alert_data['target_service']} — {len(alert_data['source_ips'])} IPs",
        "severity": 3,  # High
        "tlp": 2,  # Amber
        "tags": ["credential-stuffing", "brute-force", "automated"],
        "description": description.strip()
    }

    r = requests.post(
        f"{THEHIVE_URL}/api/v1/case",
        headers=HEADERS_THEHIVE,
        json=case_data
    )
    if r.status_code in (200, 201):
        return r.json()
    else:
        raise Exception(f"Case creation failed: {r.status_code} {r.text}")

def add_observables(case_id, ips, target_service):
    """Add IP observables to the case."""
    added = 0
    for ip_data in ips:
        obs = {
            "dataType": "ip",
            "data": ip_data["ip"],
            "message": f"Credential stuffing source IP — {ip_data.get('country', 'Unknown')}",
            "tlp": 2,
            "ioc": ip_data.get("is_malicious", False),
            "tags": ["credential-stuffing"] + (["known-malicious"] if ip_data.get("is_malicious") else [])
        }
        r = requests.post(
            f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
            headers=HEADERS_THEHIVE,
            json=obs
        )
        if r.status_code in (200, 201):
            added += 1
    return added

def block_ip(ip):
    """Block IP at WAF."""
    r = requests.post(
        f"{MOCK_API_URL}/api/waf/block",
        json={"ip": ip, "reason": "credential-stuffing", "duration": "24h"},
        timeout=5
    )
    return r.json()

def run_playbook(alert_data):
    """
    Main playbook execution.

    Returns dict with execution summary.
    """
    print("\n" + "="*60)
    print("CREDENTIAL STUFFING RESPONSE PLAYBOOK")
    print(f"Target: {alert_data['target_service']}")
    print(f"Trigger time: {datetime.now(timezone.utc).isoformat()}")
    print("="*60 + "\n")

    results = {
        "steps_completed": [],
        "ips_blocked": [],
        "case_id": None,
        "errors": []
    }

    # Step 1: Enrich all IPs
    print("STEP 1: Enriching source IPs...")
    enriched = []
    for ip in alert_data["source_ips"]:
        enriched_ip = enrich_ip(ip)
        enriched.append(enriched_ip)
        log_step(
            f"Enrich {ip}",
            f"Malicious={enriched_ip.get('is_malicious')}, Country={enriched_ip.get('country')}"
        )
    results["steps_completed"].append("enrichment")

    # Step 2: Create TheHive case
    print("\nSTEP 2: Creating TheHive case...")
    try:
        case = create_thehive_case(alert_data, enriched)
        case_id = case["_id"]
        results["case_id"] = case_id
        log_step("Create case", f"Case ID: {case_id}")
        results["steps_completed"].append("case_creation")
    except Exception as e:
        log_step("Create case", error=str(e))
        results["errors"].append(str(e))
        case_id = None

    # Step 3: Add observables
    if case_id:
        print("\nSTEP 3: Adding observables to case...")
        added = add_observables(case_id, enriched, alert_data["target_service"])
        log_step("Add observables", f"{added}/{len(enriched)} IPs added")
        results["steps_completed"].append("observables")

    # Step 4: Block malicious IPs
    print("\nSTEP 4: Blocking confirmed malicious IPs at WAF...")
    malicious = [ip for ip in enriched if ip.get("is_malicious")]
    for ip_data in malicious:
        block_result = block_ip(ip_data["ip"])
        results["ips_blocked"].append(ip_data["ip"])
        log_step(f"Block {ip_data['ip']}", f"Rule ID: {block_result.get('rule_id')}")

    if not malicious:
        log_step("IP blocking", "No confirmed malicious IPs — flagging all for analyst review")
    results["steps_completed"].append("blocking")

    # Step 5: Summary
    print("\n" + "="*60)
    print("PLAYBOOK EXECUTION COMPLETE")
    print(f"Steps completed: {', '.join(results['steps_completed'])}")
    print(f"IPs blocked: {len(results['ips_blocked'])}")
    print(f"Case ID: {results['case_id'] or 'Creation failed'}")
    if results["errors"]:
        print(f"Errors: {results['errors']}")
    print("="*60)

    return results

# Simulated alert data (in real deployment, this comes from SIEM webhook)
SIMULATED_ALERT = {
    "target_service": "GlobalBank Online Banking Portal",
    "failed_logins": 847,
    "timeframe": "3 minutes",
    "targeted_accounts": 12,
    "source_ips": [
        "45.33.32.156",
        "185.220.101.45",
        "203.0.113.42",
        "198.51.100.17",
        "192.0.2.88",
        "104.131.0.69",
        "89.248.165.100",
        "91.121.87.151"
    ]
}

if __name__ == "__main__":
    results = run_playbook(SIMULATED_ALERT)
```

### Run the playbook

```console
# Install dependencies
pip install requests

# Run the playbook
python playbook_credential_stuffing.py
```

---

## Part 3: Review Execution Output (10 minutes)

**Expected output:**

```text
============================================================
CREDENTIAL STUFFING RESPONSE PLAYBOOK
Target: GlobalBank Online Banking Portal
Trigger time: 2025-04-10T09:14:22+00:00
============================================================

STEP 1: Enriching source IPs...
[09:14:22 UTC] ✓ Enrich 45.33.32.156
         → Malicious=True, Country=RU
[09:14:22 UTC] ✓ Enrich 185.220.101.45
         → Malicious=True, Country=RU
...

STEP 2: Creating TheHive case...
[09:14:23 UTC] ✓ Create case
         → Case ID: ~abc123def456

STEP 3: Adding observables to case...
[09:14:23 UTC] ✓ Add observables
         → 8/8 IPs added

STEP 4: Blocking confirmed malicious IPs at WAF...
[09:14:23 UTC] ✓ Block 45.33.32.156
         → Rule ID: BLOCK-47283
[09:14:23 UTC] ✓ Block 185.220.101.45
         → Rule ID: BLOCK-58291

============================================================
PLAYBOOK EXECUTION COMPLETE
Steps completed: enrichment, case_creation, observables, blocking
IPs blocked: 2
Case ID: ~abc123def456
============================================================
```

**Total time:** ~1 second vs ~160 minutes manual

### Discussion points

1. **What required human intervention here?** Only verifying the outcome and deciding on accounts to review
1. **What safeguard is missing?** We should require analyst approval before blocking to prevent accidental blocking of legitimate IPs
1. **How would you add a human approval gate?** Pause playbook, send notification to analyst, wait for approval webhook before proceeding to Step 4

---

## Cleanup

```console
docker compose down -v
rm -rf mock_server
```
