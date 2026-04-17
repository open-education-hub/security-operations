# Guide 02: Setting Up and Using MISP for Threat Intelligence

**Level:** Basic

**Estimated Time:** 45 minutes

**Goal:** Deploy MISP, understand its core concepts, and use it as a threat intelligence platform

---

## What is MISP?

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform for storing, correlating, and sharing indicators of compromise (IOCs) and contextual threat data.

Think of MISP as a structured database for threat intelligence where:

* Events represent threat intelligence reports or campaigns
* Attributes are individual indicators (IPs, hashes, domains)
* Objects group related attributes (all details about one malware file)
* Galaxies provide context (which threat actor? what malware family?)

---

## Installation (Docker)

### Prerequisites

```console
# Check Docker and Docker Compose
docker --version    # Requires 20.10+
docker compose version  # Requires v2.0+
```

### Quick Start with Docker

```console
# Clone the official MISP Docker repository
git clone https://github.com/misp/misp-docker.git
cd misp-docker

# Copy the example environment file
cp template.env .env

# Edit the configuration
nano .env
```

**Key settings in `.env`:**

```ini
# Change these before deployment
MISP_ADMIN_EMAIL=admin@your-org.local
MISP_ADMIN_PASSWORD=YourStrongPassword123!
MISP_BASEURL=https://localhost

# Database (change in production)
MYSQL_PASSWORD=db_password_change_me
MYSQL_ROOT_PASSWORD=root_password_change_me

# Enable MISP workers
WORKERS=1
```

```console
# Start MISP
docker compose up -d

# Check status (wait 3-5 minutes for first startup)
docker compose ps

# View logs during startup
docker compose logs -f misp-core
```

Access MISP at: https://localhost (accept self-signed cert warning)

**Default login:**

* Email: `admin@admin.test`
* Password: `admin` (change immediately!)

---

## Initial Configuration

### Step 1: Change Default Password

1. Log in with default credentials
1. Administration → List Users
1. Click "Edit" next to admin user
1. Set a strong password

### Step 2: Configure Your Organization

1. Administration → Add Organisation
1. Set your organization name and UUID
1. This UUID is your identity in the MISP sharing community

### Step 3: Create an API Key

1. Top-right user menu → My Profile
1. Auth Keys → Add authentication key
1. Copy and save the key securely

```console
# Test your API key
curl -s -k \
  -H "Authorization: YOUR_API_KEY" \
  -H "Accept: application/json" \
  https://localhost/users/view/me.json | python3 -m json.tool
```

### Step 4: Enable Default Feeds

1. Sync Actions → List Feeds
1. Enable these feeds:
   * CIRCL OSINT Feed
   * abuse.ch URLhaus
   * MISP default feeds
1. Click "Enable feed" for each
1. Sync Actions → Fetch all feeds (wait 5-10 minutes)

---

## Core Concepts in Practice

### Understanding Events

An **Event** is a container for threat intelligence.
It represents:

* A specific malware campaign
* A phishing wave
* An incident report
* A vulnerability exploitation campaign

**Event attributes:**

* **Date**: When was the intelligence first observed?
* **Threat Level**: Informational / Low / Medium / High
* **Analysis**: Initial (raw) / Ongoing / Complete
* **Distribution**: Controls who can see this event
* **Info**: Human-readable description

### Distribution Levels

| Level | Who Can See It |
|-------|---------------|
| 0: Your Organisation Only | Only your MISP instance |
| 1: This Community Only | All members of your MISP sync community |
| 2: Connected Communities | Your community + communities they sync with |
| 3: All Communities | Any MISP instance worldwide |
| 4: Sharing Group | A defined set of trusted organizations |

**Best practice for learning:** Start with Distribution = 0 (your org only)

---

## Creating Your First Event

### Method 1: Web Interface

1. Event Actions → Add Event
1. Fill in:
   * Date: Today
   * Threat Level: Medium
   * Analysis: Initial
   * Distribution: Your Organisation Only
   * Event Info: "Test Phishing Campaign - Learning"
1. Submit

**Add attributes:**

1. In the event, click "Add Attribute"
1. Type: `ip-dst`
1. Value: `198.51.100.5`
1. Comment: "Phishing C2 server"
1. For IDS: ✓ (flag for automated detection)
1. Submit

**Repeat for:**

* Type `domain`, value `malicious-phish.example.com`
* Type `md5`, value `d41d8cd98f00b204e9800998ecf8427e`
* Type `email-src`, value `attacker@evil.example.com`

### Method 2: Quick Event from Text (IOC Import)

1. Event Actions → Add Event
1. After creating the event, click "Freetext Import"
1. Paste a mix of IOCs:

```text
192.168.100.5
malware-domain.example.com
d41d8cd98f00b204e9800998ecf8427e
https://evil.example.com/payload.exe
```

1. MISP auto-detects the types and imports them

---

## Adding Tags and Context

Tags make events searchable and integrate with standards.

### Adding TLP Tags

1. In the event view, click the tag area
1. Search for "tlp:"
1. Select `tlp:amber` for this internal event

### Adding ATT&CK Tags

1. Search for "mitre-attack"
1. Add `mitre-attack:execution:T1059.001` for PowerShell execution

### Adding Galaxy Clusters

Galaxies provide rich context:

1. In the event, click "Add Galaxy Cluster"
1. Select "Threat Actors" galaxy
1. Search for "FIN7" (or another actor)
1. Add the cluster

This links your event to all known TTPs and references for FIN7.

---

## Searching and Querying Events

### Web Interface Search

1. Event Actions → Search Attributes
1. Search by:
   * Attribute value (e.g., an IP address)
   * Type (e.g., all `domain` attributes)
   * Tag (e.g., all TLP:RED events)
   * Timestamp range

### REST API Queries

```bash
# Set variables
MISP="https://localhost"
KEY="your-api-key"

# Get all events
curl -sk -H "Authorization: $KEY" -H "Accept: application/json" \
  "$MISP/events/index" | python3 -m json.tool | head -50

# Search for a specific IP
curl -sk -H "Authorization: $KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -X POST "$MISP/attributes/restSearch" \
  -d '{"value": "198.51.100.5", "type": "ip-dst"}' \
  | python3 -m json.tool

# Get all IDS-enabled indicators from last 7 days
curl -sk -H "Authorization: $KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -X POST "$MISP/attributes/restSearch" \
  -d '{"to_ids": true, "publish_timestamp": "7d"}' \
  | python3 -m json.tool
```

### Python API (PyMISP)

```python
from pymisp import PyMISP

misp = PyMISP('https://localhost', 'your-api-key', ssl=False)

# Search for events about phishing
events = misp.search(value='phishing', searchall=True)
for event in events:
    print(f"Event {event['Event']['id']}: {event['Event']['info']}")

# Get all current IOCs
iocs = misp.search(
    publish_timestamp='7d',
    to_ids=True,
    type_attribute=['ip-dst', 'domain', 'sha256']
)
print(f"Found {len(iocs)} events with IOCs")
```

---

## Working with Feeds

Feeds are external IOC sources that MISP can automatically consume.

### Viewing Active Feeds

Sync Actions → List Feeds

You'll see feeds with:

* **Name**: Human-readable name
* **Provider**: Who maintains this feed
* **Format**: MISP feed, CSV, text
* **URL**: Where MISP fetches from
* **Enabled**: Whether it's active
* **Distribution**: How imported events are distributed

### Manually Fetching a Feed

1. List Feeds → Select a feed → Fetch Now
1. Or fetch all: Sync Actions → Fetch all feeds

### When to Use Feeds

| Feed Type | Use Case |
|-----------|----------|
| CIRCL OSINT | General threat intel, good quality |
| Abuse.ch URLhaus | Malware URLs, frequently updated |
| Abuse.ch MalwareBazaar | Malware hashes |
| Abuse.ch FeodoTracker | Botnet C2 IPs |

---

## Exporting Intelligence

### Export Event as STIX 2.1

STIX (Structured Threat Information Expression) is the standard format for threat intel exchange.

```console
# Export a specific event as STIX 2.1
curl -sk -H "Authorization: $KEY" \
  "$MISP/events/stix2/download/EVENT_ID" \
  -o event_stix2.json

# Export all recent events as STIX
curl -sk -H "Authorization: $KEY" \
  "$MISP/attributes/restSearch/returnFormat:stix2/publish_timestamp:7d" \
  -o recent_iocs_stix2.json
```

### Export as CSV for SIEM

```console
# Export as CSV (for Splunk lookup tables, etc.)
curl -sk -H "Authorization: $KEY" \
  "$MISP/attributes/restSearch/returnFormat:csv/to_ids:1/publish_timestamp:7d" \
  -o iocs.csv

head -5 iocs.csv
```

### Export YARA Rules

If events contain YARA attributes:

```console
curl -sk -H "Authorization: $KEY" \
  "$MISP/attributes/restSearch/returnFormat:yara/to_ids:1" \
  -o detection_rules.yar
```

---

## Practical Workflow: IOC Lifecycle in MISP

```text
1. RECEIVE intelligence (email, report, feed)

         ↓
2. CREATE a MISP event with appropriate distribution
         ↓
3. ADD attributes (IOCs) with type, value, comment, to_ids
         ↓
4. TAG event with TLP, ATT&CK, kill chain
         ↓
5. ADD galaxy clusters (threat actor, malware family)
         ↓
6. PUBLISH the event (when ready to share)
         ↓
7. EXPORT indicators to SIEM for automated detection
         ↓
8. REVIEW and UPDATE when indicators age out or are confirmed
```

---

## Troubleshooting Common Issues

**Can't log in:**

* Check docker logs: `docker compose logs misp-core | grep -i "password\|auth\|login"`

* Reset admin password via database

**API returns 401 Unauthorized:**

* Verify API key is correct and active
* Check if key has been revoked
* Try creating a new key

**Feed fetch fails:**

* Check internet connectivity from container: `docker exec misp_core curl -s https://www.circl.lu`
* Some feeds require registration (check feed URL)

**Events don't appear after fetch:**

* Check feed jobs: Administration → Jobs
* Look for failed jobs and their error messages

---

## Summary

You have learned to:

1. Deploy MISP with Docker
1. Understand the event/attribute/object/tag model
1. Create events manually and via IOC import
1. Tag events with TLP and ATT&CK taxonomies
1. Configure and fetch threat intel feeds
1. Query MISP via web interface and API
1. Export intelligence in various formats

**Key takeaways:**

* MISP is a structured database for threat intelligence, not just an IOC list
* Context (tags, galaxies) is as valuable as the IOCs themselves
* Start with Distribution=0 until you understand the sharing implications
* Regularly update and expire old IOCs to prevent alert fatigue
* Integrate MISP exports with your SIEM for operational use

---

*Next: Guide 03 - OSINT Tools and Techniques for Threat Intelligence*
