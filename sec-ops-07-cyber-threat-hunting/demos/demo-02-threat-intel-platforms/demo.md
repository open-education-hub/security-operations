# Demo 02: Setting Up MISP in Docker and Exploring Threat Intelligence

**Duration:** ~45 minutes

**Difficulty:** Intermediate

**Prerequisites:** Docker installed, basic Linux command line, reading material section 11

---

## Overview

In this demo, we will:

1. Deploy MISP using Docker Compose
1. Configure initial settings and create an API key
1. Import a public threat feed
1. Create a MISP event with attributes and objects
1. Query MISP via the API
1. Export indicators for use in a SIEM

---

## Prerequisites

**System requirements:**

* Docker 20.10+ and Docker Compose v2+
* 4 GB RAM minimum (8 GB recommended)
* 20 GB free disk space
* Internet access

**Check Docker installation:**

```console
docker --version
docker compose version
```

---

## Step 1: Deploy MISP with Docker Compose

Create a working directory and the Docker Compose configuration:

```console
mkdir -p ~/misp-demo && cd ~/misp-demo
```

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  misp-core:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    container_name: misp_core
    restart: unless-stopped
    depends_on:
      - misp-db
      - misp-redis
    environment:
      - MISP_BASEURL=https://localhost
      - MISP_EMAIL=admin@misp.local
      - MISP_PASSWORD=Admin1234!
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_password
      - REDIS_HOST=misp-redis
      - MISP_ENABLE_INSTALLER=false
    volumes:
      - misp-data:/var/www/MISP/app/files
      - misp-logs:/var/www/MISP/app/tmp/logs
    ports:
      - "443:443"
      - "80:80"

  misp-db:
    image: mysql:8.0
    container_name: misp_db
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_password
      - MYSQL_ROOT_PASSWORD=misp_root_password
    volumes:
      - misp-mysql:/var/lib/mysql
    command: --default-authentication-plugin=mysql_native_password

  misp-redis:
    image: redis:7-alpine
    container_name: misp_redis
    restart: unless-stopped
    volumes:
      - misp-redis:/data

  misp-workers:
    image: ghcr.io/misp/misp-docker/misp-workers:latest
    container_name: misp_workers
    restart: unless-stopped
    depends_on:
      - misp-core
    environment:
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_db_password
      - REDIS_HOST=misp-redis

volumes:
  misp-data:
  misp-logs:
  misp-mysql:
  misp-redis:
```

**Start MISP:**

```console
docker compose up -d

# Monitor startup (takes 2-5 minutes first run)
docker compose logs -f misp-core

# When you see "MISP is ready", proceed
```

---

## Step 2: Initial Configuration

### Access MISP Web Interface

Navigate to `https://localhost` in your browser.

> **Note:** Accept the self-signed certificate warning for this demo.

**Default credentials:**

* Username: `admin@admin.test`
* Password: `admin`

**Change the default password immediately:**

1. Top right → Admin → My Profile
1. Change Password
1. Set a strong password

### Create an API Key

```text
Admin → My Profile → Auth Keys → Add authentication key
```

* Comment: `Demo API Key`
* All Permissions: checked (for demo purposes)
* Copy the key - you won't see it again!

```console
# Set the API key as an environment variable
export MISP_URL="https://localhost"
export MISP_KEY="your-api-key-here"
```

---

## Step 3: Configure MISP for Threat Intelligence Feeds

### Enable Default Feeds

Navigate to: `Sync Actions → Feeds`

Enable these recommended feeds:

1. **CIRCL OSINT Feed** - Click Enable
1. **MISP default feeds** - Click Enable
1. **abuse.ch URLhaus** - Enable if listed

### Fetch Feed Data

```console
# Trigger feed fetch via API
curl -k -H "Authorization: $MISP_KEY" \
     -H "Accept: application/json" \
     -X POST "$MISP_URL/feeds/fetchFromAllFeeds"
```

Or via the web UI: `Sync Actions → Fetch all feeds`

> **Note:** Feed fetch can take several minutes. Monitor progress in `Jobs`.

---

## Step 4: Create a MISP Event (Manually)

### Via Web Interface

1. Navigate to `Event Actions → Add Event`
1. Fill in:
   * Date: Today's date
   * Threat Level: High
   * Analysis: Ongoing
   * Distribution: Your Organisation Only
   * Event Info: `FIN-STORM Phishing Campaign - March 2024`
1. Click Submit

### Add Attributes

With the event created, add attributes:

**Add a malicious IP:**

* Type: `ip-dst`
* Value: `192.0.2.15`
* Comment: `FIN-STORM C2 server`
* For IDS: checked
* Click Submit

**Add a malicious domain:**

* Type: `domain`
* Value: `update-secure-cdn.com`
* Comment: `FIN-STORM C2 domain`
* For IDS: checked

**Add a file hash:**

* Type: `sha256`
* Value: `a3f5c2e1d9b47f83a291e4c5d6789012345678901234567890123456789012345`
* Comment: `PowerShell loader dropper`
* For IDS: checked

**Add a URL:**

* Type: `url`
* Value: `https://auth-verify-portal.net/payload.ps1`
* Comment: `Malware delivery URL`
* For IDS: checked

### Add Tags

1. In the event view, click `Edit`
1. Add tags:
   * `tlp:amber`
   * `misp-galaxy:threat-actor="FIN7"` (using FIN7 as an example)
   * `mitre-attack:execution:T1059.001`
   * `mitre-attack:credential-access:T1003.001`

### Add Objects

Objects group related attributes.
Let's add a file object:

1. In the event, click `Add Object`
1. Select Template: `file`
1. Fill in:
   * filename: `invoice_march_2024.docm`
   * md5: `d41d8cd98f00b204e9800998ecf8427e` (example)
   * sha256: `a3f5c2e1d9b47f83a291e4c5d6789012345678901234567890123456789012345`
   * size-in-bytes: `145920`
   * mimetype: `application/vnd.ms-word.document.macroenabled.12`

---

## Step 5: Create Events via Python API

Install PyMISP:

```console
pip install pymisp
```

Create `create_event.py`:

```python
#!/usr/bin/env python3
"""
MISP Event Creation Demo
Creates a FIN-STORM campaign event with multiple attributes
"""

import os
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject

# Configuration
MISP_URL = os.environ.get('MISP_URL', 'https://localhost')
MISP_KEY = os.environ.get('MISP_KEY', 'your-api-key')
VERIFY_SSL = False  # Set to True in production

def create_finstorm_event(misp):
    """Create a FIN-STORM campaign event with IOCs"""

    # Create the base event
    event = MISPEvent()
    event.distribution = 0          # Your org only
    event.threat_level_id = 1       # High
    event.analysis = 1              # Ongoing
    event.info = "FIN-STORM Phishing Campaign - Financial Sector - March 2024"

    # Add tags
    event.add_tag("tlp:amber")
    event.add_tag("mitre-attack:execution:T1059.001")
    event.add_tag("mitre-attack:credential-access:T1003.001")
    event.add_tag("mitre-attack:lateral-movement:T1047")

    # Create the MISP event
    result = misp.add_event(event)
    event_id = result['Event']['id']
    print(f"[+] Created event ID: {event_id}")

    # Add network indicators
    indicators = [
        {'type': 'ip-dst',  'value': '192.0.2.15',
         'comment': 'FIN-STORM C2 server #1', 'to_ids': True},
        {'type': 'ip-dst',  'value': '198.51.100.22',
         'comment': 'FIN-STORM C2 server #2', 'to_ids': True},
        {'type': 'domain',  'value': 'update-secure-cdn.com',
         'comment': 'FIN-STORM C2 domain', 'to_ids': True},
        {'type': 'domain',  'value': 'auth-verify-portal.net',
         'comment': 'FIN-STORM phishing domain', 'to_ids': True},
        {'type': 'url',     'value': 'https://auth-verify-portal.net/payload.ps1',
         'comment': 'PS loader delivery URL', 'to_ids': True},
        {'type': 'sha256',  'value': 'a3f5c2e1d9b47f83a29' + '1' * 45,
         'comment': 'PS loader dropper hash', 'to_ids': True},
        {'type': 'sha256',  'value': '7c89d3a2f1e47b23c85' + '2' * 45,
         'comment': 'Macro dropper hash', 'to_ids': True},
        {'type': 'yara',    'value': '''
rule FIN_STORM_PS_Loader {
    meta:
        author = "SecureBank Threat Intel"
        description = "FIN-STORM PowerShell loader"
        tlp = "AMBER"
    strings:
        $s1 = "update-secure-cdn.com" ascii wide
        $s2 = "auth-verify-portal.net" ascii wide
        $s3 = "-EncodedCommand" ascii
        $b1 = { 4D 5A 90 00 }
    condition:
        uint16(0) == 0x5A4D and
        ($s1 or $s2) and $s3
}''',
         'comment': 'YARA rule for PS loader detection', 'to_ids': True},
    ]

    for ioc in indicators:
        attr = misp.add_attribute(event_id, ioc)
        print(f"[+] Added attribute: {ioc['type']} = {ioc['value'][:30]}...")

    # Add a file object
    file_object = MISPObject('file')
    file_object.add_attribute('filename', value='invoice_march_2024.docm')
    file_object.add_attribute('sha256',
                               value='7c89d3a2f1e47b23c85' + '2' * 45,
                               to_ids=True)
    file_object.add_attribute('size-in-bytes', value='145920')
    file_object.add_attribute('mimetype',
                               value='application/vnd.ms-word.document.macroenabled.12')
    file_object.add_attribute('malware-sample',
                               value='invoice_march_2024.docm',
                               comment='Weaponized Word document')

    misp.add_object(event_id, file_object)
    print(f"[+] Added file object: invoice_march_2024.docm")

    # Add a network-connection object
    network_object = MISPObject('network-connection')
    network_object.add_attribute('ip-dst', value='192.0.2.15', to_ids=True)
    network_object.add_attribute('dst-port', value='443')
    network_object.add_attribute('hostname-dst', value='update-secure-cdn.com')
    network_object.add_attribute('layer7-protocol', value='HTTPS')

    misp.add_object(event_id, network_object)
    print(f"[+] Added network object")

    print(f"\n[✓] Event {event_id} created successfully!")
    print(f"    View at: {MISP_URL}/events/view/{event_id}")

    return event_id

def search_for_indicators(misp):
    """Search for recent indicators from all events"""

    print("\n--- Searching for recent indicators ---")

    # Get all indicators from the last 7 days flagged for IDS
    results = misp.search(
        publish_timestamp='7d',
        type_attribute=['ip-dst', 'domain', 'url'],
        to_ids=True,
        pythonify=True
    )

    print(f"Found {len(results)} events with recent IOCs")

    for event in results[:3]:  # Show first 3
        print(f"\nEvent: {event.info}")
        print(f"  ID: {event.id}, TLP: ", end="")
        for tag in event.tags:
            if 'tlp' in tag.name.lower():
                print(tag.name, end=" ")
        print()

        for attr in event.attributes[:5]:  # Show first 5 attributes
            print(f"  [{attr.type}] {attr.value[:50]}")

def export_to_csv(misp, event_id):
    """Export event IOCs to CSV for SIEM ingestion"""

    print(f"\n--- Exporting IOCs for event {event_id} ---")

    event = misp.get_event(event_id, pythonify=True)

    with open('iocs_export.csv', 'w') as f:
        f.write("type,value,comment,to_ids\n")
        for attr in event.attributes:
            if attr.to_ids:
                f.write(f"{attr.type},{attr.value},{attr.comment},{attr.to_ids}\n")

    print(f"[✓] Exported to iocs_export.csv")

    # Also export as STIX 2.1
    stix_export = misp.get_stix(event_id, version='2.1')
    with open('iocs_export_stix.json', 'w') as f:
        f.write(str(stix_export))
    print(f"[✓] Exported to iocs_export_stix.json (STIX 2.1)")

if __name__ == "__main__":
    # Connect to MISP
    print(f"[*] Connecting to MISP at {MISP_URL}...")
    misp = PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_SSL)
    print(f"[✓] Connected!")

    # Create demo event
    event_id = create_finstorm_event(misp)

    # Search for recent indicators
    search_for_indicators(misp)

    # Export IOCs
    export_to_csv(misp, event_id)
```

**Run the script:**

```console
export MISP_URL="https://localhost"
export MISP_KEY="your-api-key-here"
python3 create_event.py
```

---

## Step 6: Query MISP for Hunt Preparation

Create `query_for_hunting.py`:

```python
#!/usr/bin/env python3
"""
Query MISP to extract IOCs for threat hunting
Formats output for use in SIEM tools
"""

import os
import json
from pymisp import PyMISP

MISP_URL = os.environ.get('MISP_URL', 'https://localhost')
MISP_KEY = os.environ.get('MISP_KEY', 'your-api-key')

def get_hunting_iocs(misp, lookback_days=30, tlp_max='amber'):
    """
    Extract IOCs suitable for threat hunting
    Returns dict organized by indicator type
    """

    hunting_iocs = {
        'ip': [],
        'domain': [],
        'hash_md5': [],
        'hash_sha256': [],
        'url': [],
        'yara': []
    }

    # Search for published events with IDS-enabled indicators
    results = misp.search(
        publish_timestamp=f'{lookback_days}d',
        to_ids=True,
        pythonify=True
    )

    for event in results:
        # Filter by TLP (skip TLP:RED for automated hunting)
        event_tlp = 'clear'
        for tag in event.tags:
            if 'tlp:' in tag.name.lower():
                event_tlp = tag.name.lower().split('tlp:')[1]

        # Skip TLP:RED (don't automate distribution of RED intel)
        if event_tlp == 'red':
            continue

        for attr in event.attributes:
            if not attr.to_ids:
                continue

            ioc_data = {
                'value': attr.value,
                'comment': attr.comment,
                'event_id': event.id,
                'event_info': event.info[:50],
                'timestamp': str(attr.timestamp)
            }

            if attr.type == 'ip-dst' or attr.type == 'ip-src':
                hunting_iocs['ip'].append(ioc_data)
            elif attr.type == 'domain' or attr.type == 'hostname':
                hunting_iocs['domain'].append(ioc_data)
            elif attr.type == 'md5':
                hunting_iocs['hash_md5'].append(ioc_data)
            elif attr.type == 'sha256':
                hunting_iocs['hash_sha256'].append(ioc_data)
            elif attr.type == 'url':
                hunting_iocs['url'].append(ioc_data)
            elif attr.type == 'yara':
                hunting_iocs['yara'].append(ioc_data)

    return hunting_iocs

def format_for_splunk(iocs):
    """Format IOCs as Splunk lookup table"""

    with open('splunk_ioc_lookup.csv', 'w') as f:
        f.write("indicator_type,indicator_value,source,comment\n")

        for ip in iocs['ip']:
            f.write(f"ip,{ip['value']},MISP-{ip['event_id']},{ip['comment']}\n")

        for domain in iocs['domain']:
            f.write(f"domain,{domain['value']},MISP-{domain['event_id']},{domain['comment']}\n")

        for sha256 in iocs['hash_sha256']:
            f.write(f"sha256,{sha256['value']},MISP-{sha256['event_id']},{sha256['comment']}\n")

    print("[✓] Written splunk_ioc_lookup.csv")
    print("    Usage in Splunk: | lookup splunk_ioc_lookup indicator_value as dest_ip")

def format_for_elastic(iocs):
    """Format IOCs as Elasticsearch bulk import"""

    with open('elastic_iocs.ndjson', 'w') as f:
        for ip in iocs['ip']:
            doc = {
                "indicator": {
                    "type": "ipv4-addr",
                    "ip": ip['value'],
                    "provider": "MISP",
                    "confidence": 75,
                    "description": ip['comment'],
                    "marking": {"tlp": "AMBER"}
                }
            }
            f.write(json.dumps({"index": {"_index": "threat-indicators"}}) + "\n")
            f.write(json.dumps(doc) + "\n")

    print("[✓] Written elastic_iocs.ndjson")
    print("    Import with: curl -X POST 'localhost:9200/_bulk' --data-binary @elastic_iocs.ndjson")

if __name__ == "__main__":
    misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)

    print("[*] Fetching IOCs from MISP...")
    iocs = get_hunting_iocs(misp, lookback_days=30)

    print(f"\n[✓] Retrieved:")
    print(f"    IPs:     {len(iocs['ip'])}")
    print(f"    Domains: {len(iocs['domain'])}")
    print(f"    SHA256:  {len(iocs['hash_sha256'])}")
    print(f"    MD5:     {len(iocs['hash_md5'])}")
    print(f"    URLs:    {len(iocs['url'])}")
    print(f"    YARA:    {len(iocs['yara'])}")

    format_for_splunk(iocs)
    format_for_elastic(iocs)

    # Save full JSON export
    with open('all_iocs.json', 'w') as f:
        json.dump(iocs, f, indent=2, default=str)
    print("[✓] Written all_iocs.json")
```

---

## Step 7: Explore MISP Galaxies

MISP Galaxies provide rich context about threat actors and malware.

```console
# List available galaxies via API
curl -k -s \
     -H "Authorization: $MISP_KEY" \
     -H "Accept: application/json" \
     "$MISP_URL/galaxies" | python3 -m json.tool | grep '"name"'
```

**In the web interface:**

* Navigate to `Event Actions → List Galaxies`
* Explore "Threat Actors" galaxy
* Find APT28, APT29, FIN7 entries
* Note: Each actor entry contains associated TTPs, infrastructure patterns, and references

---

## Step 8: Clean Up

```console
# Stop and remove containers (preserves volumes)
docker compose stop

# Full cleanup (removes volumes too)
docker compose down -v
```

---

## Troubleshooting

**MISP won't start:**

```console
docker compose logs misp-core | tail -50
# Common issue: database not ready yet - wait 2-3 more minutes
```

**Can't connect via API:**

```console
# Verify the container is healthy
docker compose ps
# Check for certificate issues
curl -k -H "Authorization: $MISP_KEY" "$MISP_URL/servers/getPyMISPVersion.json"
```

**Feed fetch fails:**

```console
# Check connectivity from container
docker exec misp_core curl -s https://www.circl.lu/doc/misp/feed-osint/
```

---

## Summary

In this demo you:

1. Deployed MISP with Docker Compose
1. Created a threat intelligence event with real-world IOCs and objects
1. Tagged events with TLP and MITRE ATT&CK taxonomy
1. Used the PyMISP API to create events and query indicators
1. Exported IOCs in formats suitable for SIEM ingestion (Splunk CSV, Elasticsearch NDJSON)
1. Explored MISP Galaxies for threat actor context

**Next steps:**

* Configure MISP sharing with a partner organization (via MISP synchronization)
* Set up automated feed ingestion schedules
* Integrate MISP with your SIEM for automatic IOC matching
* Connect MISP to TheHive for incident case enrichment
