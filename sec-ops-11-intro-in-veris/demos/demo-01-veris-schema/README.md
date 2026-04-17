# Demo 01: Exploring the VERIS Schema

## Overview

In this demo, we explore the VERIS JSON schema by running a local Python environment that parses, validates, and displays VERIS incident records.
Students will see how the 4-A framework maps to actual JSON fields and learn to read and navigate a VERIS record.

## Learning Objectives

* Understand the structure of a VERIS JSON record
* Navigate the 4-A dimensions (Actor, Action, Asset, Attribute) in JSON format
* Validate a VERIS record against the schema
* Read and interpret timeline fields

## Prerequisites

* Docker installed and running
* Basic familiarity with JSON format

## Setup

```console
cd demos/demo-01-veris-schema
docker compose up --build
```

The container will start a Python environment with:

* The VERIS schema loaded
* Sample incident records
* A validation script
* An interactive explorer

## Files

* `docker-compose.yml` — service definition
* `Dockerfile` — Python environment with VERIS tools
* `samples/` — sample VERIS JSON records
* `scripts/explore.py` — interactive VERIS record explorer
* `scripts/validate.py` — schema validation script

## Walk-through

### Step 1: Start the environment

```console
docker compose run veris-explorer
```

You will see an interactive Python shell with VERIS tools loaded.

### Step 2: Load a sample record

```python
import json

# Load a sample VERIS incident record
with open('/data/samples/phishing_breach.json') as f:
    incident = json.load(f)

# Inspect the top-level structure
print(list(incident.keys()))
# ['schema_version', 'incident_id', 'summary', 'security_incident',
#  'confidence', 'timeline', 'victim', 'actor', 'action', 'asset',
#  'attribute', 'impact']
```

### Step 3: Explore the 4-A dimensions

```python
# ACTOR: Who caused the incident?
print("=== ACTOR ===")
for actor_type, details in incident['actor'].items():
    print(f"  Type: {actor_type}")
    print(f"  Variety: {details.get('variety', [])}")
    print(f"  Motive: {details.get('motive', [])}")

# ACTION: What did they do?
print("\n=== ACTION ===")
for action_type, details in incident['action'].items():
    print(f"  Type: {action_type}")
    print(f"  Variety: {details.get('variety', [])}")
    print(f"  Vector: {details.get('vector', [])}")

# ASSET: What was affected?
print("\n=== ASSET ===")
for asset in incident['asset'].get('assets', []):
    print(f"  Variety: {asset['variety']}")

# ATTRIBUTE: How was it affected?
print("\n=== ATTRIBUTE ===")
for attr_type, details in incident['attribute'].items():
    print(f"  Type: {attr_type}")
    if attr_type == 'confidentiality':
        for data in details.get('data', []):
            print(f"    Data: {data['variety']} ({data.get('amount', 'unknown')} records)")
```

### Step 4: Examine the timeline

```python
# TIMELINE: When did things happen?
print("=== TIMELINE ===")
timeline = incident['timeline']

if 'incident' in timeline:
    print(f"  Incident: {timeline['incident'].get('year')}-{timeline['incident'].get('month', '??')}")

if 'compromise' in timeline:
    t = timeline['compromise']
    print(f"  Time to compromise: {t.get('value', '?')} {t.get('unit', '?')}")

if 'discovery' in timeline:
    t = timeline['discovery']
    print(f"  Time to discover: {t.get('value', '?')} {t.get('unit', '?')}")

if 'containment' in timeline:
    t = timeline['containment']
    print(f"  Time to contain: {t.get('value', '?')} {t.get('unit', '?')}")
```

### Step 5: Validate a record

```console
python /scripts/validate.py /data/samples/phishing_breach.json
```

Expected output:

```text
Validating: /data/samples/phishing_breach.json
  schema_version: PRESENT (1.3.7)
  incident_id: PRESENT
  actor: PRESENT (1 type(s))
  action: PRESENT (2 type(s))
  asset: PRESENT (3 asset(s))
  attribute: PRESENT (2 type(s))
  timeline: PRESENT
VALIDATION: PASSED
```

### Step 6: Compare multiple records

```python
import os
import json

# Load all sample records
records = []
for fname in os.listdir('/data/samples/'):
    if fname.endswith('.json'):
        with open(f'/data/samples/{fname}') as f:
            records.append(json.load(f))

print(f"Loaded {len(records)} records")

# Count actor types across all records
from collections import Counter
actor_types = []
for r in records:
    actor_types.extend(r.get('actor', {}).keys())

print(Counter(actor_types))
```

## Discussion Points

1. **Why JSON?** VERIS uses JSON because it is machine-readable, widely supported, and easy to validate with schemas.

1. **Multiple actions**: Notice that many incidents have multiple action types (e.g., phishing + malware). This is realistic — attacks are multi-stage.

1. **Unknown values**: Many fields contain "Unknown" — this reflects real-world uncertainty in incident analysis. VERIS does not require certainty; it allows recording what is known.

1. **Confidence field**: The top-level `confidence` field ("Low", "Medium", "High") lets analysts communicate how certain they are about the record's accuracy.

## Clean Up

```console
docker compose down
```
