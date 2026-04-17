# Guide 01: Understanding the VERIS Schema

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Reading for Session 11

---

## Objective

By the end of this guide, you will be able to:

* Identify the key sections of a VERIS JSON record
* Describe the purpose of each top-level field
* Navigate a VERIS incident record and extract information from each section

---

## Background

VERIS (Vocabulary for Event Recording and Incident Sharing) uses a JSON schema to record security incidents in a structured, machine-readable format.
Understanding the schema is the foundation for all VERIS work — from coding incidents manually to building automated tools.

---

## Setup

No special setup is required.
You will work with JSON examples in this guide.

If you want to follow along interactively, run:

```console
docker run --rm -it python:3.11-slim python3
```

---

## Step 1: The Top-Level Structure

A VERIS record is a JSON object.
The top-level keys are:

```json
{
  "schema_version": "1.3.7",
  "incident_id": "a1b2c3d4-...",
  "source_id": "vcdb",
  "summary": "Human-readable description of the incident",
  "security_incident": "Confirmed",
  "confidence": "High",
  "discovery_method": { ... },
  "timeline": { ... },
  "victim": { ... },
  "actor": { ... },
  "action": { ... },
  "asset": { ... },
  "attribute": { ... },
  "impact": { ... }
}
```

**Key identification fields:**

* `schema_version` — which version of the VERIS standard was used
* `incident_id` — a UUID that uniquely identifies this incident record
* `source_id` — who submitted the record (e.g., "vcdb" for community contributions)

**Status fields:**

* `security_incident`: "Confirmed", "Suspected", or "Near miss"
* `confidence`: "None", "Low", "Medium", "High" — analyst's certainty about the coding

---

## Step 2: The Timeline Section

The timeline section captures temporal information about the incident:

```json
"timeline": {
  "incident": {
    "year": 2023,
    "month": 9,
    "day": 14
  },
  "compromise": {
    "unit": "Minutes",
    "value": 15
  },
  "exfiltration": {
    "unit": "Days",
    "value": 3
  },
  "discovery": {
    "unit": "Days",
    "value": 45
  },
  "containment": {
    "unit": "Hours",
    "value": 12
  }
}
```

**Timeline sub-fields:**
| Field | Meaning |
|-------|---------|
| `incident` | When did the initial event occur? |
| `compromise` | How long from attack start to successful compromise? |
| `exfiltration` | How long from access to data leaving the network? |
| `discovery` | How long until the organization discovered the incident? |
| `containment` | How long from discovery to containment? |

**Exercise 2.1:** Given the timeline above, calculate:

* How many days passed before the incident was discovered?
* How quickly was the compromise achieved once the attack started?
* What is the total "dwell time" (from compromise to discovery)?

> **Answer:** 45 days to discover; 15 minutes to compromise; dwell time = exfiltration time + discovery lag = approximately 48 days.

---

## Step 3: The Victim Section

```json
"victim": {
  "industry": "Healthcare",
  "employee_count": "1001 to 10000",
  "country": ["US"],
  "region": ["019021"],
  "government": ["Unknown"]
}
```

**Industry values** follow the NAICS (North American Industry Classification System) labels:

* Finance
* Healthcare
* Retail
* Manufacturing
* Education
* Public Administration
* Information
* Professional Services

**Employee count ranges:**

* "1 to 10"
* "11 to 100"
* "101 to 1000"
* "1001 to 10000"
* "10001 to 25000"
* "25001 to 50000"
* "50001 to 100000"
* "Over 100000"
* "Unknown"

---

## Step 4: The 4-A Sections

Each of the four core sections (actor, action, asset, attribute) uses a similar pattern: they can contain multiple sub-types.

### Actor

```json
"actor": {
  "external": {
    "variety": ["Organized crime"],
    "motive": ["Financial"],
    "country": ["RU"]
  }
}
```

An incident can have multiple actor types:

```json
"actor": {
  "external": { "variety": ["Organized crime"] },
  "internal": { "variety": ["End-user"], "motive": ["Financial"] }
}
```

### Action

```json
"action": {
  "social": {
    "variety": ["Phishing"],
    "vector": ["Email"]
  },
  "hacking": {
    "variety": ["Use of stolen creds"],
    "vector": ["Web application"]
  }
}
```

Multiple action types are common — they represent the attack chain.

### Asset

```json
"asset": {
  "assets": [
    {"variety": "S - Database"},
    {"variety": "U - Desktop"}
  ],
  "cloud": ["Unknown"],
  "hosting": ["Internally hosted"]
}
```

### Attribute

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data": [
      {"variety": "Personal", "amount": 50000},
      {"variety": "Credentials", "amount": 200}
    ]
  },
  "availability": {
    "variety": ["Interruption"],
    "duration": {"unit": "Hours", "value": 8}
  }
}
```

---

## Step 5: Parsing a Record in Python

```python
import json

record_text = '''
{
  "schema_version": "1.3.7",
  "incident_id": "abc-001",
  "summary": "Ransomware via phishing at healthcare org",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2023, "month": 3},
    "discovery": {"unit": "Hours", "value": 8},
    "containment": {"unit": "Days", "value": 5}
  },
  "victim": {"industry": "Healthcare"},
  "actor": {
    "external": {"variety": ["Organized crime"], "motive": ["Financial"]}
  },
  "action": {
    "social": {"variety": ["Phishing"], "vector": ["Email"]},
    "malware": {"variety": ["Ransomware"], "vector": ["Email attachment"]}
  },
  "asset": {
    "assets": [{"variety": "S - File"}, {"variety": "U - Desktop"}]
  },
  "attribute": {
    "availability": {"variety": ["Extortion"], "duration": {"unit": "Days", "value": 10}}
  }
}
'''

record = json.loads(record_text)

# Extract key information
print("Summary:", record['summary'])
print("Actor type(s):", list(record['actor'].keys()))
print("Action type(s):", list(record['action'].keys()))
print("Assets:", [a['variety'] for a in record['asset']['assets']])

# Access timeline
disc = record['timeline']['discovery']
print(f"Discovery time: {disc['value']} {disc['unit']}")
```

**Run this in a Python shell** and verify the output matches your expectations.

---

## Step 6: Schema Validation Checklist

When reviewing or creating a VERIS record, use this checklist:

* [ ] `schema_version` is present
* [ ] `incident_id` is a unique UUID
* [ ] `security_incident` is one of: Confirmed, Suspected, Near miss
* [ ] `confidence` is one of: None, Low, Medium, High
* [ ] `timeline.incident.year` is present
* [ ] At least one `actor` sub-type is present
* [ ] At least one `action` sub-type is present
* [ ] At least one `asset.assets` entry is present
* [ ] At least one `attribute` sub-type is present
* [ ] All `variety` and `vector` values use VERIS-defined enumerations

---

## Summary

You have learned:

* The structure of a VERIS JSON record and the purpose of each section
* How the timeline fields capture incident progression metrics
* How the victim section categorizes the affected organization
* How the 4-A sections (actor, action, asset, attribute) each contain multiple sub-types
* How to parse and access VERIS record fields in Python

**Next steps:** Proceed to Guide 02 to learn the VERIS 4-A classification categories in depth.
