# Demo 01: VERIS Framework Overview with Worked Examples

**Duration:** 25 minutes

**Format:** Walkthrough with interactive JSON exploration

**Difficulty:** Beginner

**Directory:** `demos/demo-01-veris-overview/`

---

## Overview

This demo provides a hands-on walkthrough of the VERIS framework.
You will explore the 4A taxonomy through worked examples, examine real VERIS JSON records, and develop intuition for how the framework classifies incidents.

---

## Learning Objectives

By the end of this demo you will be able to:

* Explain the purpose and structure of the VERIS 4A taxonomy
* Navigate a VERIS JSON record and identify key fields
* Apply the Actor, Action, Asset, and Attribute dimensions to describe an incident
* Distinguish between a security incident and a data breach in VERIS terms

---

## Prerequisites

* Python 3.8+ installed
* `pip install jsonschema requests`
* Clone or download the VERIS schema: `git clone https://github.com/vz-risk/veris.git`

---

## Part 1: Understanding the 4A Taxonomy (5 minutes)

Before looking at any JSON, let's internalize the four dimensions with a concrete example.

### Worked Example: The Target 2013 Breach

In 2013, Target Corporation suffered a massive data breach affecting 40 million payment cards and 70 million customer records.
Let's classify it using VERIS:

```text
INCIDENT: Target 2013 Data Breach

ACTOR:    External
          Variety: Organized crime
          Motive:  Financial

ACTION:   Social Engineering → Phishing
          (initial compromise of HVAC vendor)

          Hacking → Use of stolen credentials
          (vendor credentials used to access Target network)

          Malware → BlackPOS (memory-scraping malware)
          (installed on POS systems to capture card data)

ASSET:    T - Point of Sale (POS terminals)
          S - Database (customer data)

ATTRIBUTE: Confidentiality
           Data: Payment card data (~40M records)
           Data: Personal information (~70M records)
           Data disclosure: Yes (confirmed breach)
```

This single classification captures the complete "story" in a machine-readable way that can be compared against thousands of other incidents.

---

## Part 2: Exploring VERIS JSON Records (15 minutes)

### Setup

```console
mkdir -p ~/veris-demo && cd ~/veris-demo
```

Create `explore_veris.py`:

```python
#!/usr/bin/env python3
"""
VERIS Framework Demo 01 - Exploring Records
Session 11 | Security Operations Master Class
"""

import json
from pathlib import Path

# ─── Sample incident records ────────────────────────────────

INCIDENTS = [
    {
        "incident_id": "demo-001",
        "source_id": "demo",
        "summary": "Phishing email led to credential theft; attacker accessed customer database",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 3},
            "discovery": {"unit": "Days", "value": 14},
            "containment": {"unit": "Hours", "value": 48}
        },
        "victim": {
            "industry": "522110",
            "industry2": "Commercial Banking",
            "employee_count": "1001 to 10000",
            "country": ["US"]
        },
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"],
                "country": ["Unknown"]
            }
        },
        "action": {
            "social": {
                "variety": ["Phishing"],
                "vector": ["Email"],
                "target": ["End-user"]
            },
            "hacking": {
                "variety": ["Use of stolen credentials"],
                "vector": ["Web application"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - Database", "amount": 1},
                {"variety": "U - Desktop", "amount": 12}
            ],
            "cloud": ["No"]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data_total": 25000,
                "data": [
                    {"variety": "Personal", "amount": 20000},
                    {"variety": "Credentials", "amount": 5000}
                ]
            }
        }
    },
    {
        "incident_id": "demo-002",
        "source_id": "demo",
        "summary": "IT admin accidentally exposed customer backup to public S3 bucket for 3 weeks",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 5},
            "discovery": {"unit": "Days", "value": 21},
            "containment": {"unit": "Hours", "value": 2}
        },
        "victim": {
            "industry": "621111",
            "industry2": "Offices of Physicians",
            "employee_count": "11 to 100",
            "country": ["US"]
        },
        "actor": {
            "internal": {
                "variety": ["System administrator"],
                "motive": ["Convenience"]
            }
        },
        "action": {
            "error": {
                "variety": ["Misconfiguration"],
                "vector": ["Unknown"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - Database", "amount": 1}
            ],
            "cloud": ["Yes"]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data_total": 8500,
                "data": [
                    {"variety": "Medical (PHI)", "amount": 8500}
                ]
            }
        }
    },
    {
        "incident_id": "demo-003",
        "source_id": "demo",
        "summary": "Ransomware deployed via phishing, encrypting 150 workstations and 4 file servers",
        "confidence": "High",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": 2024, "month": 8},
            "discovery": {"unit": "Hours", "value": 3},
            "containment": {"unit": "Days", "value": 5}
        },
        "victim": {
            "industry": "336111",
            "industry2": "Automobile Manufacturing",
            "employee_count": "10001 to 25000",
            "country": ["DE"]
        },
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"]
            }
        },
        "action": {
            "social": {
                "variety": ["Phishing"],
                "vector": ["Email"]
            },
            "malware": {
                "variety": ["Ransomware"],
                "vector": ["Email attachment"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "U - Desktop", "amount": 150},
                {"variety": "S - File", "amount": 4}
            ],
            "cloud": ["No"]
        },
        "attribute": {
            "integrity": {"variety": ["Software installation", "Alter behavior"]},
            "availability": {
                "variety": ["Encryption"],
                "duration": {"unit": "Days", "value": 5}
            }
        }
    }
]

def print_separator(char="─", width=60):
    print(char * width)

def display_4a_summary(incident: dict):
    """Extract and display the 4A classification for an incident."""
    print(f"\n{'═' * 60}")
    print(f"INCIDENT: {incident['incident_id']}")
    print(f"Summary:  {incident['summary'][:70]}...")
    print(f"{'═' * 60}")

    # ACTOR
    actors = incident.get("actor", {})
    print("\n[ACTOR]")
    for actor_type, actor_data in actors.items():
        varieties = actor_data.get("variety", ["Unknown"])
        motives = actor_data.get("motive", ["Unknown"])
        print(f"  Type:    {actor_type.capitalize()}")
        print(f"  Variety: {', '.join(varieties)}")
        print(f"  Motive:  {', '.join(motives)}")

    # ACTION
    actions = incident.get("action", {})
    print("\n[ACTION]")
    for action_type, action_data in actions.items():
        varieties = action_data.get("variety", ["Unknown"])
        vectors = action_data.get("vector", ["Unknown"])
        print(f"  Category: {action_type.capitalize()}")
        print(f"  Variety:  {', '.join(varieties)}")
        print(f"  Vector:   {', '.join(vectors)}")

    # ASSET
    assets = incident.get("asset", {}).get("assets", [])
    cloud = incident.get("asset", {}).get("cloud", ["Unknown"])
    print("\n[ASSET]")
    for asset in assets:
        print(f"  {asset['variety']} (count: {asset.get('amount', 1)})")
    print(f"  Cloud: {', '.join(cloud)}")

    # ATTRIBUTE
    attrs = incident.get("attribute", {})
    print("\n[ATTRIBUTE]")
    for attr_type, attr_data in attrs.items():
        print(f"  {attr_type.capitalize()}:")
        if attr_type == "confidentiality":
            disclosure = attr_data.get("data_disclosure", "Unknown")
            total = attr_data.get("data_total", "Unknown")
            data_types = [d["variety"] for d in attr_data.get("data", [])]
            print(f"    Disclosure: {disclosure}, Records: {total}")
            print(f"    Data types: {', '.join(data_types)}")
        elif attr_type == "availability":
            varieties = attr_data.get("variety", [])
            duration = attr_data.get("duration", {})
            print(f"    Variety: {', '.join(varieties)}")
            if duration:
                print(f"    Duration: {duration.get('value')} {duration.get('unit')}")
        elif attr_type == "integrity":
            varieties = attr_data.get("variety", [])
            print(f"    Variety: {', '.join(varieties)}")

def is_data_breach(incident: dict) -> bool:
    """Determine if an incident qualifies as a data breach."""
    confidentiality = incident.get("attribute", {}).get("confidentiality", {})
    disclosure = confidentiality.get("data_disclosure", "No")
    return disclosure in ["Yes", "Potentially"]

def classify_incident_type(incident: dict) -> str:
    """Simple ICP classification based on actions."""
    actions = set(incident.get("action", {}).keys())
    actors = incident.get("actor", {})

    if "malware" in actions and any("Ransomware" in str(v) for v in
       incident["action"].get("malware", {}).get("variety", [])):
        return "System Intrusion (Ransomware)"
    elif "social" in actions and "hacking" not in actions:
        return "Social Engineering"
    elif "error" in actions:
        return "Miscellaneous Errors"
    elif "hacking" in actions and "social" in actions:
        return "System Intrusion"
    elif "hacking" in actions:
        return "Basic Web Application Attack"
    elif "misuse" in actions:
        return "Privilege Misuse"
    else:
        return "Everything Else"

def main():
    print("\n" + "=" * 60)
    print("  VERIS Demo 01: Framework Overview with Worked Examples")
    print("  Session 11 | Security Operations Master Class")
    print("=" * 60)

    for incident in INCIDENTS:
        display_4a_summary(incident)

        # Classification
        breach = is_data_breach(incident)
        icp = classify_incident_type(incident)
        timeline = incident.get("timeline", {})
        discovery = timeline.get("discovery", {})

        print(f"\n[CLASSIFICATION]")
        print(f"  Security incident type: {icp}")
        print(f"  Is data breach: {'YES' if breach else 'NO'}")
        print(f"  Discovery time: {discovery.get('value', '?')} {discovery.get('unit', '')}")

    # Summary statistics
    print(f"\n{'═' * 60}")
    print("SUMMARY ACROSS 3 INCIDENTS")
    print(f"{'═' * 60}")

    actor_types = {}
    action_types = {}
    attributes = {}
    breaches = 0

    for inc in INCIDENTS:
        for a in inc.get("actor", {}):
            actor_types[a] = actor_types.get(a, 0) + 1
        for a in inc.get("action", {}):
            action_types[a] = action_types.get(a, 0) + 1
        for a in inc.get("attribute", {}):
            attributes[a] = attributes.get(a, 0) + 1
        if is_data_breach(inc):
            breaches += 1

    print(f"\nActor types:    {dict(sorted(actor_types.items(), key=lambda x: -x[1]))}")
    print(f"Action types:   {dict(sorted(action_types.items(), key=lambda x: -x[1]))}")
    print(f"Attributes:     {dict(sorted(attributes.items(), key=lambda x: -x[1]))}")
    print(f"Data breaches:  {breaches}/{len(INCIDENTS)}")
    print()

if __name__ == "__main__":
    main()
```

### Running the Demo

```console
python3 explore_veris.py
```

**Expected output** (abbreviated):

```text
════════════════════════════════════════════════════════════
INCIDENT: demo-001
Summary:  Phishing email led to credential theft; attacker accessed...
════════════════════════════════════════════════════════════

[ACTOR]
  Type:    External
  Variety: Organized crime
  Motive:  Financial

[ACTION]
  Category: Social
  Variety:  Phishing
  Vector:   Email
  Category: Hacking
  Variety:  Use of stolen credentials
  Vector:   Web application
...
[CLASSIFICATION]
  Security incident type: System Intrusion
  Is data breach: YES
  Discovery time: 14 Days
```

---

## Part 3: Comparing Three Incident Stories (5 minutes)

After running the script, discuss these key observations:

### Incident 1 (Banking Phishing)

* **Actor**: External organized crime — financially motivated
* **Actions**: Two-step attack (phishing → credential use) — realistic attack chain
* **Asset**: Database server — the target holding valuable data
* **Attribute**: Confidentiality only — the data was accessed but systems weren't disrupted
* **Classification**: System Intrusion

### Incident 2 (Healthcare Misconfiguration)

* **Actor**: Internal system administrator — but motive is "Convenience" (not malicious)
* **Action**: Error > Misconfiguration — *no external attacker*
* **Asset**: Cloud database — important cloud ownership tracking
* **Attribute**: Confidentiality only — data was exposed but nothing was destroyed
* **Classification**: Miscellaneous Errors

### Incident 3 (Manufacturing Ransomware)

* **Actor**: External organized crime
* **Actions**: Phishing + ransomware (multi-action)
* **Asset**: Many user devices + file servers
* **Attribute**: Integrity AND Availability (NOT Confidentiality — data was encrypted but not confirmed exfiltrated)
* **Classification**: System Intrusion (Ransomware)

### Key Observation
Incident 2 has **no malicious external actor** yet it resulted in a data breach with PHI exposure.
This is why the Error action category is critical — many real breaches are accidental.

---

## Discussion Questions

1. Why does VERIS allow multiple actions per incident? What would we lose if only one action was recorded?

1. Incident 3 does not record a Confidentiality attribute. Under what circumstances would ransomware *also* have Confidentiality? (Hint: double extortion)

1. For Incident 2, the actor motive is "Convenience." What does this mean in the context of a sysadmin creating an exposed S3 bucket?

1. How would you encode a DDoS attack that took down a website for 6 hours with no data theft?

---

## Next Steps

* Try encoding the [Target 2013 breach](#worked-example-the-target-2013-breach) from Part 1 as a JSON record
* Explore Demo 02 to classify 5 additional real-world incidents
* Browse VCDB records at https://github.com/vz-risk/VCDB to see how professionals encode incidents

---

*Demo 01 | Session 11 | Security Operations Master Class | Digital4Security*
