# Demo 04: Creating a VERIS JSON Record for an Incident

**Duration:** 25 minutes

**Format:** Step-by-step guided record creation with validation

**Difficulty:** Beginner–Intermediate

**Directory:** `demos/demo-04-veris-reporting/`

---

## Overview

In this demo you will create a complete, validated VERIS JSON record from scratch, starting from an incident narrative.
You will use a structured encoding workflow and a Python validation/export script to produce a finished record ready for submission to VCDB or an internal incident database.

---

## Learning Objectives

* Follow a systematic process to encode an incident as a VERIS record
* Correctly populate all required and key optional fields
* Use the VERIS JSON schema structure accurately
* Validate a VERIS record for completeness
* Export a VERIS record in production-ready format

---

## The Incident Narrative

> **Incident: Managed Service Provider Supply Chain Attack**
>
> In March 2024, a mid-sized financial services firm (500 employees, US-based) discovered that their managed IT service provider had been compromised. The MSP's remote monitoring and management (RMM) software was used to deploy credential-harvesting malware to 8 of the firm's workstations. Attackers used the harvested credentials to access the firm's core banking application and download records for approximately 12,000 customers including names, addresses, account numbers, and transaction histories.
>
> The incident was discovered 22 days after the initial compromise when an employee reported unusual account activity to the IT helpdesk. Investigation determined the MSP had been compromised approximately 30 days prior. Total response cost was estimated at $1.8M including forensics, legal, and customer notification.
>
> Key details:
> - The MSP's RMM agent was used as the malware delivery mechanism
> - Credential harvesting malware captured domain admin credentials
> - Core banking database was accessed using harvested credentials
> - 12,000 customer records exfiltrated: PII + bank account data
> - Discovery: internal (IT helpdesk complaint from employee)
> - MSP compromise timeline: 30 days before firm compromise

---

## Step-by-Step Encoding Workflow

### Step 1: Identify the Actor

Ask yourself: Who caused this incident?

* **Is it someone inside the organization?** No — this is an external actor.
* **Is it a business partner/vendor?** The MSP was compromised and used as a vector, but the malicious actor is the party who compromised the MSP.
* **What type of external actor?** Unknown specific variety, but the financial motivation and RMM platform compromise suggest organized crime.

```text
Actor: External
Variety: Organized crime (best fit given financial targeting)
Motive: Financial
```

*But wait — what about the MSP?* The MSP is the **vector** (how the attacker reached the victim), not the actor.
The MSP is a Partner asset that was compromised.
You might also record a Partner actor to capture the supply chain aspect.

### Step 2: Identify the Actions

The attack chain had multiple steps:

1. MSP RMM software exploited → **Hacking > Use of backdoor/C2** (via MSP's compromised RMM)
1. Credential-harvesting malware deployed → **Malware > Keylogger/Credential harvester**
1. Harvested credentials used → **Hacking > Use of stolen credentials**
1. Database accessed → **Hacking > Use of stolen credentials** (same action, banking app)

*Primary actions to record: Malware + Hacking*

### Step 3: Identify the Assets

What systems were directly involved?

* 8 workstations where malware was installed: **U - Desktop (8)**
* Core banking application/database: **S - Database (1)**
* The MSP's RMM software was the vector, not a victim asset

### Step 4: Identify the Attributes

What security properties were compromised?

* Data was confirmed exfiltrated: **Confidentiality — data_disclosure: Yes**
* Data types: PII (names, addresses), Bank account data, Transaction history
* Record count: 12,000

### Step 5: Complete the Record

Run the script to see the complete encoded record:

```console
python3 create_veris_record.py
```

---

## Record Creation and Validation Script

```python
#!/usr/bin/env python3
"""
VERIS Demo 04 - Creating a VERIS JSON Record
Session 11 | Security Operations Master Class
"""

import json
import uuid
from datetime import datetime

# ─── The complete VERIS record for the incident ─────────────────

VERIS_RECORD = {
    "schema_version": "1.3.7",
    "incident_id": str(uuid.uuid4()),
    "source_id": "demo",
    "summary": (
        "MSP supply chain attack: compromised RMM software used to deploy "
        "credential-harvesting malware to 8 workstations. Harvested domain admin "
        "credentials used to access core banking application and exfiltrate 12,000 "
        "customer records including PII and bank account data."
    ),
    "confidence": "High",
    "security_incident": "Confirmed",
    "timeline": {
        "incident": {
            "year": 2024,
            "month": 3
        },
        "compromise": {
            "unit": "Days",
            "value": 30,
            "notes": "MSP was compromised approximately 30 days before firm compromise"
        },
        "discovery": {
            "unit": "Days",
            "value": 22
        },
        "containment": {
            "unit": "Unknown",
            "value": -1
        },
        "exfiltration": {
            "unit": "Unknown",
            "value": -1
        }
    },
    "victim": {
        "victim_id": "Anonymized Financial Services Firm",
        "industry": "522110",
        "industry2": "Commercial Banking",
        "employee_count": "101 to 1000",
        "revenue": {
            "iso_currency_code": "USD",
            "amount": -1
        },
        "country": ["US"],
        "region": ["NA"],
        "locations_affected": 1,
        "notes": "~500 employees, mid-sized financial institution"
    },
    "actor": {
        "external": {
            "variety": ["Organized crime"],
            "motive": ["Financial"],
            "country": ["Unknown"],
            "region": ["Unknown"],
            "notes": "Actor compromised MSP as stepping stone to victim"
        },
        "partner": {
            "motive": ["Unknown"],
            "industry": "541513",
            "notes": "MSP was victim of initial compromise; their RMM used as attack vector"
        }
    },
    "action": {
        "hacking": {
            "variety": [
                "Use of stolen credentials",
                "Use of backdoor or C2"
            ],
            "vector": [
                "Desktop sharing software",
                "Web application"
            ],
            "notes": "RMM software served as backdoor/C2; stolen creds used for banking DB access"
        },
        "malware": {
            "variety": [
                "Keylogger",
                "Credential stealer"
            ],
            "vector": [
                "Direct install"
            ],
            "notes": "Malware deployed via compromised MSP RMM agent"
        }
    },
    "asset": {
        "assets": [
            {
                "variety": "U - Desktop",
                "amount": 8
            },
            {
                "variety": "S - Database",
                "amount": 1
            }
        ],
        "cloud": ["No"],
        "notes": "MSP RMM agent installed on victim workstations served as attack vector"
    },
    "attribute": {
        "confidentiality": {
            "data_disclosure": "Yes",
            "data_total": 12000,
            "data_victim": ["Customer"],
            "data": [
                {
                    "variety": "Personal",
                    "amount": 12000
                },
                {
                    "variety": "Bank",
                    "amount": 12000
                }
            ],
            "notes": "Names, addresses, account numbers, transaction history for 12,000 customers"
        }
    },
    "discovery_method": {
        "internal": {
            "variety": ["Reported by user"]
        }
    },
    "impact": {
        "loss": [
            {
                "variety": "Response and remediation",
                "amount": 1800000,
                "iso_currency_code": "USD",
                "notes": "Includes forensics, legal, and customer notification costs"
            }
        ],
        "overall_rating": "Major",
        "notes": "Estimated $1.8M total response cost"
    },
    "notes": (
        "Supply chain attack. MSP was initial target; victim firm was secondary target. "
        "Highlights third-party and supply chain risk in financial services. "
        "GLBA and state breach notification laws apply due to financial PII."
    )
}

# ─── Validation functions ────────────────────────────────────────

REQUIRED_TOP_KEYS = ["incident_id", "source_id", "security_incident"]
REQUIRED_4A = ["actor", "action", "asset", "attribute"]

def validate_record(record: dict) -> list:
    """Basic VERIS record validation. Returns list of issues found."""
    issues = []

    for key in REQUIRED_TOP_KEYS:
        if key not in record:
            issues.append(f"MISSING required field: '{key}'")

    for dim in REQUIRED_4A:
        if dim not in record or not record[dim]:
            issues.append(f"MISSING required dimension: '{dim}'")

    # Confidence check
    if "confidence" not in record:
        issues.append("ADVISORY: 'confidence' field not set")

    # Timeline check
    if "timeline" not in record or "incident" not in record.get("timeline", {}):
        issues.append("ADVISORY: Timeline 'incident' not set")

    # Victim industry
    if "victim" not in record or "industry" not in record.get("victim", {}):
        issues.append("ADVISORY: Victim industry (NAICS) not set")

    # At least one actor
    actor = record.get("actor", {})
    if not any(actor.get(k) for k in ["external", "internal", "partner"]):
        issues.append("MISSING: No actor sub-type populated")

    # Data breach check
    conf = record.get("attribute", {}).get("confidentiality", {})
    if conf.get("data_disclosure") in ["Yes", "Potentially"]:
        if not conf.get("data"):
            issues.append("ADVISORY: Data breach but no data types specified")
        if not conf.get("data_total") or conf.get("data_total") == 0:
            issues.append("ADVISORY: Data breach but no record count specified")

    return issues

def print_record_summary(record: dict):
    print("\n" + "─" * 65)
    print("  VERIS RECORD SUMMARY")
    print("─" * 65)
    print(f"  incident_id:    {record['incident_id'][:8]}...")
    print(f"  confidence:     {record.get('confidence', 'Not set')}")
    print(f"  type:           {record.get('security_incident', 'Unknown')}")

    print(f"\n  Summary: {record.get('summary', '')[:80]}...")

    # Timeline
    t = record.get("timeline", {})
    print(f"\n  Timeline:")
    print(f"    Year:       {t.get('incident', {}).get('year', '?')}")
    print(f"    Discovery:  {t.get('discovery', {}).get('value', '?')} {t.get('discovery', {}).get('unit', '')}")

    # Victim
    v = record.get("victim", {})
    print(f"\n  Victim:")
    print(f"    Industry:  {v.get('industry', '?')} ({v.get('industry2', '?')})")
    print(f"    Size:      {v.get('employee_count', '?')}")
    print(f"    Country:   {v.get('country', '?')}")

    # 4A summary
    print(f"\n  Actor(s):")
    for at, d in record.get("actor", {}).items():
        print(f"    [{at}] variety={d.get('variety', [])} motive={d.get('motive', [])}")

    print(f"\n  Action(s):")
    for at, d in record.get("action", {}).items():
        print(f"    [{at}] variety={d.get('variety', [])} vector={d.get('vector', [])}")

    print(f"\n  Asset(s):")
    for a in record.get("asset", {}).get("assets", []):
        print(f"    {a['variety']} x{a.get('amount', '?')}")

    print(f"\n  Attribute(s):")
    for at, d in record.get("attribute", {}).items():
        if at == "confidentiality":
            print(f"    Confidentiality: disclosure={d.get('data_disclosure')}, total={d.get('data_total')}")
            for x in d.get("data", []):
                print(f"      Data: {x['variety']} ({x.get('amount', '?')} records)")
        elif at == "availability":
            print(f"    Availability: {d.get('variety')}, duration={d.get('duration', {})}")
        elif at == "integrity":
            print(f"    Integrity: {d.get('variety')}")

    # Impact
    print(f"\n  Impact: {record.get('impact', {}).get('overall_rating', 'Unknown')}")
    for loss in record.get("impact", {}).get("loss", []):
        print(f"    {loss.get('variety')}: ${loss.get('amount', 0):,} {loss.get('iso_currency_code', '')}")

def main():
    print("\n" + "=" * 65)
    print("  VERIS Demo 04: Creating a VERIS Record")
    print("  MSP Supply Chain Attack — Financial Services")
    print("=" * 65)

    # Validate
    issues = validate_record(VERIS_RECORD)
    print(f"\n  VALIDATION RESULT: {'PASS' if not issues else 'ISSUES FOUND'}")
    if issues:
        for issue in issues:
            print(f"    ⚠ {issue}")
    else:
        print("    All required fields present.")

    # Summary
    print_record_summary(VERIS_RECORD)

    # Export to file
    output_file = "msp_supply_chain_veris.json"
    with open(output_file, "w") as f:
        json.dump(VERIS_RECORD, f, indent=2)
    print(f"\n  Record exported to: {output_file}")
    print(f"  Ready for VCDB submission or internal incident tracking.\n")

if __name__ == "__main__":
    main()
```

---

## Discussion: Encoding Decisions Made

Several judgment calls were made when encoding this record.
Understanding these helps build encoding proficiency:

### Why Partner actor in addition to External actor?

The MSP was both a victim (they were compromised) and a vector (their RMM was used against the firm).
Recording a Partner actor captures the supply chain nature of the attack and enables analysis of vendor-related incidents in aggregate data.

### Why "Use of backdoor or C2" as a hacking variety?

The attacker's RMM access functioned as a backdoor with persistent access.
While this isn't a custom backdoor, it provides equivalent capability — remote command execution on victim systems.

### Why not record the MSP systems as assets?

VERIS records the assets of the **victim organization**, not the attacker or intermediary organizations.
The MSP's systems are the MSP's incident to record.

### Why `data_total: 12000` but amounts also listed as 12000 each for two data types?

The same 12,000 customers had both PII and bank account data exposed.
The total affected individuals was 12,000 even though two data types are listed.
This is common for multi-type breaches affecting the same individuals.

---

## Extension Exercise

Try modifying the record to encode a second incident:

> "Six months later, the same firm suffered a ransomware attack, this time via a direct phishing campaign. 50 workstations were encrypted. No data was exfiltrated. Downtime: 3 days."

Which fields change?
Which stay the same?
Which attributes are different?

---

*Demo 04 | Session 11 | Security Operations Master Class | Digital4Security*
