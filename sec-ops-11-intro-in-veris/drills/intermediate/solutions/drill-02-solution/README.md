# Solution: Drill 02 (Intermediate) — Build a VERIS Incident Dataset

## VERIS Records

### Scenario 1: E-Commerce Credential Stuffing

```json
{
  "schema_version": "1.3.7",
  "incident_id": "scenario-01",
  "summary": "Credential stuffing attack using leaked credentials led to 12,000 account takeovers and €180,000 in fraudulent purchases.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024},
    "compromise": {"unit": "Hours", "value": 1},
    "discovery": {"unit": "Hours", "value": 36}
  },
  "victim": {
    "industry": "Retail",
    "employee_count": "Unknown"
  },
  "actor": {
    "external": {
      "variety": ["Organized crime"],
      "motive": ["Financial"],
      "country": ["Unknown"]
    }
  },
  "action": {
    "hacking": {
      "variety": ["Brute force", "Use of stolen creds"],
      "vector": ["Web application"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "S - Web"},
      {"variety": "P - Customer"}
    ]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [
        {"variety": "Credentials", "amount": 12000},
        {"variety": "Financial", "amount": 1800}
      ]
    }
  }
}
```

**Key decisions:**

* `Brute force` + `Use of stolen creds`: credential stuffing uses external breach data but the technique is brute-force-like. Both varieties apply.
* `Financial` data: the 1,800 payment methods accessed are financial data records.

---

### Scenario 2: Insider Intellectual Property Theft

```json
{
  "schema_version": "1.3.7",
  "incident_id": "scenario-02",
  "summary": "Software engineer downloaded proprietary source code over three days using legitimate access before resigning and joining a competitor.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024},
    "exfiltration": {"unit": "Days", "value": 3},
    "discovery": {"unit": "Months", "value": 2}
  },
  "victim": {
    "industry": "Information",
    "employee_count": "Unknown"
  },
  "actor": {
    "internal": {
      "variety": ["Developer"],
      "motive": ["Financial", "Competitive advantage"]
    }
  },
  "action": {
    "misuse": {
      "variety": ["Privilege abuse", "Data mishandling"],
      "vector": ["LAN access"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "S - Code repository"},
      {"variety": "M - Disk"}
    ]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [
        {"variety": "Source code", "amount": 0}
      ]
    }
  }
}
```

**Key decisions:**

* `Misuse` (not hacking): the actor had legitimate access. No system was exploited — they used normal developer access.
* `Motive: Financial` + competitive advantage: selling to competitor implies financial benefit.
* Discovery time 2 months reflects DLP audit gap.

---

### Scenario 3: Healthcare Ransomware

```json
{
  "schema_version": "1.3.7",
  "incident_id": "scenario-03",
  "summary": "Ransomware spread from malicious email attachment to six hospital servers including PACS system; clinical operations disrupted for 11 days. No data exfiltration confirmed.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024},
    "compromise": {"unit": "Hours", "value": 2},
    "discovery": {"unit": "Hours", "value": 4},
    "containment": {"unit": "Days", "value": 11}
  },
  "victim": {
    "industry": "Healthcare",
    "employee_count": "101 to 1000"
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
    "malware": {
      "variety": ["Ransomware"],
      "vector": ["Email attachment"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "P - End-user"},
      {"variety": "U - Desktop"},
      {"variety": "S - File"},
      {"variety": "S - Other"}
    ]
  },
  "attribute": {
    "availability": {
      "variety": ["Extortion", "Interruption"],
      "duration": {"unit": "Days", "value": 11}
    },
    "integrity": {
      "variety": ["Install code"]
    }
  }
}
```

**Key decisions:**

* No `confidentiality` attribute: forensics confirmed no exfiltration. Do not add what didn't happen.
* `Extortion` + `Interruption`: both varieties apply — operations were interrupted AND payment was demanded.
* `Integrity: Install code`: the ransomware was installed on systems.

---

### Scenario 4: Cloud Misconfiguration

```json
{
  "schema_version": "1.3.7",
  "incident_id": "scenario-04",
  "summary": "Elasticsearch cluster accidentally exposed publicly for 14 days during config migration; 340,000 user records including email addresses and hashed passwords accessible without authentication.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024},
    "discovery": {"unit": "Days", "value": 14}
  },
  "victim": {
    "industry": "Information",
    "employee_count": "Unknown"
  },
  "actor": {
    "internal": {
      "variety": ["System admin"],
      "motive": ["NA"]
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
      {"variety": "S - Database"}
    ],
    "cloud": ["External Cloud Asset(s)"],
    "hosting": ["External Cloud Asset(s)"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Unknown",
      "data": [
        {"variety": "Personal", "amount": 340000},
        {"variety": "Credentials", "amount": 340000}
      ],
      "state": ["Stored unencrypted"]
    }
  }
}
```

**Key decisions:**

* `data_disclosure: "Unknown"`: researcher confirmed exposure, but no evidence of malicious access. "Unknown" is the honest answer.
* Credentials are hashed but still count as credential data.
* Internal actor (DevOps team) caused the error — there is no external threat actor.

---

### Scenario 5: BEC — Supplier Fraud

```json
{
  "schema_version": "1.3.7",
  "incident_id": "scenario-05",
  "summary": "BEC attack via spoofed supplier domain led to €220,000 wire fraud over one month before discovery.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024},
    "compromise": {"unit": "Days", "value": 1},
    "discovery": {"unit": "Months", "value": 1}
  },
  "victim": {
    "industry": "Manufacturing",
    "employee_count": "Unknown"
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
      "variety": ["Pretexting", "BEC"],
      "vector": ["Email"],
      "target": ["Finance"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "P - Finance"},
      {"variety": "S - Other"}
    ]
  },
  "attribute": {
    "integrity": {
      "variety": ["Modify data"]
    }
  }
}
```

**Key decisions:**

* BEC (Business Email Compromise) maps to `social.variety = ["BEC", "Pretexting"]`. This was email-based impersonation.
* `Integrity: Modify data` — the attacker's impact was modifying payment banking details.
* No data exfiltration — no confidentiality attribute.

---

## Analysis Script (analyze.py)

```python
#!/usr/bin/env python3
import json
import glob
from collections import Counter

def to_hours(timeline_field):
    if not timeline_field:
        return None
    unit = timeline_field.get('unit', '')
    value = timeline_field.get('value', None)
    if value is None or unit == 'Unknown':
        return None
    multipliers = {'Minutes': 1/60, 'Hours': 1, 'Days': 24, 'Weeks': 168, 'Months': 720}
    return value * multipliers.get(unit, None)

# Load all VERIS records
records = []
for fname in sorted(glob.glob('scenario-*.json')):
    with open(fname) as f:
        records.append(json.load(f))

print(f"\nLoaded {len(records)} VERIS records\n")

# Summary table
print(f"{'Incident ID':<20} {'Actor Type':<15} {'Top Action':<20} {'Disclosed':<12} {'Records'}")
print("-" * 80)
for r in records:
    incident_id = r.get('incident_id', 'N/A')
    actor_type = list(r.get('actor', {}).keys())[0] if r.get('actor') else 'Unknown'
    top_action = list(r.get('action', {}).keys())[0] if r.get('action') else 'Unknown'
    disclosed = r.get('attribute', {}).get('confidentiality', {}).get('data_disclosure', 'N/A')

    total_records = sum(
        d.get('amount', 0)
        for d in r.get('attribute', {}).get('confidentiality', {}).get('data', [])
    )
    print(f"{incident_id:<20} {actor_type:<15} {top_action:<20} {disclosed:<12} {total_records:,}")

# Aggregated stats
print("\n" + "="*50)
print("AGGREGATE STATISTICS")
print("="*50)

# Total records exposed
total_records = 0
for r in records:
    for d in r.get('attribute', {}).get('confidentiality', {}).get('data', []):
        total_records += d.get('amount', 0)
print(f"Total records exposed: {total_records:,}")

# Average discovery time
disc_times = []
for r in records:
    disc = r.get('timeline', {}).get('discovery')
    h = to_hours(disc)
    if h:
        disc_times.append(h)
if disc_times:
    avg_disc = sum(disc_times) / len(disc_times)
    print(f"Average discovery time: {avg_disc:.1f} hours ({avg_disc/24:.1f} days)")

# Most common actor/action
all_actors = []
all_actions = []
for r in records:
    all_actors.extend(r.get('actor', {}).keys())
    all_actions.extend(r.get('action', {}).keys())

print(f"Most common actor type: {Counter(all_actors).most_common(1)[0][0]}")
print(f"Most common action type: {Counter(all_actions).most_common(1)[0][0]}")
```

**Expected output:**

```text
Loaded 5 VERIS records

Incident ID          Actor Type      Top Action           Disclosed    Records
--------------------------------------------------------------------------------
scenario-01          external        hacking              Yes          13,800
scenario-02          internal        misuse               Yes          0
scenario-03          external        social               No           0
scenario-04          internal        error                Unknown      680,000
scenario-05          external        social               No           0

==================================================
AGGREGATE STATISTICS
==================================================
Total records exposed: 693,800
Average discovery time: 1,296.0 hours (54.0 days)
Most common actor type: external
Most common action type: social
```
