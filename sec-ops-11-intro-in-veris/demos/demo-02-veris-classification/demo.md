# Demo 02: Classifying Real Incidents Using the VERIS Taxonomy

**Duration:** 30 minutes

**Format:** Guided classification exercise with Python analysis tool

**Difficulty:** Beginner–Intermediate

**Directory:** `demos/demo-02-veris-classification/`

---

## Overview

In this demo you will classify five real-world security incidents using the VERIS 4A taxonomy.
Each incident is described in plain English.
You will work through the classification process step by step, then verify your classifications using the analysis script.

---

## Learning Objectives

* Apply the VERIS 4A taxonomy to real-world incident descriptions
* Distinguish between similar incidents that differ in one dimension
* Recognize multi-action incidents and the order of actions
* Identify when an incident is a breach vs. a non-breach incident

---

## The Five Incidents to Classify

Read each incident narrative carefully before attempting classification.

---

### Incident A: The Hospital Insider

> "A nurse at a large hospital accessed the medical records of a celebrity patient who was not under her care. She shared the patient's diagnosis and treatment information with a tabloid magazine. The hospital discovered the access during a routine audit 6 weeks after it occurred."

**Your Classification Task:**

| Dimension | Your Answer |
|-----------|-------------|
| Actor type | ? |
| Actor variety | ? |
| Actor motive | ? |
| Action category | ? |
| Action variety | ? |
| Asset category | ? |
| Asset variety | ? |
| Attribute | ? |
| Data type | ? |
| Is this a breach? | ? |

---

### Incident B: The E-Commerce Attack

> "Attackers exploited a SQL injection vulnerability in a retail website's login form to extract the credentials database. They then used the extracted credentials to access 3,200 customer accounts and make fraudulent purchases. The breach was discovered by the payment processor 45 days later when fraud patterns were identified."

**Your Classification Task:**

| Dimension | Your Answer |
|-----------|-------------|
| Actor type | ? |
| Actor variety | ? |
| Actor motive | ? |
| Primary action | ? |
| Secondary action | ? |
| Asset(s) | ? |
| Attribute(s) | ? |
| Data types | ? |

---

### Incident C: The Ransomware School

> "A K-12 school district suffered a ransomware attack. An employee opened a phishing email disguised as a 'substitute teacher contract' and enabled macros on the attached document. The ransomware spread to 80 workstations and 3 servers over 4 hours, encrypting student records, financial data, and HR files. The IT team contained the attack within 12 hours. No evidence of data exfiltration was found."

**Your Classification Task:**

| Dimension | Your Answer |
|-----------|-------------|
| Actor type | ? |
| Actions (in order) | ? |
| Assets | ? |
| Attributes affected | ? |
| Is confidentiality affected? | ? |

---

### Incident D: The State-Sponsored Intrusion

> "A defense contractor's network was compromised by an advanced persistent threat actor. The attackers used a zero-day exploit in the contractor's VPN software to gain initial access, then moved laterally for 8 months harvesting classified technical documents and engineering specifications. Discovery was made by a government security agency monitoring unusual data transfers."

**Your Classification Task:**

| Dimension | Your Answer |
|-----------|-------------|
| Actor type | ? |
| Actor variety | ? |
| Actor motive | ? |
| Actions | ? |
| Assets | ? |
| Attributes | ? |
| Data types | ? |

---

### Incident E: The ATM Skimmer

> "A criminal gang physically installed skimming devices on 12 ATMs at bank branches across a city. The devices captured card magnetic stripe data and recorded PINs via a pinhole camera. Over 2 weeks, 340 card details were captured and fraudulently used. The skimmers were discovered by a bank employee during a routine maintenance check."

**Your Classification Task:**

| Dimension | Your Answer |
|-----------|-------------|
| Actor type | ? |
| Actions | ? |
| Assets | ? |
| Attributes | ? |
| Data types | ? |

---

## Running the Classification Verification Script

After completing your classifications above, run the script to see the model answers and analysis:

```console
python3 classify_incidents.py
```

---

## Analysis Script

Create `classify_incidents.py`:

```python
#!/usr/bin/env python3
"""
VERIS Demo 02 - Incident Classification Exercise
Session 11 | Security Operations Master Class
"""

CLASSIFIED_INCIDENTS = [
    {
        "incident_id": "demo-A",
        "label": "Hospital Insider",
        "narrative": "Nurse accessed celebrity patient records and shared with tabloid",
        "actor": {
            "internal": {
                "variety": ["End-user"],
                "motive": ["Financial", "Fun"]
            }
        },
        "action": {
            "misuse": {
                "variety": ["Privilege abuse"],
                "vector": ["Internal network access"]
            }
        },
        "asset": {
            "assets": [{"variety": "S - Database", "amount": 1}]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data": [{"variety": "Medical (PHI)", "amount": 1}]
            }
        },
        "teaching_notes": [
            "Internal actor - she had legitimate access to the system but misused it",
            "Misuse > Privilege abuse - accessing data outside her authorized scope",
            "Asset is a Database (medical records system)",
            "Confidentiality only - no integrity or availability impact",
            "This IS a data breach because PHI was confirmed disclosed to unauthorized party",
            "HIPAA breach notification would be required"
        ]
    },
    {
        "incident_id": "demo-B",
        "label": "E-Commerce SQLi",
        "narrative": "SQLi on retail site extracted credentials; used for fraud",
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"]
            }
        },
        "action": {
            "hacking": {
                "variety": ["SQLi", "Use of stolen credentials"],
                "vector": ["Web application"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - Database", "amount": 1},
                {"variety": "U - Desktop", "amount": 3200}
            ]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data": [
                    {"variety": "Credentials", "amount": 3200},
                    {"variety": "Payment", "amount": 3200}
                ]
            }
        },
        "teaching_notes": [
            "External organized crime - financial motive (fraud)",
            "TWO hacking varieties: SQLi (initial access) + Use of stolen creds (secondary)",
            "Both are Hacking category but different varieties",
            "Assets: Database (credential theft) and conceptually the 3200 accounts accessed",
            "Confidentiality only - data stolen but systems not disrupted",
            "Discovery method: external - payment processor detected fraud patterns"
        ]
    },
    {
        "incident_id": "demo-C",
        "label": "School Ransomware",
        "narrative": "Phishing + ransomware at K-12 school district",
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
                {"variety": "U - Desktop", "amount": 80},
                {"variety": "S - File", "amount": 3}
            ]
        },
        "attribute": {
            "integrity": {"variety": ["Software installation", "Alter behavior"]},
            "availability": {
                "variety": ["Encryption"],
                "duration": {"unit": "Hours", "value": 12}
            }
        },
        "teaching_notes": [
            "TWO actions: Phishing (delivery) then Malware/Ransomware (payload)",
            "NO Confidentiality attribute - no evidence of data exfiltration",
            "This is NOT a data breach - Integrity + Availability only",
            "Important: ransomware is NOT automatically a breach!",
            "Victim industry: Education (611110 NAICS)",
            "Discovery method was internal (IT team)"
        ]
    },
    {
        "incident_id": "demo-D",
        "label": "Defense Contractor APT",
        "narrative": "Nation-state APT, 8-month dwell time, classified document theft",
        "actor": {
            "external": {
                "variety": ["Nation-state"],
                "motive": ["Espionage"]
            }
        },
        "action": {
            "hacking": {
                "variety": ["Exploit vulnerability"],
                "vector": ["VPN"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "S - File", "amount": 1},
                {"variety": "N - VPN concentrator", "amount": 1}
            ]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data": [
                    {"variety": "Classified", "amount": -1},
                    {"variety": "Internal", "amount": -1}
                ]
            }
        },
        "teaching_notes": [
            "Nation-state actor with espionage motive - not financial",
            "Zero-day exploit = Hacking > Exploit vulnerability (zero-day variety)",
            "8-month dwell time makes this a HIGH-dwell APT incident",
            "Discovery by government agency = external discovery (unfavorable)",
            "Confidentiality: classified documents = 'Classified' data type",
            "Timeline: dwell time 8 months, discovery = external"
        ]
    },
    {
        "incident_id": "demo-E",
        "label": "ATM Skimmer Gang",
        "narrative": "Criminal gang installed skimmers on 12 ATMs, captured 340 cards",
        "actor": {
            "external": {
                "variety": ["Organized crime"],
                "motive": ["Financial"]
            }
        },
        "action": {
            "physical": {
                "variety": ["Tampering", "Skimming"],
                "vector": ["Victim facility"]
            }
        },
        "asset": {
            "assets": [
                {"variety": "T - ATM", "amount": 12}
            ]
        },
        "attribute": {
            "confidentiality": {
                "data_disclosure": "Yes",
                "data": [
                    {"variety": "Payment", "amount": 340}
                ]
            }
        },
        "teaching_notes": [
            "PHYSICAL action - skimming is always Physical category",
            "Asset: Kiosk/Terminal > ATM (T prefix)",
            "340 payment cards compromised",
            "Note the PIN camera = surveillance (also Physical variety)",
            "No Hacking or Malware - purely physical attack",
            "Discovery: internal (bank maintenance staff)"
        ]
    }
]

def display_classification(incident: dict):
    print(f"\n{'═' * 65}")
    print(f"  {incident['incident_id']}: {incident['label']}")
    print(f"  {incident['narrative']}")
    print(f"{'═' * 65}")

    for actor_type, data in incident.get("actor", {}).items():
        print(f"\n  ACTOR: {actor_type.upper()}")
        print(f"    Variety: {data.get('variety', ['?'])}")
        print(f"    Motive:  {data.get('motive', ['?'])}")

    for action_type, data in incident.get("action", {}).items():
        print(f"\n  ACTION: {action_type.upper()}")
        print(f"    Variety: {data.get('variety', ['?'])}")
        print(f"    Vector:  {data.get('vector', ['?'])}")

    for asset in incident.get("asset", {}).get("assets", []):
        print(f"\n  ASSET: {asset['variety']} (x{asset.get('amount', '?')})")

    for attr, data in incident.get("attribute", {}).items():
        print(f"\n  ATTRIBUTE: {attr.upper()}")
        if attr == "confidentiality":
            print(f"    Disclosure: {data.get('data_disclosure', '?')}")
            for d in data.get("data", []):
                print(f"    Data: {d['variety']} ({d.get('amount', '?')} records)")

    is_breach = incident.get("attribute", {}).get(
        "confidentiality", {}).get("data_disclosure", "No") in ["Yes", "Potentially"]
    print(f"\n  IS DATA BREACH: {'YES' if is_breach else 'NO (incident only)'}")

    print(f"\n  TEACHING NOTES:")
    for note in incident.get("teaching_notes", []):
        print(f"    • {note}")

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  VERIS Demo 02: Incident Classification Solutions")
    print("  Session 11 | Security Operations Master Class")
    print("=" * 65)
    for inc in CLASSIFIED_INCIDENTS:
        display_classification(inc)
    print(f"\n{'=' * 65}")
    print("  Review your answers against the classifications above.")
    print("  Pay special attention to the Teaching Notes.")
    print(f"{'=' * 65}\n")
```

---

## Post-Classification Discussion

### Common Mistakes to Watch For

**Incident A (Hospital Insider)**

* Misclassifying as "Hacking" — the nurse had legitimate access; this is Misuse.
* Forgetting to record PHI as the data type.

**Incident C (School Ransomware)**

* Automatically adding Confidentiality — the narrative explicitly says no exfiltration evidence. Confidentiality should only be recorded when there is evidence of disclosure.

**Incident D (APT)**

* Using "External > Unknown" when the narrative clearly indicates nation-state indicators (zero-day, long dwell time, defense contractor target).

**Incident E (ATM Skimmer)**

* Recording as Hacking — physical skimmer installation is Physical > Skimming, not Hacking.

---

## Key Takeaways from This Demo

1. **The actor type matters enormously**: Internal > Misuse and External > Hacking look similar in impact but are completely different incidents requiring different response.

1. **Ransomware ≠ breach**: A ransomware attack without confirmed exfiltration is an Integrity + Availability incident, not a Confidentiality breach.

1. **Multiple actions are common**: The real attack chain often has 2-3 action steps. Record them all.

1. **Physical attacks have their own category**: Don't force physical attacks into Hacking.

1. **Data types matter for breach reporting**: PHI, PCI data, and PII each trigger different regulatory obligations.

---

*Demo 02 | Session 11 | Security Operations Master Class | Digital4Security*
