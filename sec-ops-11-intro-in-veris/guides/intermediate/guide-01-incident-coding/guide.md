# Guide 01 (Intermediate) — Coding Real Incidents with VERIS

**Level:** Intermediate

**Estimated time:** 45 minutes

**Prerequisites:** Basic guides 01–03

---

## Objective

By the end of this guide, you will be able to:

* Apply the full VERIS schema to complex, multi-actor, multi-action incidents
* Handle ambiguity and missing information using appropriate VERIS conventions
* Validate a VERIS record for schema compliance
* Contribute a properly formatted record to a VCDB-style dataset

---

## The Full Coding Workflow

For real incidents, VERIS coding follows a structured process:

```text
1. Read and understand the full incident narrative

2. Extract timeline information
3. Identify victim organization profile
4. Classify Actor(s) — may be multiple
5. Classify Action(s) — attack chain, may be multiple types
6. Classify Asset(s) — all systems and people affected
7. Classify Attribute(s) — CIA impacts, data types, record counts
8. Assign confidence level
9. Validate against VERIS schema checklist
10. Anonymize if contributing externally
```

---

## Case Study 1: The Supply Chain Attack

### Incident Narrative

> In early 2023, security researchers discovered that a widely-used IT management software platform had been compromised. Attackers — later attributed with medium confidence to a nation-state actor — inserted malicious code into a legitimate software update. When customers installed the update, the malicious code created a backdoor providing persistent access to affected networks. Approximately 100 of the vendor's 18,000 customers were actively exploited. Among the victims was a European government ministry, which discovered that classified procurement documents had been exfiltrated over three months before detection. Discovery occurred when abnormal outbound network traffic was flagged by the ministry's SIEM system.

### Step 1: Timeline Extraction

| Field | Value |
|-------|-------|
| `incident.year` | 2023 |
| `incident.month` | 1 (approximately) |
| `compromise.unit` | Days |
| `compromise.value` | Unknown |
| `exfiltration.unit` | Days |
| `exfiltration.value` | ~30 |
| `discovery.unit` | Months |
| `discovery.value` | 3 |
| `containment` | Unknown |

### Step 2: Victim Profile

```json
"victim": {
  "industry": "Public Administration",
  "employee_count": "1001 to 10000",
  "country": ["Unknown"],
  "government": ["National"]
}
```

### Step 3: Actor Classification

The narrative says "attributed with medium confidence to a nation-state actor."

```json
"actor": {
  "external": {
    "variety": ["Nation-state"],
    "motive": ["Espionage"],
    "country": ["Unknown"]
  }
}
```

Note: The partner (software vendor) is a **victim** here, not an actor.
The actor used the vendor as a **vector** (supply chain), but the actor is still external.
Confidence: Medium.

### Step 4: Action Classification

The attack chain:

1. Compromise of vendor's build system (Hacking - Exploit vuln)
1. Insert malicious code in software update (Malware - Trojan)
1. Persistent backdoor (Malware - Backdoor)
1. Data exfiltration (Hacking - Use of backdoor/C2)

```json
"action": {
  "hacking": {
    "variety": ["Exploit vuln", "Use of backdoor or C2"],
    "vector": ["Supply chain software", "Remote access"]
  },
  "malware": {
    "variety": ["Backdoor", "Trojan"],
    "vector": ["Software update"]
  }
}
```

### Step 5: Asset Classification

```json
"asset": {
  "assets": [
    {"variety": "S - Other"},
    {"variety": "S - Database"}
  ],
  "hosting": ["Internally hosted"]
}
```

### Step 6: Attribute Classification

Data was exfiltrated (confidentiality), and malicious code was installed (integrity).

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data": [{"variety": "Internal", "amount": 0}],
    "state": ["Unknown"]
  },
  "integrity": {
    "variety": ["Install code"]
  }
}
```

### Complete VERIS Record

```json
{
  "schema_version": "1.3.7",
  "incident_id": "supply-chain-001",
  "source_id": "demo",
  "summary": "Supply chain attack via trojanized software update led to 3-month espionage campaign against government ministry.",
  "security_incident": "Confirmed",
  "confidence": "Medium",
  "timeline": {
    "incident": {"year": 2023, "month": 1},
    "exfiltration": {"unit": "Days", "value": 30},
    "discovery": {"unit": "Months", "value": 3}
  },
  "victim": {
    "industry": "Public Administration",
    "employee_count": "1001 to 10000",
    "country": ["Unknown"],
    "government": ["National"]
  },
  "actor": {
    "external": {
      "variety": ["Nation-state"],
      "motive": ["Espionage"],
      "country": ["Unknown"]
    }
  },
  "action": {
    "hacking": {
      "variety": ["Exploit vuln", "Use of backdoor or C2"],
      "vector": ["Supply chain software", "Remote access"]
    },
    "malware": {
      "variety": ["Backdoor", "Trojan"],
      "vector": ["Software update"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "S - Other"},
      {"variety": "S - Database"}
    ],
    "hosting": ["Internally hosted"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [{"variety": "Internal", "amount": 0}]
    },
    "integrity": {
      "variety": ["Install code"]
    }
  }
}
```

---

## Case Study 2: Two Incidents Discovered Together

### Incident Narrative

> An employee at a financial services firm accidentally emailed a spreadsheet containing 3,400 customer account numbers and balances to an external mailing list. The company reported this to the DPA within 72 hours. During the internal investigation, IT security discovered that a different employee — a senior analyst — had been downloading customer records to an encrypted USB drive over the past six months and selling them to a competitor's market research firm. The analyst had legitimate access to the data. USB transfers were detected via DLP logs. Approximately 200,000 customer records were confirmed stolen.

### Key Coding Decision: Two Records

This incident has **two separate security incidents** discovered together.
In VERIS, code them as **two separate records**.

**Rule:** If incidents have different actors and/or fundamentally different root causes, code them separately.

**Record 1: Accidental Email Breach**

```json
{
  "incident_id": "fin-accidental-001",
  "summary": "Employee accidentally sent spreadsheet with 3,400 customer records to external mailing list.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "actor": {"internal": {"variety": ["End-user"], "motive": ["NA"]}},
  "action": {"error": {"variety": ["Misdelivery"], "vector": ["Email"]}},
  "asset": {"assets": [{"variety": "S - Mail"}, {"variety": "P - End-user"}]},
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [{"variety": "Financial", "amount": 3400}]
    }
  }
}
```

**Record 2: Insider Data Theft**

```json
{
  "incident_id": "fin-insider-001",
  "summary": "Senior analyst stole 200,000 customer records via USB drive over 6 months and sold to competitor.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "actor": {"internal": {"variety": ["Manager"], "motive": ["Financial"]}},
  "action": {
    "misuse": {"variety": ["Privilege abuse", "Data mishandling"], "vector": ["LAN access"]},
    "physical": {"variety": ["Theft"], "vector": ["Unknown"]}
  },
  "asset": {"assets": [{"variety": "S - Database"}, {"variety": "M - Flash drive"}]},
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [{"variety": "Financial", "amount": 200000}]
    }
  }
}
```

---

## Handling Ambiguity

### The "Unknown" Value

Any `variety` or `vector` field can contain "Unknown" when information is not available.
This is preferred over guessing.

### The Confidence Field

* **High:** Direct evidence for all major claims
* **Medium:** Circumstantial evidence, reasonable inference
* **Low:** Limited information, significant uncertainty
* **None:** Almost entirely unknown

### Multiple Varieties

When unsure which specific variety applies, list multiple:

```json
"action": {
  "hacking": {
    "variety": ["Exploit vuln", "Use of stolen creds"],
    "vector": ["Web application"]
  }
}
```

---

## Schema Validation

```python
def validate_veris_record(record):
    errors = []
    required = ['schema_version', 'incident_id', 'security_incident',
                'actor', 'action', 'asset', 'attribute']
    for field in required:
        if field not in record:
            errors.append(f"Missing required field: {field}")

    if 'actor' in record and not record['actor']:
        errors.append("Actor section is empty")

    valid_si = ['Confirmed', 'Suspected', 'Near miss']
    if record.get('security_incident') not in valid_si:
        errors.append(f"Invalid security_incident: {record.get('security_incident')}")

    valid_conf = ['High', 'Medium', 'Low', 'None', None]
    if record.get('confidence') not in valid_conf:
        errors.append(f"Invalid confidence: {record.get('confidence')}")

    return errors
```

---

## Summary

You have learned:

* The full VERIS coding workflow for complex incidents
* How to handle supply chain attacks in the actor/action model
* When to create multiple records vs. one combined record
* How to handle ambiguity using "Unknown" values and confidence levels
* Basic validation of VERIS records

**Proceed to the intermediate drills to practice these skills.**
