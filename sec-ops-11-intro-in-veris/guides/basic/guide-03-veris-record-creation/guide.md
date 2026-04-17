# Guide 03: Creating a VERIS Record from an Incident Report

**Level:** Basic

**Estimated time:** 50 minutes

**Directory:** `guides/basic/guide-03-veris-record-creation/`

**Prerequisites:** Guide 01, Guide 02

---

## Purpose

This guide teaches you to create a complete, production-ready VERIS JSON record from an incident narrative.
You will follow a structured encoding process, learn all key JSON fields, and understand the decisions involved in accurate encoding.

---

## 1. VERIS JSON Structure Overview

A complete VERIS record has the following top-level structure:

```json
{
  "schema_version": "1.3.7",
  "incident_id": "UUID",
  "source_id": "your-org",
  "summary": "Human-readable description",
  "confidence": "High|Medium|Low",
  "security_incident": "Confirmed|Suspected|False positive",
  "timeline": { ... },
  "victim": { ... },
  "actor": { ... },
  "action": { ... },
  "asset": { ... },
  "attribute": { ... },
  "discovery_method": { ... },
  "impact": { ... },
  "notes": "free text"
}
```

### Required Fields

These fields **must** be present for a valid VERIS record:

* `incident_id`
* `source_id`
* `security_incident`
* At least one actor, action, asset, and attribute entry

### Strongly Recommended Fields

These are not technically required but are essential for analytical value:

* `schema_version`
* `summary`
* `confidence`
* `timeline.incident.year`
* `victim.industry` (NAICS code)

---

## 2. Field-by-Field Reference

### 2.1 Metadata Fields

```json
"schema_version": "1.3.7",
"incident_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
"source_id": "acme-corp",
"summary": "Phishing attack led to credential theft and customer database access",
"confidence": "High"
```

**`schema_version`**: Use the current VERIS version.
Check the VERIS GitHub for the latest.

**`incident_id`**: Use a UUID (universally unique identifier).
In Python: `import uuid; str(uuid.uuid4())`.
In bash: `uuidgen`.

**`source_id`**: Identifies your organization or system submitting the record.
For VCDB contributions, use "vcdb".
For internal records, use your org identifier.

**`confidence`**: How confident are you in the classification?

* `"High"`: Well-investigated, strong evidence for all classifications
* `"Medium"`: Investigated but some uncertainty in classification
* `"Low"`: Minimal information, significant uncertainty
* `"None"`: Essentially guessing (rarely used)

### 2.2 Security Incident Classification

```json
"security_incident": "Confirmed"
```

Options:

* `"Confirmed"`: The incident is confirmed to have occurred
* `"Suspected"`: Evidence suggests an incident but not confirmed
* `"False positive"`: Investigation showed no actual incident

### 2.3 The Timeline Object

```json
"timeline": {
  "incident": {
    "year": 2024,
    "month": 9,
    "day": 15,
    "time": {
      "unit": "Hours",
      "value": 14
    }
  },
  "compromise": {
    "unit": "Days",
    "value": 2,
    "notes": "Attacker moved laterally for ~2 days before exfiltrating"
  },
  "exfiltration": {
    "unit": "Hours",
    "value": 4
  },
  "discovery": {
    "unit": "Days",
    "value": 22
  },
  "containment": {
    "unit": "Hours",
    "value": 48
  }
}
```

**Timeline units**: "Seconds", "Minutes", "Hours", "Days", "Weeks", "Months", "Years", "Unknown"

**Value -1**: Use when the duration is unknown.
Do not leave fields empty; use -1 instead.

**What to record for each**:

* `incident`: When did the incident start/occur? At minimum provide year.
* `compromise`: How long from initial access to successful compromise of target?
* `exfiltration`: How long did the exfiltration take?
* `discovery`: How long from incident start to discovery?
* `containment`: How long from discovery to containment?

### 2.4 The Victim Object

```json
"victim": {
  "victim_id": "Acme Healthcare Inc.",
  "industry": "622110",
  "industry2": "General Medical and Surgical Hospitals",
  "employee_count": "1001 to 10000",
  "revenue": {
    "iso_currency_code": "USD",
    "amount": 450000000
  },
  "country": ["US"],
  "region": ["NA"],
  "locations_affected": 3
}
```

**`industry`**: Use the **NAICS code** (North American Industry Classification System).
Common codes:

* `522110`: Commercial Banking
* `621111`: Offices of Physicians
* `622110`: General Medical and Surgical Hospitals
* `611110`: Elementary and Secondary Schools
* `336111`: Automobile Manufacturing
* `517311`: Wired Telecommunications
* `611310`: Colleges and Universities

Look up NAICS codes at: https://www.naics.com/search/

**`employee_count`** options:

* "1 to 10", "11 to 100", "101 to 1000", "1001 to 10000", "10001 to 25000", "25001 to 50000", "50001 to 100000", "Over 100000", "Unknown"

**`country`**: ISO 3166-1 alpha-2 country codes (US, DE, GB, FR, etc.)

### 2.5 The Actor Object

```json
"actor": {
  "external": {
    "variety": ["Organized crime"],
    "motive": ["Financial"],
    "country": ["CN"],
    "region": ["APAC"],
    "notes": "Attribution based on TTP overlap with known group"
  }
}
```

**Only include actor sub-types that were present.** If only external, omit `internal` and `partner`.

**`variety`** options (External):

* "Organized crime", "Nation-state", "State-affiliated", "Hacktivist", "Competitor", "Unaffiliated", "Unknown"

**`variety`** options (Internal):

* "End-user", "System administrator", "Developer", "Finance user", "Executive", "Manager", "Other", "Unknown"

**`motive`** options:

* "Financial", "Espionage", "Convenience", "Fun", "Grudge", "Ideology", "Extortion", "Sabotage", "Unknown", "Other"

### 2.6 The Action Object

```json
"action": {
  "social": {
    "variety": ["Phishing"],
    "vector": ["Email"],
    "target": ["End-user"],
    "notes": "Spear phishing with invoice attachment"
  },
  "hacking": {
    "variety": ["Use of stolen credentials"],
    "vector": ["Web application"],
    "cve": [],
    "notes": ""
  },
  "malware": {
    "variety": ["Backdoor", "Keylogger"],
    "vector": ["Email attachment"],
    "cve": [],
    "notes": "Cobalt Strike beacon identified in memory forensics"
  }
}
```

**Include all action types present.** Each type is a separate key with its own varieties and vectors.

**`cve`**: Array of CVE IDs if a specific CVE was exploited.
E.g., `["CVE-2024-12345"]`.

**Key Hacking varieties**:

* "Brute force", "Use of stolen credentials", "SQLi", "Exploit vulnerability", "Use of backdoor or C2", "Password dumping", "Path traversal", "DNS hijacking", "Unknown"

**Key Malware varieties**:

* "Ransomware", "Backdoor", "Trojan", "Keylogger", "Spyware", "Worm", "Virus", "Exploit kit", "Downloader", "RAM scraper", "Rootkit", "Cryptominer", "Unknown"

**Key Social varieties**:

* "Phishing", "Spear phishing", "Pretexting", "Vishing", "Smishing", "Baiting", "Bribery", "Unknown"

**Key Error varieties**:

* "Misconfiguration", "Misdelivery", "Publishing error", "Gaffe", "Loss", "Omission", "Programming error", "Unknown"

### 2.7 The Asset Object

```json
"asset": {
  "assets": [
    {
      "variety": "S - Database",
      "amount": 2,
      "notes": "Primary customer DB and shadow backup DB"
    },
    {
      "variety": "U - Desktop",
      "amount": 15
    },
    {
      "variety": "N - VPN concentrator",
      "amount": 1
    }
  ],
  "cloud": ["Yes"],
  "hosting": ["External Cloud - SaaS"],
  "management": ["External Remote Management"],
  "notes": ""
}
```

**`variety`** format: `"LETTER - Description"`

* Server: "S - Database", "S - Web application", "S - File", "S - Mail", "S - Authentication", "S - DNS", "S - Backup"
* Network: "N - Router", "N - Firewall", "N - Switch", "N - VPN concentrator", "N - Wireless"
* User Device: "U - Desktop", "U - Laptop", "U - Tablet", "U - Mobile phone"
* Person: "P - End-user", "P - Executive", "P - System administrator", "P - Developer", "P - Customer"
* Media: "M - Documents", "M - Flash drive", "M - Disk drive", "M - Tape"
* Kiosk: "T - ATM", "T - Gas terminal", "T - POS terminal"
* Unknown: "U - Unknown"

**`amount`**: Number of affected assets.
Use -1 if unknown.

**`cloud`**: "Yes", "No", "Unknown" — was the asset a cloud service?

### 2.8 The Attribute Object

```json
"attribute": {
  "confidentiality": {
    "data_disclosure": "Yes",
    "data_total": 45000,
    "data_victim": ["Customer", "Employee"],
    "data": [
      {
        "variety": "Personal",
        "amount": 40000,
        "notes": "Names, addresses, SSNs"
      },
      {
        "variety": "Credentials",
        "amount": 5000,
        "notes": "Hashed passwords extracted from auth DB"
      }
    ],
    "state": "Stored",
    "notes": ""
  },
  "integrity": {
    "variety": ["Software installation"],
    "notes": "Cobalt Strike implant installed on 15 workstations"
  },
  "availability": {
    "variety": ["Interruption"],
    "duration": {
      "unit": "Hours",
      "value": 6
    },
    "notes": "Email servers offline for 6 hours during investigation"
  }
}
```

**`data_disclosure`** options:

* "Yes": Confirmed disclosure
* "No": Confirmed no disclosure
* "Potentially": Uncertain, possible disclosure (e.g., lost encrypted laptop)
* "Unknown": Insufficient information to determine

**Key `data` variety options**:

* "Personal" (PII), "Medical (PHI)", "Payment" (PCI), "Credentials", "Bank", "Classified", "Internal", "System", "Intellectual", "Unknown"

**`data_victim`**: Who owned the exposed data?

* "Customer", "Employee", "Patient", "Student", "Citizen", "Other", "Unknown"

**`state`**: Where was the data when compromised?

* "Stored", "Processed", "Transmitted", "Unknown"

### 2.9 Discovery Method

```json
"discovery_method": {
  "internal": {
    "variety": ["NIDS", "SIEM"]
  },
  "external": {
    "variety": ["Law enforcement", "Fraud detection"]
  },
  "partner": {
    "variety": ["Unknown"]
  }
}
```

**Internal discovery varieties**: "NIDS", "HIDS", "SIEM", "Reported by user", "Audit", "Antivirus", "Threat hunting", "IT review", "Log review"

**External discovery varieties**: "Customer", "Law enforcement", "Fraud detection", "Vendor or partner", "Media", "Security researcher"

### 2.10 Impact Object

```json
"impact": {
  "loss": [
    {
      "variety": "Response and remediation",
      "amount": 750000,
      "iso_currency_code": "USD",
      "rating": "Unknown"
    },
    {
      "variety": "Operational disruption",
      "amount": 200000,
      "iso_currency_code": "USD"
    }
  ],
  "overall_rating": "Major",
  "notes": ""
}
```

**`overall_rating`** options: "Unknown", "None", "Minor", "Moderate", "Major", "Critical"

**`loss variety`** options: "Asset and fraud", "Business disruption", "Data", "Lost and stolen assets", "Notification", "Operational disruption", "Response and remediation", "Reputation", "Legal and regulatory", "Unknown"

---

## 3. Worked Encoding: Complete Example

### Source Narrative

> *A university IT team discovered that a student's account was being used to access the student information system from an IP address in Eastern Europe. Investigation revealed that the student's credentials were phished via a fake university portal login page two weeks prior. The attacker accessed records for approximately 3,500 students including names, student IDs, and enrollment status. No financial data was accessed. The incident was discovered when the affected student reported not being able to log in (password changed by attacker).*

### Encoding Process

**Step 1 — Actor**: External (no legitimate access).
Not organized crime (no financial motive — accessing student records suggests data collection).
Best fit: Unknown external actor (could be organized crime or unaffiliated).
Motive: Unknown (or "Espionage" if a data broker angle is suspected, but that's a stretch).
Record as Unknown for safety.

**Step 2 — Actions**:

1. Created a fake login portal → Social Engineering > Phishing (credential harvesting via fake site)
1. Used the stolen credentials → Hacking > Use of stolen credentials

**Step 3 — Assets**: Student information system is a database: S - Database

**Step 4 — Attributes**: 3,500 student records accessed = Confidentiality.
Data types: Personal (names, student IDs, enrollment status).
No financial data.

**Step 5 — Discovery**: Student reported login problems = Internal > Reported by user

**The Complete Record**:

```json
{
  "schema_version": "1.3.7",
  "incident_id": "b5c6d7e8-f9a0-1234-bcde-f56789012345",
  "source_id": "university-it",
  "summary": "Student credentials phished via fake portal; attacker accessed student information system, viewing records for 3,500 students. Discovery via student login complaint.",
  "confidence": "High",
  "security_incident": "Confirmed",
  "timeline": {
    "incident": {
      "year": 2024,
      "month": 10
    },
    "compromise": {
      "unit": "Days",
      "value": 14,
      "notes": "Credential phishing occurred ~14 days before discovery"
    },
    "discovery": {
      "unit": "Days",
      "value": 14
    },
    "containment": {
      "unit": "Hours",
      "value": 4
    }
  },
  "victim": {
    "victim_id": "Anonymized University",
    "industry": "611310",
    "industry2": "Colleges and Universities",
    "employee_count": "1001 to 10000",
    "country": ["US"],
    "region": ["NA"]
  },
  "actor": {
    "external": {
      "variety": ["Unknown"],
      "motive": ["Unknown"],
      "country": ["Eastern Europe (unconfirmed)"],
      "region": ["EU"],
      "notes": "IP geolocation places actor in Eastern Europe; no further attribution"
    }
  },
  "action": {
    "social": {
      "variety": ["Phishing"],
      "vector": ["Web application"],
      "target": ["End-user"],
      "notes": "Fake university portal login page used to harvest credentials"
    },
    "hacking": {
      "variety": ["Use of stolen credentials"],
      "vector": ["Web application"],
      "notes": "Stolen credentials used to authenticate to legitimate student portal"
    }
  },
  "asset": {
    "assets": [
      {
        "variety": "S - Database",
        "amount": 1,
        "notes": "Student information system database"
      }
    ],
    "cloud": ["Unknown"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data_total": 3500,
      "data_victim": ["Student"],
      "data": [
        {
          "variety": "Personal",
          "amount": 3500,
          "notes": "Names, student IDs, enrollment status"
        }
      ],
      "state": "Stored"
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
        "amount": -1,
        "iso_currency_code": "USD"
      }
    ],
    "overall_rating": "Moderate",
    "notes": "FERPA notification obligations triggered. Exact remediation costs not yet determined."
  },
  "notes": "FERPA breach notification to affected students required. Fake portal domain was registered 3 days before phishing campaign began."
}
```

---

## 4. Encoding Checklist

Before finalizing a VERIS record, check:

```text
[ ] incident_id is a valid UUID
[ ] source_id is set
[ ] security_incident is set (Confirmed/Suspected/False positive)
[ ] summary is clear and concise (1-3 sentences)
[ ] confidence level is set
[ ] timeline.incident.year is populated
[ ] victim.industry is a valid NAICS code
[ ] Actor(s) are populated with variety and motive
[ ] Action(s) are populated with variety and vector
[ ] Asset(s) are populated with variety (correct letter prefix)
[ ] Attribute(s) are populated
    [ ] If Confidentiality: data_disclosure and data[] are set
    [ ] If Availability: variety and duration are set
    [ ] If Integrity: variety is set
[ ] discovery_method is populated
[ ] Notes capture any important context
```

---

## 5. Common Encoding Mistakes

| Mistake | Fix |
|---------|-----|
| Using generic "Unknown" everywhere | Use "Unknown" only when truly unknown; be specific when you can |
| Leaving out action vector | Always include vector even if "Unknown" |
| Listing all possible data types | Only list data types that were actually affected |
| Using currency amount of 0 | Use -1 for unknown amounts |
| Forgetting discovery_method | Discovery method is important for analysis; always populate |
| Conflating security event with incident | VERIS records confirmed or suspected incidents, not raw alerts |

---

## 6. Useful References

| Resource | URL |
|----------|-----|
| VERIS Schema | https://github.com/vz-risk/veris |
| VCDB Examples | https://github.com/vz-risk/VCDB/tree/master/data/json |
| NAICS Code Search | https://www.naics.com/search/ |
| ISO Country Codes | https://www.iso.org/iso-3166-country-codes.html |
| UUID Generator | `python3 -c "import uuid; print(uuid.uuid4())"` |

---

*Guide 03 | Session 11 | Security Operations Master Class | Digital4Security*
