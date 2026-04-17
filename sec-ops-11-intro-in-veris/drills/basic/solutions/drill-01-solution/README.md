# Solution: Drill 01 — VERIS Coding Practice

## Incident Analysis

### Actor

The attacker is **external** — there is no indication they had organizational access before the attack.
The motive is clearly **financial** (salary redirection fraud).
No country information is available.

### Action

Two actions form the attack chain:

1. **Social / Phishing** — fake HR email leading to credential theft
1. **Hacking / Use of stolen credentials** — logging into HR portal with stolen creds

### Assets

* `P - End-user` — the employee who was phished
* `S - Other` (HR portal/payroll system) — the system the attacker logged into

### Attributes

* **Integrity** — the attacker modified payroll data (bank account redirection) = `Modify data`
* **Confidentiality** is borderline: credentials were stolen (1 credential record). However, the main impact is integrity-based fraud, not data exfiltration to a third party.

Note: This is financial fraud, not a classic data breach.
There is no large-scale PII disclosure.

### Timeline

* `incident.year`: implied current year
* `compromise.unit`: Hours, `compromise.value`: ~12 (phished Tuesday morning, first transfer next day)
* `discovery.unit`: Days, `discovery.value`: 31
* `exfiltration`: Not applicable (no data exfiltrated — this is fraud, not exfiltration)
* `containment`: Unknown

### Confidence

**High** — the narrative clearly establishes the phishing vector, credential theft, and fraudulent transfers.

---

## Complete VERIS JSON Record

```json
{
  "schema_version": "1.3.7",
  "incident_id": "logistics-bec-001",
  "source_id": "drill",
  "summary": "Phishing email impersonating HR system led to credential theft; attacker redirected employee salary payments using stolen HR portal access.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "timeline": {
    "incident": {"year": 2024, "month": 1},
    "compromise": {"unit": "Hours", "value": 12},
    "discovery": {"unit": "Days", "value": 31}
  },
  "victim": {
    "industry": "Transportation",
    "employee_count": "101 to 1000",
    "country": ["Unknown"]
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
      "variety": ["Use of stolen creds"],
      "vector": ["Web application"]
    }
  },
  "asset": {
    "assets": [
      {"variety": "P - End-user"},
      {"variety": "S - Other"}
    ],
    "hosting": ["Internally hosted"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [
        {"variety": "Credentials", "amount": 1}
      ]
    },
    "integrity": {
      "variety": ["Modify data"]
    }
  }
}
```

---

## Discussion

**Why no large confidentiality impact?** The attacker did not download customer records or HR data — they only modified the target employee's bank account.
The confidentiality impact is limited to the stolen credential (1 record).

**Why Integrity?** The attacker modified the employee's payroll bank account in the HR system — this is a data modification, which maps to `integrity.variety = ["Modify data"]`.

**Confidence = High** because the forensic review clearly established the phishing event, credential theft timing, and first fraudulent transfer.

**"Organized crime" variety** is an inference — the pattern (phishing for financial gain) is consistent with organized crime groups that run BEC/payroll fraud operations, but we cannot confirm without attribution evidence.
A more conservative coder might use `"Unknown"` variety.
