# Solution: Drill 01 (Advanced) — VERIS Contribution to VCDB

## Model Submission

This solution demonstrates a publication-quality VERIS record based on a public incident (fictional but realistic scenario based on common DPA decision patterns).

---

## Source Incident Summary

**Source:** Fictional summary based on typical DPA decision structure

**Incident type:** Healthcare data breach via misconfigured cloud storage

**Jurisdiction:** Germany (BayLDA decision)

*"A private medical practice of 12 physicians exposed patient appointment and medical history records due to a misconfigured cloud backup service.
The backup service was configured by an external IT contractor during a system migration.
The misconfiguration left 58,000 patient records accessible via a publicly guessable URL for approximately 47 days.
The practice was unaware of the exposure until a patient reported seeing their own records when searching online.
The DPA issued a fine of €85,000.
The practice notified affected patients and the DPA within 72 hours of discovery."*

---

## VERIS Record (Validated)

```json
{
  "schema_version": "1.3.7",
  "incident_id": "vcdb-model-001",
  "source_id": "demo",
  "summary": "A small European healthcare organization's patient records were exposed via misconfigured cloud backup service implemented by an IT partner. Approximately 58,000 records accessible for 47 days. Discovery triggered by patient self-report.",
  "security_incident": "Confirmed",
  "confidence": "High",
  "discovery_method": {
    "external": {
      "partner": false,
      "media": false,
      "unknown": false
    },
    "unknown": true
  },
  "timeline": {
    "incident": {"year": 2024, "month": 3},
    "discovery": {"unit": "Days", "value": 47},
    "containment": {"unit": "Days", "value": 1}
  },
  "victim": {
    "industry": "Healthcare",
    "employee_count": "11 to 100",
    "country": ["DE"],
    "government": ["Unknown"]
  },
  "actor": {
    "partner": {
      "variety": ["Other"],
      "motive": ["NA"],
      "notes": "IT contractor misconfigured backup service during migration"
    }
  },
  "action": {
    "error": {
      "variety": ["Misconfiguration"],
      "vector": ["Unknown"],
      "notes": "Cloud backup service misconfigured to allow public URL access"
    }
  },
  "asset": {
    "assets": [
      {"variety": "S - Database"},
      {"variety": "M - Backup"}
    ],
    "cloud": ["External Cloud Asset(s)"],
    "hosting": ["External Cloud Asset(s)"]
  },
  "attribute": {
    "confidentiality": {
      "data_disclosure": "Unknown",
      "data": [
        {"variety": "Medical", "amount": 58000},
        {"variety": "Personal", "amount": 58000}
      ],
      "state": ["Transmitted unencrypted"]
    }
  }
}
```

---

## Submission Rationale

**Sources used:** Fictional scenario based on typical DPA decision structure from publicly available regulatory guidance.

**Confirmed vs. inferred:**

* Confirmed: misconfiguration by IT partner, 58,000 records affected, 47-day exposure period
* Confirmed: Medical and personal data (standard for medical practice)
* Inferred: "Organized" partner variety → used "Other" to avoid over-attribution
* Inferred: `data_disclosure: "Unknown"` — DPA decision did not confirm unauthorized access beyond patient self-report (one person)

**Classification decisions:**

* **Actor = Partner**: The IT contractor caused the breach through their misconfiguration work. While internal staff chose to use this contractor, the proximate cause is the partner's error. If the practice had no IT staff and fully delegated, this is clearly partner. Internal could also be argued if the practice should have audited the work.
* **Action = Error/Misconfiguration**: No malicious intent. The contractor did not intend to expose the data.
* **Asset = S-Database + M-Backup**: The backup service is media; the underlying patient data lives in a database. Both are valid.
* **Attribute = Confidentiality/Unknown disclosure**: We know the data was publicly accessible for 47 days. One patient confirmed access. We cannot confirm or deny whether others accessed the data maliciously.

**Confidence = High**: The DPA investigation established the facts clearly.
The main uncertainty (unauthorized access) is captured in `data_disclosure: "Unknown"`.

---

## Validator Output (Simulated)

```text
Validating: vcdb-model-001.json
  schema_version: PRESENT (1.3.7)
  incident_id: PRESENT
  security_incident: PRESENT (Confirmed)
  confidence: PRESENT (High)
  actor: PRESENT (1 type: partner)
  action: PRESENT (1 type: error)
  asset: PRESENT (2 assets)
  attribute: PRESENT (1 type: confidentiality)
  timeline: PRESENT

  Anonymization check:
    Email patterns: NONE FOUND
    URLs: NONE FOUND
    Company name patterns: NONE FOUND
    Person names: NONE FOUND

VALIDATION: PASSED
ANONYMIZATION: PASSED
STATUS: Ready for VCDB submission
```

---

## Key Learning Points

1. **Partner actors**: Many VERIS coders default to "internal" for contractor errors. But if the contractor is truly a third-party with a separate organization, use "partner."

1. **Confidence vs. data_disclosure**: These are independent. You can have `confidence: "High"` (you are sure about the facts) while `data_disclosure: "Unknown"` (the facts include uncertainty about whether data was accessed).

1. **Anonymization is essential**: VCDB records must not identify victims. The summary describes the incident type and scale without naming anyone.

1. **Multiple data varieties**: Medical records always include both `"Medical"` and `"Personal"` data varieties — patient records inherently contain PII in addition to health data.
