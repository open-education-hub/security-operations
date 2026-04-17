# Drill 02 (Intermediate): Create a Complete VERIS Incident Report

**Level:** Intermediate

**Estimated time:** 50–70 minutes

**Directory:** `drills/intermediate/drill-02-veris-incident-report/`

**Prerequisites:** Basic drills, Guides 01–03, Demo 04

---

## Overview

In this drill you will create two complete VERIS JSON records from detailed incident narratives.
Both incidents are realistic and represent common real-world scenarios.
You must encode all fields accurately including timeline, victim, actor, action, asset, attribute, discovery method, and impact.

---

## Incident 1: The Credential-Stuffing Attack on a Bank

### Narrative

> In August 2024, a mid-sized regional bank (4,200 employees, US-based, commercial banking sector) discovered that attackers had used credential stuffing to access online banking accounts. The attack began on August 3rd and was discovered on August 14th when fraud operations flagged unusual transaction patterns.
>
> Investigation revealed:
> - 8.2 million credential pairs from previous data breaches were tested against the bank's online banking portal
> - 2,847 accounts were successfully accessed using valid credentials
> - Attackers drained $340,000 from 412 of those accounts via ACH transfers before being blocked
> - 2,435 accounts were accessed and viewed but not financially exploited
> - The attack originated from a botnet with IPs across 47 countries
> - Discovery was triggered by the bank's fraud detection system (internal)
> - Containment: MFA was enforced within 6 hours of discovery
> - All affected customers were notified within 3 business days

**Your Task**: Create a complete VERIS JSON record for this incident.

---

## Incident 2: The Insider PHI Theft

### Narrative

> In January 2024, a large hospital system (12,000 employees, Atlanta, Georgia, general hospital sector) discovered that a billing department employee had been systematically accessing and exfiltrating patient records over a 3-month period.
>
> The employee, a billing specialist with access to the revenue cycle management system, accessed records of patients who were not part of their assigned billing queue. They exported patient demographics, insurance information, and diagnoses to their personal email over 87 days before being detected.
>
> Details:
> - Discovery: Internal audit during access review identified 15,000+ unauthorized record accesses
> - Access period: October 8, 2023 to January 3, 2024 (87 days)
> - Records accessed: ~8,400 patient records including names, SSNs, diagnoses, insurance details
> - The employee's motivation appears to be sale to a data broker (evidence of email contact with a suspected broker)
> - Immediate containment: account disabled within 2 hours of discovery
> - Law enforcement was notified
> - HIPAA breach notification to HHS filed within 60 days
> - Total response cost estimated at $1.2M (investigation, legal, notification, credit monitoring)

**Your Task**: Create a complete VERIS JSON record for this incident.

---

## Requirements for Each Record

Your VERIS records must include:

**Required fields:**

* `incident_id` (UUID)
* `source_id`
* `security_incident`
* Actor (type, variety, motive)
* Action (category, variety, vector)
* Asset (variety, amount)
* Attribute (type, data_disclosure for Confidentiality, data types)

**Strongly recommended fields:**

* `schema_version`
* `summary` (1–2 sentences)
* `confidence`
* `timeline.incident.year` and `month`
* `timeline.discovery` (unit and value)
* `timeline.containment` (unit and value)
* `victim.industry` (NAICS code)
* `victim.employee_count`
* `victim.country`
* `discovery_method`
* `impact.overall_rating`
* `impact.loss[]` (if costs are known)
* `notes` (regulatory obligations, notable context)

---

## Guidance Notes

### Incident 1 Hints

* Think carefully about the actor variety — is there an "organized crime" attribution, or is it "unknown"?
* The credential stuffing technique: which hacking variety?
* Two types of accounts were affected: some had money stolen, some were just viewed. How does this affect the Attribute section?
* The $340,000 theft affects the Impact section — what loss variety?
* What NAICS code for commercial banking?

### Incident 2 Hints

* Is this Internal or External actor?
* If motivation is financial (selling to data broker), how does that affect motive?
* What are the specific data types under Confidentiality?
* 87-day access period: how does this appear in the timeline?
* What NAICS code for general hospital?
* What regulatory frameworks apply? (HIPAA — note in the `notes` field)
* $1.2M response cost → what impact loss variety(ies)?

---

## Template to Start From

```json
{
  "schema_version": "1.3.7",
  "incident_id": "REPLACE-WITH-UUID",
  "source_id": "your-org",
  "summary": "REPLACE WITH SUMMARY",
  "confidence": "High",
  "security_incident": "Confirmed",
  "timeline": {
    "incident": { "year": 0, "month": 0 },
    "discovery": { "unit": "Days", "value": 0 },
    "containment": { "unit": "Hours", "value": 0 }
  },
  "victim": {
    "victim_id": "Anonymized",
    "industry": "000000",
    "employee_count": "Unknown",
    "country": ["US"]
  },
  "actor": {},
  "action": {},
  "asset": { "assets": [] },
  "attribute": {},
  "discovery_method": {},
  "impact": { "loss": [], "overall_rating": "Unknown" },
  "notes": ""
}
```

---

## Deliverables

1. Two complete VERIS JSON files named:
   * `incident_1_credential_stuffing.json`
   * `incident_2_insider_phi_theft.json`

1. A brief (5-bullet) explanation of your most significant encoding decisions for each incident.

1. Compare with the model solutions in:

   `drills/intermediate/solutions/drill-02-solution/solution.md`

---

*Drill 02 (Intermediate) | Session 11 | Security Operations Master Class | Digital4Security*
