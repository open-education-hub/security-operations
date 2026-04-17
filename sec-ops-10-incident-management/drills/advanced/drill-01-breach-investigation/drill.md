# Drill 01 (Advanced) — Data Breach Investigation

**Estimated time:** 90 minutes

**Difficulty:** Advanced

**Prerequisites:** All basic and intermediate drills; understanding of PCI DSS, forensic methodology, and GDPR

---

## Scenario

**RetailCorp** is a mid-size European e-commerce company based in the Netherlands, with 2 million customers across 12 EU countries and €340M annual revenue.
RetailCorp processes credit and debit card payments through its own checkout system and stores no card data beyond what PCI DSS allows (masked PANs only — or so they believed).

You have just received the following notification from Visa's fraud intelligence team:

```text
VISA FRAUD ALERT — CONFIDENTIAL
Date: [Today]
To: RetailCorp Security Team
Re: Compromised card batch identified

Visa's fraud analytics have identified 15,247 payment cards appearing in underground
marketplace "CardShop_EU" that trace to transactions at RetailCorp's checkout system.
The earliest fraudulent transaction on these cards dates to approximately 4 months ago.
Visa requests that RetailCorp initiate a forensic investigation immediately.

NOTE: PCI DSS requires a Qualified Security Assessor (QSA) forensic investigation
for breaches of this size. Visa will follow up within 5 business days.
```

RetailCorp was not aware of any breach.
Their last QSA audit was 6 months ago and they were certified PCI DSS Level 1 compliant.

---

## Available Evidence

You have gathered the following initial evidence artifacts.
The investigation spans a 4-month period.

### Log Retention Status

```text
Web application logs:         6 months retained ✓
Database audit logs:          90 days retained (3 months only) ✗ Missing first month
EDR telemetry:                90 days retained ✗ Missing first month
Network flow logs:            30 days retained ✗ Missing 3 months
Firewall logs:                90 days retained ✗ Missing first month
WAF logs:                     6 months retained ✓
```

### Artifacts Found in Investigation

**Artifact 1 — Web Server Access Log (6 months available):**

```text
Pattern identified: 14,200 requests to /api/checkout/process from IP 10.0.5.33 (internal)
Timeframe: Months 1–4 of the breach window
Anomaly: Each request was ~200 bytes larger than baseline checkout API requests
Baseline request size: 1,400 bytes | Observed: ~1,600 bytes
```

**Artifact 2 — Web Root Filesystem:**

```text
Filename: global_asa.dll.bak
Location: C:\inetpub\wwwroot\ (web root)
Creation date: Approximately 4 months ago (matches breach start)
Change management records: NONE found for this file
Hash: b3d4f7a29c8e1054... (not present in any legitimate IIS/ASP.NET package)
```

**Artifact 3 — Database Audit Log (90 days only — first month missing):**

```text
Event: Stored procedure MODIFIED
Object: sp_capture_payment (payment processing stored procedure)
Date: Approximately 4 months ago (outside 90-day retention — inferred from application log anomalies)
Current state of sp_capture_payment:
  - Original function: validates and passes card data to payment processor
  - Modified function: writes full card data (PAN, CVV, expiry) to temp table
    "_proc_buffer_temp" BEFORE passing to payment processor
```

**Artifact 4 — Network Flow (30 days only):**

```text
Recent pattern: Regular outbound transfers (2.1 GB total over 30-day window)
from web server (10.0.5.22) to IP 185.193.127.44 (Amsterdam, Netherlands — VPS provider)
Transfer times: Every 3 days, approximately 70 MB per transfer
Protocol: HTTPS (port 443) — encrypted, no content inspection
First observed in 30-day window; likely began 4 months ago
```

---

## Tasks

### Part A: Investigation Scope (20 minutes)

1. **Payment flow analysis:** Based on the e-commerce architecture, where in the payment flow could card data have been captured? List all possible capture points from the moment a customer enters card details to when payment confirmation is shown.

1. **Log gap analysis:** The 4-month breach predates most of your log retention. Create a table mapping: which aspects of the investigation can be answered vs. which have evidence gaps. What does this mean for your ability to determine the full scope?

1. **Immediate evidence preservation:** What evidence must be preserved right now before it is overwritten or lost? List in order of urgency.

1. **The 4-month dwell time challenge:** Why is a 4-month dwell time particularly challenging from an investigation standpoint? Name at least 3 specific problems.

---

### Part B: Forensic Timeline Reconstruction (25 minutes)

Using the four artifacts provided:

1. **Reconstruct the attack timeline** — create a chronological timeline of attacker activity from initial access to the present. Include:
   * Initial access vector (how they got in)
   * Persistence mechanism installed
   * Data capture mechanism
   * Exfiltration method and estimated data volume

1. **Identify the attack type** — what category of e-commerce attack is this? (Name it, describe how it works conceptually)

1. **Identify what is unknown** — despite the artifacts, several critical questions remain unanswered. List at least 4 things you still need to determine and describe how you would investigate each.

---

### Part C: Root Cause and Attribution (20 minutes)

Based on the four artifacts:

1. **Describe the attack vector** — how did the attacker gain initial access? What vulnerability category does this represent?

1. **Describe the persistence mechanism** — what is `global_asa.dll.bak`? How does it work? Why is its location significant?

1. **Describe the data capture technique** — explain the stored procedure modification in technical detail. How does a SQL-level skimmer work? Where is the data stored before exfiltration?

1. **Describe the exfiltration method** — what can you infer from the network flow data? Why is HTTPS used? Why every 3 days?

1. **Map to MITRE ATT&CK** — identify at least 5 techniques (use ATT&CK IDs and names)

1. **Attribution assessment** — given the artifacts, what can you say about the threat actor? What category of threat actor conducts this type of attack?

---

### Part D: Regulatory and Business Response (25 minutes)

RetailCorp processes payments under PCI DSS Level 1.
The breach affected 15,247 card numbers across EU customers.

1. **Notification obligations** — create a complete notification matrix:
   * Who must be notified?
   * By when?
   * What information is required?
   * What are the consequences of late notification?

   Include: Visa, Mastercard, acquiring bank, EU DPAs (which ones?), affected customers

1. **PCI DSS consequences** — what are the potential PCI DSS penalties and consequences following a Level 1 breach? Include: fines, assessments, operational restrictions.

1. **Executive brief for the Board of Directors** — write a 400-word brief covering:
   * What happened (non-technical summary)
   * Customer impact
   * Regulatory exposure
   * Immediate actions taken
   * Next 30 days

---

## Hints

* `global_asa.dll.bak` in the web root is not a backup file — its name is designed to avoid attention
* The stored procedure modification is a classic SQL-level card skimmer — the data is captured in a temp table and later exfiltrated
* 15,247 cards over 4 months = roughly 125 cards per day — consistent with steady-state skimming
* The Amsterdam VPS IP is likely a money mule or drop server — not necessarily where the attacker is located
* PCI DSS breach requires a mandatory PFI (Payment Forensic Investigator) investigation — the QSA certification does not protect you
* The 4-month dwell time means most EDR, DB, and network logs are gone — your primary sources are WAF logs and web server access logs
* Under GDPR, "cardholder data" (names + card numbers + expiry) is personal data — all 12 EU countries where affected customers reside may have notification requirements
