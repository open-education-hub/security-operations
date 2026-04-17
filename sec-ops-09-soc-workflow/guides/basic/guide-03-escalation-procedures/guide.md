# Guide 03 — Escalation Procedures

## Objective

By the end of this guide you will be able to:

* Identify when escalation is required based on SLAs and incident characteristics
* Follow the correct escalation path (Tier 1 → Tier 2 → Tier 3 → Management)
* Write a proper escalation handoff note
* Recognize regulatory escalation triggers (e.g., GDPR Article 33)

**Estimated time:** 25 minutes

**Level:** Basic

**Prerequisites:** Guides 01–02

---

## Escalation Overview

Escalation is the process of transferring responsibility for an incident to a higher tier when:

* The current analyst lacks the skills or authority to proceed
* The incident severity exceeds defined thresholds
* SLA deadlines are at risk
* The incident scope expands beyond normal parameters

**Escalation is not a failure.** It is a designed part of the workflow.
Under-escalation (keeping incidents at a tier that cannot handle them) is far more dangerous than over-escalation.

---

## Escalation Triggers Reference

### Tier 1 → Tier 2

Escalate from Tier 1 when ANY of the following is true:

* Alert confirmed as true positive AND more than one system affected
* Alert involves a privileged account (Domain Admin, service account)
* Evidence of lateral movement, C2 communication, or data staging
* Cannot determine true/false positive within SLA window
* Alert severity is Critical
* Alert involves ransomware indicators (VSS deletion, mass file encryption)

### Tier 2 → Tier 3

Escalate from Tier 2 when:

* Root cause cannot be determined within 4 hours
* Evidence of APT techniques (living-off-the-land, long-term persistence)
* Incident spans multiple business units or geographic regions
* Evidence of data exfiltration (DLP alert, large outbound transfer)

### Tier 3 → Management

Escalate to SOC Manager when:

* Critical production system is down or at risk
* Evidence of data breach (personal data of customers or employees)
* Law enforcement engagement is required
* Media/PR risk (breach may become public)
* External entity notification required (CSIRT, ENISA, supervisory authority)

---

## Regulatory Escalation: GDPR Article 33

When personal data of EU residents may have been breached, the clock starts immediately:

| Deadline | Action |
|----------|--------|
| **1 hour** | Notify DPO (Data Protection Officer) |
| **24 hours** | Preliminary assessment of breach scope |
| **72 hours** | Notify supervisory authority (if breach likely to result in risk to rights and freedoms) |

**Key point:** The 72-hour clock starts from when you **become aware** of the breach, not when the breach occurred.
If you discover a breach that happened 3 days ago, you are already past the deadline — escalate immediately.

---

## Scenario 1: Standard Escalation (Tier 1 → Tier 2)

**Situation:**

```text
Alert ALT-2025-09002 — High — Cobalt Strike beacon activity
Hostname: SERVER-PROD-DB-01 (Production database server)
User: svc_backup (backup service account)
Activity: Suspicious named pipe created (\\.\pipe\MSSE-4567-server)
Parent: cmd.exe ← svchost.exe
Network: SERVER-PROD-DB-01 → 185.220.101.73:443 (known C2)
```

**Triage by Tier 1:**

* Named pipe pattern matches CobaltStrike default configuration
* Source is a service account on production database server
* Destination is a known Cobalt Strike C2 (VT: 45/92 malicious)
* This is a Critical asset

**Escalation decision:** YES — escalate immediately

### Write the Escalation Note

A good escalation note transfers all context.
The Tier 2 analyst should not have to re-read the raw alert:

```markdown
## Escalation Note — ALT-2025-09002 → Tier 2

**Escalating Analyst:** Alice Nguyen (Tier 1)
**Escalation Time:** 2025-04-10 16:04 UTC
**Reason for Escalation:** Confirmed CobaltStrike beacon on critical production server

---

### Summary
CobaltStrike beacon detected on SERVER-PROD-DB-01, a critical production database server.
Service account svc_backup is exhibiting C2 communication behavior.

### Evidence
1. Named pipe \\.\pipe\MSSE-4567-server created by cmd.exe — CobaltStrike default pipe

2. Outbound connection to 185.220.101.73:443 — VT: 45/92 malicious, tagged "cobalt-strike"
3. Parent process chain: svchost.exe → cmd.exe (unusual for service account)
4. No legitimate backup jobs scheduled for this time (confirmed with IT)

### Asset Context
- Host: SERVER-PROD-DB-01 (Oracle DB, holds customer financial records)
- Account: svc_backup (service account, LOCAL_ADMIN on server)
- Asset criticality: CRITICAL
- Potential data at risk: Customer account data, transaction history

### Enrichment Done
- IP 185.220.101.73: VT=45/92, Shodan=port 443 open, no PTR, registered 2025-01-17
- svc_backup: Last 90-day activity review = only backup tasks, no interactive logins prior
- No other hosts currently communicating with 185.220.101.73 (checked SIEM)

### Actions Already Taken
- Case created: INC-2025-09002
- Alert acknowledged at 16:01 UTC
- No containment actions taken yet (awaiting Tier 2 authorization)

### Recommended Immediate Actions (Tier 2)
1. Isolate SERVER-PROD-DB-01 from network (coordinate with DBA team for controlled isolation)

2. Preserve memory dump before isolation if possible
3. Check all OTHER database servers for same named pipe / C2 connection
4. Notify DBA team and application owner immediately
5. Assess if customer data was accessible to the beacon
6. Consider GDPR Article 33 notification (production DB with customer data)

### SLA Status
- Alert time: 16:00 UTC
- Acknowledgment: 16:01 UTC (1 min — well within SLA)
- Escalation: 16:04 UTC (4 min)
- Tier 2 SLA for Critical: Investigate within 1 hour (deadline: 17:04 UTC)
```

---

## Scenario 2: Regulatory Escalation (GDPR Trigger)

**Situation:** Tier 2 investigation of the CobaltStrike case reveals:

```text
Forensic finding at 17:30 UTC:
- Memory dump analysis: CobaltStrike loaded 6 hours ago (10:00 UTC)
- SQL queries executed by beacon:
  SELECT card_number, cvv, expiry_date FROM customer_payments WHERE...
- Estimated records accessed: ~23,000 customer payment card records
- Data exfiltration: 2.3 MB sent to 185.220.101.73 at 10:45 UTC
```

**This is a data breach involving payment card data.**

### Escalation to Tier 3 + Management

```markdown
## CRITICAL ESCALATION — Data Breach — INC-2025-09002

**Escalating:** Tier 2 → Tier 3 + SOC Manager + DPO
**Time:** 2025-04-10 17:35 UTC
**Priority:** P1 — Immediate action required

### Breach Summary
Cobalt Strike beacon exfiltrated approximately 23,000 customer payment card records
(card_number, CVV, expiry_date) from production Oracle database at approximately 10:45 UTC.
Total data exfiltrated: ~2.3 MB.

### GDPR Status
- Breach discovery time: 17:35 UTC today (now)
- Breach incident time: 10:00–10:45 UTC (approx. 7 hours ago)
- **72-hour notification clock started: 17:35 UTC today**
- **Notification deadline: 17:35 UTC + 72h = 2025-04-13 17:35 UTC**
- Data involved: Customer financial data (payment cards) — HIGH RISK to individuals

### Immediate Actions Required
1. [DPO] Begin breach assessment documentation

2. [Legal] Prepare supervisory authority notification
3. [SOC Manager] Brief CISO and management immediately
4. [Tier 3] Continue forensics — establish full scope
5. [IT] Ensure full isolation of SERVER-PROD-DB-01

### Contacts to Notify
- DPO: dpo@globalbank.com
- CISO: ciso@globalbank.com
- Legal: legal-security@globalbank.com
- Supervisory Authority: German BaFin (financial regulator)
```

---

## Scenario 3: Under-escalation Risk

**What NOT to do:**

```text
Analyst receives alert for Domain Admin account logging in at 3 AM from a foreign IP.
The analyst enriches the IP, finds it "only" scores 2/92 on VirusTotal.
The analyst closes the alert as "Low risk — no VT hits — FP."
No escalation. No further investigation.

Three days later: ransomware across the entire domain.
```

**What went wrong:**

* Domain Admin at 3 AM from foreign IP is a Critical escalation trigger regardless of VT score
* VT score for a fresh attacker IP is often 0 — they rotate IPs frequently
* The analyst applied the wrong decision framework (VT score as primary indicator)
* Failure to escalate resulted in complete lack of response to a domain compromise

**Correct action:** ANY Domain Admin login anomaly escalates to Tier 2 automatically.

---

## Escalation Quick Reference Card

```text
TRIGGER → ESCALATE TO
─────────────────────────────────────
Confirmed TP + multiple hosts → Tier 2
Privileged account involved → Tier 2
C2 / lateral movement detected → Tier 2
Cannot determine TP/FP within SLA → Tier 2 (or close+tune)
Data exfiltration evidence → Tier 3
Full domain compromise suspected → Tier 3
Customer data breach → Tier 3 + Management + DPO
Ransomware → Tier 3 + Management
Production system impacted → Management notification
Media risk / regulatory breach → Management + Legal + DPO
```

---

## Knowledge Check

1. You are a Tier 1 analyst and you cannot determine if an alert is a true positive within your SLA window. What do you do?
1. A Tier 2 analyst finds that a breach occurred 60 hours ago involving customer email addresses. What regulatory action is needed and what is the deadline?
1. Name three situations where a Tier 1 analyst should escalate even before finishing their enrichment.
1. What should an escalation note always include?
1. Why is "the IP has only 2/92 VT detections" NOT a sufficient reason to close a Domain Admin login anomaly alert?
