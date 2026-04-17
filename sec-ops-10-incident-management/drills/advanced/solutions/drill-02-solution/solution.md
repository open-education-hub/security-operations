# Solution: Drill 02 (Advanced) — IR Program Design for TransLog d.o.o.

This solution provides a complete worked example of an IR program design for TransLog d.o.o.
Consulting deliverables of this type are high-stakes documents — the quality lies in the precision of the analysis and the practicality of the recommendations, not just the completeness of the template.

---

## Deliverable 1: IR Program Maturity Assessment

### Maturity Scoring (Current State)

| Dimension | Current (1–5) | Evidence from Brief | Target Y1 (1–5) |
|---------|:------------:|---------------------|:--------------:|
| **Preparation & Planning** | **1** | No formal IR plan; no CSIRT; 1 ad-hoc tabletop "played by ear"; no playbooks | **3** |
| **Detection & Analysis** | **2** | EDR deployed to all Windows endpoints; but no SIEM; no threat hunting; no centralized log analysis | **3** |
| **Containment & Response** | **1** | Stolen laptop incident: account disabled, no forensics, no PIR, no GDPR notification — the minimum response only | **3** |
| **Regulatory Compliance** | **1** | DPO appointed (part-time); breach register exists but has 0 entries (implausible given 250,000 people's data); stolen laptop not reported; NIS2 obligations not operationalized | **3** |
| **Post-Incident Learning** | **1** | No PIR conducted after the only known incident; no lessons-learned process; no metrics | **2** |

**Scale reference:** 1=None, 2=Initial, 3=Developing, 4=Defined, 5=Optimized

**Overall assessment:** TransLog is at the bottom of the maturity curve.
The organization has the minimum prerequisites (EDR, DPO, cyber insurance) but has not operationalized any of them into a functioning IR capability.
The empty breach register after 3+ years of processing 250,000 individuals' data is a red flag indicating either non-compliance with Art. 33.5 GDPR or a systemic failure to recognize and record breaches.

### Stolen Laptop Incident — Failure Analysis

The recent stolen laptop incident was handled incorrectly on multiple dimensions:

| Failure | What should have happened | Consequence |
|---------|--------------------------|-------------|
| No GDPR breach assessment | A formal risk assessment should have determined: was a notifiable breach triggered? (It was — see Deliverable 5) | Possible regulatory violation; GDPR Art. 83 fine exposure |
| No GDPR notification filed | Notification to IP RS should have been made within 72 hours if notification was required | Ongoing regulatory exposure; if the breach is later discovered, delayed notification is worse than timely notification |
| No breach register entry | Even if the breach was assessed as non-notifiable, Art. 33.5 requires it be logged | Non-compliance with GDPR record-keeping obligation |
| No forensic analysis | Was the local data copy encrypted? Was the laptop full-disk encrypted? Was it password protected? | Without this analysis, the risk assessment is incomplete; exposure cannot be quantified |
| No PIR | What policy violation allowed local data copies? How was it prevented going forward? | The root cause remains unaddressed; another coordinator could do the same thing today |
| Police report only | Police report is appropriate for the theft itself but does not constitute GDPR notification | May have created a false sense of "we reported it" |

---

## Deliverable 2: IR Team Design

### Virtual CSIRT Model

```text
                    ┌─────────────────────────────────────────┐
                    │          INCIDENT COMMANDER              │
                    │    IT Manager (internal, +386 mobile)    │
                    │    On-call: rotation across 3 IT staff   │
                    └──────┬────────────────┬──────────────────┘
                           │                │
          ┌────────────────▼───┐    ┌───────▼──────────────────┐
          │  TECHNICAL LEAD    │    │  REGULATORY/LEGAL LEAD   │
          │  IT Staff #1       │    │  DPO (part-time, ext.)   │
          │  (AWS, EDR, net.)  │    │  + External IR Legal     │
          └────────────────────┘    └──────────────────────────┘
                           │
          ┌────────────────▼────────────────────────────────┐
          │              EXTERNAL SUPPORT                    │
          │  IR Retainer Firm  |  External Forensics (DFIR) │
          │  (on-call 24/7)    |  (on-demand)               │
          └──────────────────────────────────────────────────┘
                           │
          ┌────────────────▼────────────────────────────────┐
          │           STAKEHOLDER LIAISONS                   │
          │  CEO (business decisions) | Finance (cyber ins.) │
          │  Legal counsel (contracts, law enforcement)      │
          └──────────────────────────────────────────────────┘
```

### Role Descriptions

**Incident Commander (IT Manager):** The IC is accountable for all IR decisions from initial declaration to post-incident review.
They declare severity levels, authorize containment actions, manage escalation to the CEO, and own the regulatory notification decision in coordination with the DPO.
In the virtual CSIRT model, the IC role rotates among the 3 IT staff using a documented on-call schedule.
The IC must be reachable within 15 minutes 24/7.

**Technical Lead:** The senior technical responder responsible for executing containment, analysis, and eradication steps.
For TransLog's Azure + on-prem environment, this person must be proficient in: Windows event log analysis, Azure Security Center/Sentinel alerts, EDR console (CrowdStrike/Defender ATP), network isolation procedures, and basic DFIR (memory capture, disk imaging).
The Technical Lead coordinates with the external IR retainer for major incidents.

**DPO (External, Part-Time):** The DPO is on the notification escalation path for all incidents involving personal data of EU individuals.
They are consulted within 2 hours of any incident that may involve personal data, and they own the Art. 33 notification decision and drafting.
Given TransLog's NIS2 Important Entity status, the DPO must also understand NIS2 notification obligations.
SLA with DPO service: available within 4 hours for any P1/P2 incident.

**External IR Retainer (DFIR Firm):** The retained firm provides 24/7 on-call support for P1/P2 incidents.
Services include: remote triage support, memory and disk forensics, malware analysis, threat actor identification, and legal hold support.
The retainer should include a minimum 40 hours per year included in the base fee, with hourly rates pre-negotiated for overrun.
Recommended firms for Slovenia/CEE: S&T (local presence), Sievert Cyber, or a Big 4 forensics team with CEE coverage.

**Legal Counsel (External):** Separate from the DPO, legal counsel provides advice on: law enforcement engagement, regulatory enforcement response, contractual notifications to B2B customers, employment law for insider threat cases, and evidence preservation for litigation.
Should be engaged for all P1/P2 incidents and all incidents involving law enforcement.

### Escalation Matrix

| Severity | Declare in | IC | Technical Lead | DPO | Legal | CEO | IR Retainer |
|---------|-----------|----|----|-----|-------|-----|-------------|
| **P1** — Critical | 15 min | Immediately | Immediately | Within 2 hours | Within 4 hours | Within 2 hours | Immediately |
| **P2** — High | 30 min | Within 30 min | Within 30 min | Within 4 hours | If needed | Briefing within 24h | If needed |
| **P3** — Medium | 4 hours | Same day | Same day | If personal data | No | No | No |
| **P4** — Low | Next business day | Next day | Next day | No | No | No | No |

### External Resources

| Resource | Purpose | Estimated Annual Cost |
|---------|---------|----------------------|
| IR Retainer (DFIR firm) | 24/7 P1/P2 on-call; 40h included; forensics + malware analysis | EUR 18,000–25,000/year |
| External DPO service | GDPR DPO, breach notification drafting, regulatory liaison | EUR 8,000–12,000/year (existing) |
| External legal counsel | Law enforcement, regulatory enforcement, B2B notifications | EUR 5,000 retainer + hourly |
| SI-CERT coordination | National CERT for NIS2 significant incident reporting | Free (government) |

### On-Call Coverage Design

TransLog operates 24/7.
With only 3 IT staff, true follow-the-sun coverage is impossible without external help.
Recommended model:

* **Business hours (07:00–19:00 CET):** All 3 IT staff available; IC = IT Manager
* **After-hours (19:00–07:00) and weekends:** On-call rotation among 3 IT staff, one person per week. The on-call person must be able to:
  * Answer a phone call within 15 minutes
  * Join a VPN and remote-access the environment within 30 minutes
  * Engage the IR retainer 24/7 hotline within 1 hour for any P1
* **P1 trigger for IR retainer engagement:** Any detection of active ransomware, domain compromise, or confirmed data exfiltration — the on-call person is NOT expected to handle this alone; they declare P1 and immediately engage the retainer

### Budget Allocation (EUR 80,000 Year 1)

| Category | Allocation | Items |
|---------|-----------|-------|
| IR Retainer (DFIR firm) | EUR 22,000 | 24/7 on-call, 40h included, CEE coverage |
| SIEM (Microsoft Sentinel) | EUR 18,000 | ~500 GB/day log ingestion, 90-day retention |
| TheHive + MISP (self-hosted) | EUR 3,000 | Cloud hosting + setup/integration |
| EDR expansion | EUR 5,000 | Extend to servers + Linux endpoints |
| Training (IR team) | EUR 6,000 | GCIH/GCFE for 1 staff; online IR training for all 3 |
| Tabletop exercise (external facilitator) | EUR 3,000 | Annual exercise with external facilitator |
| Legal counsel retainer | EUR 5,000 | IR legal support, law enforcement guidance |
| IR tooling (KAPE, Volatility, FTK licenses) | EUR 4,000 | Forensic toolkit |
| Contingency / incident response cost reserve | EUR 14,000 | Buffer for actual P1/P2 response costs |
| **Total** | **EUR 80,000** | |

---

## Deliverable 3: Tooling Roadmap

```text
QUARTER 1 (Month 1–3): Foundation and Visibility
  Tool 1: Microsoft Sentinel (SIEM)
    Purpose: Centralized log collection, alerting, and investigation
    Cost: ~EUR 4,500/quarter (EUR 18,000 annual)
    Why TransLog: Azure-native; integrates immediately with existing Azure
    environment; no agent deployment needed for Azure resources; enables
    centralized detection that currently does not exist

  Tool 2: TheHive (case management, self-hosted on Azure VM)
    Purpose: Incident ticketing, task assignment, timeline tracking, evidence
    Cost: EUR 800/quarter (VM hosting)
    Why TransLog: Free/open-source, self-hosted means no SaaS dependency during
    incidents; all IR documentation in one place; enables PIR automation

  Tool 3: KAPE (Kroll Artifact Parser and Extractor)
    Purpose: Rapid triage collection from Windows endpoints
    Cost: Free (open-source)
    Why TransLog: Enables fast evidence collection from Windows endpoints
    (logistics coordinator laptops etc.) during incidents like the stolen laptop

  Milestone Q1: TransLog can centrally collect and alert on security events
  from Azure + on-prem Windows; has a case management system; can perform
  basic evidence collection from Windows endpoints

QUARTER 2 (Month 4–6): Detection Enhancement
  Tool 4: MISP (Malware Information Sharing Platform, self-hosted)
    Purpose: Threat intelligence feeds, IOC management
    Cost: EUR 400/quarter (VM hosting)
    Why TransLog: Logistics sector is a high-ransomware-risk vertical; MISP
    enables automated IOC blocking at EDR and firewall level; free feeds
    available (CIRCL, ENISA, sector ISACs)

  Tool 5: Volatility 3 (memory forensics framework)
    Purpose: Memory analysis during malware/intrusion investigations
    Cost: Free (open-source)
    Why TransLog: Fileless malware (common in targeted attacks on logistics)
    leaves no disk artifacts; memory forensics is essential for attributing
    and scoping these attacks

  Milestone Q2: TransLog can match incoming events against threat intelligence;
  has memory forensics capability; IR team has practiced first collection exercise
  using TheHive + KAPE + Volatility in a tabletop drill

QUARTER 3 (Month 7–9): Response Enhancement
  Tool 6: Automated SOAR playbooks in Microsoft Sentinel
    Purpose: Automate first-response actions (quarantine host, disable account)
    triggered by high-confidence alerts
    Cost: Included in Sentinel pricing
    Why TransLog: With only 3 IT staff, automated initial response buys
    critical time during after-hours incidents

  Tool 7: Azure Backup Vault (isolated, immutable backups)
    Purpose: Ransomware-resistant backup with cross-region replication
    Cost: EUR 2,000/quarter estimate
    Why TransLog: Current backup posture is unknown/vulnerable; immutable
    backups are the single most important ransomware recovery control

  Milestone Q3: TransLog can automatically quarantine a compromised endpoint
  via EDR playbook; backup environment is isolated and immutable; first live
  drill of backup restore completed

QUARTER 4 (Month 10–12): Consolidation and Automation
  Tool 8: Vulnerability Management (Microsoft Defender Vulnerability Management
  or Tenable.io Essentials)
    Purpose: Continuous vulnerability scanning; patch prioritization
    Cost: EUR 3,000/quarter
    Why TransLog: Without visibility into unpatched systems, detection and
    response are reactive; vulnerability management enables prevention

  Milestone Q4: Full IR metrics dashboard operational; second annual tabletop
  exercise conducted; all 7 deliverables from this consulting project reviewed
  against reality; Year 2 program plan drafted
```

---

## Deliverable 4: IR Plan Outline

```text
TransLog d.o.o. — Incident Response Plan
Version: 1.0 | Classification: CONFIDENTIAL — INTERNAL

TABLE OF CONTENTS

1. INTRODUCTION AND SCOPE

   1.1 Purpose of this Plan
       [Defines what this plan is, what it covers, and what it does not cover]
   1.2 Scope
       [Geographic: 8 EU countries; Systems: Azure + on-prem Ljubljana DC;
        Data: 250,000 EU individuals, B2B customers, commercial data]
   1.3 Relationship to Other Plans
       [Business Continuity Plan, Disaster Recovery Plan, GDPR Data Breach
        Response Procedure, NIS2 Notification Procedure]
   1.4 Plan Maintenance and Review Schedule
       [Annual review; post-incident review triggers; version control]
   ⚖️ LEGAL REVIEW REQUIRED: Scope definition for NIS2 Important Entity obligations

2. ORGANIZATIONAL STRUCTURE AND ROLES
   2.1 Virtual CSIRT Model
       [Org chart; description of virtual CSIRT; role of IR retainer]
   2.2 Role Descriptions
       [IC, Technical Lead, DPO, Legal Counsel, External DFIR]
   2.3 Contact Directory
       [All CSIRT members with mobile numbers; external vendor hotlines;
        SI-CERT, IP RS, DORA/NIS2 contacts — maintained as separate annex]
   2.4 Escalation Matrix
       [P1-P4 with notify/escalation timelines]
   ⚖️ LEGAL REVIEW REQUIRED: DPO's authority and independence per GDPR Art. 38

3. INCIDENT CLASSIFICATION
   3.1 Severity Definitions (P1 through P4)
       [With examples specific to TransLog's asset inventory]
   3.2 Incident Taxonomy
       [Malware, unauthorized access, data breach, insider threat, supply chain,
        denial of service, physical security]
   3.3 Classification Decision Matrix
       [A quick-reference table combining incident type + data sensitivity +
        business impact to arrive at severity level]

4. DETECTION AND INITIAL RESPONSE (PHASE 1)
   4.1 Sources of Incident Detection
       [EDR alerts, SIEM (Sentinel), employee reports, customer reports,
        external researchers, law enforcement, threat intelligence]
   4.2 Initial Triage Procedure
       [Verify the alert; determine if incident or false positive;
        collect basic evidence]
   4.3 Incident Declaration
       [Who can declare; how; what triggers what]
   4.4 Notifications Within 60 Minutes
       [Who must be notified within 1 hour for each severity level]

5. CONTAINMENT (PHASE 2)
   5.1 Principles of Containment
       [Isolate without destroying; preserve evidence first; document everything]
   5.2 Containment Playbooks (by incident type)
       5.2.1 Ransomware Containment
       5.2.2 Account/Credential Compromise
       5.2.3 Insider Data Exfiltration
       5.2.4 Cloud Resource Compromise (Azure)
       5.2.5 Physical Security (lost/stolen device)
   5.3 Evidence Preservation During Containment
       [Chain of custody; volatile evidence; system imaging procedure]

6. ERADICATION AND RECOVERY (PHASE 3)
   6.1 Eradication Prerequisites
       [Do not eradicate before understanding the full scope of compromise]
   6.2 Root Cause Analysis
       [Timeline reconstruction; IOC identification; attack path mapping]
   6.3 System Recovery
       [Backup integrity verification; clean rebuild procedure; staged return
        to production]
   6.4 Validation Before Return to Production
       [What must be confirmed before a system is re-activated]

7. POST-INCIDENT REVIEW (PHASE 4)
   7.1 PIR Trigger and Timing
       [Mandatory for all P1/P2; optional for P3/P4; within 5 business days]
   7.2 PIR Procedure
       [Blameless format; timeline review; 5 Whys root cause analysis;
        action items]
   7.3 PIR Output and Distribution
       [PIR report format; CISO/CEO briefing; follow-up tracking]

8. REGULATORY NOTIFICATION PROCEDURES
   ⚖️ ENTIRE SECTION REQUIRES LEGAL REVIEW
   8.1 GDPR Notification (Art. 33 / Art. 34)
       [72-hour clock; IP RS contact; notification template; staged notification]
   8.2 NIS2 Significant Incident Notification
       [Early warning 24h; notification 72h; final report 1 month;
        SI-CERT contact; definitions of "significant incident"]
   8.3 Internal Notification Template Library
       [Pre-approved templates for: DPA notification, individual notification,
        B2B customer notification, executive summary, law enforcement report]

9. COMMUNICATION MANAGEMENT
   9.1 Internal Communication
       [Out-of-band channel; who can communicate what to whom]
   9.2 External Communication
       [Media policy: CISO approves; CEO signs off; no ad-hoc statements]
   9.3 Customer Communication
       [B2B customer notification triggers and templates]
   9.4 Law Enforcement Communication
       [When to engage; legal counsel required; preserve chain of custody]

10. ANNEXES
    A. Asset Inventory and Classification (maintained separately)
    B. Contact Directory (maintained separately, updated quarterly)
    C. Incident Response Playbooks (maintained separately by incident type)
    D. Evidence Collection Procedures and Chain of Custody Forms
    E. Regulatory Notification Templates
    F. Breach Register Procedure and Template
    G. Glossary of Terms
```

---

## Deliverable 5: Regulatory Integration Plan

### 1. Retrospective Assessment — Stolen Laptop

**Should TransLog have filed a GDPR notification for the stolen laptop?**

**Argument YES (notification required):**
The laptop contained a local copy of a customer database segment with personal data of EU individuals (250,000 customers).
GDPR Art. 33 notification is required when a breach is "likely to result in a risk to the rights and freedoms of natural persons." The theft of an unencrypted laptop (encryption status unknown) containing personal data from a vehicle is a *textbook notifiable breach*.
The theft establishes unauthorized third-party access.
The risk assessment cannot assume the data was never accessed — the laptop was in a public space and in the possession of an unknown third party.
IP RS (Information Commissioner of Slovenia) should have been notified within 72 hours.

**Argument NO (notification not required):**
If the laptop was **full-disk encrypted** and the encryption key was not compromised (e.g., via BitLocker with a strong PIN known only to the employee), then the data is unintelligible to any unauthorized party.
GDPR Art. 33(1) notification is not required "where the personal data breach is unlikely to result in a risk to the rights and freedoms of natural persons." With full encryption, the risk is low.

**What should TransLog do now?**
First, immediately determine: was the laptop full-disk encrypted?
If yes, with what standard, and is there log evidence confirming encryption was active?
If no: TransLog is in a state of ongoing non-compliance.
They should consult their DPO and external legal counsel, make a voluntary late notification to IP RS, and document their reasoning in the breach register.
A voluntary late notification is always better received by regulators than one triggered by a complaint or investigation.
If the breach was during a period when GDPR was in force (post-2018), fines under Art. 83 are possible, but voluntary disclosure significantly reduces that risk.

---

### 2. Breach Assessment Decision Flowchart

```text
INCIDENT DETECTED
        │
        ▼
Does the incident involve personal data of EU individuals?
(customer data, employee data, B2B contact data)
        │
   YES  │  NO ──► Log as IT incident; no regulatory notification required
        ▼
Has personal data been:
  (a) accessed without authorization, OR
  (b) lost/stolen/unavailable to authorized users, OR
  (c) modified without authorization?
        │
   YES  │  NO ──► No breach; document in incident log
        ▼
Was the data ENCRYPTED at rest with a strong standard
(AES-256/BitLocker/Azure Encryption) AND is the key secure?
        │
   YES  │  NO
        │     └──► BREACH CONFIRMED — proceed to notification
        ▼
Risk low — likely non-notifiable BUT:
  → Document in breach register (Art. 33.5 required regardless)
  → DPO review within 2 hours
  → DPO decision: notifiable or documented non-notification
        │
        ▼ (if notifiable or uncertain)
NOTIFICATION DECISION TREE:
  → GDPR Art. 33: Notify IP RS within 72 hours of awareness
  → GDPR Art. 34: Notify affected individuals if high risk
  → NIS2 Art. 23: Early warning to SI-CERT within 24 hours
    if "significant incident" (major operational disruption,
    or personal data breach with >1000 individuals, or attack
    with cross-border impact)
  → NIS2 final notification within 72 hours
  → NIS2 final report within 1 month
```

---

### 3. Notification Calendar Template

```text
ACTIVE INCIDENT NOTIFICATION TRACKER

Incident ID: [INC-YYYY-NNN]
Incident description: [Brief description]
Incident declared: [Date/Time UTC]
Personal data involved: YES / NO / TBD
NIS2 significant incident: YES / NO / TBD

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REGULATORY NOTIFICATION DEADLINES

| Framework | Obligation | Deadline | Owner | Status | Filed |
|-----------|-----------|---------|-------|--------|-------|
| NIS2 | Early warning to SI-CERT | T+24h: [Date/Time] | IC | Pending | |
| GDPR Art.33 | Notify IP RS | T+72h: [Date/Time] | DPO | Pending | |
| NIS2 | Full notification to SI-CERT | T+72h: [Date/Time] | IC+DPO | Pending | |
| GDPR Art.34 | Notify individuals (if high risk) | ASAP: [Date/Time] | DPO | Pending | |
| NIS2 | Final report to SI-CERT | T+1month: [Date] | IC | Pending | |
| Cyber insurance | Notify insurer | Per policy: [Date] | Finance | Pending | |
| B2B contracts | Notify affected B2B customers | Per contracts: TBD | Legal | Pending | |

NOTES ON EACH NOTIFICATION:
[Date/Time] ─ IP RS notification filed: [confirmation reference]
[Date/Time] ─ SI-CERT early warning sent: [reference]
[Date/Time] ─ Individual notification: [sent to X individuals via Y channel]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### 4. Regulatory Awareness Module for Virtual CSIRT (2-Hour Outline)

```text
MODULE: Regulatory Obligations for IR Responders — 2 Hours
Audience: All 3 IT staff + external DPO + Legal counsel
Format: Workshop (not lecture) — case-study driven

HOUR 1: GDPR and Personal Data in IR

  Block 1 (20 min): What is personal data in TransLog's context?
    - Customer data types: names, addresses, shipping data, tracking data
    - Employee data
    - B2B contact data (when does it become personal data?)
    - Exercise: classify 10 data types from TransLog's real systems

  Block 2 (20 min): The 72-hour clock — what starts it, what stops it
    - When does "awareness" occur? (key misunderstanding)
    - What to include in a staged Art. 33 notification
    - Art. 34 high risk threshold — worked examples
    - Case study: TransLog stolen laptop — was it notifiable?

  Block 3 (20 min): Who to notify, how, in what format
    - IP RS contact and online notification portal
    - Art. 33 notification template walkthrough
    - Art. 34 individual notification — plain language requirement
    - Breach register obligation (even for non-notifiable events)

HOUR 2: NIS2 and Multi-Framework Incidents

  Block 4 (20 min): NIS2 for Important Entities — TransLog's specific obligations
    - What is a "significant incident" under NIS2 Art. 23?
    - 24h early warning vs. 72h notification vs. 1-month report
    - SI-CERT as the point of contact
    - Difference between NIS2 and GDPR notifications (they are separate)

  Block 5 (20 min): Multi-framework incident management
    - Scenario: ransomware hits TransLog's Ljubljana DC
    - Walk through: GDPR clock, NIS2 clock, cyber insurance notification,
      B2B customer contract obligations — all running simultaneously
    - Who owns what notification? RACI exercise

  Block 6 (20 min): Q&A + documentation
    - Common pitfalls in breach notification
    - Where to find the notification templates in the IR Plan
    - Commitment to annual refresher and drill
```

---

## Deliverable 6: 12-Month IR Metrics Dashboard

### Operational Metrics (5 KPIs)

| KPI | Definition | How to Measure | Month 1 Baseline | Year-End Target |
|----|-----------|----------------|-----------------|----------------|
| **Mean Time to Detect (MTTD)** | Average time from incident start to detection confirmation | From TheHive incident tickets: (detection time) − (earliest evidence of incident start in logs) | Unknown (no measurement system) | < 4 hours for P1/P2 |
| **Mean Time to Contain (MTTC)** | Average time from incident declaration to containment confirmed | From TheHive: (containment confirmed timestamp) − (incident declared timestamp) | Unknown | < 2 hours for P1; < 8 hours for P2 |
| **Incident Volume by Severity** | Count of incidents by P1/P2/P3/P4 per month | TheHive dashboard | 0 (no system exists) | Trending data (no target — baselines needed) |
| **False Positive Rate** | % of SIEM/EDR alerts that are investigated and closed as false positive | Sentinel + EDR alert closure data | Unknown | < 40% (high FP rate indicates tuning needed) |
| **On-Call Response Time** | Time from P1 alert to first IR action by on-call person | Page-to-acknowledge timestamp in monitoring system | Not measured | 100% within 15 minutes |

### Compliance Metrics (3 KPIs)

| KPI | Definition | How to Measure | Month 1 Baseline | Year-End Target |
|----|-----------|----------------|-----------------|----------------|
| **Breach Register Completeness** | % of detected incidents involving personal data that have a corresponding breach register entry (notifiable or not) | DPO audit of breach register vs. TheHive incident log | 0% (no register entries despite 3 years of data processing) | 100% |
| **Regulatory Notification Timeliness** | % of notifiable breaches where Art. 33 notification was filed within 72 hours | DPO review; cross-reference breach register with IP RS acknowledgments | Not measurable (no prior filings) | 100% of notifiable breaches notified within 72 hours |
| **NIS2 Significant Incident Reporting Rate** | % of NIS2-qualifying incidents reported to SI-CERT within 24h | IC review; SI-CERT acknowledgment records | Not measurable | 100% of qualifying incidents reported |

### Program Maturity Metrics (2 KPIs)

| KPI | Definition | How to Measure | Month 1 Baseline | Year-End Target |
|----|-----------|----------------|-----------------|----------------|
| **IR Maturity Score (Annual)** | Average score across 5 maturity dimensions from Deliverable 1 | Annual self-assessment against the same framework, validated by external reviewer | 1.2 average (current) | 3.0 average |
| **Playbook Coverage** | % of top incident types with a written, tested playbook | Count of playbooks in IR Plan vs. taxonomy list; "tested" = used in a drill or live incident | 0% | 80% (4 of 5 priority incident types covered) |

---

## Deliverable 7: Quick-Win Recommendations

```text
Quick Win #1: Establish Out-of-Band Communication Channel
  Action: Create a phone bridge number (e.g., via Teams Audio Conferencing
  or a simple dial-in service) and a Signal group with all CSIRT members.
  Test it. Document the numbers in the IR contact sheet.
  Impact: Eliminates the scenario where incident communication fails because
  corporate email or Slack is inaccessible or compromised during a cloud incident
  Effort: 2 hours; EUR 0–200
  Owner: IT Manager
  Deadline: Day 3 of Month 1

Quick Win #2: Verify Laptop Encryption Status — All Devices
  Action: Audit all company laptops for BitLocker/full-disk encryption status.
  For any unencrypted device: enable encryption within 48 hours. Produce a
  report confirming 100% encryption coverage.
  Impact: Directly addresses the open liability from the stolen laptop incident;
  prevents future stolen-device incidents from being GDPR notifiable
  Effort: 4 hours; EUR 0 (BitLocker is included in Windows)
  Owner: IT Staff #1
  Deadline: Day 7 of Month 1

Quick Win #3: File Breach Register Entry for Stolen Laptop Incident
  Action: DPO to complete the GDPR breach register entry for the 3-month-old
  stolen laptop incident. Determine encryption status and make a documented
  notification decision (notify or documented non-notification with justification).
  Impact: Remedies ongoing non-compliance; demonstrates good faith to IP RS
  if the incident is later discovered; protects CISO and DPO from personal liability
  Effort: 2–4 hours; EUR 0
  Owner: DPO (with IT support)
  Deadline: Day 5 of Month 1

Quick Win #4: Publish IR Escalation Contact Sheet
  Action: Create a single A4 printed and digital document listing: all CSIRT
  members with personal mobile numbers; IR retainer 24/7 hotline; DPO mobile;
  IP RS contact for breach notification; SI-CERT contact for NIS2 reporting;
  cyber insurer claims line. Distribute to all CSIRT members. Post printed
  copy in the Ljubljana server room.
  Impact: Eliminates delay at the start of every incident where people are
  searching for phone numbers; the most common friction in IR
  Effort: 1 hour; EUR 0
  Owner: IT Manager
  Deadline: Day 2 of Month 1

Quick Win #5: Conduct 30-Minute GDPR Breach Awareness Briefing
  Action: DPO to run a 30-minute briefing for all 3 IT staff: what triggers the
  72-hour clock, what to do within the first 2 hours of any incident involving
  personal data, and who to call (DPO + IC). No slides required — use the
  contact sheet created in Quick Win #4.
  Impact: The most likely regulatory failure at TransLog is missing or late GDPR
  notification because IT staff don't recognize a breach when they see one.
  30 minutes of targeted training directly reduces this risk.
  Effort: 30 minutes; EUR 0
  Owner: DPO
  Deadline: Day 10 of Month 1
```

---

## Assessor Notes

When evaluating student submissions against this solution, prioritize:

1. **Realism of maturity scores** — scores of 3–4 for TransLog are incorrect; their brief clearly describes a level 1 organization
1. **Stolen laptop retrospective** — students who say "no notification needed" without assessing encryption status have made an error; the correct answer is "depends on encryption — assess immediately"
1. **Budget allocation** — allocations that ignore the IR retainer are a red flag; in a 3-person IT shop, the retainer is the most important single investment
1. **On-call design** — "on-call means IT staff checks email in the morning" is not an on-call design; must specify response time, escalation, and what the on-call person actually does at 3am
1. **Metrics that can't be measured** — if a student proposes a metric but cannot describe how to collect the data, deduct points; all metrics must have a data source
