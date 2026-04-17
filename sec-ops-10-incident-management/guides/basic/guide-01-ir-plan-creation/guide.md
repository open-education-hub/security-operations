# Guide 01 (Basic): Creating an Incident Response Plan

> **Estimated time:** 45–60 minutes
> **Level:** Basic
> **Goal:** Build a functional, organization-specific Incident Response Plan by completing each section of this guided template.

---

## Introduction

An Incident Response Plan (IRP) is the organizational document that defines *how* your organization will detect, respond to, and recover from security incidents.
Without an IRP, every incident becomes an improvised crisis.
With a tested IRP, your team knows exactly what to do, who to call, and how to document every step.

This guide walks you through the creation of a complete IRP section by section.
By the end, you will have a usable draft that can be reviewed by leadership and tested in a tabletop exercise.

---

## Section 1: Document Header and Scope

Every formal policy document needs metadata.
Complete this section:

```markdown
INCIDENT RESPONSE PLAN

Organization:     [Your Organization Name]
Document ID:      IRP-001
Version:          1.0
Effective Date:   [Date]
Last Reviewed:    [Date]
Next Review:      [Date + 1 year]
Owner:            CISO / Head of Security
Classification:   CONFIDENTIAL — Internal Use Only
Approved By:      [Name, Title]
```

**Scope statement example:**

> This Incident Response Plan applies to all information systems owned or operated by [Organization], including on-premises infrastructure, cloud environments (AWS, Azure, GCP), and third-party managed services that process, store, or transmit [Organization] data. It applies to all employees, contractors, vendors, and third parties with access to [Organization] systems.

**Exercise 1.1:** Write a scope statement for your organization.
Consider: what systems are in scope?
What about cloud services?
What about managed service providers?

---

## Section 2: Incident Classification Matrix

The classification matrix defines what constitutes a P1, P2, P3, and P4 incident.
This drives all notification and response timelines.

**Template:**

| Severity | Label | Criteria | Max Response Time | Notifications |
|---------|-------|----------|------------------|---------------|
| **P1** | Critical | Active data exfiltration; ransomware spreading; breach of critical systems; threat to human safety | 30 minutes | IR Lead, CISO, Legal, Exec Sponsor, DPO |
| **P2** | High | Confirmed compromise of sensitive system; lateral movement detected; large-scale phishing | 2 hours | IR Lead, CISO, DPO |
| **P3** | Medium | Isolated compromise; malware without lateral movement; policy violation with potential data impact | 8 hours | IR Lead, Security Manager |
| **P4** | Low | Attempted attack (blocked); policy violation without data impact; precursor activity | Next business day | Security Manager |

**Exercise 2.1:** Does this matrix fit your organization?
Adjust the criteria to match your environment.
For example:

* A hospital might escalate any incident affecting patient records to P1 regardless of spread
* A payment processor might elevate any incident touching cardholder data to P1

**Incident type examples to map:**

```text
Map each incident type to a default severity:

Ransomware spreading across network:            P___
Phishing email clicked (no payload executed):   P___
Employee opens malware-infected attachment:     P___
External port scan of web server:               P___
Unauthorized privileged account access:        P___
DDoS attack affecting customer portal:          P___
API credential exposed in public GitHub repo:   P___
Laptop reported lost/stolen (encrypted):        P___
```

---

## Section 3: Incident Response Team

Define the IRT roles and who fills them.
Use this RACI matrix template:

### Core Roles

```text
IR TEAM DIRECTORY
══════════════════════════════════════════════════════════════
Role                    | Name(s)          | Contact         | Backup
────────────────────────|─────────────────|─────────────────|──────────
IR Lead                 |                  | Phone:          |
                        |                  | Email:          |
────────────────────────|─────────────────|─────────────────|──────────
Forensics Analyst       |                  | Phone:          |
                        |                  | Email:          |
────────────────────────|─────────────────|─────────────────|──────────
SOC Analyst (on-call)   | [SOC team]       | SOC hotline:    |
────────────────────────|─────────────────|─────────────────|──────────
Legal Counsel           |                  | Phone:          |
                        |                  | Email:          |
────────────────────────|─────────────────|─────────────────|──────────
DPO (Data Protection)   |                  | Phone:          |
                        |                  | Email:          |
────────────────────────|─────────────────|─────────────────|──────────
Communications / PR     |                  | Phone:          |
────────────────────────|─────────────────|─────────────────|──────────
Executive Sponsor       |                  | Phone:          |
                        |                  | Email:          |
════════════════════════════════════════════════════════════════════════

EXTERNAL CONTACTS:
IR Retainer (vendor):   [Vendor Name]     | 24/7:
Cyber Insurance:        [Insurer]         | Claims:
Law Enforcement:        [FBI / NCSC / CERT-RO] |
```

### RACI Matrix

Complete this RACI for your team:

| Activity | IR Lead | Forensics | SOC | Legal | Comms | Exec |
|----------|---------|-----------|-----|-------|-------|------|
| Incident declaration | A | C | R | C | I | I |
| Evidence collection | A | R | C | I | - | - |
| Containment execution | A | C | R | C | - | - |
| Customer notification | A | I | - | C | R | C |
| Regulator notification | C | I | - | A | R | C |
| Media statement | I | - | - | C | A | C |
| Lessons learned | A | R | R | C | C | I |

*R=Responsible, A=Accountable, C=Consulted, I=Informed*

**Exercise 3.1:** Fill in the names above for your organization.
If a role doesn't exist, identify who would cover it.
Mark any gaps where no one is currently assigned.

---

## Section 4: Communication Procedures

### Internal Communication Tree

For a P1 incident, the notification sequence is:

```text
SOC Analyst detects incident
         ↓
    (within 15 min)
IR Lead notified by phone
         ↓
    (within 30 min)
CISO + Legal + DPO notified
         ↓
    (within 1 hour)
Executive Sponsor briefed
         ↓
    (within 2 hours)
Board notification (if warranted)
```

### Out-of-Band Communication

**Critical:** If corporate email or Teams/Slack may be compromised (e.g., BEC incident, email server compromise), use an out-of-band communication channel.

Designate your out-of-band channel:

```text
Out-of-band channel for IR communications: _______________
(Recommended: Signal group, encrypted personal email, telephone)
Signal group name: "IR-Team-OOB"
Members added at onboarding: IR Lead, CISO, Legal, Exec Sponsor
```

### Communication Templates

#### Template A: Initial P1 Notification to Executive

```text
Subject: SECURITY INCIDENT DECLARATION — P1 — [DATE/TIME]

INCIDENT: [Brief description, e.g., "Ransomware confirmed on 3 Finance workstations"]
DECLARED: [Date/Time UTC]
IR LEAD: [Name]

CURRENT STATUS: [Contained / Not Contained / Under Investigation]

AFFECTED SYSTEMS:
[List systems affected]

KNOWN IMPACT:
[Business functions affected, data at risk]

ACTIONS UNDERWAY:
[What the team is doing right now]

NEXT UPDATE: [Time, e.g., "30 minutes" or specific time]

If you need immediate escalation, call IR Lead at: [phone]
```

#### Template B: Customer Notification

```text
Subject: Important Security Notice

Dear [Customer Name],

We are writing to inform you of a security incident that may have affected
your information held with [Organization].

WHAT HAPPENED:
[Plain language description — 2-3 sentences]

WHAT INFORMATION WAS INVOLVED:
[Specify: name, email, [other fields]]

WHAT WE ARE DOING:
[Actions taken to secure systems and prevent recurrence]

WHAT YOU CAN DO:
[Specific, actionable steps — change password, monitor accounts, etc.]

If you have questions, contact [DPO/privacy contact] at [email/phone].

We sincerely apologize for any concern this may cause.

[Organization Name]
Data Protection Officer: [Name] | [Email]
```

---

## Section 5: Escalation Thresholds and Decision Points

Document the key decisions and who has authority to make them:

```text
DECISION AUTHORITY MATRIX

Decision                          | Authority              | Trigger
──────────────────────────────────|───────────────────────|─────────────────────────────
Initiate IR response              | IR Lead (unilateral)   | Any P1/P2 alert confirmed
Isolate a production server       | IR Lead + IT Manager   | Confirmed compromise
Shut down a business-critical sys | IR Lead + CISO + Exec  | Only if absolutely necessary
Notify customers                  | CISO + Legal + DPO     | Confirmed personal data breach
Notify regulators                 | Legal + DPO            | GDPR 72h clock started
Engage law enforcement            | CISO + Legal           | Criminal activity suspected
Engage IR retainer vendor         | IR Lead (P1 only)      | >4 hours, no containment
Approve public statement          | CEO + Legal + PR       | Media enquiry or disclosure
```

---

## Section 6: Evidence Handling Procedures

Include a summary reference in the IRP (detailed procedures are in the Evidence Preservation Guide):

```text
EVIDENCE HANDLING SUMMARY

1. Collect in order of volatility (RAM → Network state → Disk)

2. Hash every artifact at collection: SHA-256 minimum
3. Complete Chain of Custody form for every item
4. Store originals in write-protected, access-controlled evidence repository
5. Never work on originals — always use verified forensic copies
6. Retain evidence for minimum [12 months / per legal requirement]

Chain of Custody form location: [path/link to form]
Evidence repository: [path/URL]
```

---

## Section 7: Regulatory Notification Reference Card

Include this quick-reference card in the IRP:

```text
REGULATORY NOTIFICATION QUICK REFERENCE
(ALWAYS consult Legal and DPO before filing)

GDPR (if personal data of EU data subjects involved):
  → Notify DPA within 72 hours of awareness (Art. 33)
  → Notify individuals without undue delay if high risk (Art. 34)
  → Your lead DPA: [ANSPDCP / ICO / Other]
  → DPO contact: [Name, email]

NIS2 (if your org is essential/important entity):
  → Early warning to CSIRT within 24 hours
  → Full notification within 72 hours
  → Final report within 1 month
  → National CSIRT contact: [CERT-RO / NCSC / Other]

DORA (if financial entity):
  → Initial notification: 4 hours (major ICT incident)
  → Intermediate report: 72 hours
  → Final report: 1 month
  → Regulator contact: [ECB / National authority]

PCI-DSS (if payment card data involved):
  → Notify acquiring bank immediately upon confirmed/suspected compromise
  → Acquiring bank contact: [Contact details]
```

---

## Section 8: Post-Incident Review Requirements

Define your organization's PIR process in the IRP:

```text
POST-INCIDENT REVIEW REQUIREMENTS

P1 incidents:  PIR mandatory, within 10 business days
P2 incidents:  PIR mandatory, within 15 business days
P3 incidents:  PIR recommended, within 30 days
P4 incidents:  Documented in case notes; PIR at team discretion

PIR participants: IR Lead, Forensics Analyst, affected system owners,
                  CISO (for P1), Legal (if regulatory implications)

PIR output: Written PIR report including:
  - Complete incident timeline
  - Root cause analysis (5 Whys)
  - What worked well
  - What could be improved
  - Action items (owner, deadline, tracking ID)
  - Updated playbooks (if required)
  - Metrics: MTTD, MTTR
```

---

## Section 9: Plan Maintenance and Testing

An untested plan is not a plan.
Document your testing schedule:

```text
IRP MAINTENANCE SCHEDULE

Review frequency:    Annually (or after any major incident)
Tabletop exercises:  Quarterly
Full exercise:       Annually
Owner:               CISO / IR Lead

Change triggers:
  - Major organizational change (acquisition, cloud migration)
  - New regulatory requirement
  - Major incident that exposed plan gaps
  - Key personnel changes (IR Lead, CISO, Legal Counsel)
```

---

## Completion Checklist

Before declaring your IRP complete, verify:

```text
□ Document metadata complete (version, owner, approval signature)
□ Scope clearly defined
□ Incident classification matrix matches organizational risk
□ IRT directory fully populated with names and contact details
□ Backup contacts defined for all critical roles
□ Out-of-band communication channel established and tested
□ Communication templates reviewed by Legal and PR
□ Decision authority matrix approved by senior management
□ Evidence handling procedures cross-referenced (Guide 03)
□ Regulatory notification requirements verified with Legal/DPO
□ PIR requirements defined
□ Tabletop exercise scheduled
□ Plan review date set
□ Plan distributed to all IRT members
□ Plan stored in location accessible when primary systems are down
```

---

## Next Steps

Once your IRP draft is complete:

1. **Review with Legal Counsel** — ensure regulatory notification sections are accurate
1. **Review with HR** — ensure insider threat sections align with HR policies
1. **Get executive sign-off** — the plan only has authority if leadership approves it
1. **Schedule a tabletop exercise** — test the plan within 30 days of creation
1. **Store offline** — keep a printed copy and an offline digital copy accessible without network access

See **Guide 04 (Intermediate): Full Incident Response Exercise** for running a tabletop test of this plan.
