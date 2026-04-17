# Drill 01 (Intermediate) — Full Phishing Incident Response

**Estimated time:** 75 minutes

**Difficulty:** Intermediate

**Prerequisites:** Completion of basic drills; familiarity with MITRE ATT&CK and GDPR basics

---

## Scenario

You are the Tier 2 analyst at **AcmeCorp**, a mid-size professional services firm (800 employees).
At 10:30 UTC on a Thursday, three employees report receiving a suspicious email from "IT Support" asking them to click a link to update their Microsoft 365 password.

Your initial investigation reveals:

* Two of the three users clicked the link
* One user — **K. Martinez, Finance Manager** — entered her credentials on the fake page

K.
Martinez has access to the company's financial reporting system and can view payroll data for all 800 employees.

---

## Available Evidence

### Email Details

```text
From: it-support@acmecorp-helpdesk.biz
Subject: Urgent: Your M365 account requires verification
Received: 2024-11-14 10:15 UTC
Recipients: 3 users (2 clicked, 1 did not)
Phishing URL: https://login.microsoftonline-secure.biz/sso/auth
User-agent on click: Chrome/Windows (K. Martinez workstation)
```

### EDR Alerts (finance-ws-033 — K. Martinez's workstation)

```text
10:28 — Credential entered on external site (browser history logged by EDR)
10:44 — New email inbox rule created via MAPI:
         Rule name: "AutoFilter"
         Action: Delete all emails containing "password", "account", "security alert"
10:51 — M365 audit log: new device registered for MFA
         Device: "iPhone" — not matching any corporate device inventory
11:02 — SharePoint audit log: 47 files downloaded from "Finance Reports" folder
         File types: .xlsx, .pdf (financial statements, payroll reports)
```

### Threat Intelligence

```text
Domain: login.microsoftonline-secure.biz
  Registered: 2024-11-10 (4 days before attack)
  VirusTotal: 22/80 vendors flag as phishing
  WHOIS: Privacy protected, registrar: NameSilo (used frequently by threat actors)
  Infrastructure: Hosted on bulletproof hosting in Russia
```

---

## Tasks

### Part A: Initial Assessment (20 minutes)

1. **Classify the incident:** Type, severity (P1–P5), and scope
1. **Identify all affected systems and users:** Who is affected, and what data do they have access to?
1. **Map to MITRE ATT&CK:** Identify a minimum of 4 techniques used in this attack (use ATT&CK IDs)
1. **GDPR assessment:** AcmeCorp is a UK company (GDPR equivalent via UK GDPR). Payroll data was accessed. Does a data breach notification obligation exist? Justify.

---

### Part B: Containment Plan (20 minutes)

Write a **prioritized containment action list** in sequence.
For each action:

* Specify what you do
* Specify who executes it (you / IT / M365 admin / Legal)
* Specify timing (immediate, within 10 min, within 1 hour)

Your plan must specifically address:

* K. Martinez's active M365 sessions
* The inbox rule created at 10:44
* The new MFA device registered at 10:51
* The SharePoint download at 11:02
* The other two users who clicked (one entered credentials, one didn't — how does this change your plan?)

---

### Part C: Eradication (10 minutes)

1. What must be removed or reset to fully eradicate the attacker's access?
1. How do you verify eradication is complete? (What does "done" look like?)
1. What is the risk of premature eradication (acting too quickly)?

---

### Part D: Evidence Documentation (10 minutes)

1. List all evidence to preserve in this incident, with:
   * Evidence type (log, file, screenshot, etc.)
   * Source system
   * Retention priority (critical / important / useful)
1. Create one complete **chain of custody record** for the M365 audit log export (the most legally important piece of evidence in this case)

---

### Part E: Communication (15 minutes)

1. Write the **SBAR brief** for the CISO (2-minute verbal brief — write out what you would say)
1. Write the **first paragraph** of the ICO breach notification (UK GDPR — the UK supervisory authority is the ICO)
1. Write a **draft message to K. Martinez** explaining why her account has been suspended and what she should do

---

## Hints

* The inbox rule created at 10:44 is a persistence/defense evasion technique — what is the attacker hiding?
* The new MFA device registered at 10:51 means that **a password reset alone is not sufficient** — the attacker will retain access even after you reset the password
* SharePoint downloading 47 files at 11:02 likely represents data exfiltration — payroll data for 800 employees is classified as "sensitive personal data" under UK GDPR
* K. Martinez's account may be **actively used by the attacker right now** as you investigate — this affects your urgency
* The other user who clicked but did not enter credentials: check whether they have any active sessions from unusual locations
* UK GDPR requires notification to the ICO within 72 hours of becoming aware of a breach
