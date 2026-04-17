# Drill 02 Intermediate Solution: Ransomware Scenario Analysis

---

## Section 1 Solutions: Immediate Response

### Q1 — Top 5 Containment Actions

```text
Priority 1: IMMEDIATELY segment FILE-SRV01 from the network
  Reason: Active ransomware encryption is spreading. Every second the
  server remains connected, more files are encrypted. Stop the spread
  NOW — preserve what's left.

Priority 2: Block all outbound connections from the internal network
  at the perimeter firewall (or at least block C2 IPs)
  Reason: If double extortion exfiltration is still in progress,
  cutting outbound stops data loss. Also kills active C2 sessions.

Priority 3: Disable VPN access (kill all active VPN sessions, temporarily
  disable VPN service for all non-emergency users)
  Reason: Attacker VPN access at 01:02 UTC means the attacker has
  legitimate credentials. They may maintain access or re-enter.

Priority 4: Preserve evidence — do NOT power off systems yet
  Reason: Memory contains malware code, C2 keys, possibly attacker
  commands. Power off destroys this. Collect volatile evidence first.

Priority 5: Page CISO and activate the Incident Response Plan
  Reason: This is a P1 incident. CISO needs to authorize response
  decisions (ransom, breach notification, law enforcement). You cannot
  make these decisions alone.
```

### Q2 — VPN Authentication Significance

The attacker authenticated via VPN at **01:02 UTC** — 2 hours and 13 minutes before ransomware deployment at 03:15 UTC.

This tells us:

* The attacker had valid VPN credentials
* The 2-hour window was used for pre-deployment activity (staging, reconnaissance, persistence establishment)
* This was NOT an opportunistic attack — it required prior credential theft
* The attacker chose 03:15 UTC (Saturday night/Sunday morning) deliberately — lowest chance of detection

**Critical question:** Was this the FIRST time these credentials were used externally?
Check 7-30 days of VPN logs for this account.

### Q3 — The 57-Minute Pre-Deployment Window (02:18–03:15)

The beacon starting at 02:18 = attacker established C2 from FILE-SRV01 specifically.

In the 57 minutes before encryption:

* **Most likely activity:** Data staging and exfiltration (double extortion)
* Attacker likely ran directory enumeration to identify valuable files
* Created archive of customer data
* Exfiltrated via C2 or secondary channel (HTTPS to cloud)
* Planted ransomware executable on all discoverable shares
* Set scheduled tasks/GPO for mass deployment
* Deleted Volume Shadow Copies to prevent recovery
* Then triggered encryption

This is the **"Collect → Stage → Exfil → Deploy"** pattern seen in REvil, LockBit, and Conti ransomware operations.

### Q4 — Backup Server Critical Concern

**HIGHEST PRIORITY CONCERN:** Are the backups still intact?

Modern ransomware operators specifically target backup systems.
If `BACKUP-SRV01` is on the same network segment and accessible via the same compromised account, the attacker almost certainly:

1. Located and encrypted backup files, OR
1. Deleted backup sets, OR
1. Corrupted backup data

**You cannot assume backups are clean until verified.**

Before initiating recovery:

* Disconnect BACKUP-SRV01 from the network (if not already done)
* Verify backup integrity offline (check last good backup date)
* Check if backup files have the `.retailco_enc` extension

If backups are compromised: recovery options are severely limited.
This may increase pressure toward ransom payment (though payment must be authorized by CISO + Legal and screened against OFAC sanctions lists).

---

## Section 2 Solutions: Scoping

### Q6 — DC01 Scheduled Task Significance

A scheduled task created on the Domain Controller by the attacker means:

* The attacker has **Domain Admin or equivalent privileges**
* They can deploy to ALL domain-joined systems via GPO
* They likely already have persistence on the DC itself
* Full domain compromise — must assume ALL domain credentials are compromised

This is the highest possible scope for a Windows incident.
All accounts should be considered compromised until verified.

### Q7 — POS Terminal Status + Regulatory

If POS terminals (handling payment card data) are encrypted:

* **PCI-DSS**: Immediate notification to card brands (Visa, Mastercard, Amex) and acquiring bank required
* **PCI-DSS**: Forensic investigation by a PCI Forensic Investigator (PFI) required
* **State breach notification laws**: May apply depending on cardholder state of residence
* **Timeline**: PCI notification is immediate (24-48 hours)

---

## Section 3 Solutions: Initial Access

### Q8–Q10 — Initial Access Chain

**Expected findings:**

VPN log shows account `m.taylor` (Maria Taylor, Finance Manager) logged in from `185.234.219.44` at 01:02 UTC.

Authentication history shows this external IP first appeared **7 days earlier** — suggesting credentials were stolen 7 days before the ransomware deployment.
This is consistent with a broker-to-operator model (Initial Access Broker sells access to ransomware operator).

Email investigation shows a phishing email received by `m.taylor@retailco.com` 8 days earlier:

```text
Subject: "FW: Q3 Budget Review — Final Numbers"
From: cfo-alerts@retailco-finance.net (lookalike domain)
Attachment: Q3_Budget_Final.xlsm
SPF: FAIL, DKIM: FAIL
```

**Complete attack chain:**

```text
Day -8: Phishing email with .xlsm to Finance Manager
Day -8: Finance Manager opened attachment → Excel macro → credential theft
Day -7: Attacker acquired VPN credentials (from keylogger or credential theft)
Day -7 to Day -1: Possible credential selling period (IAB model)
Day 0 (01:02): VPN login with stolen credentials
Day 0 (02:18): Lateral movement to FILE-SRV01, C2 beacon
Day 0 (02:18-03:15): Reconnaissance, data staging, exfiltration
Day 0 (03:15): Ransomware deployment via GPO/scheduled tasks
```

---

## Section 4 Solutions: Double Extortion

### Q11 — Exfiltration Evidence

Expected findings: Large outbound transfer from FILE-SRV01 between 02:18 and 03:10 UTC:

* Approximately 47 GB transferred to external IP `94.130.88.15` over HTTPS
* This is the attacker's exfiltration server (different from C2 in some ransomware families)

### Q12 — Data Breach Scope

```text
Data exposed: ~500,000 customer records
Data types: Names, email addresses, purchase history, payment tokens

Regulatory frameworks:
  GDPR (if EU customers): 72-hour notification to supervisory authority
  UK GDPR (if UK customers): 72-hour notification to ICO
  CCPA (if California customers): Notification within 72 hours
  PCI-DSS: If full card data in the export — immediate card brand notification
  Sector-specific: Check state breach notification laws for customer states

Notification timeline (most urgent first):
  Day 0-1:  PCI notification (if card data)
  Day 0-3:  GDPR/ICO notification if high risk to individuals
  Day 1-30: Customer notification (timing per jurisdiction)
  Day 1:    Law enforcement (FBI, CISA, local LE)
```

---

## Section 5 Solution: Executive Briefing

```text
EXECUTIVE BRIEFING — RANSOMWARE INCIDENT
=========================================
Date: Saturday 23 November 2024, 04:00 UTC

• WHAT HAPPENED: Our systems were attacked by ransomware criminals who had
  secretly accessed our network for 8 days. In the early hours of this morning,
  they encrypted files across our servers and are demanding payment to restore
  access. Before encrypting, they copied approximately 47 GB of customer data.

• BUSINESS IMPACT: Our central file server and potentially other systems are
  encrypted. We cannot access customer records, operational files, or some
  systems. 500,000 customer records may have been stolen by the attackers.
  Retail operations may be impacted until systems are restored.

• CURRENT STATUS: The attack has been contained — we have disconnected
  affected systems and blocked attacker access. The ransomware is no longer
  spreading. Our incident response team and IT are working to assess the full
  damage. Backup integrity is being checked as our primary recovery path.

• WHAT WE'RE DOING: SOC is conducting a full forensic investigation to
  understand the scope. IT is assessing backup recovery options. Legal
  counsel is being engaged for breach notification obligations. We are
  prepared to notify law enforcement (FBI Cyber Division).

• DECISION REQUIRED: We need authorization from you to:
  (1) Engage an external Incident Response firm (recommend: [firm name])
  (2) Authorize legal counsel to prepare breach notifications
  (3) Decision on ransom payment — Legal and CISO recommend against, but
      it's a board-level decision given the potential customer impact.
  Please call the incident bridge at [number] at your earliest availability.
```
