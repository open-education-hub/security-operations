# Solution: Drill 01 — Full Phishing Incident Response

## Part A: Initial Assessment

### Incident Classification

| Dimension | Value |
|-----------|-------|
| Type | BEC-adjacent phishing → credential theft → data exfiltration |
| Severity | **P1** — Finance Manager account actively compromised, payroll data accessed, attacker may still have access via rogue MFA device |
| Scope | 1 confirmed compromised account, 3 users targeted, 47 files exfiltrated from Finance |
| GDPR Required | **YES** — Payroll data = personal data (names + financial info). Likely exfiltrated (47 files). 72h clock running since 11:02 UTC. |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|-----|---------|
| Spearphishing Link | T1566.002 | Fake M365 login URL sent to 3 users |
| Credentials from Web Browsers / Phishing | T1056.003 | Credentials entered on attacker-controlled site |
| Email Collection — Email Forwarding/Hiding Rules | T1114.003 | Inbox rule created to delete security alerts |
| Multi-Factor Authentication — SIM Swapping/Device Registration | T1556.006 | New MFA device registered at 10:51 |
| Exfiltration Over Web Service — Exfiltration to Cloud Storage | T1567 | 47 files downloaded from SharePoint |
| Establish Accounts | T1136 | New MFA device = persistent access vector |

---

## Part B: Containment Plan

**Sequenced action list (with timing):**

| Priority | Time | Action | Owner | Why |
|----------|------|--------|-------|-----|
| 1 | 10:30 NOW | Export K. Martinez's M365 audit logs (last 24h) | L2 Analyst | Preserve before any account action changes context |
| 2 | 10:32 | Revoke ALL active M365 sessions for K. Martinez | IT + L2 | Attacker may be actively using the account |
| 3 | 10:33 | Remove the rogue MFA device from K. Martinez's account | IT | Password reset alone won't help while rogue MFA exists |
| 4 | 10:35 | Reset K. Martinez's M365 password | IT | Prevent new logins |
| 5 | 10:36 | Delete the inbox rule that deletes security alerts | IT/L2 | Attacker uses this to prevent detection of their own activity |
| 6 | 10:38 | Block the phishing domain (login.microsoftonline-secure.biz) at DNS and email gateway | IT/Network | Prevent the 2nd user who clicked from potentially entering credentials |
| 7 | 10:40 | Quarantine all copies of the original phishing email from all M365 mailboxes | IT | Prevent additional users from clicking |
| 8 | 10:45 | Begin investigation of what 47 files were downloaded from SharePoint | L2 | Required for GDPR scope assessment |
| 9 | 10:50 | Notify CISO and Legal of P1 incident | IR Manager | Trigger regulatory notification process |

---

## Part C: Eradication Plan

**Removal checklist:**

* ✓ Rogue MFA device removed
* ✓ Active sessions revoked
* ✓ Malicious inbox rule deleted
* ✓ Password reset with forced new enrollment
* ✓ Original phishing emails removed from all mailboxes
* ✓ Phishing domain blocked

**Verification:**

* Check M365 sign-in logs: no active sessions for K. Martinez from unexpected IPs
* Verify inbox rules: no forwarding or deletion rules remaining
* Verify only known MFA devices registered to K. Martinez
* Confirm user can log in from known device/IP with re-enrolled MFA

---

## Part D: Evidence Documentation

**Evidence list:**

| Evidence | Type | Priority |
|---------|------|----------|
| M365 audit logs for K. Martinez | Cloud logs | Critical |
| M365 sign-in logs (all users) | Cloud logs | High |
| Browser history from finance-ws-033 | Endpoint artifact | High |
| SharePoint access log (47 files) | Cloud logs | Critical (GDPR) |
| Email headers of phishing email | Email artifact | High |
| Screenshot of inbox rule | Screenshot | Medium |

**Chain of Custody Record (M365 Audit Logs):**

```text
CHAIN OF CUSTODY RECORD

Evidence ID:     EVID-INC2024-1201-001
Case ID:         INC-2024-1201
Description:     M365 Unified Audit Log export for K. Martinez
                 Time window: 2024-11-13 00:00 to 2024-11-14 12:00 UTC
                 Format: CSV, 4,892 records
Hash (SHA-256):  [Hash of exported CSV]
Collection Date: 2024-11-14 10:35 UTC
Collected By:    L2 Analyst (J. Garcia)
Collection Method: M365 Compliance Center → Audit → Custom export
Storage Location: Encrypted case storage /evidence/INC-2024-1201/

TRANSFERS:
  From: J. Garcia → To: IR Manager (Legal review)
  Date: 2024-11-14 11:00 UTC
  Hash Verified: YES
```

---

## Part E: Communication

### SBAR Brief for CISO

**S (Situation):** We have a confirmed P1 phishing incident.
Finance Manager K.
Martinez's M365 account was compromised via credential phishing at approximately 10:28 UTC today.

**B (Background):** The attacker used a convincing fake M365 login page.
After capturing credentials, they: (1) created an inbox rule to delete security alerts, (2) registered a new MFA device for persistent access, (3) downloaded 47 files from the Finance SharePoint folder.
The attacker had access for approximately 34 minutes before detection.

**A (Assessment):** The account is now contained — session revoked, MFA device removed, password reset.
The primary risk is the 47 downloaded files which include payroll data (personal data under GDPR).
This constitutes a personal data breach. 72-hour GDPR notification window began at ~11:02 UTC.

**R (Recommendation):** Engage Legal immediately for GDPR notification.
Continue forensic review of the 47 files to quantify scope.
Expand investigation to the 2 other users who clicked (one who did not enter credentials — confirm by reviewing browser logs).

---

### GDPR Notification First Paragraph (DPA)

```text
To: [National DPA — Supervisory Authority]
Subject: Personal Data Breach Notification — Article 33 GDPR
Date: 2024-11-14

AcmeCorp hereby notifies you of a personal data breach discovered on
2024-11-14 at approximately 11:30 UTC. An unauthorized party obtained
access to the Microsoft 365 account of a Finance Manager through a
phishing attack and subsequently downloaded 47 files from the company's
finance SharePoint document library. These files contain employee payroll
information including names, salaries, and bank account numbers for
approximately [X] employees. The breach period is estimated to be between
11:02 UTC and 11:30 UTC on 2024-11-14. This notification is submitted
within 72 hours of the organization becoming aware of the breach
[awareness time: 10:30 UTC, 2024-11-14].
```
