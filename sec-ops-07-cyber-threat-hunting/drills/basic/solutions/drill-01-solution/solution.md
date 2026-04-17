# Drill 01 Solution: Generating Hunting Hypotheses from TTPs

**This is the instructor solution.
Do not distribute to students before submission.**

---

## Task 1: TTP Extraction and ATT&CK Mapping

| Phase | Observed Behavior | ATT&CK Technique ID | ATT&CK Technique Name | Tactic |
|-------|------------------|--------------------|-----------------------|--------|
| 1. Initial Access | VPN appliance exploitation | T1190 | Exploit Public-Facing Application | Initial Access |
| 1. Initial Access | Valid account usage after exploitation | T1078 | Valid Accounts | Initial Access / Persistence |
| 2. Persistence | Creating new local admin accounts with service-like names | T1136.001 | Create Account: Local Account | Persistence |
| 3. Discovery | Using net.exe, nltest.exe, whoami.exe, ipconfig.exe, arp.exe | T1082 | System Information Discovery | Discovery |
| 3. Discovery | nltest.exe for domain trust enumeration | T1482 | Domain Trust Discovery | Discovery |
| 3. Discovery | net.exe for user/group enumeration | T1087 | Account Discovery | Discovery |
| 4. Lateral Movement | RDP with new accounts | T1021.001 | Remote Desktop Protocol | Lateral Movement |
| 4. Lateral Movement | WinRM for remote management | T1021.006 | Windows Remote Management | Lateral Movement |
| 5. Collection | Staging files in SysWOW64\Tasks\ | T1074.001 | Local Data Staging | Collection |
| 6. Exfiltration | Rclone to cloud storage | T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| 6. Exfiltration | Rclone binary renamed | T1036.003 | Masquerading: Rename System Utilities | Defense Evasion |
| 7. Impact | LOCKBIT 3.0 ransomware deployment | T1486 | Data Encrypted for Impact | Impact |

**Scoring notes:**

* Full credit: All major techniques identified, correct IDs, correct tactics
* Partial credit: Minor errors in IDs or missing sub-technique specificity
* Accept T1078.001 (Default Accounts) or T1078.002 (Domain Accounts) as also correct

---

## Task 2: Sample Hypotheses

*(Any 4 of the following are acceptable.
Quality of hypothesis matters more than which 4 were chosen.)*

---

### Hypothesis #1: New Local Administrator Account Creation

**Threat Actor / Technique:**
VIPER-HEALTH using T1136.001 (Create Account: Local Account) for persistence

**Hypothesis Statement:**
"If VIPER-HEALTH has gained access to healthcare organization systems and is creating persistence via local admin accounts (T1136.001), I would expect to observe new local user account creation events (Windows Security Event ID 4720) followed quickly by local group membership additions (Event ID 4732 - adding to Administrators group), for accounts with service-account-like names (prefix 'svc-') that were not created through the normal IT provisioning process, on domain-joined workstations and servers over the past 30 days."

**Specific Indicators to Hunt For:**

* Event ID 4720: New user account created, account name matching `svc-*` or `monitor*` or `healthmon*`
* Event ID 4732: User added to local Administrators group, within 10 minutes of account creation
* Account created outside normal IT business hours (outside 08:00-18:00)
* Account creator is not in the IT admin accounts list (unexpected actor)

**Baseline:**

* Normal service accounts are created by IT admins during business hours
* Service account creation should be accompanied by change management tickets
* Legitimate service accounts are typically created centrally via AD, not as local accounts

**Data Sources:**

* Windows Security Event Logs (Event ID 4720, 4732): Direct evidence of account creation and group modification
* Active Directory changes log: To differentiate local vs. domain accounts
* IT change management system: To correlate with authorized changes

**Prioritization Justification:**
Persistence mechanisms discovered early can prevent ransomware deployment.
Account creation is a very specific indicator with few legitimate false positives.
High impact (indicates active intrusion) and high huntability (clear, specific events available in Security logs).

---

### Hypothesis #2: Discovery Using Native Windows Tools

**Threat Actor / Technique:**
VIPER-HEALTH using T1082 (System Information Discovery), T1482 (Domain Trust Discovery), T1087 (Account Discovery)

**Hypothesis Statement:**
"If VIPER-HEALTH is conducting internal reconnaissance using native Windows tools (nltest.exe, net.exe, whoami.exe, arp.exe), I would expect to observe these executables running in rapid succession from the same host and user account in Windows Security Event ID 4688 logs or Sysmon Event ID 1 logs, particularly: nltest.exe with /domain_trusts or /dclist arguments, net.exe with 'user', 'group', or 'localgroup' arguments, over the past 30 days."

**Specific Indicators to Hunt For:**

* `nltest.exe /domain_trusts` - enumerate domain trusts
* `nltest.exe /dclist:DOMAIN` - enumerate domain controllers
* `net.exe user /domain` - enumerate domain users
* `net.exe group "Domain Admins" /domain` - enumerate admin group
* Multiple of these tools running within 5 minutes from same user/host

**Baseline:**

* IT administrators may use these tools occasionally
* Monitor for frequency and context: an employee running 5 discovery commands in 3 minutes is not normal
* These tools are rarely used by regular end users

**Data Sources:**

* Windows Security Event ID 4688 with command-line auditing: Process execution with arguments
* Sysmon Event ID 1: More reliable, captures full command line

**Prioritization Justification:**
Discovery activity is an early indicator that can halt the attack before lateral movement or data staging.
False positive rate is low (employees rarely run domain enumeration commands).
Medium-to-high huntability (requires command-line logging to be enabled).

---

### Hypothesis #3: Rclone Exfiltration Tool (Renamed)

**Threat Actor / Technique:**
VIPER-HEALTH using T1567.002 (Exfiltration to Cloud Storage) with T1036.003 (Rename System Utilities)

**Hypothesis Statement:**
"If VIPER-HEALTH is using Rclone (renamed as `svchostmon.exe` or `systeminform.exe`) to exfiltrate data to cloud storage (T1567.002, T1036.003), I would expect to observe: (1) processes with these specific names executing from unexpected paths, (2) large outbound HTTPS traffic to cloud storage IPs (Google Drive: 142.250.x.x, Mega.nz: 31.216.x.x), (3) Rclone configuration files in %APPDATA%\Microsoft\, visible in Sysmon process logs and network connection logs over the past 30 days."

**Specific Indicators to Hunt For:**

* Process named `svchostmon.exe` or `systeminform.exe` in Sysmon EID 1
* Large data transfers (>100MB) to cloud storage provider IPs
* File creation events in `%APPDATA%\Microsoft\` with `.conf` extension (Rclone config)
* Rclone signatures: PE import hash, specific strings (can be done via Sysmon/EDR)

**Baseline:**

* `svchost.exe` processes run from `C:\Windows\System32\` only; anything else is suspicious
* Legitimate cloud storage sync tools would be known IT-approved applications
* Large outbound transfers during off-hours are suspicious

**Data Sources:**

* Sysmon Event ID 1: Process creation to detect renamed binary
* Firewall/proxy logs: Outbound HTTPS traffic to cloud storage IPs
* Sysmon Event ID 11: File creation to detect Rclone config files

**Prioritization Justification:**
Exfiltration detection is critical—successful exfiltration means patient data breach.
High impact.
Huntability is medium (requires proxy/firewall with destination IP/domain data, and process creation logs).

---

### Hypothesis #4: RDP Lateral Movement

**Threat Actor / Technique:**
VIPER-HEALTH using T1021.001 (Remote Desktop Protocol) for lateral movement

**Hypothesis Statement:**
"If VIPER-HEALTH is using RDP for lateral movement (T1021.001) with newly-created service-like accounts, I would expect to observe Windows Security Event ID 4624 (successful logon) with LogonType 10 (RemoteInteractive) for accounts matching the `svc-*` naming pattern, connecting from internal systems to other internal systems (particularly servers), during unusual hours, visible in Domain Controller and server security event logs over the past 30 days."

**Specific Indicators to Hunt For:**

* Event ID 4624, LogonType=10, AccountName matching `svc-*`
* Source and destination are internal IPs (lateral movement, not initial access)
* Multiple different destination hosts within a short timeframe (lateral spread)
* RDP activity at unusual hours (nights, weekends)

**Baseline:**

* IT admins use RDP, but from known admin workstations with known accounts
* Service accounts rarely use interactive logons (RDP is interactive)
* Regular employees don't typically RDP to servers

**Data Sources:**

* Windows Security Event Logs: Event ID 4624/4625 on servers and DCs
* Network logs: TCP port 3389 connection logs

---

## Task 3: Prioritization Matrix

| TTP | Huntability (1-3) | Impact (1-3) | Total | Rank |
|-----|-------------------|-------------|-------|------|
| T1136.001: Create Local Admin Account | 3 | 3 | 6 | 1 |
| T1482: Domain Trust Discovery (nltest) | 3 | 2 | 5 | 2 |
| T1567.002: Rclone Exfiltration | 2 | 3 | 5 | 2 |
| T1021.001: RDP Lateral Movement | 3 | 2 | 5 | 2 |
| T1074.001: Data Staging in SysWOW64 | 2 | 2 | 4 | 5 |
| T1190: VPN Exploitation | 1 | 3 | 4 | 5 |
| T1486: Ransomware Deployment | 1 | 3 | 4 | 5 |

**Scoring justifications:**

* **T1136.001 (Create Account):** Huntability=3 (clear, specific event IDs; few FPs); Impact=3 (confirms active intrusion)
* **T1482 (Domain Trust Discovery):** Huntability=3 (specific tool + arguments, rare legitimate use); Impact=2 (discovery only, not yet destructive)
* **T1567.002 (Rclone):** Huntability=2 (requires proxy logs AND process logs); Impact=3 (data breach = HIPAA violation)
* **T1021.001 (RDP):** Huntability=3 (clear event ID 4624, LogonType 10); Impact=2 (indicates spread but not yet data loss)
* **T1074.001 (Data Staging):** Huntability=2 (requires file monitoring, high FP potential from legitimate temp files); Impact=2 (staging is pre-exfiltration)
* **T1190 (VPN Exploitation):** Huntability=1 (requires VPN appliance logs, often not in SIEM); Impact=3 (initial compromise but may be past)
* **T1486 (Ransomware):** Huntability=1 (by the time ransomware deploys, it's too late to hunt); Impact=3 (catastrophic)

**Key insight:** Focus hunting on early kill chain TTPs with high huntability (account creation, discovery commands) to catch attackers before they reach exfiltration or ransomware deployment.

---

## Task 4: Data Source Assessment (Sample for Top 2 Hypotheses)

### Hypothesis 1: Account Creation

**Required Data Source: Windows Security Event Logs (Event ID 4720, 4732)**

* **Availability:** Check Splunk/SIEM for `source="WinEventLog:Security" EventCode IN (4720, 4732)`. If no results in 7 days, logs are not flowing.
* **Coverage:** Typically 95%+ coverage for domain-joined systems (DC logs are centralized). Local-only systems may not forward logs.
* **Retention:** 30-90 days depending on SIEM storage tier.
* **Quality Issues:** Event ID 4720 only fires if auditing for "Account Management" is enabled (not default on all systems). Check: `auditpol /get /category:"Account Management"`
* **Gap Impact:** If account management auditing is off on servers, we would miss account creation there. HIGH RISK.

**Required Data Source: IT Change Management System**

* **Availability:** ServiceNow, Jira, or similar. Requires integration or manual correlation.
* **Coverage:** Only covers changes submitted through formal process. Emergency/ad-hoc changes may not be logged.
* **Retention:** Typically 1+ year (compliance requirement)
* **Quality Issues:** Not all account creations are tracked in change management; informal IT practices create gaps
* **Gap Impact:** Without this, we cannot distinguish authorized vs. unauthorized account creation. Manual verification required.

---

## Grading Rubric

### Task 1: ATT&CK Mapping (20 points)

* 20 pts: All 7 phases mapped, accurate technique IDs, correct tactic classification
* 15 pts: 5-6 phases correct, minor errors in IDs or tactics
* 10 pts: 4 phases correct, several inaccuracies
* 5 pts: Partial mapping, major gaps or errors

### Task 2: Hypothesis Quality (40 points, 10 per hypothesis)

Per hypothesis:

* 10 pts: Complete, specific, testable; all template fields filled with meaningful content; indicators are concrete; baseline documented
* 7-9 pts: Mostly complete; hypothesis is clear but some elements are vague
* 4-6 pts: Hypothesis present but too vague or missing key elements
* 1-3 pts: Attempted but fundamentally unclear or untestable

### Task 3: Prioritization (20 points)

* 20 pts: Logical scoring, good justification, recognizes huntability tradeoffs
* 15 pts: Scoring is reasonable, justification present but thin
* 10 pts: Scoring done but logic not clearly explained
* 5 pts: Matrix completed but scoring appears arbitrary

### Task 4: Data Source Assessment (20 points)

* 20 pts: Specific, practical assessment; identifies how to verify availability; realistic gap impact analysis
* 15 pts: Good coverage but misses one or two important considerations
* 10 pts: Basic assessment; somewhat generic
* 5 pts: Superficial; little practical utility

---

*Instructor Note: This drill assesses foundational hunting skills.
Students who struggle with hypothesis formulation should revisit Guide 01 and Demo 01 before proceeding to intermediate drills.*
