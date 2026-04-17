# Solution: Drill 01 (Advanced) — Purple Team Exercise Planning

## Task 1: Scoping

**In scope:**

* Employee workstations (Windows endpoints) — primary attack surface
* Internal file servers and Active Directory — lateral movement targets
* The SOC's SIEM, EDR, and network monitoring tools (validate detection coverage)
* Email gateway (test phishing detection bypass)

**Out of scope:**

* OT/SCADA systems — safety-critical; an accidental disruption to industrial control systems could have physical consequences. Test separately with OT-specific red team.
* Customer-facing systems — risk of business impact; out of scope for internal exercise
* Production databases with real customer data — data protection law prohibits using live PII in exercises

**Assumed breach scenario:**
Red team starts with a low-privileged user account (T1 user: `jdoe@energy.local`) and access to a standard employee workstation.
This simulates post-phishing initial access and avoids needing to test email defences (which can be tested separately).

**Rules of engagement:**

* No actual data deletion or encryption (simulate ransomware up to the `vssadmin delete shadows` step; do not execute)
* No lateral movement to OT network
* Exercise duration: 3 days
* "Stop" signal: if any action risks business disruption, red team pauses and notifies exercise lead
* Deconfliction channel: secure chat between red team lead and SOC lead (open throughout)

**Notification protocol:**

* SOC management and CISO are informed
* L1/L2 SOC analysts are **NOT** told (blind test to validate real detection capability)
* L1 analysts are told within 2 hours of exercise end (debrief)
* Exercise coordinator embedded with blue team observes and records detection outcomes

---

## Task 2: Detection Hypotheses (5 of 9)

**Technique 1: Spearphishing Attachment (T1566.001)**

```text
Technique:   Spearphishing Attachment (T1566.001)
Hypothesis:  There is evidence of phishing delivery if the email gateway logs show
             an inbound email with a macro-enabled attachment (.docm, .xlsm) from
             an external sender to employee mailboxes.
Log Source:  Email gateway (Proofpoint/Defender for Office 365), Exchange mail trace
Query Logic: eventSource = email-gateway
             AND attachment.extension IN ('.docm', '.xlsm', '.xls', '.doc')
             AND sender.domain NOT IN allowlist
Expected:    Email blocked/quarantined OR delivery record + attachment hash
```

**Technique 3: PowerShell (T1059.001)**

```text
Technique:   PowerShell (T1059.001)
Hypothesis:  There is evidence of malicious PowerShell use if Event ID 4104 logs
             show PowerShell ScriptBlock logging of obfuscated or encoded commands
             executed by non-admin users, especially from a suspicious parent process.
Log Source:  Windows Event Log (Microsoft-Windows-PowerShell/Operational), EDR
Query Logic: EventID = 4104
             AND scriptBlockText CONTAINS ("-enc" OR "IEX" OR "Invoke-Expression"
               OR "System.Net.WebClient" OR "DownloadString")
             AND UserName NOT IN admin-accounts
Expected:    Alert with script content; Fileless malware typically visible here
```

**Technique 4: Scheduled Task (T1053.005)**

```text
Technique:   Scheduled Task (T1053.005)
Hypothesis:  There is evidence of scheduled task persistence if Windows Event ID 4698
             shows a new task created by a non-standard user, especially one with
             suspicious command-line content or run as SYSTEM.
Log Source:  Windows Security Event Log (Event ID 4698, 4702)
Query Logic: EventID IN (4698, 4702)
             AND SubjectUserName NOT IN ("SYSTEM", known-admin-accounts)
             AND TaskContent CONTAINS ("-enc" OR "http" OR ".exe" OR "powershell")
Expected:    Alert on task name, creator identity, and command line
```

**Technique 5: OS Credential Dumping — LSASS (T1003.001)**

```text
Technique:   LSASS Credential Dumping (T1003.001)
Hypothesis:  There is evidence of credential dumping if EDR telemetry shows a process
             opening a memory handle to lsass.exe with PROCESS_VM_READ access, or if
             Sysmon Event ID 10 logs a non-system process accessing lsass.
Log Source:  EDR (Defender for Endpoint), Sysmon Event ID 10
Query Logic: Sysmon EventID = 10
             AND TargetImage = "C:\\Windows\\System32\\lsass.exe"
             AND SourceImage NOT IN ("C:\\Windows\\System32\\svchost.exe",
               "C:\\Windows\\System32\\werfault.exe")
Expected:    EDR alert: "Credential access - lsass memory read" OR Sysmon alert
```

**Technique 8: Exfiltration Over C2 (T1041)**

```text
Technique:   Exfiltration Over C2 Channel (T1041)
Hypothesis:  There is evidence of data exfiltration if network proxy/firewall logs show
             large volumes of HTTPS traffic (> 10 MB) from an internal host to an IP
             that is not in the corporate whitelist, especially if the IP matches a
             known C2 IOC (192.0.2.88).
Log Source:  Next-gen firewall / proxy logs, NetFlow
Query Logic: destinationIP = 192.0.2.88
             OR (totalBytesOut > 10000000 AND destinationIP NOT IN known-cloud-IPs
               AND protocol = HTTPS)
Expected:    Alert with source host, destination IP, bytes transferred, duration
```

---

## Task 3: Tabletop Simulation Results

**Action 1: Spearphishing — mshta.exe from winword.exe**

| Detection Question | Answer |
|-------------------|--------|
| Does your email gateway scan `.docm` for macros? | Ideally yes (Defender for Office 365 detonates attachments in a sandbox) |
| Does EDR alert on `mshta.exe` spawning from `winword.exe`? | Yes — most EDR platforms flag Office spawning `mshta.exe` as high-confidence malware |
| SIEM rule for this process chain? | Should exist: `winword.exe` → `mshta.exe` or `cmd.exe` |
| **Detection outcome** | **Detected** — EDR high-confidence alert + email gateway sandbox |

**Action 2: Scheduled Task `MicrosoftUpdateTask`**

| Detection Question | Answer |
|-------------------|--------|
| Collecting Event ID 4698? | Must verify — Windows audit policy must have "Object Access: Audit Other Object Access Events" enabled |
| Alerting on new tasks from non-standard user? | Depends on rule implementation |
| **Detection outcome** | **Partial** — detected only if Event 4698 is collected AND there is a rule for it |

**Action 3: Mimikatz / LSASS Dump**

| Detection Question | Answer |
|-------------------|--------|
| EDR with credential theft protection? | Defender for Endpoint has Attack Surface Reduction (ASR) rules that block LSASS memory access |
| Alert on non-system process accessing lsass? | Yes — ASR rule or Sysmon rule |
| Windows Credential Guard enabled? | Rarely enabled by default — must check GPO |
| **Detection outcome** | **Detected** if ASR rules enabled; **Missed** if EDR is in audit-only mode |

**Action 4: Net view / Net share enumeration**

| Detection Question | Answer |
|-------------------|--------|
| Alert on network share enumeration? | Command-line logging (Event 4688 with process args) + Sysmon would capture this |
| False positive likelihood? | HIGH — `net view` is used legitimately by users and helpdesk daily |
| **Detection outcome** | **Missed** in most environments due to high FPR — requires UEBA (user behaviour baseline) to distinguish |

**Action 5: Exfil to known C2 IP 192.0.2.88**

| Detection Question | Answer |
|-------------------|--------|
| Is this IP in SIEM blocklist? | Depends on threat intelligence feed integration |
| Proxy/firewall logging HTTPS CONNECT? | Should be — SSL inspection or at minimum connection metadata |
| **Detection outcome** | **Detected** if threat intel feed includes this IOC; **Missed** if not |

---

## Task 4: Gap Analysis

| Technique | Detected? | Gap | Priority | Remediation |
|-----------|-----------|-----|----------|-------------|
| Spearphishing Attachment | Yes | None significant | Low | Maintain sandbox policy |
| Malicious Macro Execution | Yes | None — process chain alert worked | Low | — |
| PowerShell | Partial | ScriptBlock logging not enabled | Medium | Enable via GPO: PowerShell ScriptBlock Logging |
| Scheduled Task | Partial | Event 4698 not consistently collected | HIGH | Verify audit policy on all endpoints; SIEM rule |
| LSASS Dump | Partial | ASR in audit-only mode | CRITICAL | Enable ASR rule: Block credential stealing from lsass.exe |
| Network Share Discovery | Missed | High FPR makes rule impractical without UEBA | Medium | Implement UEBA baseline; alert on anomalous `net` commands |
| Lateral Tool Transfer | Not tested | No coverage of SMB file transfer alerts | HIGH | Sysmon file creation events on servers |
| Exfil over C2 | Partial | C2 IP not in IOC feed | HIGH | Integrate MISP feed; auto-import IOCs from ISAC |
| Inhibit Recovery | Not tested | No coverage | CRITICAL | Alert on `vssadmin delete shadows`, `wbadmin delete` commands |

---

## Task 5: Executive Summary for CISO

**Purple Team Exercise: Energy SOC vs.
Sandstorm TTPs — Executive Summary**

Our first purple team exercise tested the SOC's ability to detect 9 ATT&CK techniques used by the Sandstorm threat actor.
Of 9 techniques tested:

* **3 fully detected** (phishing delivery, macro execution, LSASS with ASR)
* **4 partially detected** (PowerShell, scheduled task, network share, C2 exfil)
* **2 not covered** (lateral tool transfer, inhibit recovery)

**Top 3 Critical Gaps:**

1. **Ransomware inhibit recovery** (no detection for `vssadmin delete shadows`) — a ransomware attack would succeed before detection
1. **ASR rules in audit-only mode** — credential dumping would succeed; ASR must be switched to enforcement mode
1. **Threat intelligence IOC not in SIEM** — known C2 IP from ISAC was not imported; should have been automatic

**Recommended priorities (next 60 days):**

1. Switch ASR rules from audit to enforce mode (1 day, no cost)
1. Add detection rule for VSS deletion commands (2 days)
1. Automate IOC import from ISAC into SIEM (2 weeks, minimal cost)

**Proposed next exercise**: In 6 months, after remediations are implemented.
Test lateral movement and OT network boundary specifically.
