# Solution: Drill 02 — Containment Decisions Under Pressure

## Task 1: Containment Decision Matrix

### Option A: Full Network Isolation of SAP/Fleet Server

| Dimension | Assessment |
|-----------|-----------|
| What is protected | Stops active exfiltration immediately. Prevents attacker from downloading additional stages or receiving commands. Prevents lateral movement from this server. |
| Operational impact | **HIGH** — SAP ERP goes offline (3,200 employees lose access). Fleet management loses GPS updates (3 trucks showing incorrect coordinates — safety risk). Customer portal may be affected. Estimate: significant business disruption for hours to days. |
| Evidence preserved | Memory contents preserved (server remains on). Active network connections terminated (but connection state is logged). EDR telemetry preserved. |
| Evidence destroyed | Active network session (forensic value of live traffic lost). Cannot observe what the attacker does next. |
| **Recommendation** | **CONDITIONAL YES** — Preferred option, but acquire memory image first (even 10 minutes matters). Coordinate with fleet management on truck safety before pulling the network cable. |

---

### Option B: Block External IP at Firewall Only

| Dimension | Assessment |
|-----------|-----------|
| What is protected | Terminates communication with the known C2 server (45.33.32.156). |
| Operational impact | **LOW** — SAP and fleet systems remain operational. Users unaffected. |
| Evidence preserved | Server remains live; full forensic access possible. Active monitoring can continue. |
| Evidence destroyed | Minimal — firewall blocks but logs the blocked attempts. |
| **Recommendation** | **CONDITIONAL YES — as an immediate parallel action, NOT as a substitute for isolation.** Blocking the IP is fast (2 minutes) and stops the active data flow. However, the malware is still running on the server and may have additional C2 channels or establish a new connection to a different IP. Do this NOW while preparing for full isolation. |

**Critical caveat:** The attacker almost certainly has fallback C2 infrastructure.
Blocking one IP is not sufficient containment.

---

### Option C: Kill Only the Active Outbound Connections

| Dimension | Assessment |
|-----------|-----------|
| What is protected | Terminates specific TCP sessions transferring data. |
| Operational impact | **VERY LOW** — Systems remain fully operational. |
| Evidence preserved | Memory and disk evidence fully intact. |
| Evidence destroyed | The killed connection; attacker may re-establish immediately. |
| **Recommendation** | **NO as a standalone action.** Killing connections without blocking the IP or isolating the host is ineffective — the malware will reconnect within seconds. This buys you nothing. Only useful if combined with IP blocking (Option B). |

---

### Option D: Do Nothing Until Memory Image Complete

| Dimension | Assessment |
|-----------|-----------|
| What is protected | Full forensic evidence preserved. Can observe attacker behavior during acquisition. |
| Operational impact | **NONE** immediately — but the attacker is actively exfiltrating and may escalate. |
| Evidence preserved | Maximum evidence preservation. Attacker TTPs observable. |
| Evidence destroyed | Nothing — but data continues leaving the organization during acquisition window. |
| **Recommendation** | **NO as a complete strategy — but the principle is correct.** A full memory acquisition takes 10–30 minutes depending on RAM size. The answer is not "do nothing" but "block the IP AND acquire memory simultaneously before full isolation." Do not sacrifice all evidence, but do not allow exfiltration to continue for 30 minutes either. |

---

### Option E: Shut Down the SAP/Fleet Server

| Dimension | Assessment |
|-----------|-----------|
| What is protected | Terminates all malware activity. No further damage possible. |
| Operational impact | **HIGH** — Same as Option A for business operations. Worse for forensics. |
| Evidence preserved | Disk evidence preserved. **Memory evidence DESTROYED.** The `IEX DownloadString` payload is fileless — it lives only in memory. Shutdown permanently destroys it. |
| Evidence destroyed | **ALL volatile evidence** — RAM, running processes, network connections, in-memory malware payload. |
| **Recommendation** | **NO.** Shutdown is the worst option forensically. The malware uses a fileless technique (PowerShell IEX); the payload exists only in RAM. Shutdown means you can never analyze what the malware was doing, where else it connected, or what it exfiltrated. Choose Option A (isolation) over Option E (shutdown) always — they have the same operational impact but Option A preserves evidence. |

---

## Task 2: Recommended Containment Sequence (14:30–15:30)

### T+0 (14:30) — IMMEDIATE (You + IT, 2 minutes)

1. **Block IP 45.33.32.156 at the perimeter firewall** (IT executes, you authorize)
   * Terminates active data exfiltration NOW
   * Fast, low-risk, reversible
   * Preserves all evidence

1. **Call fleet management operations:** "We have a security incident. Are any trucks in active transit where GPS loss would create a safety risk? We may need to briefly suspend GPS for servers." Get operational clearance.

1. **Notify CISO** (you): 30-second verbal — "We have confirmed malware on SAP server with active data exfiltration. I'm blocking the IP now and preparing for full isolation. Need your decision on operational shutdown in 10 minutes."

---

### T+5 (14:35) — START FORENSICS SIMULTANEOUSLY (You)

1. **Begin memory acquisition on SAP/Fleet server** using Magnet RAM Capture or WinPmem
   * Run acquisition to a pre-staged external drive or network share (NOT the same server)
   * This runs in background during next steps
   * Estimated time: 10–20 minutes depending on RAM

1. **Capture current network state** before anything changes:

   ```powershell
   netstat -anob > C:\IR\netstat_capture.txt
   Get-Process > C:\IR\processes.txt
   Get-ScheduledTask | Where-Object {$_.State -eq "Running"} > C:\IR\tasks.txt
```

---

### T+10 (14:40) — BACKUP SERVER (CISO authorizes, IT executes)

1. **Isolate the backup server immediately** — its connection to the same C2 IP means:
   * If attacker can reach/modify backups → recovery impossible
   * Backups must be preserved before attacker can encrypt or delete them
   * This is the highest-risk item discovered at 14:15

1. **Verify backup integrity:** Check if any backup jobs ran in the last 6 hours and whether the files are intact. If backups are compromised, escalate immediately.

---

### T+20 (14:50) — FULL ISOLATION (after memory acquisition begins or completes)

1. **Network-isolate the SAP/Fleet server** (physical network disconnection or VLAN isolation)
   * Coordinate with fleet operations (confirm truck safety first)
   * Document exact time of isolation
   * Preserve the isolated server for forensics — do NOT reboot or shutdown

1. **Inform IT Helpdesk** to communicate SAP outage to affected users: "Emergency maintenance in progress. ETA unknown."

---

### T+30 (15:00) — SCOPE EXPANSION (You + IT)

1. **Search for lateral movement** — check network logs for other systems connecting to 45.33.32.156
    * Any other host that communicated with this IP is potentially compromised
    * Run firewall log query: `grep 45.33.32.156 /var/log/firewall.log`

1. **Review sap-batch-user account** — which systems is this account valid on? Disable it across ALL systems immediately.

---

### T+45 (15:15) — LEGAL AND REGULATORY (CISO + Legal)

1. **Engage Legal counsel** — confirm GDPR breach notification obligations (see Task 3)
1. **Preserve the chain of custody** for all evidence collected — document who acquired what, when, with what tool, stored where

---

### T+60 (15:30) — STATUS BRIEF

1. **CISO briefing** — present initial scope assessment, containment status, evidence collected, regulatory timeline

---

## Task 3: GDPR and NIS2 Assessment

### Has a personal data breach occurred?

**YES — A personal data breach has occurred.** The evidence shows:

* 2.3 GB transferred to an external attacker-controlled IP over 6 hours
* SAP contains customer shipping data (names, addresses) and employee data (HR module)
* Even if the contents are not yet confirmed, the unauthorized access itself constitutes a breach under GDPR Art. 4(12)

The 72-hour clock **starts now** (approximately 14:30 CET Wednesday).

### Supervisory Authority

**Datatilsynet** (Norwegian Data Protection Authority) — Norway's DPA under the EEA GDPR equivalent.
Notification portal: https://www.datatilsynet.no

### GDPR Notification Deadline

* Discovery time: Wednesday 14:30 CET
* 72-hour deadline: **Saturday 14:30 CET**
* Notify Datatilsynet even if the full scope is not yet determined (use Art. 33(4) — phased notification)

### NIS2 Obligations

NordicLogistics is a **transport sector essential entity** under NIS2 (Directive 2022/2555, transposed into Norwegian law via the EEA Agreement).

| Timeline | Obligation |
|----------|-----------|
| **Within 24 hours** | Early warning to national NIS2 competent authority (in Norway: NSM — Nasjonal sikkerhetsmyndighet) |
| **Within 72 hours** | Incident notification with initial assessment (impact, nature of incident) |
| **Within 1 month** | Final incident report (full analysis, root cause, remediation) |

NIS2 notification is **separate from and in addition to** GDPR notification to Datatilsynet.

### Other Regulatory Obligations

* **Norwegian Personopplysningsloven** (Data Protection Act) — aligned with GDPR, same obligations
* **Potential customs/transport sector reporting** — if SAP contains any information about hazardous goods or customs declarations, consult sector-specific regulations (Toll- og avgiftsdirektoratet)
* **Employee data:** SAP HR module compromise means employee personal data was potentially exfiltrated — same GDPR obligations apply

---

## Task 4: Communication Drafts

### A. SBAR Brief to CISO (verbal, 2 minutes)

> "Here's the situation as of 14:30. **Situation:** We have confirmed malware on our SAP/Fleet server. Starting at approximately 07:30 this morning, the attacker transferred 2.3 gigabytes of data to an external IP in the Netherlands. The malware is PowerShell-based and runs under our sap-batch-user service account.
>
> **Background:** This likely started earlier than 07:30 — the 12 login failures this morning may be a symptom of the attacker's activity, not a coincidence.
>
> **Assessment:** This is a P1 incident. We have a confirmed data breach under GDPR — SAP contains customer shipping data and employee HR data. We have a 72-hour notification window to Datatilsynet starting now. The backup server also appears to be compromised, which threatens our recovery capability. The fleet management system sharing the same server adds operational complexity.
>
> **Recommendation:** I need your authorization to: (1) fully isolate the SAP/Fleet server — this will take SAP offline for an estimated 4–8 hours minimum; (2) immediately isolate the backup server; and (3) engage Legal to begin the GDPR notification process. I've already blocked the external IP at the firewall. What is your decision on the full server isolation?"

---

### B. Message to Affected Employees

```text
From: IT Security Team <security@nordiclogistics.no>
To: [12 affected employees]
Subject: SAP Access — Temporary Suspension

Dear colleague,

We are aware that you reported difficulty accessing SAP this morning.

We are currently conducting emergency maintenance on the SAP platform due to a
security issue that requires immediate attention. As a precautionary measure,
we have suspended access for a small number of accounts while we work to resolve
the issue and verify the integrity of the system.

Your account access will be restored as soon as our security team has completed
the necessary checks. We anticipate providing an update within [X hours].

If you have urgent work that cannot wait, please contact your manager to arrange
temporary alternative arrangements.

We apologize for the disruption and will communicate updates as they become available.

IT Security Team
NordicLogistics AS
```
