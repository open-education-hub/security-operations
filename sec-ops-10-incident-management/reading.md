# Session 10: Incident Response and Management

**Estimated reading time:** ~2 hours

**Level:** Intermediate to Advanced

**Prerequisites:** Sessions 01–09

---

## Table of Contents

1. [What is Incident Response?](#1-what-is-incident-response)
1. [IR Frameworks: NIST SP 800-61 and SANS PICERL](#2-ir-frameworks)
1. [Phase 1: Preparation](#3-phase-1-preparation)
1. [Phase 2: Detection and Analysis](#4-phase-2-detection-and-analysis)
1. [Phase 3: Containment](#5-phase-3-containment)
1. [Phase 4: Eradication](#6-phase-4-eradication)
1. [Phase 5: Recovery](#7-phase-5-recovery)
1. [Phase 6: Post-Incident Activity](#8-phase-6-post-incident-activity)
1. [Communication During Incidents](#9-communication-during-incidents)
1. [Regulatory Notification Requirements](#10-regulatory-notification-requirements)
1. [Digital Forensics Fundamentals](#11-digital-forensics-fundamentals)
1. [Evidence Handling and Chain of Custody](#12-evidence-handling-and-chain-of-custody)
1. [IR Plan and Playbook Development](#13-ir-plan-and-playbook-development)
1. [Tabletop Exercises](#14-tabletop-exercises)
1. [References](#15-references)

---

## 1. What is Incident Response?

An **incident** is any event that actually or potentially jeopardizes the confidentiality, integrity, or availability of information or information systems and constitutes a violation of security policies.
Incident response (IR) is the organized approach to managing the aftermath of a security breach or cyberattack.

The goals of incident response are:

1. **Limit damage** (minimize scope and impact)
1. **Restore operations** (return to normal as quickly as safely possible)
1. **Understand what happened** (root cause analysis)
1. **Prevent recurrence** (fix what allowed it)
1. **Meet legal obligations** (evidence preservation, regulatory notification)

### Incident vs. Event vs. Alert

| Term | Definition | Example |
|------|-----------|---------|
| **Event** | Any observable occurrence in a system | User login, file access, network packet |
| **Alert** | An event flagged as potentially significant | Firewall blocked suspicious connection |
| **Incident** | A confirmed violation or threat | Ransomware executing on a workstation |

Not every alert is an incident.
The triage process (Session 09) determines whether an alert becomes an incident.

### Types of Incidents

```text
INCIDENT TAXONOMY
├── Malware
│   ├── Ransomware
│   ├── Trojan/RAT
│   ├── Wiper
│   └── Cryptominer
├── Unauthorized Access
│   ├── Compromised credentials
│   ├── Privilege escalation
│   └── Unauthorized remote access
├── Data Breach
│   ├── Exfiltration
│   └── Accidental exposure
├── Denial of Service
│   ├── DDoS (volumetric)
│   └── Application layer
├── Social Engineering
│   ├── Phishing
│   ├── BEC (Business Email Compromise)
│   └── Vishing
├── Insider Threat
│   ├── Malicious
│   └── Accidental
└── Web Application Attack
    ├── SQL injection
    ├── XSS
    └── API abuse
```

---

## 2. IR Frameworks

### NIST SP 800-61 Rev 2

The NIST Computer Security Incident Handling Guide defines a four-phase cycle:

```text
        ┌─────────────────────────────────────────┐
        │                                         │
        ▼                                         │
  [1. Preparation]                          [Learn]
   Plan, train, tool                              │
        │                                         │
        ▼                                         │
  [2. Detection & Analysis]            [4. Post-Incident]
   Detect, triage, classify                       │
        │                                         │
        ▼                                         │
  [3. Containment, Eradication, Recovery]─────────┘
   Stop the bleeding, clean up, restore
```

### SANS PICERL

The SANS framework expands the cycle into six phases:

| Phase | Letter | Focus |
|-------|--------|-------|
| **P**reparation | P | Build the capability before incidents happen |
| **I**dentification | I | Detect and confirm the incident |
| **C**ontainment | C | Limit the blast radius |
| **E**radication | E | Remove the threat from the environment |
| **R**ecovery | R | Restore normal operations |
| **L**essons Learned | L | Improve for next time |

The key difference: SANS PICERL is more detailed, separating "Containment" from "Eradication" explicitly.
NIST groups these.

### Comparing the Two

Both frameworks agree on the fundamentals.
In practice, most organizations follow NIST 800-61 for structure but use the SANS terminology for day-to-day communication.
This course uses NIST 800-61 as the primary reference.

---

## 3. Phase 1: Preparation

Preparation is the most important — and most neglected — phase.
Organizations that invest in preparation handle incidents dramatically better than those that don't.

### Key Preparation Activities

#### 1. Develop an IR Plan

An IR plan documents:

* Roles and responsibilities (who does what)
* Communication procedures (who to notify, when, how)
* Escalation thresholds (what triggers P1)
* Tools and resources available
* Legal and regulatory requirements

**IR Plan components:**

```text
IR Plan Table of Contents:

1. Purpose and Scope

2. Incident Classification Matrix
3. Roles and Responsibilities
   - IR Manager
   - SOC Analyst
   - CISO
   - Legal Counsel
   - PR/Communications
   - Business Continuity
4. Communication Procedures
   - Internal notification tree
   - External notification requirements
5. Response Procedures by Incident Type
   (Playbooks for: phishing, malware, DDoS, data breach, insider threat)
6. Evidence Handling Procedures
7. Post-Incident Review Process
8. Contact Directory
```

#### 2. Establish the CSIRT

A **Computer Security Incident Response Team (CSIRT)** is the team responsible for handling incidents.
It may be:

* Internal (SOC team escalated)
* Dedicated IR team (large organizations)
* Outsourced (IR retainer with a DFIR firm)

Core CSIRT roles:

* **IR Manager** — coordinates the response, owns communications
* **Forensic Analyst** — collects and analyzes evidence
* **Malware Analyst** — reverse engineers malicious code
* **Threat Intelligence Analyst** — contextualizes the attacker
* **Legal Counsel** — advises on regulatory requirements and evidence
* **PR/Communications** — manages external messaging

#### 3. Build and Maintain Toolkits

Every CSIRT needs a readily available toolkit:

**Evidence Collection Toolkit:**

* FTK Imager (disk imaging)
* Volatility / Avast CaptureBAK (memory acquisition)
* Network capture tools (Wireshark, tcpdump)
* USB write blocker (hardware)
* Hashing tools (sha256sum)
* Pre-built collection scripts

**Analysis Toolkit:**

* Volatility 3 (memory analysis)
* Autopsy / Sleuth Kit (disk forensics)
* FLARE VM (malware analysis)
* Ghidra / IDA (reverse engineering)
* Wireshark / NetworkMiner (PCAP analysis)
* MISP / OpenCTI (threat intelligence)

#### 4. Conduct Tabletop Exercises

Tabletop exercises test the IR plan by walking through simulated scenarios.
They expose:

* Gaps in the plan
* Unclear responsibilities
* Missing tools or access
* Communication breakdowns
* Incorrect assumptions about system recovery time

**Run tabletop exercises at minimum:**

* Annually (all scenarios)
* After any major infrastructure change
* After a real incident (to test "lessons learned" were implemented)

---

## 4. Phase 2: Detection and Analysis

### Detection Sources

Incidents are detected through many channels:

| Source | Example |
|--------|---------|
| SIEM alerts | Correlation rule fires on anomalous login |
| EDR alerts | Ransomware process terminated by behavior engine |
| IDS/IPS | Exploit attempt blocked by signature |
| User report | Employee reports suspicious email |
| External notification | FBI/CISA notifies of compromise |
| Threat intel | Your IP appears in botnet C2 traffic |
| System logs | Error logs reveal exploitation |
| Bug bounty | Researcher reports vulnerability |

### Initial Analysis Steps

When an incident is suspected:

1. **Preserve the state** — do not power off systems (volatile evidence loss)
1. **Document everything** — time-stamp every observation
1. **Establish severity** — use the incident classification matrix
1. **Determine scope** — how many systems? What data is at risk?
1. **Notify stakeholders** — per the communication procedure

### Incident Severity Classification

| Severity | Criteria | Example |
|----------|---------|---------|
| **Critical (P1)** | Active breach, data loss likely, critical systems affected, ransomware spreading | Ransomware on production network |
| **High (P2)** | Confirmed compromise, single system, limited data exposure | Credential theft on workstation |
| **Medium (P3)** | Suspected compromise, no confirmed data access, policy violation | Phishing click, no credential entry |
| **Low (P4)** | No compromise, informational, audit/compliance | Port scan from external |

### Initial Triage Questions

For any suspected incident, answer:

1. What was the **first indicator**? (When did it start?)
1. What **systems** are involved? (Hostnames, IPs)
1. What **data** might be at risk? (Data classification, location)
1. Is the **attacker still active**? (Ongoing vs historical)
1. What **TTPs** are being used? (MITRE ATT&CK mapping)

---

## 5. Phase 3: Containment

Containment is about **stopping the bleeding** — preventing the incident from getting worse while preserving evidence for investigation.

### Short-Term vs Long-Term Containment

| Type | Timing | Goal | Example |
|------|--------|------|---------|
| **Short-term** | Immediately during incident | Stop immediate threat, buy time | Network isolation, account disable |
| **Long-term** | After immediate threat controlled | Stable state while investigation continues | Isolated clean environment, monitoring in place |

### Containment Strategies

#### Network-Level

```console
# Block attacker IP at firewall
iptables -A INPUT -s 185.220.101.5 -j DROP
iptables -A OUTPUT -d 185.220.101.5 -j DROP

# Isolate host in VLAN (firewall rule or switch ACL)
# (depends on network equipment)
```

#### Endpoint-Level (EDR)
Most EDR platforms support "network isolation" mode:

* Host can still communicate with EDR server (for remote investigation)
* All other network traffic blocked
* Preserves system state for forensic analysis

#### Account-Level

```powershell
# Disable compromised account in Active Directory
Disable-ADAccount -Identity "m.compromised"

# Force password reset and revoke active sessions
Set-ADAccountPassword -Identity "m.compromised" -Reset -NewPassword (ConvertTo-SecureString "Temp@123!" -AsPlainText -Force)

# Revoke all active sessions (Azure AD)
Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.com"
```

### The Isolation Decision

**Isolate immediately vs.
Monitor first:**

| Isolate Immediately | Monitor Before Isolating |
|--------------------|--------------------------|
| Ransomware spreading | APT — isolating alerts attacker, loses the trail |
| Critical data actively exfiltrating | Intelligence gathering opportunity |
| Destructive attack in progress | Attribution investigation needed |

The decision depends on: evidence preservation needs, business impact of isolation, and whether the attacker is already aware they're detected.

### Preserving Evidence Before Containment

Before isolating or powering off a system:

1. **Network capture** — start `tcpdump` to capture outbound traffic
1. **Memory dump** — acquire RAM image (Volatility, DumpIt, winpmem)
1. **Log collection** — export current logs from SIEM for the time window
1. **Screenshot** — document running processes and network connections
1. **Hash all known-bad files** — before they can be modified

```bash
# Quick volatile evidence collection script
# Run BEFORE isolation or shutdown

# Memory acquisition
winpmem_mini_x64.exe -o memory.raw

# Network connections
netstat -anob > network_connections.txt
arp -a > arp_table.txt

# Running processes
tasklist /v > processes.txt
wmic process get Name,ProcessId,ParentProcessId,CommandLine /format:list > processes_detail.txt

# Auto-start locations
autoruns.exe /accepteula /nobanner -a * > autoruns.txt

# Hash all running executables
Get-WmiObject Win32_Process | ForEach-Object {
  if ($_.ExecutablePath) {
    Get-FileHash $_.ExecutablePath | Select-Object Hash,Path
  }
} > running_hashes.txt
```

---

## 6. Phase 4: Eradication

After containment, eradication focuses on **removing the threat** from the environment completely.

### Eradication Steps

1. **Identify all attacker footholds** — every backdoor, persistence mechanism, compromised account
1. **Remove malware** — quarantine or delete malicious files
1. **Remove persistence mechanisms** — scheduled tasks, registry run keys, services, startup scripts
1. **Close vulnerabilities** — patch the exploited vulnerability, fix the misconfiguration
1. **Verify complete removal** — scan the system and check for any remnants

### Eradication Verification

A common mistake is incomplete eradication.
Attackers often establish multiple persistence mechanisms.
After removing the obvious backdoor, verify:

```text
ERADICATION CHECKLIST:
□ All known malware files removed or quarantined
□ AV full system scan completed — clean
□ Scheduled tasks reviewed (schtasks /query)
□ Services reviewed (sc query type= all)
□ Registry Run/RunOnce keys reviewed
□ Startup folders reviewed
□ WMI subscriptions reviewed
□ Browser extensions reviewed (for credential theft)
□ Backdoor user accounts removed
□ SSH authorized_keys reviewed (Linux)
□ Crontabs reviewed (Linux)
□ All flagged accounts have password reset
□ All flagged systems patched for exploited vulnerability
```

### When to Rebuild vs. Clean

| Rebuild (Reimage) | Clean (Remediate) |
|-------------------|-------------------|
| Ransomware encrypted system | Known malware, well-understood |
| Rootkit detected | Adware/PUP |
| Unknown malware, unclear scope | Phishing click with no payload |
| Domain controller compromised | Standard workstation, no lateral movement |
| UEFI/firmware compromise | Server with confirmed single infection |

**Default position for modern IR:** When in doubt, reimage.
Storage is cheap; uncertainty is expensive.

---

## 7. Phase 5: Recovery

Recovery brings systems back to normal operations in a controlled, verified manner.

### Recovery Principles

1. **Verify before restoring** — confirm the clean state of systems before reconnecting them
1. **Staged reconnection** — bring systems back gradually, monitoring closely
1. **Prioritize by business criticality** — bring critical systems back first
1. **Validate with users** — confirm systems function correctly before declaring resolved

### Recovery Steps

```text
RECOVERY SEQUENCE:

1. Verify clean state (AV scan, integrity check)

2. Restore from known-good backup (if reimaged)
   OR confirm clean state of remediated system
3. Reconnect to network in monitored segment first
4. Test functionality (critical business processes)
5. Monitor closely for 48-72 hours (watch for re-infection)
6. If clean: reconnect to production network
7. Remove temporary monitoring infrastructure
8. Declare incident closed
```

### Backup Integrity Verification

Before restoring from backup:

* Verify backup was created before the compromise (check backup timestamps vs first indicator of compromise)
* Verify backup integrity (hash check if available)
* Test restore in isolated environment before production

---

## 8. Phase 6: Post-Incident Activity

The post-incident review (PIR) or **lessons learned** meeting is the most underperformed phase.

### Post-Incident Review Objectives

1. Document a complete timeline of the incident
1. Identify root cause
1. Identify detection failures (Why wasn't this caught earlier?)
1. Identify response failures (What slowed us down?)
1. Generate action items to prevent recurrence

### PIR Report Structure

```text
POST-INCIDENT REVIEW REPORT

Incident ID: INC-2024-1147
Date of Report: 2024-11-21
Incident Date: 2024-11-14 to 2024-11-16

Executive Summary (1 paragraph)

Timeline of Events
  [Complete chronological sequence from attack start to recovery]

Root Cause Analysis
  Initial Access: [How did the attacker get in?]
  Persistence: [How did they maintain access?]
  Lateral Movement: [How did they spread?]
  Impact: [What was accessed/damaged?]

Detection Analysis
  Time to Detect: 6h 22m
  Detection Source: EDR behavioral alert
  Detection Gap: Why wasn't initial access detected?
    → Missing log source: Perimeter web proxy logs not in SIEM

Response Analysis
  Time to Contain: 2h 14m from detection
  What worked well:
    → Analyst followed playbook, isolation was fast
  What didn't work:
    → Memory dump failed due to wrong tool version
    → IR manager not reachable for first 45 min (no on-call procedure)

Action Items
  #1: Add web proxy logs to SIEM [Owner: SIEM team, Due: Nov 30]
  #2: Update memory acquisition tools on IR jump kit [Owner: Forensics, Due: Nov 22]
  #3: Implement IR manager on-call rotation [Owner: SOC Manager, Due: Dec 1]
```

### The Blameless Culture

Post-incident reviews are most effective when they focus on **system failures** rather than individual blame.
The "5 Whys" technique helps identify root causes:

```text
Why was the phishing email not detected?
→ The email filter didn't flag it.

Why didn't the email filter flag it?
→ The malicious link used a newly registered domain, not yet in blocklists.

Why wasn't the domain in blocklists?
→ No threat intel feed subscription includes newly registered domains.

Why is there no such subscription?
→ Budget constraints — the subscription costs €2,000/year.

Why hasn't this been approved?
→ No one formally requested it after the last phishing incident.

ROOT CAUSE: No formal process for evaluating threat intel coverage gaps post-incident.
ACTION ITEM: Establish quarterly threat intel coverage review.
```

---

## 9. Communication During Incidents

### Internal Communication

**Incident Command** during a P1 incident:

* Designate an **Incident Commander** (IC) — single person responsible for coordination
* IC does NOT do technical work — they manage people, communication, and decisions
* Technical teams report status to IC on a regular cadence (every 30 min for P1)
* IC escalates to executive team when required

**Internal communication channels:**

* Dedicated incident Slack/Teams channel: `#incident-INC-2024-1147`
* Out-of-band channel (if compromise may include communication tools): encrypted messaging app or telephone
* Bridge call for major incidents

### Executive Communication

Keep executives informed but don't overwhelm them:

```text
EXECUTIVE BRIEFING — P1 Incident
Time: 2024-11-14 11:00 UTC

SITUATION: We are responding to a ransomware incident affecting 3 workstations
in the Finance department. No servers affected. Financial data may be at risk.

STATUS: Infected systems isolated. Investigation ongoing. Recovery expected
within 4-6 hours if no further spread.

IMPACT: Finance team partially unavailable. Workaround: manual processes.
Customer-facing systems not affected.

NEXT BRIEF: 13:00 UTC unless situation changes.
```

### External Communication

**DO NOT** communicate externally without legal/PR review:

* Media inquiries: refer to PR team
* Customer notifications: legal review required
* Regulatory notifications: legal counsel manages this process

---

## 10. Regulatory Notification Requirements

### European Union — GDPR

Under GDPR Article 33, a personal data breach must be:

* Reported to the **supervisory authority (DPA)** within **72 hours** of becoming aware
* If the breach is likely to cause high risk to individuals, notify **affected individuals** "without undue delay"

**What triggers GDPR notification:**

* Personal data (name, email, ID, health data) accessed by unauthorized party
* Personal data lost or destroyed
* Personal data made unavailable (e.g., ransomware encrypting HR records)

**What does NOT trigger notification:**

* Breach affecting only non-personal data
* Attack that was fully blocked with no data access
* Incident where data was encrypted with strong keys and no exfiltration occurred

### NIS2 Directive (EU, 2024)

For essential and important entities under NIS2:

* **Initial notification within 24 hours** (early warning)
* **Full notification within 72 hours** (incident notification)
* **Final report within 1 month** (post-incident report)

### US Regulations

| Regulation | Sector | Notification Requirement |
|-----------|--------|-------------------------|
| HIPAA | Healthcare | 60 days from discovery (affected individuals + HHS) |
| PCI DSS | Payment card | Immediate to card brands; 72h to acquiring bank |
| SEC Rule (2023) | Public companies | 4 business days (material incidents) |
| CISA Reporting (2024) | Critical infrastructure | 72 hours |

### Practical Implications for IR Teams

1. The **72-hour GDPR clock starts from when you become aware** — not from when the incident started
1. Assess early: does this incident involve personal data? Engage legal immediately if yes
1. Document your discovery timeline precisely — regulators will scrutinize this
1. "We didn't know if personal data was accessed" is not a reason to delay — regulatory guidance says: report when you **cannot rule out** personal data access

---

## 11. Digital Forensics Fundamentals

### The Forensic Process

```text
EVIDENCE ACQUISITION
        │
        ▼
EVIDENCE PRESERVATION
(hash, seal, chain of custody)
        │
        ▼
EVIDENCE ANALYSIS
        │
        ▼
DOCUMENTATION & REPORTING
```

### Locard's Exchange Principle (Applied to Digital)

In physical forensics, Edmond Locard's principle states: "Every contact leaves a trace." In digital forensics, every attacker action leaves artifacts:

* **Registry entries** from malware installation
* **Event log entries** from authentication events
* **Prefetch files** from executed programs
* **Browser artifacts** from phishing link clicks
* **Memory artifacts** from running processes
* **Network logs** from C2 communication

The challenge: some artifacts are volatile (disappear on reboot), others persist but can be overwritten.

### Types of Digital Evidence

| Category | Examples | Volatility |
|----------|---------|------------|
| **Live system (volatile)** | RAM, running processes, network connections | Lost on shutdown |
| **Disk artifacts** | Files, registry, logs, prefetch | Persistent but can be overwritten |
| **Network artifacts** | PCAP, flow data, proxy logs | Persistent (if retained) |
| **Cloud artifacts** | API logs, CloudTrail, M365 audit | Persistent (varies by retention) |

### Order of Volatility

Collect evidence in order from most volatile to least:

1. CPU registers, cache
1. **RAM/memory** — capture immediately
1. Network connections, routing tables
1. Running processes
1. Open files and handles
1. **Disk image** — before shutdown
1. Remote logs and monitoring data
1. Physical configuration and environment

---

## 12. Evidence Handling and Chain of Custody

### Chain of Custody

**Chain of custody (CoC)** is the documentation of who collected, handled, stored, and analyzed evidence.
It is essential for:

* Legal proceedings (evidence admissibility)
* Internal investigations (HR, legal)
* Regulatory audits

Every piece of evidence must have a CoC document recording:

```text
CHAIN OF CUSTODY RECORD

Evidence ID:    EVID-INC2024-1147-001
Description:    Memory dump from finance-ws-042
                (winpmem_mini output, 16 GB)
Hash (SHA256):  4abc5d6e7f...
Collection Date: 2024-11-14 09:52 UTC
Collected By:   J. Garcia (Tier 2 Analyst)
Collection Method: winpmem_mini_x64.exe -o memory.raw
Storage Location: Encrypted NAS /evidence/INC-2024-1147/

CUSTODY TRANSFERS:
  From: J. Garcia   To: M. Forensics   Date: 2024-11-14 11:00 UTC
  Reason: Analysis
  Condition: Hash verified 4abc5d6e7f... [matches]

  From: M. Forensics  To: Evidence Safe  Date: 2024-11-16 18:00 UTC
  Reason: Case closure, long-term preservation
  Condition: Hash verified 4abc5d6e7f... [matches]
```

### Evidence Integrity

Always hash evidence at collection time.
Verify the hash before and after every transfer.
Use **SHA-256** minimum (MD5 is no longer acceptable for legal proceedings).

```console
# Hash a memory image on collection
sha256sum memory.raw > memory.raw.sha256

# Verify before analysis
sha256sum -c memory.raw.sha256

# Create a forensic copy (bit-for-bit image) with hash
dd if=/dev/sda bs=4096 | tee disk.img | sha256sum > disk.img.sha256
```

### Evidence Storage

* Store on **write-protected** media or a locked evidence repository
* Maintain **access logs** (who accessed evidence and when)
* Encrypt evidence at rest
* Keep backup copies in physically separate locations
* Retain according to the retention policy (typically minimum 1 year, often longer for criminal cases)

---

## 13. IR Plan and Playbook Development

### IR Plan vs. IR Playbook

| Document | Purpose | Audience |
|---------|---------|---------|
| **IR Plan** | Strategic — organization's overall approach to IR | Management, all staff |
| **IR Playbook** | Tactical — step-by-step response for a specific incident type | IR analysts |
| **Runbook** | Technical — specific commands and procedures | Engineers |

### Playbook Template

```markdown
# Incident Response Playbook: [Incident Type]
Version: X.X
Effective: YYYY-MM-DD
Owner: IR Team Lead

## 1. Scope
This playbook covers [incident type] incidents.

## 2. Trigger Criteria
This playbook is initiated when:
- [Criterion 1]
- [Criterion 2]

## 3. Initial Severity Assessment
- Criteria for P1/P2/P3

## 4. Containment Steps
### 4.1 Immediate Actions (first 30 minutes)
1. Step 1

2. Step 2

### 4.2 Short-term Containment
...

## 5. Eradication Steps
1. **Identify all persistence mechanisms** (scheduled tasks, registry run keys, backdoor accounts, web shells, cron jobs)

2. **Remove malware artifacts** (quarantine or delete malicious files, clean registry entries)
3. **Terminate attacker sessions** (kill processes, revoke tokens, close reverse shells)
4. **Remove backdoor accounts** (audit and delete attacker-created accounts)
5. **Patch the exploited vulnerability** (apply vendor patch or implement workaround)
6. **Rotate compromised credentials** (all accounts with access to affected systems)

## 6. Recovery Steps
1. **Verify clean state** (full AV/EDR scan, confirm no persistence remains)

2. **Restore from known-good backup** or rebuild from baseline image
3. **Validate backup integrity** (hash check; confirm backup pre-dates compromise)
4. **Reconnect to monitored segment** (not directly to production)
5. **Test critical business functions** (confirm system operates correctly)
6. **Monitor intensively for 48–72 hours** (watch for re-infection indicators)
7. **Reconnect to production** (only after clean monitoring period)
8. **Declare incident closed** and update case management system

## 7. Evidence Collection Requirements
- **Collect in order of volatility**: RAM first, then network state, running processes, disk
- **Hash immediately**: SHA-256 every artifact at time of collection
- **Document collection**: who, when, what tool, what storage location
- **Write-protect originals**: use hardware write blockers for physical media
- **Forensic copies only**: never analyze originals; always work on verified copies

## 8. Communication Requirements
- Who to notify: IR Lead → CISO → Legal → Executive → (if P1) Board
- When: at incident declaration; at each severity change; at containment; at resolution
- Templates: use pre-approved templates for executive briefings, customer notifications, regulatory filings
- Out-of-band: if corporate email may be compromised, use Signal or phone for IR coordination

## 9. Regulatory Requirements
- GDPR applicability: Yes if personal data of EU data subjects is involved
- If yes: notify supervisory authority within **72 hours** of awareness (GDPR Art. 33)
- If high risk to individuals: also notify affected individuals without undue delay (GDPR Art. 34)
- NIS2: 24h early warning, 72h full notification to national CSIRT (for essential/important entities)
- DORA: 4h initial, 72h intermediate, 1 month final (for EU financial entities)
- PCI-DSS: Immediately notify acquiring bank on confirmed or suspected card data compromise

## 10. Post-Incident Documentation
- **Incident record**: full timeline, affected systems, evidence log, actions taken, notifications made
- **Executive summary**: 1-page non-technical summary for leadership
- **PIR report**: root cause analysis, what worked, what didn't, action items with owners and deadlines
- **Updated playbooks**: incorporate lessons learned into IR playbooks before next exercise
- **Metrics**: record MTTD, MTTR, MTTRC for program performance tracking
```

---

## 14. Tabletop Exercises

Tabletop exercises are discussion-based simulations of incident response scenarios.
They do not involve actual systems — participants work through a scenario verbally.

### Tabletop Exercise Structure

```text
PHASE 1: SETUP (15 min)
  - Ground rules
  - Introduce scenario
  - Assign roles

PHASE 2: SCENARIO INJECT 1 (20 min)
  - Introduce first piece of information
  - Teams discuss: What do you know? What do you do?

PHASE 3: SCENARIO INJECT 2 (20 min)
  - Add complications (attacker escalates, regulator calls, etc.)
  - Teams adapt their response

PHASE 4: SCENARIO INJECT 3 (20 min)
  - Resolution scenario

PHASE 5: HOT WASH (30 min)
  - What went well?
  - What gaps did we identify?
  - What action items do we generate?
```

### Sample Tabletop Scenario: Ransomware

**Inject 1:**
> It is 09:00 Monday. Your IT help desk receives 5 calls in 10 minutes from Finance department users reporting their files are encrypted and showing a ransom demand. Discuss: What do you do in the next 30 minutes?

**Inject 2:**
> Your IR manager has been isolated in a meeting and cannot be reached. The CEO walks into the SOC asking for a status update. Meanwhile, the encryption has spread to 3 more departments. The backup system log shows the attacker also encrypted last night's backups.

**Inject 3:**
> It is now 13:00. You have confirmed: 200 workstations encrypted, backup server compromised, HR data including personal employee data may have been exfiltrated before encryption. A journalist calls asking for a comment on reports of a ransomware attack at your company.

---

## 15. References

1. **NIST SP 800-61 Rev 2** — Computer Security Incident Handling Guide. https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
1. **SANS Incident Response Process** — https://www.sans.org/white-papers/
1. **GDPR Article 33** — Data Breach Notification. https://gdpr.eu/article-33-breach-notification/
1. **NIS2 Directive** — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555
1. **CISA Incident Response Playbooks** — https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
1. **TheHive Project** — Open-source IR case management. https://thehive-project.org/
1. **Volatility Foundation** — Memory forensics framework. https://volatilityfoundation.org/
1. **ENISA** — "Good Practice Guide for Incident Management." https://www.enisa.europa.eu/
1. **Mandiant/Google** — "M-Trends Annual Threat Report" — industry MTTD/MTTR benchmarks
1. **RFC 3227** — "Guidelines for Evidence Collection and Archiving." https://tools.ietf.org/html/rfc3227

---

*End of Session 10 Reading Material*
