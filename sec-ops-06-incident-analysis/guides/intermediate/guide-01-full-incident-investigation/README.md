# Guide 01 (Intermediate): Conducting a Full Incident Investigation

**Level:** Intermediate

**Estimated time:** 45 minutes

**Prerequisites:** Guides 01–03 (Basic), Demo 01–02, Reading (all sections)

---

## Purpose

This guide provides an end-to-end investigation methodology for a complete incident.
By the end, you will be able to:

* Execute a full investigation workflow from alert to PIR
* Apply threat-centric thinking at each investigation phase
* Use structured analytical techniques to scope and attribute incidents
* Produce investigation-quality documentation

---

## The THREAT Framework

This guide uses the **THREAT** investigation framework — a mnemonic designed for SOC analysts:

```text
T — Triage      Validate the alert and establish initial context
H — Hunt        Expand beyond the initial alert to find related activity
R — Reconstruct Build the complete timeline of adversary activity
E — Enumerate   Catalog all affected systems, accounts, and data
A — Attribute   Map to ATT&CK, identify actor characteristics
T — Track       Document findings and track remediation
```

---

## Phase T: Triage

### 1.1 Alert Validation (< 5 minutes for P3/P4, immediate for P1/P2)

**Answer these questions before opening a ticket:**

1. Is this alert technically valid? (Is the detection rule logic sound?)
1. Does the raw log data support the alert?
1. Is this a known false positive pattern for this environment?
1. Is there corroborating evidence from another source?

**Triage checklist:**

```text
[ ] Reviewed the raw log event(s) that triggered the alert
[ ] Confirmed the alert logic applies to this event
[ ] Checked the asset owner/role for context
[ ] Queried SIEM for last 24h activity from same host/user
[ ] Checked if same host/user has generated similar alerts recently
[ ] Checked IP/domain/hash against threat intel (VirusTotal, internal TI)
[ ] Made go/no-go decision: real incident or false positive
```

### 1.2 Initial Characterization

Once confirmed as a real incident, characterize it:

```text
Incident Characterization Form
================================
Initial alert:      [Alert name and rule ID]
Affected host:      [Hostname and IP]
Affected user:      [Username and department]
Host criticality:   [CRITICAL / HIGH / MEDIUM / LOW]
Incident type:      [NIST category]
Initial severity:   [P1-P5 from matrix]
Kill chain phase:   [Estimated current phase]
Detection source:   [EDR / SIEM / Proxy / Email GW / User report]
Time of alert:      [UTC]
Estimated time of compromise: [UTC or "unknown — investigating"]
```

### 1.3 Open the Ticket

Document immediately — even incomplete information.
The ticket is a living document.

Required fields at ticket creation:

* Incident ID (auto-assigned by ticketing system)
* Title (concise, descriptive)
* Severity (initial — may change)
* Affected host(s)
* Affected user(s)
* SIEM alert ID or reference
* Analyst assigned

---

## Phase H: Hunt

Hunting expands the investigation beyond the initial alert.
The goal is to find everything the attacker has done, not just what triggered the first alert.

### 2.1 Time-Based Expansion

Look at all activity from the affected host and user in the 24–48 hours before the alert:

```spl
(host="AFFECTED-HOST" OR user="affected.user")
earliest=-48h latest=now
| table _time, host, sourcetype, EventID, User, CommandLine, dest_ip
| sort _time
```

Look for:

* Unusual processes before the alert time
* Connections to external IPs that aren't normal for this user
* File access outside normal working hours
* Service/scheduled task creations

### 2.2 IOC-Based Hunting

Extract all IOCs from the initial alert and hunt for them across all systems:

| IOC Type | Hunt Query |
|----------|-----------|
| IP address | `index=firewall dest_ip="ATTACKER_IP"` |
| Domain | `index=dns query="malicious.domain"` |
| File hash | `index=sysmon MD5="badhash"` |
| Process name | `index=sysmon Image="*suspicious.exe*"` |
| Registry key | `index=sysmon EventID=13 TargetObject="*run_key*"` |

### 2.3 TTP-Based Hunting

If you've identified one technique, hunt for related techniques in the same tactic:

**Example:** If you found T1003.001 (LSASS dump), also hunt for:

* T1003.002 (SAM dump)
* T1003.003 (NTDS dump)
* T1078.002 (Valid Domain Accounts — using dumped creds)
* T1021.002 (Lateral movement via SMB with stolen creds)

### 2.4 Lateral Movement Detection

For every compromised system, check for authentication attempts to other systems:

```spl
index=winlogs EventCode=4624 Logon_Type=3 Source_Network_Address="COMPROMISED_HOST_IP"
| table _time, Account_Name, ComputerName, Source_Network_Address
| sort _time
```

For every compromised account, check for authentication from unusual locations:

```spl
index=winlogs EventCode=4624 Account_Name="compromised_user"
| stats count by Source_Network_Address
| sort -count
```

---

## Phase R: Reconstruct

### 3.1 Establish Patient Zero

Patient zero is the *first* affected system or user.
Identifying it tells you:

* The initial attack vector
* The initial access technique
* How long the attacker has been present

Work backward in time from the first confirmed malicious event:

```text
Known event: Malware on WS-JSMITH at 09:44
  → What was on WS-JSMITH before that?
  → Did jsmith click a link? Open an attachment? Visit a site?
  → Was there a phishing email in the last 24 hours?
  → Were there unusual DNS queries or proxy hits in the hours before?
```

### 3.2 Build the Full Timeline

Follow Guide 03 methodology.
Ensure:

* All timestamps are UTC
* All log sources are represented
* Gaps are documented
* Each entry maps to a kill chain phase

### 3.3 Calculate Dwell Time

```text
Dwell time = Detection time − Earliest evidence of compromise

Example:
  Detection: 2024-11-15 09:52 UTC
  Earliest compromise: 2024-11-15 09:44 UTC (macro execution)
  Dwell time: 8 minutes (fast-detected)

  But if analyst finds earlier IOC:
  Detection: 2024-11-15 09:52 UTC
  Earliest compromise: 2024-11-01 14:00 UTC (earlier recon email)
  Dwell time: 14 days (significant — full credential reset needed)
```

Long dwell time implications:

* All credentials the user has accessed should be considered compromised
* All systems the user touched should be investigated
* Assume multiple persistence mechanisms installed
* Consider "assume breach" posture for broader network

---

## Phase E: Enumerate

### 4.1 Affected Systems Inventory

```text
Systems Inventory — INC-2024-0847
====================================
System        IP              Role          Status       Evidence Collected
──────────────────────────────────────────────────────────────────────────
WS-JSMITH     192.168.10.42   Workstation   COMPROMISED  YES — full forensic image
WS-MWILSON    192.168.10.67   Workstation   SUSPECTED    YES — volatile evidence
FILE-SRV01    10.0.1.10       File Server   ACCESSED     YES — auth logs
DC01          10.0.1.5        Domain Ctrl   ACCESSED     YES — auth logs
MAIL01        10.0.1.20       Mail Server   DELIVERY     YES — mail logs only
```

### 4.2 Affected Accounts Inventory

```text
Accounts Inventory — INC-2024-0847
=====================================
Account          Type        Compromise    Credentials Reset   MFA Status
─────────────────────────────────────────────────────────────────────────
jsmith           User        CONFIRMED     REQUIRED            Enrolled
mwilson          User        SUSPECTED     REQUIRED            Enrolled
administrator    Domain Admin ACCESSED     REQUIRED            NOT ENROLLED
svc_backup       Service     UNKNOWN       REQUIRED            N/A
```

### 4.3 Affected Data Inventory

Determine what data the attacker could have accessed:

```text
Data Inventory — INC-2024-0847
=================================
Data Type          Location           Volume    Accessed?   Sensitivity
──────────────────────────────────────────────────────────────────────
Finance data       FILE-SRV01\Finance Unknown   POSSIBLE    HIGH (PII, PCI)
HR records         FILE-SRV01\HR      Unknown   POSSIBLE    HIGH (PII, GDPR)
Email (jsmith)     Exchange           Unknown   LIKELY      MEDIUM
Local files        WS-JSMITH          Unknown   CONFIRMED   TBD

Exfiltration confirmed? NO (no large outbound transfers detected)
Data breach notification required? UNDETERMINED — awaiting file access log analysis
```

---

## Phase A: Attribute

### 5.1 ATT&CK Mapping

Map all observed behaviors to ATT&CK techniques (see Demo 02 and Demo 04 for tools).

Minimum mapping output:

* Technique IDs for each observed TTP
* Confidence level
* Evidence reference

### 5.2 Actor Characterization

Even without full attribution, characterize the actor based on observed behavior:

```text
Actor Characterization — INC-2024-0847
=========================================
Sophistication:    MEDIUM
  Rationale: Used commodity phishing email (not custom delivery),
             standard reverse shell (not living-off-the-land initially),
             but attempted credential dumping (above script-kiddie level)

Primary motive:    UNKNOWN — financial (credential theft) or espionage
                   Cannot determine without post-exfil analysis

Targeting:         OPPORTUNISTIC likely (mass phishing campaign targeting
                   multiple users with same email)

Tools observed:    PowerShell reverse shell, Mimikatz-like LSASS access,
                   standard Windows discovery commands

Unique TTPs:       None identified — commodity attack chain
Attribution:       NONE — insufficient data for actor identification
```

### 5.3 Detection Gap Analysis

For each phase of the attack:

```text
Detection Gap Analysis
=======================
Phase            Detected?   How?                  Gap?
───────────────────────────────────────────────────────────────────
Recon            NO          N/A                   No inbound scanning logs
Weaponize        NO          N/A                   N/A (off-network)
Delivery         DELAYED     SIEM (macro rule)     Email not flagged (DMARC none)
Exploitation     YES         Sysmon (process chain) 7-min detection lag
Installation     NO          Not detected          No File Integrity Monitoring
C2               DELAYED     Firewall log review   No outbound anomaly alert
Discovery        NO          Not alerted            No AD query monitoring
Credential Dump  NO          Not detected          No LSASS access alert
Lateral Movement PARTIAL     Auth log (post-event) No real-time lateral alert
Exfiltration     N/A         N/A                   No DLP deployed
```

---

## Phase T: Track

### 6.1 Update the Incident Ticket

Update the ticket with:

* Confirmed affected systems and accounts
* Timeline summary
* Containment actions taken
* Outstanding tasks

### 6.2 Remediation Tracking

For each gap identified, create a finding with:

* Gap description
* Risk level
* Recommended remediation
* Owner
* Target date
* Status

### 6.3 Prepare the PIR Outline

Begin the Post-Incident Report immediately after containment:

```markdown
# Post-Incident Report — INC-2024-0847

## 1. Executive Summary
[2-3 sentences: what happened, impact, current status]

## 2. Timeline of Events
[Full timeline from Part R]

## 3. Root Cause Analysis
[Why did the incident occur?]
Primary: User clicked phishing email
Contributing: DMARC not enforced, MFA not fully deployed

## 4. Scope and Impact
[What was affected?]
[Systems, Accounts, Data, Business operations]

## 5. Response Actions Taken
[Chronological list of response actions]

## 6. Findings and Recommendations
[Each gap + remediation]

## 7. Lessons Learned
[What worked? What didn't? What would you do differently?]
```

---

## Investigation Quality Checklist

Before closing any investigation:

```text
Full Investigation Quality Checklist
======================================
TRIAGE
[ ] Alert validated from raw log data
[ ] False positive ruled out with evidence
[ ] Ticket created with initial characterization

HUNT
[ ] All IOCs searched across all systems
[ ] Lateral movement checked for all compromised hosts
[ ] Second and third victim systems investigated

RECONSTRUCT
[ ] Complete timeline built (all log sources)
[ ] All timestamps in UTC
[ ] Clock skew documented
[ ] Coverage gaps identified and documented
[ ] Patient zero identified or search exhausted

ENUMERATE
[ ] All affected systems listed with status
[ ] All affected accounts listed with compromise status
[ ] Affected data types and sensitivity documented
[ ] Breach notification assessment completed

ATTRIBUTE
[ ] All observed TTPs mapped to ATT&CK
[ ] Detection gap analysis completed
[ ] Actor characterization documented

TRACK
[ ] All containment actions documented
[ ] All evidence collected with chain of custody
[ ] Remediation items created with owners and dates
[ ] PIR drafted
[ ] Stakeholders notified per escalation matrix
```
