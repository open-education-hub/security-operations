# Guide 04 (Intermediate) — IR Playbook Execution: Ransomware Response

## Objective

By the end of this guide you will be able to:

* Execute a complete ransomware incident response from detection to recovery
* Make containment decisions under time pressure
* Coordinate between IR team, IT, management, and legal
* Complete all required documentation including GDPR assessment

**Estimated time:** 45 minutes

**Level:** Intermediate

**Prerequisites:** Guides 01–03, Demo 01–02

---

## Scenario

**Organization:** HealthTech Solutions AG (Berlin, Germany)

* 350 employees, healthcare IT provider
* Processes patient scheduling data for 50 hospital clients
* Subject to: GDPR, NIS2 (essential entity), German KHZG

**Time:** 2025-04-14, Monday, 03:47 UTC

**Initial Alert:**

```text
CRITICAL ALERT — P1 — RANSOMWARE SPREADING
Source: CrowdStrike EDR
Affected: FILESERVER-PROD-01, FILESERVER-PROD-02
Activity:
  - Mass file rename: 4,847 files renamed .locked in 3 minutes
  - VSS deletion via vssadmin.exe
  - Spreading via SMB to additional servers
  - Ransom note: "How_To_Recover_Files.txt" dropped to all shares

Patient scheduling data: YES (FILESERVER-PROD-01 hosts patient appointment data)
```

---

## Phase 1: Identification (0–15 minutes)

### Immediate triage

```text
[03:47] Alert acknowledged by on-call analyst
[03:48] P1 declared — immediately invoke IR plan
[03:48] On-call analyst calls IR Manager (mobile): "Ransomware spreading on production file servers — P1 — activating IR team"
[03:49] IR Manager calls: CTO, DPO, IT Director
[03:50] War room established: Signal group "INC-2025-HealthTech-01"
```

### Initial scope assessment

**SIEM queries to run immediately:**

```spl
# What systems are actively communicating during the ransomware spread?
index=endpoint EventCode=5145 (path="*.locked" OR path="*How_To_Recover*")
| stats count by ComputerName, ObjectName
| sort -count

# What is the patient zero?
index=endpoint CommandLine="*vssadmin*" OR CommandLine="*shadow*"
| sort _time
| head 5
```

**Simulated findings:**

* FILESERVER-PROD-01: 4,847 files renamed (started 03:44)
* FILESERVER-PROD-02: 891 files renamed (started 03:46 — spreading via SMB)
* SERVER-DB-01: 0 files (not yet reached)
* WORKSTATION-HELPDESK-04: 23 files renamed (patient zero — started 03:42)
* Patient zero: john.hoffman@healthtech.de, Helpdesk workstation

**Timeline reconstruction:**

```text
03:42 - Ransomware executes on WORKSTATION-HELPDESK-04 (patient zero)
03:44 - Spreads to FILESERVER-PROD-01 via SMB (file share access)
03:46 - Spreads to FILESERVER-PROD-02 via SMB
03:47 - EDR fires P1 alert
03:48 - Analyst acknowledges
```

**Dwell time before execution:** Unknown — investigate later.

---

## Phase 2: Containment (15–45 minutes)

### Simultaneous containment actions

```text
[03:51] CONTAINMENT DECISION: IMMEDIATE FULL ISOLATION — no delay
         Reason: Active spreading, patient data at risk, P1
         Authorization: IR Manager (verbal, documented in ticket)
```

**Execute ALL of these simultaneously (split team):**

**Analyst 1 — EDR isolation:**

```console
# Isolate all confirmed affected systems simultaneously
crowdstrike-isolate --hostname WORKSTATION-HELPDESK-04
crowdstrike-isolate --hostname FILESERVER-PROD-01
crowdstrike-isolate --hostname FILESERVER-PROD-02

# Check SERVER-DB-01 (not yet infected — isolate anyway as precaution)
crowdstrike-isolate --hostname SERVER-DB-01
```

**Analyst 2 — Network segmentation:**

```text
Contact Network team on-call:
"Emergency: Isolate VLAN-FileServers (VLAN 20) and VLAN-Helpdesk (VLAN 30) from
the rest of the network. Keep them accessible only from SOC VLAN 100."
```

**Analyst 3 — Credential containment:**

```text
1. Reset john.hoffman password immediately (patient zero user)

2. Check if john.hoffman is a service account → NO (standard helpdesk user)
3. Check if john.hoffman has any privileged access → Helpdesk admin on JIRA only
4. Check for other user sessions from same source IP as compromise
```

**IR Manager — Backup check:**

```text
Call IT Director: "Are backups for FILESERVER-PROD-01 and PROD-02 intact?
Are backup systems on an isolated network from file servers?"
[Result: Backups on BACKUPSERVER-01, separate VLAN, confirmed not reached]
```

### Containment verification

```text
[03:58] All systems isolated
[03:59] VLAN isolation confirmed by network team
[04:01] Backup integrity confirmed
[04:05] Check: any new ransomware activity in last 5 minutes → NEGATIVE
        Containment successful
```

---

## Phase 3: GDPR Assessment (Parallel with Containment)

**This runs simultaneously — DPO is already on the war room call.**

### GDPR trigger checklist

```text
□ Is personal data involved?
  YES — FILESERVER-PROD-01 contains patient scheduling data
  Approximate records: 12,000 patient appointment records (name, DOB, appointment time, hospital)

□ What type of data?
  Patient appointment data — sensitive health-adjacent data
  Likely qualifies as health data under GDPR Article 9

□ What is the risk to individuals?
  Moderate: scheduling data alone not highly sensitive
  Risk: patients could be re-identified with appointment times
  Risk: data could be used in targeted phishing (knowing someone's hospital visit)

□ Is the 72-hour clock running?
  YES — from moment of awareness: 03:47 UTC on 2025-04-14
  Notification deadline: 03:47 UTC on 2025-04-17 (Wednesday)

□ NIS2 obligation?
  YES — HealthTech is essential entity (healthcare IT)
  24-hour early warning required: by 03:47 UTC on 2025-04-15

□ Actions:
  [03:52] DPO notified on war room call — clock noted
  [04:15] DPO to draft Article 33 notification — send by 2025-04-16 12:00
  [04:15] IT Security to draft NIS2 early warning — send by 2025-04-15 09:00
```

---

## Phase 4: Eradication and Recovery (4 hours to 3 days)

### Ransomware identification

```console
# From the ransom note content:
# "Your files have been encrypted by LockBit 3.0..."
# Check nomoreransom.org for LockBit 3.0 → NO free decryptor available
# Check dark web monitoring: stolen data posted? → No evidence yet
```

### Eradication steps

```text
□ Identify initial compromise vector for john.hoffman (investigate later in detail)
□ Collect ransom note for analysis
□ Preserve disk images of all infected systems (for potential future decryptors)
□ Identify the LockBit initial access: (SIEM investigation shows RDP brute force on
  WORKSTATION-HELPDESK-04 succeeded at 2025-04-13 22:15 from IP 45.33.32.156)
□ Patch RDP: emergency network-level authentication enforcement
□ Close RDP public exposure (WORKSTATION-HELPDESK-04 had RDP port 3389 directly
  exposed to internet — firewall misconfiguration)

Decision on infected systems: REBUILD (LockBit = very difficult to clean, rebuild is faster)
```

### Recovery plan

```text
Priority order for restoration (based on business impact):

1. FILESERVER-PROD-01 (patient scheduling data — highest business criticality)

2. FILESERVER-PROD-02 (employee shared drives)
3. WORKSTATION-HELPDESK-04 (single workstation — lower priority)

Recovery steps for FILESERVER-PROD-01:
□ Deploy new VM from standard template
□ Apply all patches
□ Configure MFA for all access
□ Restore from backup (2025-04-13 22:00 backup — predates compromise)
□ Verify backup hash matches original
□ Test restore in isolated environment
□ Confirm patient data is intact and accessible
□ Re-enable access for hospital clients in staged manner
□ Enhanced monitoring: 30 days elevated alert threshold
```

---

## Phase 5: Documentation Throughout

**Incident timeline (maintained in real-time in TheHive):**

```text
[03:47] EDR P1 alert received — ransomware on FILESERVER-PROD-01/02
[03:48] P1 declared. IR Manager, CTO, DPO, IT Director notified
[03:50] War room established (Signal group INC-2025-HealthTech-01)
[03:51] Containment authorized by IR Manager
[03:51] EDR isolation initiated for all 4 systems
[03:52] DPO engaged — GDPR 72h clock noted: deadline 2025-04-17 03:47 UTC
[03:56] Network VLAN isolation confirmed
[03:58] All systems isolated — no new ransomware activity
[04:01] Backup integrity confirmed by IT Director
[04:05] Scope assessment: patient zero = WORKSTATION-HELPDESK-04, john.hoffman
[04:10] Patient data scope: ~12,000 records on FILESERVER-PROD-01
[04:15] NIS2 early warning drafted — submit by 2025-04-15 09:00
[04:15] GDPR Art. 33 notification drafted — submit by 2025-04-16 12:00
[05:30] FILESERVER-PROD-01 restore from backup initiated
[08:45] FILESERVER-PROD-01 restore complete — testing
[09:15] Hospital clients notified: "File access restored"
...
```

---

## Phase 6: Lessons Learned

**Conducted 2025-04-17 (3 days after incident)**

**Root cause:** RDP exposed directly to internet on helpdesk workstation → brute forced → ransomware deployed.

**Key improvements:**

1. Remove all direct internet-facing RDP exposure (emergency scan already done — 3 other systems found)
1. Enable MFA on all remote access methods
1. Apply network segmentation: helpdesk VLAN cannot access file servers directly
1. Deploy EDR on remaining unprotected systems (4 found)
1. Improve backup monitoring: verify backup completeness daily

---

## Key Takeaways

1. **Speed of containment matters more than perfection of scope** — with active spreading, every minute costs more encrypted files
1. **GDPR assessment starts at detection, not at the end** — DPO in the war room from minute 5
1. **Backups are only as good as their isolation** — backups on the same network would have been encrypted too
1. **Patient zero investigation is critical** — don't just recover, find out how they got in
1. **Documentation in real-time** — during a 6-hour response, you won't remember the exact timestamps without notes

---

## Knowledge Check

1. LockBit spreads via SMB. If you isolate WORKSTATION-HELPDESK-04 first but not the file servers, what happens?
1. The DPO asks you at 04:05: "Is patient data at risk?" You don't know yet. What do you say?
1. You find a free LockBit decryptor on a GitHub repository. Should you use it?
1. The ransom demand is €800,000. Management asks you whether they should pay. What do you advise?
