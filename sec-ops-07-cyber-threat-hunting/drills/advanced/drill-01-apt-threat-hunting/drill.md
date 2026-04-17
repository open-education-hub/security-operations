# Drill 01 (Advanced): Full APT Threat Hunting Exercise

**Level:** Advanced

**Estimated Time:** 3-4 hours

**Submission Format:** Complete hunt package (report + queries + detections + MISP export)

---

## Learning Objectives

* Conduct a multi-hypothesis, end-to-end threat hunt against an APT-level adversary
* Correlate evidence across multiple data sources to build a complete attack timeline
* Apply Diamond Model analysis to understand the full intrusion set
* Create production-quality Sigma rules from hunt findings
* Produce both tactical and strategic intelligence from hunt findings

---

## Scenario

You are the lead threat hunter at **AeroSpace Dynamics GmbH**, a German aerospace manufacturer.
Your organization is a tier-1 supplier to several European defense programs.

**Context:** The German BSI (Federal Office for Information Security) has published an advisory warning that APT-class threat actors linked to a foreign intelligence service are targeting aerospace and defense contractors in Europe to steal intellectual property related to advanced propulsion systems — which is exactly the domain your company works in.

**Your mission:** Conduct a proactive threat hunt to determine if your organization has been compromised.
You have 30 days of log data.

---

## Available Intelligence

### BSI Advisory Summary (TLP:GREEN)

> **THREAT GROUP: IRON-FALCON**
>
> IRON-FALCON is a nation-state-level APT group assessed with high confidence to be sponsored by a foreign intelligence service. They target aerospace, defense, and advanced manufacturing organizations in Western Europe and North America.
>
> **Known TTPs (ATT&CK):**
> - T1566.001/T1566.002: Spearphishing (attachments and links)
> - T1059.001: PowerShell with AMSI bypass
> - T1547.001: Registry Run key persistence
> - T1053.005: Scheduled task persistence
> - T1078.002: Valid Domain Accounts (after credential theft)
> - T1550.003: Pass-the-Ticket (Kerberoasting + ticket use)
> - T1021.001/T1021.002: RDP and SMB lateral movement
> - T1057: Process Discovery
> - T1083: File and Directory Discovery
> - T1560.001: Archive Collected Data
> - T1048.003: Exfiltration Over Alternative Protocol (DNS/ICMP)
> - T1041: Exfiltration Over C2 Channel (HTTPS)
>
> **Known Infrastructure Patterns:**
> - C2 domains impersonate industrial software vendors (Siemens, Honeywell, Schneider Electric naming patterns)
> - Prefer dedicated servers in Netherlands and Germany
> - Use Let's Encrypt certificates
> - Dwell time: 45-90 days before exfiltration
>
> **Known Malware:**
> - FALCON-GATE (custom implant, modular)
> - STEELBIRD (custom keylogger, in-memory only)
> - Modified Cobalt Strike (custom profile masquerading as Windows Update traffic)

---

## Log Data Excerpts (30-Day Dataset)

### Appendix A: Anomalous Authentication Events

```text
# Authentication log anomalies (Windows Security Events)

2024-02-15 02:14:33  EventID=4624 LogonType=3 TargetUserName=l.wagner
  SourceIP=10.45.0.88 (Engineering workstation pool)
  TargetServer=ENG-SRV-001 (Engineering file server)
  Auth=NTLMv2
  [NOTE: l.wagner normally authenticates from 10.45.0.12 only]

2024-02-15 02:31:05  EventID=4624 LogonType=3 TargetUserName=l.wagner
  SourceIP=10.45.0.88 → TargetServer=CAD-SRV-002 (CAD/Design server)
  Auth=NTLMv2

2024-02-15 02:45:19  EventID=4624 LogonType=3 TargetUserName=l.wagner
  SourceIP=10.45.0.88 → TargetServer=BACKUP-SRV-01 (Backup server)
  Auth=NTLMv2

2024-02-15 03:15:44  EventID=4688 Process=net.exe
  Args: "net use \\BACKUP-SRV-01\E$ /user:CORP\l.wagner *"
  Host=10.45.0.88 User=l.wagner

2024-02-20 03:05:11  EventID=4769 [Kerberos Service Ticket Request]
  AccountName=svc_backup ServiceName=CAD-SRV-002$
  TicketEncryptionType=0x17 (RC4 — weak, used for Kerberoasting)
  ClientAddress=10.45.0.88
  [NOTE: RC4 is unusual; 97% of Kerberos in environment uses AES256]

2024-03-01 - 2024-03-05  EventID=4624 LogonType=10 (RemoteInteractive/RDP)
  User=svc_backup Source=10.45.0.88 → Multiple engineering servers
  [NOTE: Service account using RDP is highly suspicious]
```

### Appendix B: Process Execution Anomalies

```text
2024-02-12 14:22:01  Sysmon EID=1 Host=ENGWS-l.wagner-001 User=l.wagner
  Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine=powershell.exe -NoP -sta -NonI -W Hidden
              -Enc [very long base64 string ~800 chars]
  ParentImage=C:\Users\l.wagner\AppData\Local\Temp\doc_viewer.exe
  MD5=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

2024-02-12 14:22:09  Sysmon EID=3 (NetworkConnect) Host=ENGWS-l.wagner-001
  Image=powershell.exe
  DestIP=193.142.147.15 DestPort=443
  Protocol=tcp

2024-02-12 14:22:33  Sysmon EID=11 (FileCreate) Host=ENGWS-l.wagner-001
  TargetFilename=C:\Users\l.wagner\AppData\Roaming\Microsoft\Siemens_Updater.exe
  Image=powershell.exe

2024-02-12 14:23:15  Sysmon EID=13 (RegistryEvent) Host=ENGWS-l.wagner-001
  TargetObject=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SiemensUpdate
  Details=C:\Users\l.wagner\AppData\Roaming\Microsoft\Siemens_Updater.exe /q
  Image=powershell.exe

2024-03-08 09:15:22  Sysmon EID=1 Host=CAD-SRV-002 User=l.wagner
  Image=C:\Windows\System32\cmd.exe
  CommandLine=cmd.exe /c dir "C:\Projects\PropulsionX9\" /s /b > C:\Windows\Temp\x.tmp
  ParentImage=C:\Users\l.wagner\AppData\Roaming\Microsoft\Siemens_Updater.exe

2024-03-08 09:18:44  Sysmon EID=1 Host=CAD-SRV-002 User=l.wagner
  Image=C:\Windows\System32\rar.exe
  CommandLine=rar.exe a -hp "C:\Windows\Temp\proj.rar" "C:\Projects\PropulsionX9\" -r
  ParentImage=C:\Windows\System32\cmd.exe

2024-03-08 09:44:01  Sysmon EID=3 Host=CAD-SRV-002 User=l.wagner
  Image=C:\Users\l.wagner\AppData\Roaming\Microsoft\Siemens_Updater.exe
  DestIP=193.142.147.15 DestPort=443
  BytesSent=387,421,184  [~370 MB]
  Duration=1842 seconds  [~31 minutes]
```

### Appendix C: DNS Anomalies

```text
DNS Query Log — Host: ENGWS-l.wagner-001 — Feb 12 - Mar 10

Resolved domains (frequency, sorted):
  siemens-software-updates.de      → 193.142.147.15   [1,240 queries]
  support.siemens-software-updates.de → 193.142.147.15 [892 queries]
  api.siemens-software-updates.de  → 193.142.147.15   [445 queries]

Domain registration info (OSINT, from report):
  siemens-software-updates.de: Registered 2024-01-15 (28 days before initial access)
  Registrar: NameCheap (privacy protection)
  Certificate: Let's Encrypt, issued 2024-01-16
  Actual Siemens domain: siemens.com (not this)
```

### Appendix D: File System Events

```text
2024-03-08 09:18:44  rar.exe archive created: C:\Windows\Temp\proj.rar
  Archive size: 395,124,736 bytes (~377 MB)
  Source directory: C:\Projects\PropulsionX9\
  Password protected: YES (encrypted header)

2024-03-08 09:44:02  proj.rar deleted after upload completed
  No backup copy found
```

---

## Tasks

### Task 1: Complete ATT&CK Kill Chain Mapping (20 points)

Using ALL evidence from Appendices A-D:

1. Map every observable event to an ATT&CK technique
1. Reconstruct the complete attack timeline from initial compromise to exfiltration
1. Identify which techniques overlap with known IRON-FALCON TTPs
1. Assess: Is this likely IRON-FALCON or a different actor? Justify your assessment.

---

### Task 2: Diamond Model Analysis (15 points)

Perform a Diamond Model analysis of this intrusion:

1. **Adversary:** What do we know or can infer about the adversary?
1. **Infrastructure:** Map all identified infrastructure. What can be pivoted?
1. **Capability:** What tools and techniques were used? Custom vs. commodity?
1. **Victim:** Why is this organization/data the target?

Identify 3 potential pivots you would pursue to find related intrusions or infrastructure.

---

### Task 3: Multi-Hypothesis Hunt Queries (25 points)

Write **5 production-quality Sigma rules** targeting the confirmed TTPs in this intrusion.
Each rule must:

* Be correctly formatted YAML Sigma
* Have a proper UUID (format, not real UUID is fine)
* Include ATT&CK tags
* Include meaningful false positive documentation
* Have an appropriate severity level

Rules to create:

1. Registry Run key set by unusual parent (covers the Siemens_Updater persistence)
1. Kerberoasting detection (RC4 Kerberos ticket requests)
1. Service account using RDP (T1021.001)
1. Data archiving with password (rar.exe with encryption flag)
1. Large outbound HTTPS transfer (>100MB, anomaly threshold)

---

### Task 4: Full Hunt Report (25 points)

Write a complete, professional hunt report including:

1. **Hunt metadata** (ID, trigger, scope, dates, hunter)
1. **Executive summary** for CISO (3-5 sentences, no jargon)
1. **Technical findings** for IR/SOC team
1. **Complete attack timeline** (table format)
1. **Attribution assessment** with confidence level and evidence basis
1. **Business impact assessment** (quantify if possible)
1. **Data gaps** identified
1. **Recommendations** (immediate, short-term, long-term)
1. **New detections created**

---

### Task 5: MISP Event (15 points)

Create a MISP event (JSON structure or actual export) for this intrusion that:

1. Contains all confirmed IOCs with appropriate types and to_ids flags
1. Has a MISP object for the dropped malware (Siemens_Updater.exe)
1. Has appropriate TLP tagging (TLP:AMBER for internal; you may also create a TLP:GREEN version with sanitized intel for sharing)
1. Includes IRON-FALCON galaxy cluster (or threat-actor attribute)
1. Maps to at least 5 ATT&CK techniques via tags
1. Includes a YARA rule (as a `yara` attribute) for the Siemens_Updater malware based on known strings

---

## Evaluation Criteria

| Task | Points | Key Criteria |
|------|--------|-------------|
| Task 1: Kill chain mapping | 20 | Completeness, accuracy, attribution assessment |
| Task 2: Diamond Model | 15 | All four elements, actionable pivots |
| Task 3: Sigma rules | 25 | Correct YAML, appropriate logic, low FP documentation |
| Task 4: Hunt report | 25 | Professional quality, complete, actionable |
| Task 5: MISP event | 15 | Completeness, correct types, YARA rule quality |
| **Total** | **100** | |

---

## Bonus Tasks (Extra Credit)

**Bonus 1 (+5 pts):** Write a Python script that queries MISP for all indicators from this event and outputs them as a Splunk lookup table CSV.

**Bonus 2 (+5 pts):** Design a detection playbook (1 page) that would allow a Level 1 SOC analyst to handle an alert from your Kerberoasting Sigma rule, including escalation criteria.

**Bonus 3 (+5 pts):** Explain how the attacker's choice of "siemens-software-updates.de" is an example of a specific social engineering technique.
What about the naming pattern would make employees likely to trust it?
What controls could prevent this?
