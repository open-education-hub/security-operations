# Demo 02: Threat-Centric Analysis Using MITRE ATT&CK Navigator

**Duration:** ~30 minutes

**Level:** Intermediate

**Environment:** Web browser (MITRE ATT&CK Navigator — no Docker required)

**Tool URL:** https://mitre-attack.github.io/attack-navigator/

---

## Overview

This demo demonstrates how to use MITRE ATT&CK as a threat-centric analysis tool during and after an incident.
Rather than just matching IOCs, a threat-centric analyst maps observed behaviors to ATT&CK techniques to:

1. Understand the attacker's goals at each stage
1. Hunt for undetected activity using the same technique catalog
1. Identify detection gaps in the current environment
1. Communicate findings to stakeholders using a standardized language

---

## Scenario

The phishing incident from Demo 01 has expanded.
During the investigation, the following additional behaviors were observed:

```text
1. WS-JSMITH: WINWORD.EXE → CMD.EXE → POWERSHELL.EXE (encoded command)

2. WS-JSMITH: PowerShell reverse TCP shell to 185.220.101.47:4444
3. WS-JSMITH: net user /domain, net group "Domain Admins" /domain
4. WS-JSMITH: Scheduled task created for persistence
5. WS-JSMITH: LSASS memory read by malicious process (Mimikatz-like)
6. DC01: Authentication from WS-JSMITH using harvested credentials (lateral)
7. FILE-SRV01: Large archive created and copied to network share
8. FILE-SRV01: Outbound HTTPS transfer to cloud storage provider (exfil)
```

---

## Part 1: Map the Incident to ATT&CK

### Step 1.1 — Open ATT&CK Navigator

Navigate to: https://mitre-attack.github.io/attack-navigator/

Click **"Create New Layer"** → **"Enterprise ATT&CK"**

### Step 1.2 — Map each observed behavior

For each observation below, find the matching ATT&CK technique and annotate it in the navigator (color: red = confirmed, yellow = suspected):

| # | Observed Behavior | ATT&CK Technique ID | Technique Name | Tactic |
|---|-------------------|---------------------|----------------|--------|
| 1 | WINWORD spawns CMD spawns PowerShell with -Enc | T1566.001 | Spearphishing Attachment | Initial Access |
| 2 | VBA macro executes PowerShell | T1204.002 | User Execution: Malicious File | Execution |
| 3 | PowerShell -Enc (obfuscation) | T1059.001 | Command and Scripting: PowerShell | Execution |
| 4 | Reverse TCP shell | T1059.001 | PowerShell | Execution |
| 5 | C2 over TCP port 4444 | T1095 | Non-Application Layer Protocol | C2 |
| 6 | net user /domain | T1087.002 | Account Discovery: Domain Account | Discovery |
| 7 | net group "Domain Admins" | T1069.002 | Permission Groups: Domain Groups | Discovery |
| 8 | Scheduled task for persistence | T1053.005 | Scheduled Task/Job | Persistence |
| 9 | LSASS memory read | T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| 10 | Lateral movement using dumped creds | T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| 11 | Large archive created (staging) | T1074.001 | Data Staged: Local Data Staging | Collection |
| 12 | Exfiltration over HTTPS | T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration |

**How to annotate in Navigator:**

1. Search for the technique ID in the search box (top right)
1. Click the technique cell
1. Right-click → "Edit annotation" → Set color and add comment

### Step 1.3 — Save your layer

Click the save icon (disk icon, top left) → Download as JSON.
Name it:
`INC-2024-0847-attack-map.json`

---

## Part 2: Load a Pre-Built Attack Map

A pre-built ATT&CK Navigator layer for this incident is provided at:

```text
demos/demo-02-threat-centric-analysis/data/INC-2024-0847-attack-map.json
```

### Step 2.1 — Load the layer

1. Click **"Open Existing Layer"** → **"Upload from local"**
1. Select `INC-2024-0847-attack-map.json`

The layer shows:

* **Red**: Confirmed techniques (observed in logs)
* **Orange**: Suspected techniques (likely based on campaign context)
* **Yellow**: Detection coverage gaps

### Step 2.2 — Analyze the coverage map

Notice the following gaps (shown in yellow):

* **T1027 — Obfuscated Files or Information**: Encoding detected but no automatic de-obfuscation alerting
* **T1070.004 — File Deletion**: No evidence of log deletion but no monitoring either
* **T1136.001 — Create Local Account**: Not monitored — attacker could have added backdoor account

---

## Part 3: Build a Detection Coverage Map

### Step 3.1 — Create a new layer for detection coverage

In Navigator, create a **new layer** alongside the incident layer.

For each technique in the incident map, score your detection coverage:

* **Score 3** (green): Automated alert exists and tested
* **Score 2** (yellow): Alert exists but not tuned/tested
* **Score 1** (orange): Manual hunt only
* **Score 0** (red): No detection

Example scores for this environment:

| Technique | Coverage Score | Notes |
|-----------|---------------|-------|
| T1566.001 | 2 | Email gateway catches most, not all spear-phishing |
| T1059.001 | 3 | Sysmon + SIEM rule fires on WINWORD → PS chain |
| T1053.005 | 2 | Scheduled task creation monitored, not alerted |
| T1003.001 | 1 | No Mimikatz alert — manual Sysmon hunt required |
| T1021.002 | 2 | Lateral movement alert exists, slow aggregation |
| T1048.002 | 0 | No HTTPS content inspection — DLP not deployed |

### Step 3.2 — Export the comparison

Navigator allows two layers to be displayed simultaneously.
Use the **"Create layer from other layers"** feature to generate a combined view showing techniques detected vs. not detected.

---

## Part 4: Hunt for Undetected Activity

Using the ATT&CK map, identify three techniques that are **likely but unconfirmed** based on the campaign pattern:

**Hypothesis 1 — T1082 (System Information Discovery)**
If the attacker ran `whoami /all` and `net group`, they likely also ran `systeminfo` or queried the registry for OS version.

Hunt query (Sysmon logs):

```text
EventID:1 AND Computer:"WS-JSMITH" AND CommandLine:("systeminfo" OR "ver" OR "Get-WmiObject Win32_OperatingSystem")
```

**Hypothesis 2 — T1552.001 (Credentials in Files)**
After compromising a system, attackers often search for stored credentials in configuration files.

Hunt query:

```text
EventID:1 AND Computer:"WS-JSMITH" AND CommandLine:("password" OR "passwd" OR "credentials" OR "findstr /si password")
```

**Hypothesis 3 — T1070.003 (Clear Command History)**
Sophisticated attackers clear PowerShell history to cover tracks.

Hunt query:

```text
EventID:1 AND Computer:"WS-JSMITH" AND CommandLine:("Clear-History" OR "Remove-Item.*ConsoleHost_history" OR "Set-PSReadlineOption")
```

---

## Part 5: Actor Attribution

Using the observed TTPs, query MITRE ATT&CK to identify threat groups that use this technique combination.

Navigate to: https://attack.mitre.org/groups/

Search for groups that commonly use:

* T1566.001 (Spearphishing Attachment)
* T1059.001 (PowerShell)
* T1003.001 (LSASS Credential Dumping)
* T1021.002 (SMB Lateral Movement)

**Common actors using this combination:**

* **FIN7** — financially motivated, retail/hospitality targeting
* **APT29 (Cozy Bear)** — nation-state, broad targeting
* **TA505** — financially motivated, broad targeting

**Important caveat:** TTP-based attribution is probabilistic.
Many actors use the same tools (especially commodity tools like Metasploit/Cobalt Strike).
Attribution requires additional signals beyond TTPs.

---

## Part 6: Export for Stakeholder Reporting

### Export the ATT&CK layer as an image

Click the camera icon → Export as SVG or PNG.
This image can be included in the Post-Incident Report.

### Export ATT&CK Navigator layer (JSON format)

The JSON can be imported by:

* Other analysts investigating the same campaign
* Threat intelligence platforms (MISP, OpenCTI)
* Detection engineering teams to prioritize new detections

---

## Key Takeaways

1. **IOC-based response is insufficient** — attackers change IPs, domains, and hashes easily. TTPs persist.
1. **ATT&CK gives shared language** — both between analysts and between organizations sharing threat intel.
1. **Coverage maps reveal gaps** — mapping what you *didn't* detect is as valuable as mapping what you did.
1. **Hunting from ATT&CK** — each confirmed technique generates hypotheses for undetected activity using the same tactic.

---

## Discussion Questions

1. The attacker used encoded PowerShell (`-Enc`). This is T1027 (Obfuscation). What detection techniques specifically counter obfuscation?
1. The exfiltration technique (T1048.002) had score 0. What tool or control would provide detection coverage?
1. Can ATT&CK be used to definitively attribute an attack to a specific actor? Why or why not?
1. A colleague argues that ATT&CK is too complex for day-to-day SOC work. How would you respond?
