# Final Practice Quiz: Session 07 — Cyber Threat Hunting and Intelligence Gathering

**Format:** 5 short-answer questions + 2 long-answer questions

**Time:** 45-60 minutes

**Purpose:** Consolidate learning and practice applying concepts before the final assessment

---

## Part A: Short Answer Questions (5 × 10 points = 50 points)

Answer each question in 3-5 sentences.

---

### Question 1: Hypothesis Formation

A threat hunter at a financial company reads a new report stating that a ransomware group is using **scheduled tasks** for persistence (ATT&CK T1053.005) and **NTDS.dit extraction** for credential theft (T1003.003).

Write ONE complete hunting hypothesis that targets the NTDS.dit extraction technique.
Your hypothesis must include: the threat scenario, the specific observable evidence, the data source, and the time window.

**Sample Strong Answer:**
> "If the ransomware group has established a foothold in our financial organization environment and is using NTDS.dit extraction for credential theft (T1003.003), I would expect to observe processes such as `vssadmin.exe` creating volume shadow copies, followed by copying operations targeting `%SYSTEMROOT%\NTDS\ntds.dit` or accessing the file via the shadow copy path (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\NTDS\ntds.dit`), visible in Windows Security Event ID 4663 (file access auditing on the NTDS directory) and Sysmon Event ID 11 (file create) logs on all domain controllers over the past 30 days."

**What makes this strong:**

* Specific technique (T1003.003)
* Named process (vssadmin.exe) and the file path
* Named data source (Event ID 4663, Sysmon EID 11)
* Specific target system type (domain controllers)
* Time window specified

---

### Question 2: Sigma Rule Concepts

Explain the difference between a Sigma rule's `selection` block and `filter` block.
Give a specific example of when you would use a `filter` block in a rule designed to detect Mimikatz-style LSASS memory access.

**Sample Strong Answer:**
> A **selection** block defines what events to match — the positive indicators of suspicious activity. A **filter** block defines known-legitimate events to exclude from the selection to reduce false positives. In a Sigma rule detecting LSASS memory access (T1003.001), the selection would match Sysmon Event ID 10 events where the TargetImage ends with `\lsass.exe` and the GrantedAccess value includes `0x1fffff` or `0x1410` (common Mimikatz access masks). The filter would exclude known-legitimate processes that also access LSASS for security purposes, such as `MsMpEng.exe` (Windows Defender), `SenseIR.exe` (Microsoft Defender for Endpoint), and `csrss.exe` (Windows system process). The condition would then be `selection and not filter`, meaning: match LSASS access events that are not from known-legitimate security tools.

---

### Question 3: TLP Application

Your incident response team has just finished handling an intrusion.
The IR report contains: (a) IOCs of the attacker's infrastructure, (b) the specific CVE that was exploited, (c) your internal network architecture that the attacker mapped during discovery, and (d) the name of the attacker group with medium-confidence attribution.

For each of the four elements, specify which TLP level you would apply and briefly justify your choice.

**Sample Strong Answer:**
> **(a) IOCs (infrastructure IOCs):** TLP:AMBER — These should be shared with your sector ISAC and trusted peers to enable them to block the same infrastructure. Not fully public yet as the attacker may rotate if they learn it's been detected, but valuable for community defense.
>
> **(b) CVE exploited:** TLP:GREEN — Vulnerability disclosures are generally public information once a CVE exists. Sharing this with the community enables patching and defense. If it's a zero-day not yet disclosed, treat as TLP:AMBER until publicly disclosed.
>
> **(c) Internal network architecture:** TLP:RED — Your network architecture is sensitive internal information. Sharing it would help attackers who haven't yet targeted you. This must not leave the incident response team. Keep TLP:RED.
>
> **(d) Attribution (medium confidence):** TLP:AMBER — Attribution information should be shared with trusted peers (ISAC, H-ISAC) to correlate with other incidents and improve collective intelligence, but the medium confidence level and potential for defamation claims means it should not be made fully public yet.

---

### Question 4: OSINT Investigation

You are investigating a suspicious domain: `support-auth-globalcorp[.]com`.
Describe the step-by-step OSINT investigation process you would follow, naming at least 4 tools you would use and what specific information you would seek from each.

**Sample Strong Answer:**
> **Step 1 — WHOIS (whois.com or command line):** Check registration date (very new = suspicious), registrar, registrant (often privacy-protected for malicious domains), and name servers. A domain registered < 30 days ago with privacy protection and bulletproof hosting NS is a major red flag.
>
> **Step 2 — VirusTotal (virustotal.com):** Check the domain's detection rate across security vendors, first submission date, historical resolutions (which IPs has this domain pointed to?), and the Relations tab for linked files and URLs.
>
> **Step 3 — crt.sh (Certificate Transparency):** Search for `%.support-auth-globalcorp.com` to discover subdomains that have received TLS certificates. This reveals the full scope of the domain's infrastructure (staging, admin, api subdomains, etc.).
>
> **Step 4 — Shodan (shodan.io):** Investigate the IP address this domain resolves to. Check what ports are open, what services are running, what certificates are present. A Cobalt Strike default port (50050) or a self-signed cert would confirm malicious use.
>
> **Step 5 — URLScan (urlscan.io):** Submit the domain for safe analysis. See what the webpage looks like, what other domains/IPs it loads, and whether there are any malicious redirect chains or phishing page indicators.

---

### Question 5: Intelligence Types

A CISO asks your threat intelligence team to answer three questions:

1. "Are any of our employee email addresses currently in criminal marketplaces?"
1. "What TTPs is the FIN7 ransomware group currently using in our sector?"
1. "What is the overall ransomware threat trend for healthcare organizations over the next 18 months?"

For each question, identify whether it requires tactical, operational, or strategic intelligence, and explain what the intelligence product should look like.

**Sample Strong Answer:**
> **Question 1 — Tactical Intelligence:** This is a tactical question requiring specific, actionable IOC-level information (credential exposure is immediate and enables a direct action: password reset). The intelligence product should be a **Flash Alert** delivered within 4 hours of detection, listing the compromised email addresses, the source where they were found (forum name if TLP permits), and immediate recommended actions (reset password, enable MFA, notify affected users).
>
> **Question 2 — Operational Intelligence:** This requires understanding of a specific threat actor's current campaign activity — a mid-level question about who is doing what, now. The product should be a **Threat Actor Brief** (2-4 pages) covering current TTP profile mapped to ATT&CK, recent campaigns, tools used (Cobalt Strike configurations, custom malware), and tailored hunting recommendations for the CISO's sector. Shared weekly or when significant changes are observed.
>
> **Question 3 — Strategic Intelligence:** This is a long-horizon trend question informing investment and risk decisions. The product should be a **Threat Landscape Assessment** (5-10 pages) covering ransomware ecosystem trends, healthcare-specific targeting patterns, emerging tactics (AI-generated phishing, double extortion evolution), regulatory risk, and strategic recommendations for the CISO to present to the board. Produced quarterly.

---

## Part B: Long Answer Questions (2 × 25 points = 50 points)

---

### Question 6: Data-Driven Hunt Scenario (25 points)

Your SOC analyst has flagged an unusual pattern during a routine review.
The following Splunk query was run against 90 days of data:

```splunk
index=sysmon EventID=1
| stats count as process_count by ParentImage, Image
| sort count asc
| head 20
```

The results include this row:

```text
ParentImage: C:\Windows\SysWOW64\msiexec.exe
Image:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Count:       1
```

The analyst also found Sysmon EventID=3 (NetworkConnect) records showing this PowerShell instance connected to `45.89.125.203:443` 30 seconds after launch.

**Answer the following:**

a) **Assessment (5 pts):** Is this suspicious?
Explain your reasoning step-by-step.
What would make you more or less concerned?

b) **Investigation Steps (10 pts):** Write 3 Splunk queries you would run to investigate this finding further.
Describe what each query is looking for.

c) **Hypothesis (5 pts):** Write a formal hunting hypothesis based on this initial finding.

d) **Detection (5 pts):** Write a Sigma rule (correct YAML format) that would detect this specific behavior (msiexec spawning PowerShell).

**Sample Strong Answer:**

**a) Assessment:**
> This is **highly suspicious** and warrants immediate investigation. The parent-child relationship (msiexec.exe → powershell.exe) is not a standard Windows behavior. Legitimate software installers do not typically launch PowerShell as a child process; installation logic runs within msiexec itself. The combination of: (1) unusual parent-child relationship, (2) only 1 occurrence in 90 days (rare = suspicious under stack counting), and (3) immediate network connection to an external IP on port 443 within 30 seconds, strongly suggests a malicious installer or a lure file executing a PowerShell downloader/stager. The count of 1 would be less concerning if we had evidence it corresponded to a known software installation (verifiable via change management).

**b) Investigation Queries:**

```splunk
-- Query 1: Full context around the event
index=sysmon EventID=1 ParentImage="*\\msiexec.exe"
  Image="*\\powershell.exe"
| table _time, ComputerName, User, CommandLine, ParentCommandLine, MD5
```

*Purpose: Get full command line of both msiexec and PowerShell to understand what was being installed and what PowerShell was told to do.*

```splunk
-- Query 2: Network activity from same host around same time
index=sysmon EventID=3
  (Image="*\\powershell.exe" OR Image="*\\msiexec.exe")
  DestinationIp="45.89.125.203"
| table _time, ComputerName, User, Image, DestinationIp, DestinationPort, Initiated
```

*Purpose: Confirm all network connections to this IP; check if other processes on the same host connected to the same destination.*

```splunk
-- Query 3: What else happened on that host that day?
| inputlookup [search index=sysmon EventID=1
               ParentImage="*\\msiexec.exe"
               Image="*\\powershell.exe"
               | head 1 | fields ComputerName]
index=sysmon ComputerName="<HOSTNAME>"
  earliest=-2h latest=+2h relative to the suspicious event
| table _time, EventID, Image, CommandLine, TargetFilename, DestinationIp
| sort _time
```

*Purpose: Build the full timeline of what happened on this host around the suspicious event.*

**c) Hypothesis:**
> "If a threat actor is using a malicious installer (MSI file) to execute a PowerShell stager as part of an initial compromise attempt (T1218.007, T1059.001), I would expect to observe msiexec.exe spawning PowerShell with download/execution arguments, followed by a network connection to an attacker-controlled IP within 60 seconds, visible in Sysmon EventID 1 and 3 logs across all Windows workstations and servers over the past 30 days."

**d) Sigma Rule:**

```yaml
title: MSIExec Spawning PowerShell Shell
id: f7a8b9c0-d1e2-3456-789a-bcde01234567
status: experimental
description: |
  Detects msiexec.exe spawning PowerShell, which may indicate a
  malicious MSI installer used as an initial access vector.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\msiexec.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Very rare; some custom enterprise software deployments
    - Verify against software change management before closing
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1218.007
```

---

### Question 7: MISP Event Design (25 points)

You are a threat intelligence analyst at a healthcare company.
After completing a threat hunt, you have confirmed the following:

* **Compromised system:** HOSP-WS-0234
* **Initial access:** Malicious LNK file in a ZIP archive sent via phishing
* **Dropper hash (SHA256):** `9f8e7d6c5b4a3928374655647382910a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e`
* **C2 IP:** `91.92.248.50`
* **C2 Domain:** `health-analytics-cdn[.]net`
* **Malware:** In-memory only (no file dropped after initial stage)
* **Data accessed:** Patient scheduling database
* **TLP:** AMBER (shared with H-ISAC)
* **Suspected group:** VIPER-HEALTH (medium confidence, 4/5 TTP overlap)

**Design the MISP event structure** by answering:

a) **(5 pts)** Write the event metadata (info string, threat level, analysis, distribution, tags including TLP and minimum 3 ATT&CK).

b) **(10 pts)** List all attributes with: type, value, to_ids flag (true/false), and a one-sentence comment for each.
Justify why you set to_ids to true or false for each.

c) **(5 pts)** Design one MISP Object for the LNK file dropper.
List all relevant object attributes.

d) **(5 pts)** Write a YARA rule (as a MISP `yara` attribute) targeting the C2 domain/infrastructure.
Include at least 3 strings and an appropriate condition.

**Sample Strong Answer:**

**a) Event Metadata:**

```yaml
info: "VIPER-HEALTH Phishing Campaign - Healthcare Sector - LNK Dropper"
threat_level_id: 1  # High
analysis: 1         # Ongoing (host still under investigation)
distribution: 1     # This community only (TLP:AMBER scope)
tags:
  - "tlp:amber"
  - "mitre-attack:initial-access:T1566.001"     # Spearphishing attachment
  - "mitre-attack:execution:T1204.002"           # User execution malicious file
  - "mitre-attack:command-and-control:T1071.001" # Application layer protocol
  - "kill-chain:delivery"
  - "healthcare"
```

**b) Attributes:**

| Type | Value | to_ids | Comment |
|------|-------|--------|---------|
| sha256 | `9f8e7d6c...` | TRUE | LNK dropper file hash; block in EDR |
| ip-dst | `91.92.248.50` | TRUE | C2 server IP; block at firewall immediately |
| domain | `health-analytics-cdn.net` | TRUE | C2 domain; block at DNS filter |
| filename | [malicious].lnk | FALSE | Filename alone insufficient; too generic, high FP risk |
| text | `VIPER-HEALTH` | FALSE | Attribution note; context only, not actionable for detection |
| text | `Patient scheduling database accessed on HOSP-WS-0234` | FALSE | Context/victim data; not detection-relevant |

**to_ids rationale:** Set TRUE only for indicators that can trigger automated detection with high confidence and low false positive risk.
The hash and C2 indicators are specific and high-confidence.
The filename alone would block any `.lnk` file (too many legitimate ones).
Attribution text is purely contextual.

**c) LNK Object:**

```yaml
object_type: "file"
attributes:
  - type: "filename"
    value: "Q1_Reports_2024.zip.lnk"
    to_ids: false
  - type: "sha256"
    value: "9f8e7d6c5b4a3928374655647382910a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"
    to_ids: true
  - type: "mimetype"
    value: "application/x-ms-shortcut"
    to_ids: false
  - type: "malware-sample"
    value: "Q1_Reports_2024.zip.lnk"
    comment: "LNK file used as initial dropper in phishing attack"
    to_ids: false
```

**d) YARA Rule:**

```yara
rule VIPER_HEALTH_C2_Infrastructure {
    meta:
        author = "Healthcare TI Team"
        description = "VIPER-HEALTH C2 infrastructure indicators"
        tlp = "AMBER"
        date = "2024-03-15"
        confidence = "medium"
    strings:
        $domain1 = "health-analytics-cdn.net" ascii wide
        $domain2 = "health-analytics-cdn" ascii wide
        $ip1 = "91.92.248.50" ascii
        $ua1 = "HealthAnalyticsClient/2.1" ascii  // custom UA seen in traffic
        $path1 = "/api/v2/health-data" ascii       // C2 path pattern
    condition:
        ($domain1 or $domain2 or $ip1) and
        (1 of ($ua*, $path*))
}
```

---

*End of Final Practice Quiz*

*Review any areas where your answers differed significantly from the sample answers.
Re-read the relevant sections of the Session 07 reading material.*
