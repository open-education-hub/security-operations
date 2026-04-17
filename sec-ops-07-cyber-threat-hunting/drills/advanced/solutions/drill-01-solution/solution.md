# Drill 01 Advanced Solution: Full APT Threat Hunting Exercise

---

## Task 1: ATT&CK Kill Chain Mapping

### Complete Timeline and Technique Mapping

| Date/Time | Event | System | ATT&CK ID | Technique | Confidence |
|-----------|-------|--------|-----------|-----------|------------|
| ~Feb 05-10 (est.) | Spearphishing email sent to l.wagner | Email gateway | T1566.001 | Spearphishing Attachment | Inferred |
| 2024-02-12 ~14:20 | l.wagner opens malicious doc, executes doc_viewer.exe | ENGWS-l.wagner-001 | T1204.002 | User Execution: Malicious File | Confirmed |
| 2024-02-12 14:22:01 | Obfuscated PowerShell executed from doc_viewer.exe | ENGWS-l.wagner-001 | T1059.001, T1027 | PowerShell + Obfuscation | Confirmed |
| 2024-02-12 14:22:09 | PowerShell connects to C2 (193.142.147.15:443) | ENGWS-l.wagner-001 | T1071.001 | Application Layer Protocol: Web | Confirmed |
| 2024-02-12 14:22:33 | FALCON-GATE implant (Siemens_Updater.exe) dropped | ENGWS-l.wagner-001 | T1105 | Ingress Tool Transfer | Confirmed |
| 2024-02-12 14:23:15 | Registry Run key set for persistence | ENGWS-l.wagner-001 | T1547.001 | Registry Run Keys | Confirmed |
| 2024-02-12 ongoing | C2 beaconing to siemens-software-updates.de | ENGWS-l.wagner-001 | T1071.001 | HTTPS C2 | Confirmed |
| 2024-02-15 02:14:33 | Lateral movement to ENG-SRV-001 via l.wagner credentials | ENG-SRV-001 | T1021.002, T1078.002 | SMB/Windows Admin Shares + Valid Account | Confirmed |
| 2024-02-15 02:31:05 | Lateral movement to CAD-SRV-002 | CAD-SRV-002 | T1021.002 | SMB Lateral Movement | Confirmed |
| 2024-02-15 02:45:19 | Access to backup server | BACKUP-SRV-01 | T1021.002 | SMB | Confirmed |
| 2024-02-15 03:15:44 | net use command to map backup share | BACKUP-SRV-01 | T1021.002 | SMB | Confirmed |
| 2024-02-20 03:05:11 | Kerberoasting: RC4 Kerberos ticket for svc_backup | DC | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Confirmed |
| 2024-03-01-05 | svc_backup RDP to engineering servers (cracked password used) | Multiple servers | T1021.001, T1078 | RDP + Valid Account | Confirmed |
| 2024-03-08 09:15:22 | Directory listing of PropulsionX9 project | CAD-SRV-002 | T1083 | File and Directory Discovery | Confirmed |
| 2024-03-08 09:18:44 | RAR archive of PropulsionX9 with password | CAD-SRV-002 | T1560.001 | Archive Collected Data: Local Data Staging | Confirmed |
| 2024-03-08 09:44:01 | Exfiltration of ~370MB to C2 | CAD-SRV-002 | T1041 | Exfiltration Over C2 Channel | Confirmed |
| 2024-03-08 09:44:02 | Archive deleted post-exfiltration | CAD-SRV-002 | T1070.004 | Indicator Removal: File Deletion | Confirmed |

### Attribution Assessment

**Assessment: HIGH CONFIDENCE IRON-FALCON**

**Evidence supporting IRON-FALCON attribution:**

1. Domain naming pattern `siemens-software-updates.de` exactly matches known IRON-FALCON pattern of impersonating industrial software vendors (BSI advisory mentions Siemens, Honeywell, Schneider)
1. Let's Encrypt certificate on C2 domain — matches known IRON-FALCON infrastructure pattern
1. Infrastructure hosted in Germany (IP 193.142.147.15 is in Germany) — matches known preference
1. Kerberoasting + RDP lateral movement — matches known TTPs
1. Target profile: Aerospace/propulsion technology — exactly IRON-FALCON's stated target set
1. Dwell time: 24 days from initial access to exfiltration — within 45-90 day range, slightly fast but consistent
1. FALCON-GATE custom implant named "Siemens_Updater" — consistent with custom tool usage

**TTP overlap with BSI advisory:** 11/12 confirmed TTPs match IRON-FALCON

**Confidence caveats:**

* We have not confirmed malware binary analysis to verify it is the FALCON-GATE family specifically
* Tool sharing with other groups possible but unlikely given custom implant

---

## Task 2: Diamond Model Analysis

### Adversary

* **Assessment:** IRON-FALCON (high confidence)
* **Sponsorship:** Foreign intelligence service (nation-state)
* **Motivation:** IP theft - specifically propulsion technology
* **Operational sophistication:** High - custom malware, patient dwell time, specific targeting
* **Operational timezone:** Activity at 02:00-04:00 CET (Europe) and 09:00-10:00 CET suggests operation from UTC+3 to UTC+5 timezone

### Infrastructure
| Asset | Type | Value | Status |
|-------|------|-------|--------|
| siemens-software-updates.de | C2 domain | 193.142.147.15 | Active (at time of hunt) |
| support.siemens-software-updates.de | C2 subdomain | 193.142.147.15 | Active |
| api.siemens-software-updates.de | C2 subdomain | 193.142.147.15 | Active |
| 193.142.147.15 | C2 IP | ASN TBD | Active |
| Let's Encrypt certificate | Infrastructure cert | Fingerprint TBD | Active |

**Infrastructure patterns:**

* Domain: [vendor]-software-updates.de/com pattern
* IP: German/Dutch hosting (known preference)
* Certificate: Let's Encrypt (fast, automated, anonymous)

### Capability
| Capability | Type | Purpose |
|-----------|------|---------|
| doc_viewer.exe + PowerShell dropper | Custom + commodity | Initial stage |
| Siemens_Updater.exe (FALCON-GATE) | Custom implant | Persistence + C2 |
| Obfuscated PowerShell | Modified commodity | Execution |
| Kerberoasting | Commodity technique | Credential access |
| rar.exe with encryption | Commodity tool | Data preparation |

**Sophistication assessment:** High - uses mix of custom implants (indicates significant investment) and commodity tools (to avoid attributability).

### Victim

* AeroSpace Dynamics GmbH
* Focus: PropulsionX9 project data (~377MB of design files)
* Why targeted: Tier-1 supplier to European defense programs; propulsion technology has significant military value
* Secondary impact: Credentials for backup systems obtained (potential future access)

### Pivoting Opportunities

**Pivot 1: IP to other victims**
Search passive DNS records for 193.142.147.15: "What other domains resolved to this IP?
What other organizations accessed these domains?"

**Pivot 2: Domain naming pattern**
Search for other domains registered with pattern `[vendor]-software-updates.[country]` in certificate transparency logs and domain registration databases.
This may reveal other IRON-FALCON infrastructure not yet identified.

**Pivot 3: doc_viewer.exe hash**
Submit MD5 `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6` to VirusTotal and malware analysis services.
If this is a known IRON-FALCON dropper, there may be previous reports identifying other TTPs or infrastructure we haven't seen in this intrusion.

---

## Task 3: Sigma Rules

### Rule 1: Registry Run Key Set by Unusual Parent

```yaml
title: Registry Persistence via Run Key Set by Non-System Parent
id: a1b2c3d4-e5f6-7890-ab12-cd34ef567890
status: stable
description: |
  Detects setting of HKCU or HKLM Run registry keys by processes
  that are not typical system processes. Particularly alerts on
  registry persistence set by processes in user profile directories.

  IRON-FALCON was observed setting persistence via HKCU Run key using
  a malicious implant (Siemens_Updater.exe) dropped in AppData.
references:
    - https://attack.mitre.org/techniques/T1547/001/
author: Hunt Team
date: 2024/03/15
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
    filter_system:
        Image|startswith:
            - 'C:\Windows\system32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_installer:
        Image|endswith:
            - '\msiexec.exe'
            - '\setup.exe'
            - '\install.exe'
            - '\Update.exe'
    condition: selection and not filter_system and not filter_installer
falsepositives:
    - Software installers writing to Run keys from temp directories
    - Some legitimate user-space software (verify with software inventory)
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

### Rule 2: Kerberoasting via RC4 Ticket Request

```yaml
title: Kerberoasting via Weak RC4 Encryption Kerberos Ticket Request
id: b2c3d4e5-f6a7-8901-bc23-de45fa678901
status: stable
description: |
  Detects Kerberos service ticket requests using RC4 encryption (etype 0x17/23).
  Modern Active Directory uses AES encryption by default; RC4 requests typically
  indicate Kerberoasting attacks attempting to crack service account passwords offline.

  IRON-FALCON used Kerberoasting to obtain svc_backup credentials for lateral movement.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://adsecurity.org/?p=3458
author: Hunt Team
date: 2024/03/15
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'  # RC4-HMAC
    filter_machine_accounts:
        AccountName|endswith: '$'   # Machine accounts use RC4 legitimately
    filter_admin:
        ServiceName: 'krbtgt'      # TGT requests are normal
    condition: selection and not filter_machine_accounts and not filter_admin
falsepositives:
    - Legacy applications requiring RC4 Kerberos (disable RC4 if possible)
    - Some Windows 7 clients (legacy; should be phased out)
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
```

### Rule 3: Service Account Using Interactive RDP

```yaml
title: Service Account Using RDP Interactive Logon
id: c3d4e5f6-a7b8-9012-cd34-ef56789012ab
status: experimental
description: |
  Detects service accounts (naming pattern svc_*, svc-*, service_*)
  authenticating via RDP (LogonType 10). Service accounts should not
  require interactive desktop sessions; this pattern indicates credential
  theft and misuse.

  IRON-FALCON used a cracked svc_backup account for RDP lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/001/
    - https://attack.mitre.org/techniques/T1078/
author: Hunt Team
date: 2024/03/15
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10       # RemoteInteractive (RDP)
        TargetUserName|startswith:
            - 'svc_'
            - 'svc-'
            - 'service_'
            - 'srv_'
    filter_helpdesk:
        SubjectUserName: 'helpdesk_rds'   # Known legitimate exception
    condition: selection and not filter_helpdesk
falsepositives:
    - Break-glass scenarios (documented in change management)
    - Some RDS/Citrix configurations using service accounts (rare)
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.001
    - attack.credential_access
    - attack.t1078
```

### Rule 4: RAR Archive with Encryption/Password

```yaml
title: RAR Archive Creation with Password Encryption
id: d4e5f6a7-b8c9-0123-de45-f6789012bcd3
status: stable
description: |
  Detects creation of password-protected RAR archives using command-line
  flags that enable encryption (-hp encrypts headers, -p sets password).
  This is a common technique for staging sensitive data before exfiltration,
  as encrypted archives bypass DLP content inspection.

  IRON-FALCON archived PropulsionX9 project data with encryption before exfiltrating.
references:
    - https://attack.mitre.org/techniques/T1560/001/
author: Hunt Team
date: 2024/03/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_rar:
        Image|endswith:
            - '\rar.exe'
            - '\WinRAR.exe'
    selection_encryption:
        CommandLine|contains:
            - ' -hp'    # Encrypt headers (stronger than -p)
            - ' -p '    # Password
    condition: selection_rar and selection_encryption
falsepositives:
    - Legitimate encrypted backup operations (verify with IT)
    - Some legal/compliance archival processes
level: medium
tags:
    - attack.collection
    - attack.t1560.001
    - attack.exfiltration
```

### Rule 5: Large HTTPS Outbound Transfer Anomaly

```yaml
title: Large HTTPS Data Transfer to External Destination
id: e5f6a7b8-c9d0-1234-ef56-78901234cde5
status: experimental
description: |
  Detects large data transfers (>100MB) via HTTPS to external destinations.
  Requires network connection data with bytes_out field from proxy or firewall.
  May indicate data exfiltration over the C2 channel.

  Note: This rule requires tuning based on environment. Large file transfers
  to known cloud providers (SharePoint, Dropbox, OneDrive) may need filtering.

  IRON-FALCON exfiltrated ~370MB of design files over HTTPS to C2 server.
references:
    - https://attack.mitre.org/techniques/T1041/
author: Hunt Team
date: 2024/03/15
logsource:
    category: proxy
    product: generic
detection:
    selection:
        dst_port: 443
        bytes_out|gte: 104857600  # 100MB in bytes
    filter_known_cloud:
        dst_host|contains:
            - '.sharepoint.com'
            - '.onedrive.com'
            - '.dropbox.com'
            - '.box.com'
            - '.google.com'
            - '.microsoftonline.com'
    condition: selection and not filter_known_cloud
falsepositives:
    - Legitimate large file transfers to business partners
    - Software updates/downloads (add destination hosts to filter)
    - Video conferencing (Zoom, Teams - add to filter)
level: medium
tags:
    - attack.exfiltration
    - attack.t1041
```

---

## Task 4: Hunt Report Summary

*(Full format given; students should expand each section)*

```text
HUNT REPORT: HUNT-2024-ADB-007
Classification: TLP:AMBER
Date: 2024-03-15
Hunter: [Name]

EXECUTIVE SUMMARY (CISO)
AeroSpace Dynamics has suffered a targeted intrusion by a nation-state-level
threat actor (assessed with high confidence as IRON-FALCON). The attacker
gained access on February 12, 2024 via a phishing email sent to engineer
L. Wagner, maintained presence for 24 days, escalated to multiple engineering
servers, and exfiltrated approximately 370MB of PropulsionX9 propulsion
system design files on March 8. No evidence of destructive activity.
Incident response must begin immediately.

ATTACK TIMELINE: [see Task 1 table]

ATTRIBUTION: IRON-FALCON, high confidence (11/12 TTP overlap with BSI advisory)

BUSINESS IMPACT:
- PropulsionX9 design data (377MB) exfiltrated to nation-state adversary
- Potential compromise of competitive advantage / defense program data
- Regulatory notification may be required (NIS2, German IT Security Act §8b)
- Customer notification obligation if propulsion data is customer IP

IMMEDIATE ACTIONS REQUIRED:

1. Isolate ENGWS-l.wagner-001, CAD-SRV-002, ENG-SRV-001, BACKUP-SRV-01

2. Reset all credentials for l.wagner, svc_backup, and any other accounts
   that authenticated from 10.45.0.88
3. Block 193.142.147.15 and siemens-software-updates.de at perimeter
4. Notify PropulsionX9 project stakeholders (management decision)
5. Engage cyber incident response firm with APT forensics capability
```

---

## Task 5: MISP Event Structure (Key Elements)

```yaml
event:
  info: "IRON-FALCON Intrusion - AeroSpace Dynamics - PropulsionX9 Data Exfiltration"
  threat_level_id: 1  # Critical
  analysis: 1         # Ongoing (IR in progress)
  distribution: 0     # Internal only (TLP:AMBER)
  tags:
    - "tlp:amber"
    - "mitre-attack:initial-access:T1566.001"
    - "mitre-attack:execution:T1059.001"
    - "mitre-attack:persistence:T1547.001"
    - "mitre-attack:credential-access:T1558.003"
    - "mitre-attack:lateral-movement:T1021.001"
    - "mitre-attack:exfiltration:T1041"
    - "kill-chain:actions-on-objectives"

  galaxy_clusters:
    - galaxy: "Threat Actor"
      cluster: "IRON-FALCON"
    - galaxy: "Malware"
      cluster: "FALCON-GATE"

  attributes:
    - type: "ip-dst"
      value: "193.142.147.15"
      to_ids: true
      comment: "IRON-FALCON C2 server"
    - type: "domain"
      value: "siemens-software-updates.de"
      to_ids: true
    - type: "md5"
      value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
      to_ids: true
      comment: "doc_viewer.exe dropper"
    - type: "yara"
      to_ids: true
      value: |
        rule IRON_FALCON_Siemens_Updater_Implant {
            meta:
                author = "AeroSpace Dynamics Threat Hunt"
                description = "IRON-FALCON FALCON-GATE implant masquerading as Siemens updater"
                tlp = "AMBER"
                date = "2024-03-15"
            strings:
                $s1 = "Siemens_Updater" ascii wide
                $s2 = "siemens-software-updates" ascii wide
                $s3 = "/q" ascii
                $path1 = "AppData\\Roaming\\Microsoft\\" ascii wide
                $ua1 = "SiemensUpdateClient/1.0" ascii wide
            condition:
                uint16(0) == 0x5A4D and
                2 of ($s*) and
                1 of ($path*, $ua*)
        }
```

---

## Bonus Task Answers

### Bonus 1: Python MISP to Splunk CSV

```python
from pymisp import PyMISP
import csv

misp = PyMISP('https://your-misp', 'api-key', ssl=False)
event = misp.get_event(EVENT_ID, pythonify=True)

with open('apt_iocs_splunk.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['type', 'value', 'comment', 'confidence'])
    for attr in event.attributes:
        if attr.to_ids:
            writer.writerow([attr.type, attr.value, attr.comment, 'high'])
```

### Bonus 3: Domain Social Engineering

The domain `siemens-software-updates.de` exploits:

* **Authority**: Siemens is a trusted industrial software vendor with genuine update infrastructure
* **German TLD (.de)**: Appears locally relevant, consistent with German Siemens operations
* **Urgency cue** ("updates"): Updates feel like something that needs action
* **Legitimate-looking pattern**: "vendor + software + updates + country" is exactly what corporate update domains look like

**Controls to prevent this:**

1. Email Security Gateway with domain age check (< 60 days = flag)
1. DNS resolver that checks against known threat intel (e.g., Pi-hole with threat feeds, Cisco Umbrella)
1. Web proxy with SSL inspection and category filtering
1. Employee awareness training on typosquatting and domain impersonation
1. Strict software update policies (all updates through SCCM/WSUS only, no user-initiated downloads)
