# Drill 02 Intermediate Solution: Threat Intelligence Report

---

## Task 1: Sample Tactical Intelligence Report

---

**Classification: TLP:AMBER**
**Date: 2024-03-13**
**Title: SWIFT Payment Fraud via Credential Theft — Incident IR-2024-047 IOCs and Detections**
**Reference: IR-2024-047**
**Author: Threat Intelligence Team**
**Distribution: SOC Team, Security Engineering, CISO (per TLP:AMBER)**

---

### Executive Summary

GlobalBank AG experienced a targeted intrusion between March 7-9, 2024, resulting in unauthorized access to the SWIFT payment relay system and fraudulent transaction modifications totaling €700,000 (with €1,400,000 blocked).
The attacker used compromised service account credentials obtained from dark web markets, moved laterally to the SWIFT connector server, and modified payment files.
This report provides technical IOCs, ATT&CK mapping, and immediate detection guidance.

---

### Incident Overview

**Dwell Time:** ~24-36 hours

**Detection Method:** UEBA alert on unusual admin logon pattern

**Impact:** Financial fraud (€700,000 confirmed loss); potential data exposure (unknown scope)

The attacker used legitimate credentials for `svc_reporting@globalbank.ag` (likely obtained from a previous breach or phishing, then sold on Ramp cybercriminal forum approximately Feb 15, 2024) to gain VPN access.
Post-access, they created a persistence account, moved laterally using pass-the-hash, and accessed the SWIFT Connector Server (SWIFT-RELAY-01) where they modified 3 of 412 viewed payment files.

---

### IOC Table

| Indicator | MISP Type | Value | For IDS | Confidence | Context |
|-----------|-----------|-------|---------|------------|---------|
| VPN source IP | `ip-src` | `45.152.66.234` | YES | High | Initial VPN access; may be exit node |
| C2 domain | `domain` | `corporate-reporting-api.com` | YES | High | Cobalt Strike C2 |
| C2 IP | `ip-dst` | `91.92.248.115` | YES | High | Cobalt Strike team server |
| Malware hash | `sha256` | `4c5d6e7f...` (full hash in appendix) | YES | High | Fake svchost.exe on SWIFT relay |
| Malware path | `filename` | `C:\Windows\svchost.exe` | YES | High | NOT legitimate (real = System32) |
| Named pipe | `named-pipe` | `\\.\pipe\GoogleChrome` | YES | High | Cobalt Strike beacon IoC |
| Rogue account | `text` | `svc_monitor_01` | NO | High | Context only; account deleted |

**Note on VPN source IP:** This IP may be a VPN exit node used by multiple users/threats.
Do not block without verification that it is not shared infrastructure.

---

### ATT&CK Technique Mapping

| Phase | Technique ID | Technique Name | Observed |
|-------|-------------|----------------|---------|
| Initial Access | T1078.002 | Valid Accounts: Domain Accounts | svc_reporting credentials used |
| Persistence | T1136.001 | Create Account: Local Account | svc_monitor_01 created |
| Persistence | T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Probable (DC log gap) |
| Lateral Movement | T1550.002 | Pass the Hash | PtH to domain controllers |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | RDP to SWIFT-RELAY-01 |
| Lateral Movement | T1021.006 | Windows Remote Management | WinRM observed |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 |
| Command & Control | T1090 | Proxy (possible) | VPN/proxy to 45.152.66.234 |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name | svchost.exe in wrong path |
| Impact | T1565.002 | Data Manipulation: Transmitted Data Manipulation | SWIFT payment modification |

---

### Immediate Detection Recommendations

**Detection 1: Cobalt Strike Named Pipe Detection**

```splunk
index=sysmon EventID=17 OR EventID=18
  PipeName="\\GoogleChrome" OR PipeName LIKE "%Chrome%"
  NOT (Image="C:\\Program Files\\Google\\Chrome\\*")
| table _time, ComputerName, User, Image, PipeName
```

*Priority: Deploy immediately.
This catches an active C2 technique.*

**Detection 2: svchost.exe Outside System32**

```splunk
index=sysmon EventID=1 Image="*\\svchost.exe"
  NOT Image="C:\\Windows\\System32\\svchost.exe"
  NOT Image="C:\\Windows\\SysWOW64\\svchost.exe"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
```

*Priority: Deploy immediately.
Zero legitimate reason for svchost.exe outside System32.*

**Detection 3: New Local Admin Account Creation Off-Hours**

```splunk
index=wineventlog EventCode=4720
| eval hour=strftime(_time, "%H"), dow=strftime(_time, "%u")
| where (hour < "08" OR hour > "18") OR dow > "5"  -- Outside business hours
| join AccountName [search index=wineventlog EventCode=4732 Group_Name="Administrators"]
| table _time, ComputerName, AccountName, SubjectUserName
```

*Priority: High.
New admin accounts at 03:14 should have been caught immediately.*

---

*[End of Tactical Report - see Appendix for full SHA256 hashes and timeline]*

---

## Task 2: Sample Strategic Intelligence Brief

---

**Classification: TLP:AMBER**
**Date: 2024-03-13**
**To: Chief Information Security Officer**
**From: Threat Intelligence Team**
**Subject: SWIFT Fraud Incident — Strategic Assessment**

---

### What Happened

Between March 7-9, 2024, GlobalBank AG was targeted by a financially motivated threat actor who gained unauthorized access to our SWIFT payment processing system.
The attacker used login credentials for a service account that had been compromised and sold on criminal marketplaces approximately three weeks prior.
Using these credentials, the attacker navigated to our SWIFT payment relay server and modified payment instructions to redirect €2.1 million.
SWIFT's own fraud detection systems blocked two of three fraudulent transactions; one transaction of €700,000 was completed before containment.

**Business Impact:**

* Confirmed financial loss: €700,000
* SWIFT connectivity required temporary suspension during investigation (8 hours)
* Potential regulatory notification obligation under GDPR/NIS2 (Data Protection team engaged)
* Reputational risk if incident becomes public

---

### Threat Landscape Context

SWIFT-targeting fraud is not new, but it is increasingly sophisticated.
Since the 2016 Bangladesh Bank heist ($81 million), threat groups specifically research and target SWIFT connector infrastructure.
The SWIFT ISAC has documented a 34% increase in attempted payment fraud via system compromise in 2023 vs. 2022.
Financial institutions are targeted because the payoff is direct and immediate; attackers do not need to monetize data theft separately.

Our incident follows a pattern seen at 5 other European financial institutions in the past 12 months, suggesting organized criminal groups are systematically targeting the sector.

---

### Attribution Assessment

**Probable actor: DAGGER-FISH (Medium Confidence)**

Our technical team identified similarities with a known criminal group called DAGGER-FISH that has targeted SWIFT systems at other financial institutions.
This is not a confirmed attribution—we share 3 of 5 key behavioral indicators with their known pattern, but lack the forensic certainty required for a definitive statement.
There is also a possibility this could be a copycat group using similar tools.

**What we know:** Financially motivated criminal group, likely operating from Eastern Europe, specializing in SWIFT fraud, with a track record of preparing attacks over 30-45 days before execution.

**Confidence caveat:** We will continue monitoring and may revise this assessment as peer organizations share intelligence.

---

### Strategic Recommendations

1. **Immediate: Credential exposure monitoring program.** The credentials used in this attack were available on criminal marketplaces 3 weeks before the attack. We had access to this information but did not act on it. Establish a formal process: when compromised credentials are found in threat intel feeds, they must be treated as an active incident and immediately revoked and changed.

1. **Short-term: SWIFT "super-segment" network isolation.** SWIFT connector servers should have no direct network path from corporate infrastructure. Implement a dedicated privileged access workstation (PAW) for all SWIFT administration, with no internet access and enhanced monitoring.

1. **Short-term: Privileged account review.** Service accounts like `svc_reporting` should not have VPN access. Audit all service accounts with network access privileges and apply least-privilege principles.

1. **Medium-term: Threat intelligence program maturation.** This incident reveals a gap in our intelligence dissemination process. Raw threat intelligence was available but not translated into action. Invest in a formal process for converting intelligence findings into operational decisions within 24 hours of receipt.

1. **Ongoing: Peer intelligence sharing.** Engage with FS-ISAC SWIFT Working Group to share our TTPs and receive early warning of similar campaigns targeting peers.

---

### What Remains Unknown

* Whether additional data was exfiltrated beyond SWIFT files (investigation ongoing)
* The full lateral movement scope (6-hour log gap limits reconstruction)
* How the original service account credentials were compromised

---

## Task 3: Quality Review Answers

### 1. TLP Downgrade Justification

**Risk taken:** TLP:RED means this information should not leave the immediate group present when it was shared (the IR team).
By downgrading to TLP:AMBER, we are allowing sharing within our organization and with direct clients/partners who need to know.

**Safeguards applied:**

* Removed specific details about the criminal forum (Ramp) from the TLP:AMBER version — knowing which specific dark web forum is sensitive
* Removed information about our specific security control gaps (DC log missing for 6 hours) from the AMBER version — this would help attackers
* Retained TLP:AMBER marking on all shared versions to prevent further distribution
* Did not include the specific bank account details of the fraudulent transactions
* Obtained internal legal/compliance approval before sharing externally

**Best practice:** When downgrading TLP, explicitly document what was removed or modified from the higher-TLP version, and why.

### 2. Attribution Confidence Communication

**How to communicate "medium confidence" without undermining value:**

Use structured language: *"We assess with moderate confidence that this activity is consistent with DAGGER-FISH, based on overlap of 3 of 5 key TTPs."* This:

* Makes the confidence explicit (not hidden)
* States the evidential basis (3/5 TTPs)
* Doesn't say "probably not DAGGER-FISH" (which would suggest we're less certain)
* Allows the reader to make their own assessment

**Avoid:** "It could be DAGGER-FISH, but we're not sure." This undermines the intelligence without adding useful information.

**To increase to high confidence:**

* Independent confirmation from another source (peer bank with same attacker)
* Forensic malware analysis confirming DAGGER-FISH custom tools (not just similar TTPs)
* Law enforcement sharing (FBI, Europol) confirming active case attribution
* Infrastructure overlap (same C2 server used in confirmed prior DAGGER-FISH campaign)

### 3. Intelligence Gaps

| Gap | What We Don't Know | Collection to Fill Gap |
|-----|---------------------|------------------------|
| Credential theft vector | How was svc_reporting's password originally stolen? Phishing? Previous breach? Insider? | Forensic analysis of svc_reporting account history; email security logs; review of all systems where this account authenticated |
| Full exfiltration scope | What else did the attacker access/copy beyond SWIFT files? | Memory forensics on affected systems; full DLP audit; review all file access logs on accessed servers |
| Attacker infrastructure extent | Are there other C2 domains/IPs we don't know about? | Passive DNS pivoting from known C2 IP/domain; certificate transparency search; dark web monitoring for GlobalBank mentions |

### 4. Intelligence Lifecycle Failure

This incident represents a failure in the **Dissemination phase** of the intelligence lifecycle, potentially compounded by a failure in the **Planning and Direction phase**.

**What happened:** The threat intelligence team found the compromised credentials on Ramp forum approximately 3 weeks before the incident.
This represents *collection* and *processing* completing successfully.
However, the intelligence was not effectively *disseminated* to the people who could act on it (the identity/access team, the SOC), or if it was shared, no formal *action process* existed.

**What should have happened:**

1. When credentials are found in dark web monitoring, this should trigger an immediate, time-boxed response (change the password within 4 hours)
1. The PIR (Priority Intelligence Requirement) should have included: "Are any GlobalBank credentials currently exposed?"
1. The dissemination process should have a defined SLA: credential exposure intel → action within 1 business day

This is the difference between intelligence that sits in a report and intelligence that changes decisions.
The former is not intelligence—it's noise.

---

## Grading Notes

**Task 1 common errors:**

* Including full SHA256 hashes in tactical report is correct; students should not over-sanitize tactical intelligence
* Named pipe should be listed as IOC (it's a specific Cobalt Strike indicator)
* Students often miss T1558.001 (Golden Ticket) because it's implied, not explicitly stated

**Task 2 common errors:**

* Using technical jargon (hashes, PIDs, Cobalt Strike) in executive brief
* Not providing business impact in concrete terms (€ amounts, regulatory implications)
* Missing the "what we don't know" section (critical for CISO risk understanding)

**Task 3, Q4:** Accept any reasonable identification of the lifecycle phase failure.
The key insight is that intelligence without action is useless.
Award full points for any answer that identifies the dissemination/action gap and proposes a solution.
