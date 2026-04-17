# Solution: Project 02 — Full Incident Analysis Workflow

**Project:** SEC-OPS-PROJ-02

**Covers:** Sessions 06–08

---

## Overview

This solution provides model answers and scoring guidance for each part of the incident investigation.
The artefact dataset is designed to reveal a targeted Cobalt Strike intrusion against Caldera Pharmaceuticals.
Students should independently reach these conclusions through evidence-based analysis.

---

## Incident Summary (Answer Key)

**What happened:** A targeted threat actor gained initial access via a spearphishing email with a weaponised Word document.
The macro dropped a Cobalt Strike Beacon which established C2 communications.
The attacker moved laterally from `WS-CALDERA-014` to `WS-CALDERA-022` and likely accessed the `\\fileserver\research\` share containing pharmaceutical R&D documents.

**Timeline (key events):**

| Time (UTC) | Event |
|-----------|-------|
| 2024-11-13T05:58:22Z | Phishing email received, user `jbrown` opens Word attachment |
| 2024-11-13T05:59:04Z | WINWORD.EXE spawns cmd.exe → PowerShell → drops `svchost32.exe` to `C:\Users\jbrown\AppData\Local\Temp\` |
| 2024-11-13T06:00:11Z | `svchost32.exe` achieves persistence via Scheduled Task `\Microsoft\Windows\Update Checker` |
| 2024-11-13T06:12:04Z | First C2 beacon to `analytics-cdn.caldera-updates.net` (resolved to `198.51.100.47`) |
| 2024-11-13T07:15:33Z | Lateral movement: `WS-CALDERA-014` authenticates to `WS-CALDERA-022` via SMB (Event 4624, LogonType 3) |
| 2024-11-13T07:31:07Z | Second Beacon dropped on `WS-CALDERA-022` |
| 2024-11-13T07:43:00Z | SIEM alert fires (DNS monitoring detects C2 domain) |

---

## Part 1 Model Answer — Triage Note

```markdown
# Triage Note — INC-2024-1147 — 2024-11-13T07:55Z

- Confirmed: Both WS-CALDERA-014 and WS-CALDERA-022 beaconing to 198.51.100.47 (analytics-cdn.caldera-updates.net)
- First beacon observed: 2024-11-13T06:12Z — over 90 minutes BEFORE alert fired (detection gap)
- Domain registered 2024-11-08 — 5 days old, classic "recently registered for attack" indicator
- Domain resolves to Bulletproof hosting AS (AS12345 — known to host malicious infrastructure)
- User jbrown is the primary victim — logged into WS-CALDERA-014 at time of compromise
- Suspicious binary svchost32.exe present in C:\Users\jbrown\AppData\Local\Temp\ — NOT a legitimate Windows process
- Lateral movement confirmed: 014 → 022 at 07:15Z, approximately 63 minutes after initial compromise
- Immediate actions required:

  1. Network block 198.51.100.47 and analytics-cdn.caldera-updates.net NOW

  2. Isolate WS-CALDERA-014 and WS-CALDERA-022 from the network
  3. Determine if any other hosts contacted the C2 domain (query SIEM for all DNS lookups of analytics-cdn.caldera-updates.net across all hosts)
- Status: Active incident — attacker likely still has access via scheduled task on both hosts
```

---

## Part 2 Model Answer — Network Forensics

**Key findings from PCAP analysis:**

```python
# Beaconing analysis — connections to 198.51.100.47:443
# Expected output: connections at ~60s intervals with ±30% jitter
# 06:12:04, 06:13:07, 06:14:02, 06:15:03, ... (every ~60 seconds)

# tshark command to extract TCP connection times
tshark -r /artefacts/network/caldera_pcap.pcapng \
  -Y "ip.dst == 198.51.100.47 and tcp.flags.syn == 1" \
  -T fields -e frame.time_epoch -e ip.src -e tcp.dstport
```

**Expected findings:**

* 87 TCP connections to `198.51.100.47:443` from `10.10.5.14` over 4 hours
* Average interval: 62.3 seconds (consistent with Cobalt Strike default + jitter)
* Total bytes transferred: ~2.3 MB outbound (small keepalive traffic)
* Large outbound transfer at 07:38Z: 45 MB from `10.10.5.14` to `198.51.100.47` (exfiltration indicator)
* The 45 MB transfer matches the size of the `research_pipeline_Q4.zip` file on the file server

**Beacon characteristics:**

* TLS 1.2 connection with JA3 fingerprint matching Cobalt Strike default profile
* HTTP/S POST requests every ~60s (C2 check-ins)
* Server certificate is self-signed (not a legitimate CDN)

---

## Part 3 Model Answer — Host Forensics

**Initial access vector:** `WINWORD.EXE` → `cmd.exe /c powershell.exe -nop -w hidden -e <base64>` (Event ID 4688 at 05:59:04Z)

**Persistence mechanism:** Scheduled Task `\Microsoft\Windows\Update Checker` created at 06:00:11Z (Event ID 4698):

```xml
<Task>
  <Actions>
    <Exec>
      <Command>C:\Users\jbrown\AppData\Local\Temp\svchost32.exe</Command>
    </Exec>
  </Actions>
  <Triggers>
    <BootTrigger/>
  </Triggers>
</Task>
```

**Lateral movement:**

* Event 4624 (LogonType=3) at 07:15:33Z: `WS-CALDERA-014\jbrown` → `WS-CALDERA-022` using stolen credentials
* Subsequent 4688 events on WS-CALDERA-022 show `svchost32.exe` being copied and executed

---

## Part 4 Model Answer — Malware Analysis

**Binary classification:** Cobalt Strike Beacon (x64 PE)

**Key strings evidence:**

```text
strings /artefacts/malware/memory_strings.txt | grep -i important

# Expected strings:
Content-Type: application/octet-stream
Accept: */*
analytics-cdn.caldera-updates.net
/jquery-3.3.1.min.js              # C2 URL path (malleable C2 profile)
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)  # UA string
AAAAAAAA                           # Cobalt Strike encoded config marker
\Microsoft\Windows\Update Checker  # Persistence key
```

**YARA match:**

```text
CobaltStrike_Beacon_x64 : /artefacts/malware/suspicious_binary.exe
MZ_Executable             : /artefacts/malware/suspicious_binary.exe
```

**ATT&CK techniques:**

* T1059.001 — PowerShell (initial execution)
* T1053.005 — Scheduled Task (persistence)
* T1071.001 — Web Protocols (C2)
* T1105 — Ingress Tool Transfer (binary download)
* T1008 — Fallback Channels (Beacon failover)

---

## Part 5 Model Answer — Kill Chain & Diamond Model

### Cyber Kill Chain

| Stage | Evidence |
|-------|---------|
| Reconnaissance | Not visible in current artefacts; likely LinkedIn/OSINT on jbrown (pharma researcher) |
| Weaponisation | Word document with VBA macro that drops PowerShell loader |
| Delivery | Spearphishing email (jbrown opened Word attachment at 05:58Z per Outlook calendar event) |
| Exploitation | CVE-2024-XXXX (macro execution — no vulnerability exploitation, social engineering only) |
| Installation | `svchost32.exe` dropped + Scheduled Task created for persistence |
| C2 | Cobalt Strike Beacon beaconing to `analytics-cdn.caldera-updates.net` every ~60s |
| Actions on Objectives | Lateral movement → credential theft → 45 MB exfiltration (R&D documents) |

### Diamond Model

| Element | Analysis |
|---------|----------|
| **Adversary** | Highly targeted; custom malleable C2 profile; pharmaceutical sector targeting → APT with IP theft motive. Consistent with known APT groups (e.g., Lazarus, APT41) but insufficient evidence for attribution. Sophistication: High |
| **Capability** | Cobalt Strike (commercial RAT); custom C2 profile; anti-detection techniques; lateral movement capability |
| **Infrastructure** | Bulletproof hosting; recently registered domain; self-signed TLS certificate. Likely single-use infrastructure for this campaign |
| **Victim** | Caldera Pharmaceuticals — pharmaceutical R&D. Target: Q4 research pipeline data. Victim characterisation: high-value IP, likely inadequate security investment relative to data value |

---

## Part 6 Model Answer — Incident Report Key Elements

An excellent incident report will contain:

**IOC Table:**
| IOC | Type | Notes |
|-----|------|-------|
| `198.51.100.47` | IPv4 C2 | Bulletproof hosting |
| `analytics-cdn.caldera-updates.net` | Domain | Registered 2024-11-08 |
| `d41d8cd98f00b204e9800998ecf8427e` | MD5 hash | `svchost32.exe` |
| `C:\Users\jbrown\AppData\Local\Temp\svchost32.exe` | File path | Beacon binary |
| `\Microsoft\Windows\Update Checker` | Scheduled Task | Persistence mechanism |

**Remediation items (minimum 6):**

1. Wipe and reimage both affected hosts — do not trust any system where Cobalt Strike ran
1. Rotate all credentials for `jbrown` and any other account that authenticated via affected hosts
1. Delete the Scheduled Task on any hosts where the beacon achieved persistence
1. Block C2 IP and domain at all network egress points (firewall, DNS RPZ)
1. Hunt for the Cobalt Strike beacon across all endpoints using YARA rules and hash search
1. Notify Data Protection Officer — R&D data exfiltration may trigger GDPR Article 33 notification
1. Engage external forensics firm to determine full extent of data exfiltration (45 MB transfer)
1. Provide security awareness training to all email users; simulate phishing quarterly

---

## Scoring Notes for Instructors

* Part 1 (10 pts): Key facts in triage note must include: C2 IP identified, time of first contact, affected users/hosts, immediate action items
* Part 2 (20 pts): Full marks require: beaconing interval calculated, exfiltration data volume identified, C2 protocol characterised
* Part 3 (20 pts): Full marks require: initial access vector (WINWORD macro), persistence mechanism (Scheduled Task), lateral movement method
* Part 4 (15 pts): Full marks require: Cobalt Strike classification with YARA confirmation, C2 domain from strings, at least 3 ATT&CK mappings
* Part 5 (15 pts): All 7 kill chain stages addressed; all 4 diamond model elements populated with evidence
* Part 6 (20 pts): All 9 sections present; IOC table complete; ≥6 specific remediation steps; executive narrative is jargon-free
