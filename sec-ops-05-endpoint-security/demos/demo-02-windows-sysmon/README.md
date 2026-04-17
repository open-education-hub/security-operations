# Demo 02: Windows Sysmon — Simulating Endpoint Telemetry on Linux

## Overview

This demo simulates Sysmon-style event generation on a **Linux container** to show you what Sysmon captures when suspicious activity occurs on a Windows system.
We use a Python script that generates realistic Sysmon XML events based on common attack patterns.

> **Why Linux?** Sysmon is Windows-only. Since we're working in Docker on Linux, we simulate Sysmon events programmatically. Real Sysmon deployment is covered in Guide 01.

**What you will learn:**

* What Sysmon events look like in XML format
* Which Sysmon event IDs fire for which activities
* How to detect malicious patterns in Sysmon data
* How Sysmon differs from native Windows logging

**Time required:** 25 minutes

**Prerequisites:** Docker installed

---

## Files

```text
demo-02-windows-sysmon/
├── docker-compose.yml
├── Dockerfile
├── sysmon_simulator.sh     ← runs "suspicious" commands and logs events
├── sysmon_events.xml       ← pre-generated sample Sysmon XML events
├── parse_sysmon.py         ← parses and analyzes Sysmon events
└── README.md               ← this file
```

---

## Part 1: Understanding Sysmon Events

### What Sysmon Event 1 (Process Create) Looks Like

When malware executes, Sysmon records a complete picture:

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-03-15T14:20:15.456789000Z"/>
    <Computer>WORKSTATION01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2024-03-15 14:20:15.456</Data>
    <Data Name="ProcessGuid">{a1b2c3d4-1234-5678-abcd-ef0123456789}</Data>
    <Data Name="ProcessId">4592</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="FileVersion">10.0.19041.546 (WinBuild.160101.0800)</Data>
    <Data Name="Description">Windows PowerShell</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">PowerShell.EXE</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==</Data>
    <Data Name="CurrentDirectory">C:\Users\jdoe\AppData\Local\Temp\</Data>
    <Data Name="User">CORP\jdoe</Data>
    <Data Name="LogonGuid">{a1b2c3d4-5678-1234-abcd-ef0123456789}</Data>
    <Data Name="LogonId">0x1a2b3c</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">MD5=A1B2C3D4E5F6,SHA256=ABCDEF1234567890,IMPHASH=11223344</Data>
    <Data Name="ParentProcessGuid">{d4e5f6a7-8901-2345-bcde-f01234567890}</Data>
    <Data Name="ParentProcessId">3120</Data>
    <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
    <Data Name="ParentCommandLine">"WINWORD.EXE" /n "C:\Users\jdoe\Downloads\invoice_march.docm"</Data>
    <Data Name="ParentUser">CORP\jdoe</Data>
  </EventData>
</Event>
```

**Key fields to always examine:**

* `Image` — what process ran
* `CommandLine` — full command with arguments
* `ParentImage` — what spawned this process
* `User` — which user ran it
* `CurrentDirectory` — working directory (temp = suspicious)
* `Hashes` — for threat intel lookups
* `IntegrityLevel` — Medium=user, High=admin, System=SYSTEM

---

## Part 2: Suspicious Activity Patterns

### Pattern 1: Office → PowerShell (T1059.001)

**Sysmon Event 1 — PowerShell spawned by Word**

```xml
<Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA==</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
```

**Detection rule:** ANY Office application (`WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`) spawning `powershell.exe`, `cmd.exe`, `wscript.exe`, or `mshta.exe`.

---

### Pattern 2: Network Connection by Script (T1071.001)

**Sysmon Event 3 — Network connection**

```xml
<Event>
  <System>
    <EventID>3</EventID>
    <TimeCreated SystemTime="2024-03-15T14:20:19.012Z"/>
    <Computer>WORKSTATION01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">4592</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="User">CORP\jdoe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIp">10.10.5.22</Data>
    <Data Name="SourcePort">54231</Data>
    <Data Name="DestinationIp">185.234.219.47</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationHostname">update.microsoft-cdn-delivery.com</Data>
  </EventData>
</Event>
```

**Detection rule:** `powershell.exe` or `cmd.exe` making outbound TCP connections to external IPs.

---

### Pattern 3: LSASS Memory Access — Credential Dump (T1003.001)

**Sysmon Event 10 — Process accessing LSASS**

```xml
<Event>
  <System>
    <EventID>10</EventID>
    <TimeCreated SystemTime="2024-03-15T14:22:01.901Z"/>
  </System>
  <EventData>
    <Data Name="SourceProcessId">5891</Data>
    <Data Name="SourceImage">C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data>
    <Data Name="TargetProcessId">648</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
    <Data Name="GrantedAccess">0x1FFFFF</Data>
    <Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9d414|...</Data>
  </EventData>
</Event>
```

**Detection rule:** ANY process accessing `lsass.exe` with `GrantedAccess` containing `0x1FFFFF` or `0x1010` (READ_PROCESS_MEMORY).

**Why this matters:** This is the exact signature of Mimikatz credential dumping.

---

### Pattern 4: Registry Persistence (T1547.001)

**Sysmon Event 13 — Registry value set**

```xml
<Event>
  <System>
    <EventID>13</EventID>
    <TimeCreated SystemTime="2024-03-15T14:20:25.678Z"/>
  </System>
  <EventData>
    <Data Name="EventType">SetValue</Data>
    <Data Name="ProcessId">5891</Data>
    <Data Name="Image">C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data>
    <Data Name="TargetObject">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper</Data>
    <Data Name="Details">C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe</Data>
  </EventData>
</Event>
```

---

### Pattern 5: Remote Thread Injection (T1055.001)

**Sysmon Event 8 — CreateRemoteThread**

```xml
<Event>
  <System>
    <EventID>8</EventID>
    <TimeCreated SystemTime="2024-03-15T14:23:45.234Z"/>
  </System>
  <EventData>
    <Data Name="SourceProcessId">5891</Data>
    <Data Name="SourceImage">C:\Users\jdoe\AppData\Local\Temp\WinUpdate.exe</Data>
    <Data Name="TargetProcessId">1234</Data>
    <Data Name="TargetImage">C:\Windows\System32\explorer.exe</Data>
    <Data Name="NewThreadId">6789</Data>
    <Data Name="StartAddress">0x7FFE12340000</Data>
    <Data Name="StartModule">-</Data>
    <Data Name="StartFunction">-</Data>
  </EventData>
</Event>
```

**Detection:** Any unsigned process creating a remote thread in a signed system process (`explorer.exe`, `svchost.exe`, `services.exe`).

---

### Pattern 6: DNS Beaconing (T1071.004)

**Sysmon Event 22 — DNS Query**

```xml
<Event>
  <System>
    <EventID>22</EventID>
  </System>
  <EventData>
    <Data Name="ProcessId">5891</Data>
    <Data Name="QueryName">update.microsoft-cdn-delivery.com</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">type:  5 ::185.234.219.47;</Data>
    <Data Name="Image">C:\Users\jdoe\AppData\Roaming\Microsoft\wuhelper.exe</Data>
  </EventData>
</Event>
```

**Beaconing detection:** Same process making DNS queries to the same domain at regular intervals (e.g., every 60 seconds).

---

## Part 3: Run the Interactive Demo

```bash
# Start the container
docker-compose up --build

# Or run interactively
docker-compose run sysmon-demo bash

# Inside the container, trigger simulated suspicious activity
bash sysmon_simulator.sh

# Analyze the generated events
python3 parse_sysmon.py --file /var/log/sysmon_events.xml
python3 parse_sysmon.py --detect-suspicious
```

---

## Part 4: Sysmon Configuration Best Practices

A good Sysmon config reduces noise while maximizing detection value.

### Minimal Effective Config

```xml
<Sysmon schemaversion="4.82">
  <!-- Capture MD5, SHA256, and Import Hash for threat intel -->
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <!-- Check driver signature revocation -->
  <CheckRevocation/>

  <EventFiltering>
    <!-- Event 1: Process Create — capture all, exclude high-volume noise -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- System processes that generate too much noise -->
        <Image condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</Image>
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <ParentImage condition="is">C:\Windows\System32\services.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event 3: Network Connect — only capture external destinations -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationIp condition="begin with">10.</DestinationIp>
        <DestinationIp condition="begin with">192.168.</DestinationIp>
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event 10: ProcessAccess — only watch LSASS -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event 11: FileCreate — watch only high-risk locations -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event 22: DNS — capture all for C2 detection -->
    <!-- No filter — capture all DNS queries -->
  </EventFiltering>
</Sysmon>
```

---

## Key Takeaways

1. **Sysmon dramatically extends Windows logging.** Native Windows only gives you that `cmd.exe` ran. Sysmon gives you the full command line, parent process, network connections, and file operations.

1. **Event 1 (Process Create) with parent context** is the single most valuable endpoint event. Always ask: "What spawned this process?"

1. **Event 10 (ProcessAccess to LSASS)** is effectively a zero-false-positive alert for credential dumping attempts.

1. **Event 22 (DNS queries)** enables C2 beacon detection — look for regular intervals and unusual domain patterns.

1. **Good configuration matters.** Unfiltered Sysmon generates too much noise. Start with a community config and tune from there.
