# Guide 01: Deploying and Configuring Sysmon (Docker-Based Simulation)

**Level:** Basic

**Time required:** 45 minutes

**Prerequisites:** Docker installed, reading.md Section 5 completed

---

## Learning Objectives

By the end of this guide, you will be able to:

1. Explain what Sysmon is and why it's used
1. Install and configure Sysmon (conceptually) on a Windows system
1. Use a Docker-based simulation to generate and analyze Sysmon events
1. Identify the most critical Sysmon event IDs for security monitoring
1. Write basic Sysmon configuration rules to reduce noise

---

## Overview

Sysmon (System Monitor) is a free Windows system service from Microsoft Sysinternals that provides detailed logging of process creations, network connections, file changes, registry modifications, and more.
It is one of the most cost-effective security controls available for Windows environments.

**Why Sysmon instead of (or in addition to) native Windows logging?**

* Native Windows Event 4688 requires policy changes for command line logging
* Sysmon captures full command lines, parent process info, file hashes, and network connections automatically
* Sysmon Event ID 10 (LSASS access) has near-zero false positives for credential dumping detection
* Sysmon Event ID 22 (DNS queries) enables C2 beacon detection

---

## Step 1: Understand the Deployment Model

### Real-World Sysmon Deployment (Windows)

In a production environment, Sysmon is deployed as follows:

```text
1. Download Sysmon from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

2. Prepare a configuration file (sysmonconfig.xml)
3. Deploy via Group Policy, SCCM, Ansible, or manually

# Install (run as Administrator)
sysmon64.exe -accepteula -i sysmonconfig.xml

# Update configuration
sysmon64.exe -c sysmonconfig.xml

# Uninstall
sysmon64.exe -u

# Check status
sc query sysmon64
```

After installation:

* Sysmon runs as a Windows service (`sysmon64`)
* Events appear in **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**
* Or accessible via PowerShell: `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'`

### Docker-Based Simulation (This Guide)

Since we're on Linux, we simulate Sysmon deployment using the Docker environment from Demo 02.

```console
cd demos/demo-02-windows-sysmon
docker-compose run sysmon-demo bash
```

---

## Step 2: Writing a Sysmon Configuration File

A Sysmon configuration file is an XML document that tells Sysmon what to log and what to ignore.
Poor configuration = too much noise; good configuration = actionable signal.

### Configuration Structure

```xml
<Sysmon schemaversion="4.82">
  <!-- Hash algorithms to compute for file/process events -->
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <!-- Check if code signing certificates are revoked -->
  <CheckRevocation/>

  <EventFiltering>
    <!-- Rules go here, grouped by event type -->
    <!-- onmatch="include" = ONLY log matching events -->
    <!-- onmatch="exclude" = log all EXCEPT matching events -->

    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- High-volume, known-good: exclude to reduce noise -->
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### Step 2.1: Configure Process Creation (Event ID 1)

The default for Event ID 1 is: log everything except what we exclude.
This is the safest approach.

```xml
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <!-- Exclude very noisy system processes -->
    <!-- Windows Defender updates -->
    <Image condition="begin with">C:\Program Files\Windows Defender\</Image>
    <!-- Antivirus scanner processes -->
    <Image condition="end with">MsMpEng.exe</Image>
    <!-- Software update processes (customize per environment) -->
    <CommandLine condition="contains">C:\Windows\SoftwareDistribution\</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

### Step 2.2: Configure Network Connections (Event ID 3)

Network connections generate the most noise.
Filter to capture only what matters:

```xml
<RuleGroup name="" groupRelation="or">
  <NetworkConnect onmatch="include">
    <!-- Include connections from scripting engines -->
    <Image condition="end with">powershell.exe</Image>
    <Image condition="end with">cmd.exe</Image>
    <Image condition="end with">wscript.exe</Image>
    <Image condition="end with">cscript.exe</Image>
    <Image condition="end with">mshta.exe</Image>
    <!-- Include connections to non-standard ports -->
    <DestinationPort condition="is not">80</DestinationPort>
    <DestinationPort condition="is not">443</DestinationPort>
    <DestinationPort condition="is not">53</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

> **Tuning Note:** This "include" approach will miss some C2 on port 80/443. For higher security, change to exclude-based and filter out known-good internal destinations.

### Step 2.3: Configure LSASS Monitoring (Event ID 10)

```xml
<RuleGroup name="" groupRelation="or">
  <ProcessAccess onmatch="include">
    <!-- Alert on ANY access to LSASS -->
    <TargetImage condition="end with">lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

Then exclude known-legitimate LSASS accessors:

```xml
<ProcessAccess onmatch="exclude">
  <!-- Known AV products that legitimately read LSASS -->
  <SourceImage condition="contains">MsMpEng.exe</SourceImage>
  <SourceImage condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</SourceImage>
</ProcessAccess>
```

### Step 2.4: Configure Registry Monitoring (Events 12, 13, 14)

```xml
<RuleGroup name="" groupRelation="or">
  <RegistryEvent onmatch="include">
    <!-- Persistence locations — Run keys -->
    <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Run</TargetObject>
    <!-- Startup folder registry references -->
    <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</TargetObject>
    <!-- Hijackable COM objects -->
    <TargetObject condition="contains">SOFTWARE\Classes\CLSID</TargetObject>
    <!-- Security providers (can be abused for credential theft) -->
    <TargetObject condition="contains">SYSTEM\CurrentControlSet\Control\SecurityProviders</TargetObject>
  </RegistryEvent>
</RuleGroup>
```

### Step 2.5: Configure File Creation (Event ID 11)

```xml
<RuleGroup name="" groupRelation="or">
  <FileCreate onmatch="include">
    <!-- Executables in user-writable locations -->
    <TargetFilename condition="contains">\AppData\</TargetFilename>
    <TargetFilename condition="contains">\Temp\</TargetFilename>
    <TargetFilename condition="contains">\ProgramData\</TargetFilename>
    <!-- Script files anywhere -->
    <TargetFilename condition="end with">.ps1</TargetFilename>
    <TargetFilename condition="end with">.vbs</TargetFilename>
    <TargetFilename condition="end with">.bat</TargetFilename>
    <TargetFilename condition="end with">.hta</TargetFilename>
  </FileCreate>
</RuleGroup>
```

---

## Step 3: Complete Minimal Configuration

Create a file called `sysmon-minimal.xml`:

```xml
<Sysmon schemaversion="4.82">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <!-- Event ID 1: Process Create — log all, exclude noise -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="begin with">C:\Windows\System32\wbem\</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connections — include scripting engines -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <Image condition="end with">wscript.exe</Image>
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">mshta.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 10: LSASS access — always alert -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event ID 11: File create in suspicious locations -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 13: Registry — Run keys and persistence points -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event ID 22: DNS — capture all queries (for C2 detection) -->
    <!-- No filter = capture all -->

    <!-- Event ID 8: CreateRemoteThread — injection detection -->
    <!-- No filter = capture all (rare in normal operation) -->
  </EventFiltering>
</Sysmon>
```

---

## Step 4: Apply and Test Configuration

### In the Docker simulation:

```console
# Start the container
docker-compose run sysmon-demo bash

# Run the attack simulation (generates Sysmon-format events)
bash /app/sysmon_simulator.sh

# Analyze with detection rules
python3 /app/parse_sysmon.py --file /var/log/sysmon_events.xml --all

# Check for suspicious patterns
python3 /app/parse_sysmon.py --file /var/log/sysmon_events.xml --detect-suspicious
```

### On a Real Windows System (Reference):

```powershell
# Query Sysmon events via PowerShell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 100 |
  Select-Object Id, TimeCreated, Message |
  Format-List

# Filter for LSASS access attempts
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object { $_.Id -eq 10 } |
  Select-Object TimeCreated, Message

# Filter for network connections by powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object { $_.Id -eq 3 -and $_.Message -like '*powershell*' } |
  Select-Object TimeCreated, Message
```

---

## Step 5: Forwarding Sysmon Events to a SIEM

### Using Windows Event Forwarding (WEF)

Windows can forward events natively to a Windows Event Collector:

```xml
<!-- Subscription query for Sysmon events -->
<QueryList>
  <Query Id="0">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1 or EventID=3 or EventID=8 or EventID=10 or
        EventID=11 or EventID=13 or EventID=22 or EventID=25)]]
    </Select>
  </Query>
</QueryList>
```

### Using a Log Shipper (Beats/NXLog/Splunk UF)

```yaml
# Filebeat configuration for Sysmon
filebeat.inputs:
  - type: winlog
    event_logs:
      - name: Microsoft-Windows-Sysmon/Operational
        level: verbose

output.elasticsearch:
  hosts: ["siem:9200"]
  index: "sysmon-%{+yyyy.MM.dd}"
```

---

## Checkpoint: Verification Questions

Before moving to the next section, make sure you can answer:

1. What does Sysmon Event ID 10 detect, and why does it have near-zero false positives for credential dumping?
1. Why should you use an `exclude` list (rather than `include`) for Event ID 1 (Process Create)?
1. What is the IMPHASH and why is it useful for threat intelligence?
1. What additional information does Sysmon Event 1 provide that native Windows Event 4688 does not (without extra configuration)?
1. Which Sysmon event would fire when malware creates a scheduled task?

---

## Summary

| What You Learned | Key Command/Config |
|-----------------|-------------------|
| Sysmon installation model | `sysmon64.exe -accepteula -i config.xml` |
| Critical event IDs | 1, 3, 8, 10, 11, 13, 22, 25 |
| Configuration structure | XML with include/exclude rules |
| LSASS monitoring | Event 10 on `lsass.exe` |
| Registry persistence | Event 13 on `CurrentVersion\Run` |
| SIEM forwarding | WEF or Beats/NXLog |

**Next Guide:** Guide 02 — Analyzing Windows Event Logs for Security Events
