# Demo 03: SIEM-Based Investigation of a Multi-Stage Attack

**Duration:** ~60 minutes

**Level:** Intermediate

**Environment:** Docker (Splunk Enterprise)

---

## Overview

This demo uses Splunk running in Docker to investigate a multi-stage attack.
Pre-loaded log data covers a complete attack progression: spear-phishing delivery → endpoint compromise → credential theft → lateral movement → data exfiltration.

You will write Splunk queries (SPL) to detect each stage of the attack and build a comprehensive attack timeline.

---

## Lab Setup

### Start the environment

```console
cd demos/demo-03-siem-investigation
docker compose up -d
```

Wait for Splunk to start (approximately 90 seconds):

```console
docker compose logs -f splunk | grep "Ansible playbook complete"
```

### Access Splunk

| URL | Username | Password |
|-----|----------|---------|
| http://localhost:8000 | admin | SecOps2024! |

### Verify data is loaded

In Splunk, run:

```spl
index=* | stats count by index
```

Expected output:

```text
index           count
sysmon          2847
winlogs         5612
firewall         891
proxy            432
email            156
dns             1204
```

---

## Scenario Background

**Date:** 2024-11-15

**Target:** ACME Corporation

**Environment:** Windows Active Directory domain (`acme.local`)
**Hosts involved:**

* `WS-JSMITH` (192.168.10.42) — Jane Smith's workstation
* `WS-RBROWN` (192.168.10.67) — Robert Brown's workstation
* `DC01` (10.0.1.5) — Domain Controller
* `FILE-SRV01` (10.0.1.10) — File Server
* `MAIL01` (10.0.1.20) — Mail Server

---

## Investigation Module 1: Initial Access (Phishing)

### Query 1.1 — Find phishing delivery events

```spl
index=email
| eval spf_fail = if(spf_result="FAIL",1,0)
| eval dkim_fail = if(dkim_result="FAIL",1,0)
| where spf_fail=1 OR dkim_fail=1
| table _time, to_address, from_address, subject, sender_ip, attachment_name, spf_result, dkim_result
| sort _time
```

**Expected findings:**

* Email to `jsmith@acme.local` at 09:42 UTC from spoofed domain
* Attachment: `Invoice_INV-2024-8847.docm`

### Query 1.2 — Correlate with user click (proxy log)

```spl
index=proxy user="jsmith" earliest="2024-11-15T09:40:00" latest="2024-11-15T09:50:00"
| table _time, user, dest_ip, dest_port, uri, http_method, status_code, bytes_out
| sort _time
```

**Expected findings:**

* HTTP GET to `185.220.101.47/track` at 09:44:22 (link click from email)

### Query 1.3 — Find the attachment hash

```spl
index=sysmon EventID=11 Computer="WS-JSMITH" TargetFilename="*.docm"
| table _time, Computer, User, TargetFilename, MD5, SHA256
```

**Record the hash** — you'll use it for the IOC hunt later.

---

## Investigation Module 2: Execution (Macro + PowerShell)

### Query 2.1 — Detect Office process spawning shell

```spl
index=sysmon EventID=1
| where like(ParentImage, "%WINWORD%") OR like(ParentImage, "%EXCEL%") OR like(ParentImage, "%POWERPNT%")
| where like(Image, "%cmd.exe%") OR like(Image, "%powershell.exe%") OR like(Image, "%wscript.exe%")
| table _time, Computer, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort _time
```

**Expected finding:** `WS-JSMITH` — `WINWORD.EXE → CMD.EXE → POWERSHELL.EXE` at 09:44:35

### Query 2.2 — Detect encoded PowerShell

```spl
index=sysmon EventID=1 Image="*powershell.exe*"
| where like(CommandLine, "%-Enc%") OR like(CommandLine, "%-EncodedCommand%") OR like(CommandLine, "%-e %")
| table _time, Computer, User, CommandLine, ParentImage
| sort _time
```

### Query 2.3 — Detect suspicious PowerShell flags (AMSI/ETW bypass patterns)

```spl
index=sysmon EventID=1 Image="*powershell.exe*"
| eval suspicious_flags = if(
    like(CommandLine, "%-NonI%") AND
    like(CommandLine, "%-NoP%") AND
    like(CommandLine, "%-W Hidden%"),
    "HIGH CONFIDENCE MALICIOUS", "check manually"
  )
| where suspicious_flags="HIGH CONFIDENCE MALICIOUS"
| table _time, Computer, User, CommandLine, suspicious_flags
```

---

## Investigation Module 3: C2 Communication

### Query 3.1 — Detect first outbound connection from compromised host

```spl
index=firewall src_ip="192.168.10.42" action=allow
| where NOT cidrmatch("192.168.0.0/16", dest_ip)
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
| table _time, src_ip, dest_ip, dest_port, protocol, bytes_out
| sort _time
| head 20
```

**Expected finding:** TCP connection to `185.220.101.47:4444` at 09:45:02

### Query 3.2 — Detect C2 beaconing pattern

```spl
index=firewall dest_ip="185.220.101.47"
| timechart span=1m count as connections
| eval suspicious = if(connections>0, "beaconing", "quiet")
```

### Query 3.3 — DNS resolution for C2 domain

```spl
index=dns src_ip="192.168.10.42"
| where answer!="" AND NOT cidrmatch("10.0.0.0/8", answer)
| table _time, query, answer, query_type
| sort _time
```

---

## Investigation Module 4: Discovery

### Query 4.1 — Detect AD enumeration commands

```spl
index=sysmon EventID=1 Computer="WS-JSMITH"
| where like(CommandLine, "%net user%") OR
        like(CommandLine, "%net group%") OR
        like(CommandLine, "%net localgroup%") OR
        like(CommandLine, "%Get-ADUser%") OR
        like(CommandLine, "%dsquery%") OR
        like(CommandLine, "%ldapsearch%")
| table _time, Computer, User, CommandLine, ParentImage
| sort _time
```

**Expected findings at ~09:47-09:49:**

* `net user /domain`
* `net group "Domain Admins" /domain`
* `ipconfig /all`

### Query 4.2 — Detect Sysmon network connections from new processes

```spl
index=sysmon EventID=3 Computer="WS-JSMITH"
| where NOT (DestinationIp="192.168.0.0/16" OR DestinationIp="10.0.0.0/8")
| table _time, Image, DestinationIp, DestinationPort, Protocol
| sort _time
```

---

## Investigation Module 5: Credential Dumping

### Query 5.1 — Detect LSASS memory access

```spl
index=sysmon EventID=10 Computer="WS-JSMITH" TargetImage="*lsass.exe*"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
```

**LSASS access flag reference:**

* `0x1010` or `0x1410` = Mimikatz standard access
* `0x143a` = sekurlsa::logonpasswords access mask

**Expected finding:** LSASS process accessed by malicious powershell process with access mask `0x1010`.

### Query 5.2 — Detect credential dump indicators in Windows Event Log

```spl
index=winlogs EventCode=4688 Computer="WS-JSMITH"
| where like(Process_Command_Line, "%sekurlsa%") OR
        like(Process_Command_Line, "%logonpasswords%") OR
        like(Process_Command_Line, "%lsadump%")
| table _time, Account_Name, Process_Name, Process_Command_Line
```

---

## Investigation Module 6: Lateral Movement

### Query 6.1 — Detect SMB lateral movement (Event ID 4624 Type 3)

```spl
index=winlogs EventCode=4624 Logon_Type=3
| where NOT (Account_Name="ANONYMOUS LOGON" OR Account_Name="$")
| lookup hosts.csv ip as Source_Network_Address OUTPUT hostname as source_hostname
| table _time, Account_Name, Source_Network_Address, source_hostname, Workstation_Name, ComputerName
| sort _time
```

### Query 6.2 — Detect authentication from compromised workstation to servers

```spl
index=winlogs EventCode=4624
| where Source_Network_Address="192.168.10.42"
| where ComputerName!="WS-JSMITH"
| table _time, Account_Name, ComputerName, Source_Network_Address, Logon_Type
| sort _time
```

**Expected findings:**

* Authentication from `WS-JSMITH` (192.168.10.42) to `DC01` using `administrator` credentials
* Authentication from `WS-JSMITH` to `FILE-SRV01`

---

## Investigation Module 7: Data Collection and Exfiltration

### Query 7.1 — Detect large file archiving

```spl
index=sysmon EventID=11 Computer="FILE-SRV01"
| where like(TargetFilename, "%.zip") OR like(TargetFilename, "%.rar") OR like(TargetFilename, "%.7z")
| eval file_size_mb = round(FileSize/1048576, 2)
| where file_size_mb > 100
| table _time, Computer, User, TargetFilename, file_size_mb
```

**Expected finding:** `data.zip` (4,312 MB) created at ~10:45 on FILE-SRV01

### Query 7.2 — Detect large outbound data transfers

```spl
index=firewall src_ip="10.0.1.10"
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
| eval bytes_out_mb = round(bytes_out/1048576, 2)
| where bytes_out_mb > 100
| table _time, src_ip, dest_ip, dest_port, bytes_out_mb, protocol
| sort -bytes_out_mb
```

**Expected finding:** 4,312 MB outbound to `https://storage.googleapis.com` (cloud storage)

### Query 7.3 — Detect DNS queries to cloud storage (pre-exfil staging)

```spl
index=dns src_ip="10.0.1.10" query="*storage.googleapis.com*" OR query="*s3.amazonaws.com*" OR query="*onedrive.live.com*"
| table _time, src_ip, query, answer
| sort _time
```

---

## Investigation Module 8: Building the Complete Attack Timeline

### Query 8.1 — Multi-source timeline correlation

```spl
(index=email to_address="*jsmith*")
OR (index=proxy user="jsmith" earliest="2024-11-15T09:40:00")
OR (index=sysmon Computer="WS-JSMITH" EventID=1 ParentImage="*WINWORD*")
OR (index=sysmon Computer="WS-JSMITH" EventID=3 DestinationIp="185.220.101.47")
OR (index=winlogs EventCode=4624 Source_Network_Address="192.168.10.42")
OR (index=sysmon Computer="FILE-SRV01" EventID=11)
OR (index=firewall src_ip="10.0.1.10" NOT (dest_ip="10.0.0.0/8"))
| eval phase = case(
    index=="email", "1-Delivery",
    (index=="proxy" AND like(uri, "%185.220.101.47%")), "2-User Click",
    (index=="sysmon" AND EventID==1 AND like(ParentImage, "%WINWORD%")), "3-Exploitation",
    (index=="sysmon" AND EventID==3), "4-C2 Established",
    (index=="winlogs" AND EventCode==4624 AND NOT ComputerName=="WS-JSMITH"), "5-Lateral Movement",
    (index=="sysmon" AND EventID==11 AND Computer=="FILE-SRV01"), "6-Collection",
    (index=="firewall" AND bytes_out > 100000000), "7-Exfiltration",
    true(), "Unknown"
  )
| table _time, phase, host, sourcetype, _raw
| sort _time
```

---

## Investigation Module 9: IOC Hunting

### Query 9.1 — Hunt for C2 IP across all hosts

```spl
index=firewall dest_ip="185.220.101.47"
| stats count, values(src_ip) as infected_hosts, min(_time) as first_seen, max(_time) as last_seen by dest_ip
| eval duration_hours = round((last_seen-first_seen)/3600, 2)
| table dest_ip, count, infected_hosts, first_seen, last_seen, duration_hours
```

### Query 9.2 — Hunt for malware hash across all endpoints

```spl
index=sysmon (EventID=1 OR EventID=7 OR EventID=15)
| where like(MD5, "3b4c9e2f1a8d7e6f5b4c3d2e1f0a9b8c") OR
        like(SHA256, "a3f9b2c1e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2")
| stats count by Computer, Image, TargetFilename
```

---

## Challenge Queries

**Challenge 1:** Write a query to detect ALL encoded PowerShell executions (not just from Office) and calculate how many unique users have triggered this in the last 30 days.

**Challenge 2:** The attacker used `net group "Domain Admins" /domain`.
Write a query to detect AD group enumeration for ANY sensitive group (Domain Admins, Enterprise Admins, Schema Admins, Backup Operators).

**Challenge 3:** Write an alert that would trigger if any single workstation makes more than 50 network connections to unique external IPs within a 5-minute window (lateral movement scanner pattern).

---

## Cleanup

```console
docker compose down -v
```
