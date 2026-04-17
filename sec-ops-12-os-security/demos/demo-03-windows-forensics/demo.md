# Demo 03: Windows Forensics Basics

**Estimated time:** 40 minutes

---

## Overview

This demo provides a simulated Windows forensics investigation environment.
Using PowerShell Core and pre-generated forensic data files, you will analyze:

* Registry hive artifacts (Run keys, Shellbags, UserAssist)
* Prefetch-style execution records
* LNK (shortcut) file metadata
* Windows Event Log patterns (reconstructing an incident timeline)
* MFT timestamps and timestomping detection

This simulates a post-incident forensic review where you have collected artifacts from a compromised Windows workstation.

---

## Learning Objectives

* Parse and interpret Windows registry forensic artifacts
* Analyze prefetch records to establish execution history
* Examine LNK files to reconstruct file access history
* Rebuild an incident timeline from event log data
* Detect timestomping from MFT timestamp inconsistencies

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-03-windows-forensics
docker compose up --build
docker compose run win-forensics pwsh
```

---

## Step 1: Registry Forensics

The registry contains valuable evidence of attacker activity even after cleanup attempts.

```powershell
# Load the forensic data
. /scripts/load-forensics.ps1

# Review recently modified registry keys (persistence indicators)
Analyze-RegistryPersistence

# Output: Analyzing HKLM Run Keys...
# Name              Value                                          Last Modified
# SecurityHealth    C:\Windows\System32\SecurityHealthSystray.exe  2023-11-12 09:15
# WindowsUpdater    C:\ProgramData\svchost32.exe                   2024-01-14 02:47 *** RECENT ***
#
# ALERT: 'WindowsUpdater' was added on 2024-01-14 at 02:47 (3am!)
# Path C:\ProgramData\svchost32.exe is NOT a Windows system binary
```

```powershell
# Examine UserAssist (recently executed programs, ROT13-encoded)
Analyze-UserAssist

# UserAssist records every GUI application the user ran:
# Decoded Name: C:\Users\alice\Downloads\setup.exe   Count: 1   Last Run: 2024-01-14 14:23:05
# Decoded Name: C:\Windows\System32\cmd.exe          Count: 47  Last Run: 2024-01-14 14:51:22
# Decoded Name: C:\ProgramData\svchost32.exe         Count: 12  Last Run: 2024-01-15 09:33:11
#
# svchost32.exe ran 12 times! This is NOT a Windows binary.
```

```powershell
# Examine ShimCache (AppCompatCache) - records all executables that ran
Analyze-ShimCache

# ShimCache contains executables that Windows noted for compatibility shimming:
# Path: C:\Users\alice\Downloads\nc64.exe    Last Modified: 2024-01-14 14:25:00
#   *** netcat in Downloads - classic tool for reverse shells ***
# Path: C:\Users\alice\AppData\Local\Temp\mimikatz.exe    Last Modified: 2024-01-14 14:48:00
#   *** MIMIKATZ - credential dumper! ***
```

```powershell
# Examine USB device history
Analyze-UsbHistory

# USBSTOR registry entries:
# Device: SanDisk Ultra USB 3.0
#   Serial: 4C530001030622111552&0
#   First Connected: 2024-01-14 14:20:15
#   Last Connected:  2024-01-14 14:55:42
#   Drive Letter:    E:\
#
# Attacker connected a USB drive during the incident window!
```

---

## Step 2: Prefetch Analysis

Prefetch files prove application execution, even after the files are deleted.

```powershell
# Analyze prefetch records
Analyze-Prefetch

# === Execution History from Prefetch ===
# Filename                      Hash      RunCount  Last 3 Run Times
# CMD.EXE                       B3B3E51A  47        2024-01-14 14:51, 14:49, 14:47
# MIMIKATZ.EXE                  F1A2B3C4  1         2024-01-14 14:48:02
#   Files accessed: lsass.dmp, sekurlsa.dll, mimilib.dll
# NC64.EXE                      A1234567  3         2024-01-14 14:26, 14:29, 14:32
#   Files accessed: ws2_32.dll (network connections!)
# SVCHOST32.EXE                 99887766  12        2024-01-14 14:52, many more
# PSEXEC.EXE                    DEADBEEF  2         2024-01-15 09:10, 09:15
#   Volume info: \\SERVER02\ (executed from a network share!)
```

```powershell
# Deep dive into MIMIKATZ execution
Inspect-Prefetch "MIMIKATZ.EXE"

# MIMIKATZ.EXE-F1A2B3C4.pf Analysis:
#   Executable Path:  C:\Users\alice\AppData\Local\Temp\mimikatz.exe
#   Run Count:        1
#   Last Run:         2024-01-14 14:48:02
#   Volume:           C:\ (local execution)
#
# Files accessed during execution:
#   C:\Windows\System32\lsass.exe       (LSASS process touched!)
#   C:\Windows\System32\samlib.dll      (SAM library)
#   C:\Windows\System32\cryptbase.dll   (crypto functions)
#   C:\Users\alice\AppData\Local\Temp\lsass.dmp  (DUMP FILE CREATED!)
#
# VERDICT: Mimikatz ran, accessed LSASS, created a dump file
# The dump file C:\Users\alice\AppData\Local\Temp\lsass.dmp was the output
```

---

## Step 3: LNK File Analysis

LNK files reveal what files the user accessed, including files on USB drives or network shares.

```powershell
# Analyze LNK files from the user's Recent folder
Analyze-LnkFiles

# === LNK File Analysis ===
# LNK File: passwords.xlsx.lnk
#   Created:      2024-01-14 14:22:30
#   Target Path:  E:\passwords.xlsx        *** USB DRIVE (E:\)! ***
#   Volume Type:  Removable               *** USB/external storage ***
#   Volume Label: BACKUP_USB
#   Machine ID:   ALICE-WORKSTATION
#
# LNK File: creds.txt.lnk
#   Created:      2024-01-14 14:23:05
#   Target Path:  E:\creds.txt             *** ALSO FROM USB ***
#   Volume Type:  Removable
#
# LNK File: annual_report_draft.docx.lnk
#   Created:      2024-01-13 09:15:00
#   Target Path:  \\FILESERVER01\hr\annual_report_draft.docx  *** NETWORK SHARE ***
#   Volume Type:  Network
```

```powershell
# The LNK analysis reveals:
# 1. Alice accessed files from a USB drive (E:\passwords.xlsx, E:\creds.txt)
# 2. This correlates with the USB connection time (14:22-14:23)
# 3. The file names suggest the attacker brought their own credentials on USB
# 4. Alice also accessed \\FILESERVER01 — lateral movement target
Summarize-LnkFindings
```

---

## Step 4: Windows Event Log Incident Timeline

```powershell
# Reconstruct the full incident timeline from event logs
Build-IncidentTimeline

# === INCIDENT TIMELINE: 2024-01-14 ===
#
# 14:20:15  USB device connected (USBSTOR registry event)
#           Device: SanDisk Ultra USB
#
# 14:22:30  4663 - File accessed: E:\passwords.xlsx by alice (SACL audit)
# 14:23:05  4663 - File accessed: E:\creds.txt by alice
#
# 14:23:00- Brute force from external (likely testing creds found on USB)
# 14:47:23  247 × 4625 (failed logon) then 4624 success - alice from 10.0.5.123
#
# 14:48:00  Sysmon 1 - mimikatz.exe launched (cmdline: sekurlsa::logonpasswords)
# 14:48:02  Sysmon 10 - mimikatz.exe → lsass.exe (PROCESS_VM_READ)
# 14:48:05  Sysmon 11 - File created: C:\Users\alice\AppData\Local\Temp\lsass.dmp
#
# 14:49:10  3 × nc64.exe execution (Prefetch: network connections via ws2_32.dll)
#           Likely reverse shell attempts
#
# 14:50:15  7045 - Service created: "WindowsUpdater" (C:\ProgramData\svchost32.exe)
# 14:50:17  4698 - Scheduled task created: "\WindowsTelemHelper" (encoded PS)
#
# 14:52:00  Sysmon 1 - svchost32.exe spawned (malware C2 beacon starts)
#
# 14:55:42  USB device disconnected
#
# 15:10:44  1102 - Security audit log cleared by alice
#           (but Sysmon log NOT cleared - attacker forgot)
```

---

## Step 5: MFT Timestamp Analysis and Timestomping Detection

```powershell
# Examine MFT timestamps for evidence tampering
Analyze-Timestamps

# MFT Timestamp Analysis for: C:\ProgramData\svchost32.exe
#
# $STANDARD_INFORMATION (user-visible, can be modified by attacker):
#   Created:      2020-03-15 08:00:00   <-- appears old (legitimate-looking)
#   Modified:     2020-03-15 08:00:00
#   MFTModified:  2020-03-15 08:00:00
#   Accessed:     2024-01-14 14:52:00
#
# $FILE_NAME (set by NTFS, harder to modify):
#   Created:      2024-01-14 14:50:15   <-- actual creation time!
#   Modified:     2024-01-14 14:50:15
#   MFTModified:  2024-01-14 14:50:15
#
# *** TIMESTOMPING DETECTED! ***
# $SI timestamps show 2020 but $FN timestamps show 2024-01-14
# The attacker used timestomping to make malware appear old/legitimate
# Tools: timestomp.exe, PowerShell [IO.File]::SetCreationTime()
```

```powershell
# Compare against file creation order in MFT
Analyze-MftSequence

# MFT Entry #45231: C:\ProgramData\svchost32.exe
#   MFT Entry Number: 45231
#   Parent Directory: C:\ProgramData\ (MFT #44891)
#   Filename MFT timestamps: 2024-01-14 14:50:15
#
#   ADJACENT MFT entries (created around the same time):
#   #45228: C:\ProgramData\temp_config.dat  (2024-01-14 14:49:55)
#   #45229: C:\ProgramData\update.log       (2024-01-14 14:50:02)
#   #45230: C:\ProgramData\net.dat          (2024-01-14 14:50:10)
#   #45231: C:\ProgramData\svchost32.exe    (2024-01-14 14:50:15)
#
# MFT sequence confirms all these files were created together at 14:50.
# The $SI timestamps claiming 2020 are definitively fabricated.
```

---

## Step 6: Build the Full Forensic Report

```powershell
# Generate a complete forensic report
Build-ForensicReport -OutputPath /reports/forensic_report.txt

cat /reports/forensic_report.txt
```

The report will cover:

1. **Initial Access:** USB device brought onto network with credential files
1. **Credential Access:** Mimikatz ran against LSASS memory (dump created)
1. **Persistence:** Service (svchost32.exe) + Scheduled Task (encoded PS) installed
1. **Defense Evasion:** Timestomping on malware files; Security log cleared
1. **Exfiltration:** Credential files accessed from USB and likely exfiltrated
1. **Indicators of Compromise:**
   * File: `C:\ProgramData\svchost32.exe`
   * File: `C:\Users\alice\AppData\Local\Temp\mimikatz.exe`
   * File: `C:\Users\alice\AppData\Local\Temp\lsass.dmp`
   * Registry: `HKLM\SOFTWARE\...\Run\WindowsUpdater`
   * Network: USB device (SanDisk, serial: 4C530001030622111552)

---

## Clean Up

```console
docker compose down
```

---

## Key Takeaways

* **Registry artifacts** (UserAssist, ShimCache, USBSTOR) prove what ran and what connected, even after cleanup
* **Prefetch files** are essential — they prove execution and show files accessed, even after the malware is deleted
* **LNK files** reveal file access history including USB and network paths
* **Timestomping** is detected by comparing `$STANDARD_INFORMATION` vs. `$FILE_NAME` timestamps in the MFT
* **Event log clearing** (Event 1102) does not erase Sysmon logs — always deploy multiple logging channels
* **The incident timeline** must span multiple artifact types; no single artifact tells the complete story
