# Windows Forensics Demo - Forensic Analysis Functions
# Simulates forensic artifact analysis for a compromised Windows workstation

function Show-ForensicsHelp {
    Write-Host "`n=== Windows Forensics Demo — Available Commands ===" -ForegroundColor Cyan
    Write-Host "Analyze-RegistryPersistence    - Check Run keys, UserAssist, ShimCache"
    Write-Host "Analyze-UserAssist             - Decode UserAssist execution records"
    Write-Host "Analyze-ShimCache              - Review AppCompatCache execution history"
    Write-Host "Analyze-UsbHistory             - Check USBSTOR registry for connected devices"
    Write-Host "Analyze-Prefetch               - Review prefetch execution records"
    Write-Host "Inspect-Prefetch [name]        - Deep dive into a specific prefetch file"
    Write-Host "Analyze-LnkFiles               - Parse LNK shortcut forensic data"
    Write-Host "Summarize-LnkFindings          - Summarize LNK analysis findings"
    Write-Host "Build-IncidentTimeline         - Reconstruct the full incident timeline"
    Write-Host "Analyze-Timestamps             - Detect timestomping via MFT analysis"
    Write-Host "Analyze-MftSequence            - Analyze MFT entry sequence for file creation order"
    Write-Host "Build-ForensicReport [-OutputPath]  - Generate complete forensic report"
    Write-Host ""
}

function Analyze-RegistryPersistence {
    Write-Host "`n=== Registry Persistence Analysis ===" -ForegroundColor Cyan
    Write-Host "`n  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run:" -ForegroundColor White
    @(
        [PSCustomObject]@{Name="SecurityHealth";  Value="C:\Windows\System32\SecurityHealthSystray.exe"; Modified="2023-11-12 09:15:22"; Status="CLEAN"}
        [PSCustomObject]@{Name="OneDriveSetup";   Value="C:\Windows\SysWOW64\OneDriveSetup.exe";         Modified="2023-09-01 08:00:11"; Status="CLEAN"}
        [PSCustomObject]@{Name="WindowsUpdater";  Value="C:\ProgramData\svchost32.exe";                  Modified="2024-01-14 02:47:33"; Status="SUSPICIOUS"}
    ) | ForEach-Object {
        $color = if ($_.Status -eq "SUSPICIOUS") { "Red" } else { "Green" }
        $flag  = if ($_.Status -eq "SUSPICIOUS") { "  *** ADDED 3AM! NOT A WINDOWS BINARY ***" } else { "" }
        Write-Host ("  {0,-20} {1,-55} {2}{3}" -f $_.Name, $_.Value, $_.Modified, $flag) -ForegroundColor $color
    }
}

function Analyze-UserAssist {
    Write-Host "`n=== UserAssist — GUI Application Execution History ===" -ForegroundColor Cyan
    Write-Host "  (HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist)"
    Write-Host "  (Entries are ROT13-encoded in the registry)" -ForegroundColor DarkGray
    @(
        [PSCustomObject]@{Name="C:\Users\alice\Downloads\setup.exe";      Count=1;  LastRun="2024-01-14 14:21:05"}
        [PSCustomObject]@{Name="C:\Windows\System32\cmd.exe";             Count=47; LastRun="2024-01-14 14:51:22"}
        [PSCustomObject]@{Name="C:\Users\alice\AppData\Local\Temp\mimikatz.exe"; Count=1; LastRun="2024-01-14 14:48:01"}
        [PSCustomObject]@{Name="C:\ProgramData\svchost32.exe";            Count=12; LastRun="2024-01-15 09:33:11"}
        [PSCustomObject]@{Name="C:\Windows\System32\notepad.exe";         Count=8;  LastRun="2024-01-13 15:30:00"}
    ) | ForEach-Object {
        $sus = $_.Name -match "mimikatz|svchost32|Temp\\setup|Downloads\\setup"
        $color = if ($sus) { "Red" } else { "White" }
        $flag  = if ($sus) { "  ***" } else { "" }
        Write-Host ("  Count:{0,-3} LastRun:{1}  {2}{3}" -f $_.Count, $_.LastRun, $_.Name, $flag) -ForegroundColor $color
    }
}

function Analyze-ShimCache {
    Write-Host "`n=== ShimCache (AppCompatCache) — All Executed Binaries ===" -ForegroundColor Cyan
    @(
        [PSCustomObject]@{Path="C:\Windows\System32\cmd.exe";                       Modified="2023-09-12 08:00"; Status="CLEAN"}
        [PSCustomObject]@{Path="C:\Windows\System32\powershell.exe";               Modified="2023-10-01 09:15"; Status="CLEAN"}
        [PSCustomObject]@{Path="C:\Users\alice\Downloads\nc64.exe";                Modified="2024-01-14 14:25"; Status="SUSPICIOUS"}
        [PSCustomObject]@{Path="C:\Users\alice\AppData\Local\Temp\mimikatz.exe";   Modified="2024-01-14 14:48"; Status="CRITICAL"}
        [PSCustomObject]@{Path="C:\ProgramData\svchost32.exe";                     Modified="2020-03-15 08:00"; Status="SUSPICIOUS"}
    ) | ForEach-Object {
        $color = switch ($_.Status) { "CRITICAL" { "Red" } "SUSPICIOUS" { "Yellow" } default { "Green" } }
        $flag  = switch ($_.Status) { "CRITICAL" { "  *** CREDENTIAL DUMPER ***" } "SUSPICIOUS" { "  *** INVESTIGATE ***" } default { "" } }
        Write-Host ("  [{0,-10}] {1,-55} Modified:{2}{3}" -f $_.Status, $_.Path, $_.Modified, $flag) -ForegroundColor $color
    }
}

function Analyze-UsbHistory {
    Write-Host "`n=== USB Device History (USBSTOR Registry) ===" -ForegroundColor Cyan
    Write-Host @"
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

  Device: Disk&Ven_SanDisk&Prod_Ultra_USB_3.0
    Friendly Name:  SanDisk Ultra USB 3.0
    Serial:         4C530001030622111552&0
    First Connected: 2024-01-14 14:20:15 UTC  *** 5 MINUTES BEFORE ATTACK ***
    Last Connected:  2024-01-14 14:55:42 UTC
    Assigned Drive:  E:\
    
  Device: Disk&Ven_Kingston&Prod_DataTraveler
    Friendly Name:  Kingston DataTraveler
    Serial:         00A1234567890B&0
    First Connected: 2023-08-15 10:30:00 UTC
    Last Connected:  2023-08-15 10:45:00 UTC
    Assigned Drive:  E:\

"@ -ForegroundColor Yellow
    Write-Host "  FORENSIC NOTE: The SanDisk connected at 14:20:15 — exactly when the" -ForegroundColor Red
    Write-Host "  attacker accessed passwords.xlsx and creds.txt from E:\            " -ForegroundColor Red
}

function Analyze-Prefetch {
    Write-Host "`n=== Prefetch Execution Records ===" -ForegroundColor Cyan
    Write-Host "  (C:\Windows\Prefetch\*.pf — parsed with PECmd simulation)" -ForegroundColor DarkGray
    @(
        [PSCustomObject]@{File="CMD.EXE";         Hash="B3B3E51A"; Count=47; LastRun="2024-01-14 14:51:22"; Status="NORMAL"}
        [PSCustomObject]@{File="POWERSHELL.EXE";  Hash="C4A5B1E2"; Count=15; LastRun="2024-01-14 14:52:00"; Status="NORMAL"}
        [PSCustomObject]@{File="MIMIKATZ.EXE";    Hash="F1A2B3C4"; Count=1;  LastRun="2024-01-14 14:48:02"; Status="CRITICAL"}
        [PSCustomObject]@{File="NC64.EXE";        Hash="A1234567"; Count=3;  LastRun="2024-01-14 14:32:05"; Status="SUSPICIOUS"}
        [PSCustomObject]@{File="SVCHOST32.EXE";   Hash="99887766"; Count=12; LastRun="2024-01-15 09:33:11"; Status="SUSPICIOUS"}
        [PSCustomObject]@{File="PSEXEC.EXE";      Hash="DEADBEEF"; Count=2;  LastRun="2024-01-15 09:15:00"; Status="SUSPICIOUS"}
    ) | ForEach-Object {
        $color = switch ($_.Status) { "CRITICAL" { "Red" } "SUSPICIOUS" { "Yellow" } default { "Gray" } }
        Write-Host ("  {0,-18} [{1}] Count:{2,-3} LastRun:{3}" -f $_.File, $_.Hash, $_.Count, $_.LastRun) -ForegroundColor $color
        if ($_.Status -ne "NORMAL") {
            $note = switch ($_.File) {
                "MIMIKATZ.EXE"  { "    !! Credential dumper — accessed lsass.exe and wrote lsass.dmp" }
                "NC64.EXE"      { "    !! Netcat — connected to network (ws2_32.dll referenced)" }
                "SVCHOST32.EXE" { "    !! Fake svchost — NOT a Windows binary (note: svchost32, not svchost)" }
                "PSEXEC.EXE"    { "    !! PsExec — remote execution tool (ran from \\SERVER02\ network share!)" }
            }
            Write-Host $note -ForegroundColor DarkYellow
        }
    }
}

function Inspect-Prefetch {
    param([string]$Name = "MIMIKATZ.EXE")
    Write-Host "`n=== Prefetch Deep Analysis: $Name ===" -ForegroundColor Cyan
    switch ($Name.ToUpper()) {
        "MIMIKATZ.EXE" {
            Write-Host @"
  Source:           C:\Windows\Prefetch\MIMIKATZ.EXE-F1A2B3C4.pf
  Executable Path:  C:\Users\alice\AppData\Local\Temp\mimikatz.exe
  Run Count:        1
  Last Run Time:    2024-01-14 14:48:02 UTC
  Volume:           C:\ (local drive execution)

  Files referenced during execution (from prefetch metadata):
    C:\Windows\System32\lsass.exe           *** LSASS process accessed! ***
    C:\Windows\System32\lsasrv.dll
    C:\Windows\System32\samlib.dll          *** SAM library ***
    C:\Windows\System32\cryptbase.dll
    C:\Windows\System32\ntdsapi.dll
    C:\Users\alice\AppData\Local\Temp\lsass.dmp  *** DUMP FILE OUTPUT ***
    C:\Windows\System32\msvcrt.dll
    C:\Windows\SysWOW64\bcrypt.dll

  VERDICT: Mimikatz executed once, accessed LSASS and SAM, produced lsass.dmp
"@ -ForegroundColor Yellow
        }
        "PSEXEC.EXE" {
            Write-Host @"
  Source:           C:\Windows\Prefetch\PSEXEC.EXE-DEADBEEF.pf
  Executable Path:  \\SERVER02\ADMIN$\PSEXESVC.EXE
  Run Count:        2
  Last Run Time:    2024-01-15 09:15:00 UTC
  Volume:           \\SERVER02\ (NETWORK SHARE! Ran from remote host)

  FORENSIC NOTE: PsExec ran from a network share on SERVER02.
  This means the attacker moved laterally to SERVER02 and executed tools there.
  Check SERVER02's event logs for Event ID 7045 (service installation by PsExec).
"@ -ForegroundColor Red
        }
        default { Write-Host "  No detailed data for: $Name" }
    }
}

function Analyze-LnkFiles {
    Write-Host "`n=== LNK File Forensic Analysis ===" -ForegroundColor Cyan
    Write-Host "  (C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\)" -ForegroundColor DarkGray
    @(
        [PSCustomObject]@{
            LnkFile="passwords.xlsx.lnk"; Created="2024-01-14 14:22:30"
            TargetPath="E:\passwords.xlsx"; VolumeType="Removable"; VolumeLabel="BACKUP_USB"
            Machine="ALICE-WORKSTATION"; Status="SUSPICIOUS"
        },
        [PSCustomObject]@{
            LnkFile="creds.txt.lnk"; Created="2024-01-14 14:23:05"
            TargetPath="E:\creds.txt"; VolumeType="Removable"; VolumeLabel="BACKUP_USB"
            Machine="ALICE-WORKSTATION"; Status="SUSPICIOUS"
        },
        [PSCustomObject]@{
            LnkFile="annual_report_draft.docx.lnk"; Created="2024-01-13 09:15:00"
            TargetPath="\\FILESERVER01\hr\annual_report_draft.docx"; VolumeType="Network"; VolumeLabel=""
            Machine="ALICE-WORKSTATION"; Status="NOTE"
        },
        [PSCustomObject]@{
            LnkFile="budget_2024.xlsx.lnk"; Created="2024-01-12 14:30:00"
            TargetPath="C:\Users\alice\Documents\budget_2024.xlsx"; VolumeType="Local"; VolumeLabel=""
            Machine="ALICE-WORKSTATION"; Status="CLEAN"
        }
    ) | ForEach-Object {
        $color = switch ($_.Status) { "SUSPICIOUS" { "Red" } "NOTE" { "Yellow" } default { "Gray" } }
        Write-Host ""
        Write-Host "  LNK: $($_.LnkFile)" -ForegroundColor $color
        Write-Host "    Created:     $($_.Created)"
        Write-Host "    Target:      $($_.TargetPath)"
        Write-Host "    Volume Type: $($_.VolumeType)  Label: $($_.VolumeLabel)"
        Write-Host "    Machine:     $($_.Machine)"
        if ($_.Status -eq "SUSPICIOUS") {
            Write-Host "    *** Files from REMOVABLE USB correlated with USBSTOR connection! ***" -ForegroundColor Red
        }
    }
}

function Summarize-LnkFindings {
    Write-Host "`n=== LNK Analysis Summary ===" -ForegroundColor Yellow
    Write-Host @"
  Key Findings:
  1. Attacker accessed 'passwords.xlsx' and 'creds.txt' from USB (E:\)
     at 14:22-14:23 — right after the USB was connected at 14:20:15
  
  2. File names (passwords.xlsx, creds.txt) suggest these were credential files
     brought to the victim's workstation by the attacker
  
  3. Access to \\FILESERVER01\hr\ indicates the attacker was aware of 
     network shares — potential lateral movement target
  
  4. LNK timestamps correlate precisely with USB history from USBSTOR
     registry — high confidence these occurred during the attack
"@
}

function Build-IncidentTimeline {
    Write-Host "`n=== FULL INCIDENT TIMELINE: 2024-01-14 ===" -ForegroundColor Cyan
    Write-Host "  (Reconstructed from: USBSTOR, LNK files, Security events, Sysmon, Prefetch)" -ForegroundColor DarkGray
    Write-Host ""
    @(
        @{Time="14:20:15"; Event="USB connected: SanDisk Ultra (E:\ = passwords.xlsx, creds.txt)"; Source="USBSTOR"; Level="INFO"}
        @{Time="14:21:05"; Event="setup.exe executed from Downloads (UserAssist)"; Source="UserAssist"; Level="WARN"}
        @{Time="14:22:30"; Event="E:\passwords.xlsx accessed (attacker reading credentials)"; Source="LNK+SACL"; Level="CRIT"}
        @{Time="14:23:05"; Event="E:\creds.txt accessed (attacker reading credentials)"; Source="LNK"; Level="CRIT"}
        @{Time="14:23:01"; Event="Brute force begins: 247 × 4625 Failed Logon from 10.0.5.123"; Source="Security"; Level="CRIT"}
        @{Time="14:47:23"; Event="SUCCESS: 4624 Logon - alice from 10.0.5.123 (Type 3 Network)"; Source="Security"; Level="CRIT"}
        @{Time="14:48:01"; Event="mimikatz.exe launched (Sysmon 1: sekurlsa::logonpasswords)"; Source="Sysmon"; Level="CRIT"}
        @{Time="14:48:02"; Event="Sysmon 10: mimikatz.exe → lsass.exe (0x1010 PROCESS_VM_READ)"; Source="Sysmon"; Level="CRIT"}
        @{Time="14:48:05"; Event="Sysmon 11: File created: C:\Users\alice\AppData\Local\Temp\lsass.dmp"; Source="Sysmon"; Level="CRIT"}
        @{Time="14:49:10"; Event="nc64.exe executed (x3) — reverse shell attempts to C2"; Source="Prefetch"; Level="CRIT"}
        @{Time="14:50:15"; Event="7045: Service 'WindowsUpdater' installed (C:\ProgramData\svchost32.exe)"; Source="System"; Level="CRIT"}
        @{Time="14:50:17"; Event="4698: Scheduled task '\WindowsTelemHelper' created (encoded PS)"; Source="Security"; Level="CRIT"}
        @{Time="14:52:00"; Event="svchost32.exe starts — malware C2 beacon active"; Source="UserAssist"; Level="CRIT"}
        @{Time="14:55:42"; Event="USB device disconnected"; Source="USBSTOR"; Level="INFO"}
        @{Time="15:10:44"; Event="1102: Security audit log CLEARED by alice"; Source="Security"; Level="CRIT"}
    ) | ForEach-Object {
        $color = switch ($_.Level) { "CRIT" { "Red" } "WARN" { "Yellow" } default { "DarkGray" } }
        Write-Host ("  {0}  [{1,-8}] {2}" -f $_.Time, $_.Source, $_.Event) -ForegroundColor $color
    }
}

function Analyze-Timestamps {
    Write-Host "`n=== MFT Timestamp Analysis (Timestomping Detection) ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  File: C:\ProgramData\svchost32.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "  `$STANDARD_INFORMATION (user-visible, modifiable by attacker):" -ForegroundColor Yellow
    Write-Host "    Created:      2020-03-15 08:00:00   <-- appears to be 4 years old" -ForegroundColor Yellow
    Write-Host "    Modified:     2020-03-15 08:00:00" -ForegroundColor Yellow
    Write-Host "    MFTModified:  2020-03-15 08:00:00" -ForegroundColor Yellow
    Write-Host "    Accessed:     2024-01-14 14:52:00   (access time is real)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  `$FILE_NAME (set by NTFS kernel, NOT easily modifiable by user tools):" -ForegroundColor Green
    Write-Host "    Created:      2024-01-14 14:50:15   <-- ACTUAL creation time!" -ForegroundColor Green
    Write-Host "    Modified:     2024-01-14 14:50:15" -ForegroundColor Green
    Write-Host "    MFTModified:  2024-01-14 14:50:15" -ForegroundColor Green
    Write-Host ""
    Write-Host "  *** TIMESTOMPING DETECTED ***" -ForegroundColor Red
    Write-Host "  The `$SI timestamps (2020) contradict the `$FN timestamps (2024)." -ForegroundColor Red
    Write-Host "  The attacker used timestomping to make malware look 4 years old." -ForegroundColor Red
    Write-Host "  Tools used: timestomp.exe, PowerShell [IO.File]::SetCreationTime()" -ForegroundColor Red
}

function Analyze-MftSequence {
    Write-Host "`n=== MFT Entry Sequence Analysis ===" -ForegroundColor Cyan
    Write-Host "  Adjacent MFT entries reveal files created at the same time:" -ForegroundColor DarkGray
    Write-Host ""
    @(
        @{Entry=45228; File="C:\ProgramData\temp_config.dat";  Time="2024-01-14 14:49:55"}
        @{Entry=45229; File="C:\ProgramData\update.log";       Time="2024-01-14 14:50:02"}
        @{Entry=45230; File="C:\ProgramData\net.dat";          Time="2024-01-14 14:50:10"}
        @{Entry=45231; File="C:\ProgramData\svchost32.exe";    Time="2024-01-14 14:50:15"}
        @{Entry=45232; File="C:\ProgramData\cfg.ini";          Time="2024-01-14 14:50:20"}
    ) | ForEach-Object {
        $color = if ($_.File -match "svchost32") { "Red" } else { "Yellow" }
        Write-Host ("  MFT #{0}: {1,-45} Created: {2}" -f $_.Entry, $_.File, $_.Time) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host "  CONCLUSION: svchost32.exe was created at 14:50:15 on 2024-01-14," -ForegroundColor White
    Write-Host "  NOT in 2020 as the `$SI timestamps claim. Timestomping confirmed." -ForegroundColor White
}

function Build-ForensicReport {
    param([string]$OutputPath = "/reports/forensic_report.txt")
    
    $report = @"
================================================================================
                    FORENSIC INVESTIGATION REPORT
                    Incident Date: 2024-01-14
                    Analyst: [Your Name]
                    System: ALICE-WORKSTATION
================================================================================

EXECUTIVE SUMMARY
-----------------
A threat actor gained access to ALICE-WORKSTATION on 2024-01-14 using a
combination of USB-delivered credentials and a network brute-force attack.
The attacker dumped NTLM credentials via Mimikatz, established persistence via
a malicious service and scheduled task, and cleared the Security event log.

TIMELINE OF EVENTS
------------------
14:20:15  USB device (SanDisk Ultra) connected to workstation
14:22:30  Attacker read E:\passwords.xlsx from USB (credential exfiltration)
14:23:05  Attacker read E:\creds.txt from USB
14:23:01  Network brute-force attack initiated from 10.0.5.123
14:47:23  Successful logon as 'alice' from 10.0.5.123
14:48:02  Mimikatz executed: LSASS memory dump created (lsass.dmp)
14:49:10  Netcat (nc64.exe) executed 3 times (reverse shell attempts)
14:50:15  Malicious service 'WindowsUpdater' installed (svchost32.exe)
14:50:17  Malicious scheduled task created (encoded PowerShell downloader)
14:52:00  Malware beacon (svchost32.exe) became active
14:55:42  USB device disconnected
15:10:44  Security event log cleared (anti-forensics)

ARTIFACTS IDENTIFIED
--------------------
1. MALWARE FILES:
   - C:\ProgramData\svchost32.exe (SHA256: 99887766aabbccdd...)
   - C:\Users\alice\AppData\Local\Temp\mimikatz.exe (DELETED but in prefetch)
   - C:\Users\alice\AppData\Local\Temp\lsass.dmp (credential dump)
   - C:\Users\alice\Downloads\nc64.exe (netcat)

2. PERSISTENCE MECHANISMS:
   - Registry: HKLM\...\Run\WindowsUpdater = C:\ProgramData\svchost32.exe
   - Service: 'WindowsUpdater' (SYSTEM, Automatic start)
   - Scheduled Task: '\WindowsTelemHelper' (PowerShell downloader, at logon)

3. TIMESTOMPING EVIDENCE:
   - svchost32.exe: SI timestamps show 2020-03-15, FN timestamps show 2024-01-14

4. INDICATORS OF COMPROMISE (IOCs):
   - Network: 10.0.5.123 (attacker source IP)
   - C2: http://evil.com/payload.ps1 (decoded from scheduled task)
   - USB Serial: 4C530001030622111552

RECOMMENDED ACTIONS
-------------------
1. IMMEDIATE: Isolate the workstation from the network
2. Reset alice's credentials (compromised via Mimikatz)
3. Check all systems for svchost32.exe (lateral movement likely)
4. Investigate SERVER02 (PsExec ran from \\SERVER02\ share)
5. Block 10.0.5.123 at perimeter firewall
6. Search SIEM for any connections to http://evil.com

================================================================================
"@
    
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`n=== Forensic Report Generated ===" -ForegroundColor Green
    Write-Host "  Report saved to: $OutputPath" -ForegroundColor Green
    Write-Host $report
}

Write-Host "Windows Forensics Demo loaded." -ForegroundColor Green
Write-Host "Type Show-ForensicsHelp to see available commands." -ForegroundColor Cyan
