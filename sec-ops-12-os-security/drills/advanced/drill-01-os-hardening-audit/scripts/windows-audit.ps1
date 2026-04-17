# Windows Hardening Audit Script — WIN-APPSERVER-01
# Run inside the container: . /audit/scripts/windows-audit.ps1; Start-Audit

$script:Pass = 0
$script:Fail = 0
$script:Warn = 0
$script:Findings = @()

function Add-Finding {
    param($ID, $CIS, $Severity, $Control, $CurrentState, $RequiredState, $EvidenceCmd, $RemediationCmd)
    $script:Findings += [PSCustomObject]@{
        ID            = $ID
        CIS           = $CIS
        Severity      = $Severity
        Control       = $Control
        CurrentState  = $CurrentState
        RequiredState = $RequiredState
        EvidenceCmd   = $EvidenceCmd
        RemediationCmd= $RemediationCmd
    }
}

function Check-Pass { param($msg) Write-Host "[PASS] $msg" -ForegroundColor Green; $script:Pass++ }
function Check-Fail { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:Fail++ }
function Check-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow; $script:Warn++ }

# Simulated Windows audit state (intentional misconfigurations)
$SimulatedState = @{
    # Password policy
    MinPasswordLength      = 8       # CIS: >= 14
    PasswordComplexity     = 1       # CIS: 1 (PASS)
    MaxPasswordAge         = 9999    # CIS: <= 365
    PasswordHistorySize    = 10      # CIS: >= 24
    LockoutThreshold       = 10      # CIS: <= 5
    LockoutDuration        = 5       # CIS: >= 15

    # Services
    SMBv1Enabled           = $true   # CIS: disabled
    PrintSpoolerRunning    = $true   # CIS: disabled on non-print servers
    TelnetRunning          = $false

    # Logging
    PSScriptBlockLogging   = $false  # CIS: enabled
    PSTranscription        = $false  # CIS: enabled
    SecurityLogSize        = 20480   # CIS: >= 196608 KB
    FirewallLoggingEnabled = $false  # CIS: enabled

    # Credentials
    RunAsPPL               = $null   # CIS: 1
    WDigestEnabled         = 1       # CIS: 0 (disabled)
    CredentialGuard        = $false  # CIS: enabled
    CachedLogons           = 10      # CIS: <= 1

    # IIS
    IISDirectoryBrowsing   = $true   # CIS: disabled
    IISTLSVersion          = "TLS1.0,TLS1.1,TLS1.2"  # CIS: TLS1.2+ only

    # WinRM
    WinRMOverHTTP          = $true   # CIS: HTTPS only
}

function Start-Audit {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " CIS L1 Audit: WIN-APPSERVER-01 (Windows Server 2022)"       -ForegroundColor Cyan
    Write-Host " Audit Date: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ' -AsUTC)"
    Write-Host "============================================================" -ForegroundColor Cyan

    Write-Host "`n=== A1: Account and Authentication Policy ===" -ForegroundColor Cyan

    $ml = $SimulatedState.MinPasswordLength
    if ($ml -ge 14) { Check-Pass "MinPasswordLength=$ml (≥14)" }
    else {
        Check-Fail "MinPasswordLength=$ml (should be ≥14, CIS 1.1.5)"
        Add-Finding "WIN-001" "CIS 1.1.5" "High" "Minimum password length" $ml "14" `
            "net accounts | grep 'Minimum password length'" `
            "net accounts /MINPWLEN:14"
    }

    $pc = $SimulatedState.PasswordComplexity
    if ($pc -eq 1) { Check-Pass "PasswordComplexity=Enabled" }
    else { Check-Fail "PasswordComplexity=Disabled (CIS 1.1.6)" }

    $mpa = $SimulatedState.MaxPasswordAge
    if ($mpa -le 365) { Check-Pass "MaxPasswordAge=$mpa (≤365)" }
    else {
        Check-Fail "MaxPasswordAge=$mpa (should be ≤365, CIS 1.1.2)"
        Add-Finding "WIN-002" "CIS 1.1.2" "Medium" "Maximum password age" $mpa "365" `
            "net accounts | grep 'Maximum password age'" `
            "net accounts /MAXPWAGE:365"
    }

    $ph = $SimulatedState.PasswordHistorySize
    if ($ph -ge 24) { Check-Pass "PasswordHistory=$ph (≥24)" }
    else {
        Check-Fail "PasswordHistory=$ph (should be ≥24, CIS 1.1.4)"
        Add-Finding "WIN-003" "CIS 1.1.4" "Medium" "Password history" $ph "24" `
            "net accounts | grep 'Length of password history'" `
            "net accounts /UNIQUEPW:24"
    }

    $lt = $SimulatedState.LockoutThreshold
    if ($lt -le 5 -and $lt -gt 0) { Check-Pass "LockoutThreshold=$lt (≤5)" }
    else {
        Check-Fail "LockoutThreshold=$lt (should be 1-5, CIS 1.2.1)"
        Add-Finding "WIN-004" "CIS 1.2.1" "High" "Account lockout threshold" $lt "5" `
            "net accounts | grep 'Lockout threshold'" `
            "net accounts /LOCKOUTTHRESHOLD:5"
    }

    $ld = $SimulatedState.LockoutDuration
    if ($ld -ge 15) { Check-Pass "LockoutDuration=$ld min (≥15)" }
    else {
        Check-Fail "LockoutDuration=$ld min (should be ≥15, CIS 1.2.2)"
        Add-Finding "WIN-005" "CIS 1.2.2" "Medium" "Account lockout duration" $ld "15" `
            "net accounts | grep 'Lockout duration'" `
            "net accounts /LOCKOUTDURATION:15"
    }

    Write-Host "`n=== A2: Windows Services and Attack Surface ===" -ForegroundColor Cyan

    if ($SimulatedState.SMBv1Enabled) {
        Check-Fail "SMBv1 ENABLED (should be disabled, CIS 18.3.3)"
        Add-Finding "WIN-006" "CIS 18.3.3" "Critical" "SMBv1 Protocol" "Enabled" "Disabled" `
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol" `
            "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    } else { Check-Pass "SMBv1 disabled" }

    if ($SimulatedState.PrintSpoolerRunning) {
        Check-Fail "Print Spooler running on non-print server (PrintNightmare risk)"
        Add-Finding "WIN-007" "CIS 18.9.59" "High" "Print Spooler service" "Running" "Stopped/Disabled" `
            "Get-Service Spooler | Select-Object Status,StartType" `
            "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled"
    } else { Check-Pass "Print Spooler disabled" }

    if ($SimulatedState.IISDirectoryBrowsing) {
        Check-Fail "IIS Directory Browsing ENABLED (information disclosure)"
        Add-Finding "WIN-008" "CIS 7.2" "Medium" "IIS Directory Browsing" "Enabled" "Disabled" `
            "Get-WebConfigurationProperty -pspath 'IIS:\Sites\*' -filter system.webServer/directoryBrowse -name enabled" `
            "Set-WebConfigurationProperty -pspath 'IIS:\' -filter 'system.webServer/directoryBrowse' -name 'enabled' -value 'False'"
    } else { Check-Pass "IIS Directory Browsing disabled" }

    if ($SimulatedState.WinRMOverHTTP) {
        Check-Fail "WinRM configured over HTTP (unencrypted, CIS 18.9.102.1)"
        Add-Finding "WIN-009" "CIS 18.9.102.1" "High" "WinRM transport security" "HTTP" "HTTPS" `
            "winrm enumerate winrm/config/listener" `
            "winrm delete winrm/config/listener?Address=*+Transport=HTTP"
    } else { Check-Pass "WinRM over HTTPS only" }

    Write-Host "`n=== A3: Logging and Audit Policy ===" -ForegroundColor Cyan

    if (-not $SimulatedState.PSScriptBlockLogging) {
        Check-Fail "PowerShell Script Block Logging DISABLED (CIS 18.9.100.1)"
        Add-Finding "WIN-010" "CIS 18.9.100.1" "High" "PS Script Block Logging" "Disabled" "Enabled" `
            "Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            "reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"
    } else { Check-Pass "PowerShell Script Block Logging enabled" }

    if (-not $SimulatedState.PSTranscription) {
        Check-Fail "PowerShell Transcription DISABLED (CIS 18.9.100.3)"
        Add-Finding "WIN-011" "CIS 18.9.100.3" "Medium" "PS Transcription" "Disabled" "Enabled" `
            "Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
            "reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription' /v EnableTranscripting /t REG_DWORD /d 1 /f"
    } else { Check-Pass "PowerShell Transcription enabled" }

    $secLog = $SimulatedState.SecurityLogSize
    if ($secLog -ge 196608) { Check-Pass "Security log size=$secLog KB (≥196608)" }
    else {
        Check-Fail "Security log size=$secLog KB (should be ≥196608 KB, CIS 18.9.26.2)"
        Add-Finding "WIN-012" "CIS 18.9.26.2" "Medium" "Security log size" "${secLog}KB" "196608KB" `
            "Get-EventLog -List | Where-Object { `$_.Log -eq 'Security' } | Select-Object MaximumKilobytes" `
            "wevtutil sl Security /ms:196608"
    }

    Write-Host "`n=== A4: Credential and Privilege Protection ===" -ForegroundColor Cyan

    $ppl = $SimulatedState.RunAsPPL
    if ($ppl -eq 1) { Check-Pass "LSA RunAsPPL=1 (LSASS Protection enabled)" }
    else {
        Check-Fail "LSA RunAsPPL=$ppl (should be 1, CIS 2.3.11.4)"
        Add-Finding "WIN-013" "CIS 2.3.11.4" "Critical" "LSASS Protection (RunAsPPL)" "Not set" "1" `
            "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL" `
            "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v RunAsPPL /t REG_DWORD /d 1 /f"
    }

    $wdigest = $SimulatedState.WDigestEnabled
    if ($wdigest -eq 0) { Check-Pass "WDigest disabled (UseLogonCredential=0)" }
    else {
        Check-Fail "WDigest ENABLED (UseLogonCredential=$wdigest) — plaintext creds in memory, CIS 2.3.11.2"
        Add-Finding "WIN-014" "CIS 2.3.11.2" "Critical" "WDigest Authentication" "Enabled" "Disabled" `
            "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential" `
            "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential /t REG_DWORD /d 0 /f"
    }

    if (-not $SimulatedState.CredentialGuard) {
        Check-Fail "Credential Guard DISABLED (CIS 2.3.11.5)"
        Add-Finding "WIN-015" "CIS 2.3.11.5" "High" "Credential Guard" "Disabled" "Enabled" `
            "Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name EnableVirtualizationBasedSecurity" `
            "# Enable via Group Policy: Computer Config > Admin Templates > System > Device Guard > Turn On VBS"
    } else { Check-Pass "Credential Guard enabled" }

    $cl = $SimulatedState.CachedLogons
    if ($cl -le 1) { Check-Pass "CachedLogonsCount=$cl (≤1)" }
    else {
        Check-Fail "CachedLogonsCount=$cl (should be ≤1, CIS 2.3.7.1)"
        Add-Finding "WIN-016" "CIS 2.3.7.1" "High" "Cached Logon Credentials" $cl "1" `
            "Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name CachedLogonsCount" `
            "reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v CachedLogonsCount /t REG_SZ /d 1 /f"
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " AUDIT SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    $total = $script:Pass + $script:Fail + $script:Warn
    $pct = [math]::Round(($script:Pass / $total) * 100)
    Write-Host "  PASS: $($script:Pass)" -ForegroundColor Green
    Write-Host "  FAIL: $($script:Fail)" -ForegroundColor Red
    Write-Host "  WARN: $($script:Warn)" -ForegroundColor Yellow
    Write-Host "  Compliance: $pct% ($($script:Pass)/$total controls passing)"
    Write-Host ""

    Write-Host "=== FINDINGS TABLE ===" -ForegroundColor Cyan
    $script:Findings | Sort-Object {
        switch ($_.Severity) { "Critical" {0} "High" {1} "Medium" {2} "Low" {3} default {4} }
    } | Format-Table ID, CIS, Severity, Control, CurrentState, RequiredState -Wrap
}

Write-Host "Audit script loaded. Run 'Start-Audit' to begin." -ForegroundColor Green
