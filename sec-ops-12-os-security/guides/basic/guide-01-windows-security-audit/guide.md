# Guide 01: Windows Security Audit Checklist

**Level:** Basic

**Estimated time:** 45 minutes

**Prerequisites:** Session 12 reading (Sections 2–5)

---

## Objective

By the end of this guide you will be able to:

* Conduct a systematic Windows security audit using PowerShell
* Evaluate a Windows system against CIS Benchmark Level 1 requirements
* Identify LSASS and credential protection status
* Review AppLocker, Windows Defender, and Firewall configuration
* Check for common persistence indicators (registry, services, scheduled tasks)
* Produce a structured security findings report

---

## Setup

```console
cd guides/basic/guide-01-windows-security-audit
docker compose up --build
docker compose run win-audit pwsh
```

---

## Section 1: Identity and Access Management

### 1.1 User Account Inventory

```powershell
# List all local user accounts
Get-LocalUser | Select-Object Name, SID, Enabled, PasswordNeverExpires, LastLogon, Description |
  Format-Table -AutoSize

# CIS Check: Guest account must be disabled
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    Write-Host "FAIL: Guest account is ENABLED" -ForegroundColor Red
    Write-Host "  Fix: Disable-LocalUser -Name 'Guest'"
} else {
    Write-Host "PASS: Guest account is disabled" -ForegroundColor Green
}

# CIS Check: Administrator account should be disabled or renamed
$admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($admin -and $admin.Enabled) {
    Write-Host "WARN: Built-in Administrator account is ENABLED" -ForegroundColor Yellow
    Write-Host "  Recommendation: Disable or rename this account"
}
```

### 1.2 Administrators Group

```powershell
# Who has local admin rights?
Get-LocalGroupMember -Group "Administrators" |
  Select-Object Name, ObjectClass, PrincipalSource | Format-Table

# CIS Check: Administrators group should contain minimal accounts
# Expected: only the renamed Administrator + any explicitly approved admin accounts
```

### 1.3 Password Policy

```powershell
# Check current password policy
net accounts

# CIS Level 1 Minimum Requirements:
# Minimum password length:  14
# Lockout threshold:         5 attempts
# Lockout duration:          15 minutes
# Password complexity:      Enabled

# Review via registry (Group Policy applied settings)
$pwPolicy = @{
    "MinPasswordLength"    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").MinimumPasswordLength
}
Write-Host "Min Password Length: $($pwPolicy['MinPasswordLength'])"
```

---

## Section 2: LSASS and Credential Protection

### 2.1 LSASS Protected Process Light

```powershell
# Check RunAsPPL status (protects LSASS from memory reading)
$ppl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
if ($ppl -eq 1) {
    Write-Host "PASS: LSASS RunAsPPL is ENABLED (Mimikatz cannot read LSASS)" -ForegroundColor Green
} else {
    Write-Host "FAIL: LSASS RunAsPPL is DISABLED" -ForegroundColor Red
    Write-Host "  Fix: Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (requires reboot)"
}
```

### 2.2 Credential Guard

```powershell
# Check Credential Guard / VBS status
try {
    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard `
           -ErrorAction Stop
    $cgRunning = $vbs.SecurityServicesRunning -contains 1
    if ($cgRunning) {
        Write-Host "PASS: Credential Guard is RUNNING (LSAIso active)" -ForegroundColor Green
    } else {
        Write-Host "WARN: Credential Guard is NOT running" -ForegroundColor Yellow
        Write-Host "  Requires: 64-bit OS, UEFI, Secure Boot, Hyper-V, TPM 2.0"
    }
} catch {
    Write-Host "INFO: Cannot query Device Guard status in this environment" -ForegroundColor Gray
}
```

### 2.3 Wdigest Authentication (Plaintext Credential Risk)

```powershell
# WDigest stores plaintext credentials in LSASS when enabled
$wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
             -ErrorAction SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) {
    Write-Host "CRITICAL: WDigest is ENABLED - plaintext passwords stored in LSASS memory!" -ForegroundColor Red
    Write-Host "  Fix: Set UseLogonCredential = 0"
    Write-Host "  New-ItemProperty -Force -Path 'HKLM:\...\WDigest' -Name UseLogonCredential -Value 0"
} else {
    Write-Host "PASS: WDigest is disabled (plaintext creds not cached)" -ForegroundColor Green
}
```

---

## Section 3: Windows Security Features

### 3.1 Windows Defender

```powershell
# Check Defender status
try {
    $defender = Get-MpComputerStatus
    Write-Host "Antivirus Enabled:         $($defender.AntivirusEnabled)"
    Write-Host "Real-Time Protection:      $($defender.RealTimeProtectionEnabled)"
    Write-Host "Behavior Monitor Enabled:  $($defender.BehaviorMonitorEnabled)"
    Write-Host "Network Inspection:        $($defender.NISEnabled)"
    Write-Host "Antivirus Signature Age:   $($defender.AntivirusSignatureAge) days"

    if (-not $defender.RealTimeProtectionEnabled) {
        Write-Host "FAIL: Real-time protection is DISABLED" -ForegroundColor Red
    }
    if ($defender.AntivirusSignatureAge -gt 7) {
        Write-Host "WARN: Signatures are $($defender.AntivirusSignatureAge) days old (update needed)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "INFO: Windows Defender status not available in this environment" -ForegroundColor Gray
}
```

### 3.2 Windows Firewall

```powershell
# Verify all firewall profiles are enabled and set to block inbound
Get-NetFirewallProfile | ForEach-Object {
    $status = if ($_.Enabled -and $_.DefaultInboundAction -eq "Block") { "PASS" } else { "FAIL" }
    $color  = if ($status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "[$status] $($_.Name): Enabled=$($_.Enabled), InboundDefault=$($_.DefaultInboundAction)" -ForegroundColor $color
}

# Check for dangerous "allow all" rules
$risky = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  Where-Object { $_.LocalPort -eq "Any" -and $_.RemoteAddress -eq "Any" }
if ($risky) {
    Write-Host "CRITICAL: Found overly permissive inbound rules:" -ForegroundColor Red
    $risky | Select-Object DisplayName, Profile | Format-Table
}
```

### 3.3 AppLocker Status

```powershell
# Check AppLocker service and policy
$appid = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
if ($appid -and $appid.Status -eq "Running") {
    Write-Host "PASS: Application Identity service (AppIDSvc) is running" -ForegroundColor Green
} else {
    Write-Host "WARN: AppIDSvc not running — AppLocker may not be enforcing" -ForegroundColor Yellow
}

# Check if policy is configured
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $ruleCount = ($policy.RuleCollections | Measure-Object).Count
    Write-Host "INFO: AppLocker has $ruleCount rule collections configured"
    $policy.RuleCollections | ForEach-Object {
        Write-Host "  Collection: $($_.RuleCollectionType) - Rules: $(($_.Rules | Measure-Object).Count)"
    }
} catch {
    Write-Host "WARN: AppLocker policy not configured or not available" -ForegroundColor Yellow
}
```

---

## Section 4: Legacy Protocol and Protocol Security

```powershell
# SMBv1 - exploited by EternalBlue (WannaCry, NotPetya)
try {
    $smb = Get-SmbServerConfiguration
    if ($smb.EnableSMB1Protocol) {
        Write-Host "CRITICAL: SMBv1 is ENABLED - vulnerable to EternalBlue!" -ForegroundColor Red
        Write-Host "  Fix: Set-SmbServerConfiguration -EnableSMB1Protocol `$false"
    } else {
        Write-Host "PASS: SMBv1 is disabled" -ForegroundColor Green
    }
} catch {
    Write-Host "INFO: SMB status not available" -ForegroundColor Gray
}

# NTLMv1 compatibility level (should be 5 = NTLMv2 only)
$lm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").LMCompatibilityLevel
$lmStatus = switch ($lm) {
    5 { "PASS: NTLMv2 only (level 5)" }
    4 { "WARN: Level 4 — NTLMv2 responses only, NTLMv1 accepted from clients" }
    3 { "WARN: Level 3 — NTLMv2 responses only" }
    default { "FAIL: Level $lm — LM/NTLMv1 still active (credential relay risk!)" }
}
$color = if ($lm -ge 5) { "Green" } elseif ($lm -ge 3) { "Yellow" } else { "Red" }
Write-Host "[$color] NTLM Compatibility Level: $lmStatus" -ForegroundColor $color
```

---

## Section 5: Logging and Auditing

```powershell
# Check advanced audit policy
$auditCategories = @(
    "Logon/Logoff",
    "Account Logon",
    "Process Creation",
    "Special Logon"
)

foreach ($cat in $auditCategories) {
    $result = auditpol /get /category:$cat 2>$null
    Write-Host "Category: $cat"
    Write-Host $result
}

# PowerShell logging
$moduleLog = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
               -ErrorAction SilentlyContinue).EnableModuleLogging
$scriptLog = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
               -ErrorAction SilentlyContinue).EnableScriptBlockLogging

Write-Host "PowerShell Module Logging:       $(if($moduleLog -eq 1){'ENABLED'}else{'DISABLED - WARN'})"
Write-Host "PowerShell Script Block Logging: $(if($scriptLog -eq 1){'ENABLED'}else{'DISABLED - WARN'})"
```

---

## Section 6: Persistence Indicators

```powershell
# Review registry Run keys for suspicious entries
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    try {
        $entries = Get-ItemProperty $key -ErrorAction Stop
        $entries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            $suspicious = $_.Value -match "Temp|AppData\\Local\\Temp|\.\.\\|\.(cmd|vbs|js)\b"
            $color = if ($suspicious) { "Red" } else { "Gray" }
            $flag  = if ($suspicious) { "  *** SUSPICIOUS ***" } else { "" }
            Write-Host "  $($_.Name): $($_.Value)$flag" -ForegroundColor $color
        }
    } catch {}
}

# Non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"
} | Select-Object TaskName, TaskPath, State,
    @{N="Action";E={$_.Actions.Execute}} | Format-Table -AutoSize

# Services running from unusual paths
Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
  Where-Object {
    $_.State -eq "Running" -and
    $_.PathName -notmatch "system32|SysWOW64|Program Files" -and
    $_.PathName -notmatch "^$"
  } | Select-Object Name, PathName, State | Format-Table
```

---

## Section 7: Generate Audit Report

```powershell
$report = [ordered]@{}

# Check each control
$report["Guest Account Disabled"]         = (Get-LocalUser -Name "Guest" -EA SilentlyContinue)?.Enabled -eq $false
$report["RunAsPPL LSASS Protection"]      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).RunAsPPL -eq 1
$report["WDigest Disabled"]               = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -EA SilentlyContinue).UseLogonCredential -ne 1
$report["SMBv1 Disabled"]                 = ((Get-SmbServerConfiguration -EA SilentlyContinue)?.EnableSMB1Protocol) -eq $false
$report["NTLM Level 5"]                   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).LMCompatibilityLevel -ge 5
$report["Firewall All Profiles Enabled"]  = (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -eq 0
$report["Firewall Inbound Block"]         = (Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne "Block" }).Count -eq 0
$report["PS Script Block Logging"]        = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -EA SilentlyContinue).EnableScriptBlockLogging -eq 1

Write-Host "`n=== WINDOWS SECURITY AUDIT REPORT ===" -ForegroundColor Cyan
Write-Host ("=" * 50)
$pass = 0; $fail = 0
$report.GetEnumerator() | ForEach-Object {
    if ($_.Value -eq $true) {
        Write-Host "  [PASS] $($_.Key)" -ForegroundColor Green; $pass++
    } else {
        Write-Host "  [FAIL] $($_.Key)" -ForegroundColor Red; $fail++
    }
}
Write-Host ("=" * 50)
Write-Host "  Score: $pass PASS / $fail FAIL out of $($pass+$fail) checks"
$score = [math]::Round(($pass / ($pass+$fail)) * 100)
Write-Host "  Compliance: $score%" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
```

---

## Summary

You have completed a Windows security audit covering:

| Category | Key Checks |
|----------|-----------|
| Identity | Guest/Admin accounts, Administrators group membership |
| Credential Protection | RunAsPPL, Credential Guard, WDigest disabled |
| Security Features | Defender, Firewall, AppLocker status |
| Legacy Protocols | SMBv1 disabled, NTLMv1 blocked |
| Logging | Advanced Audit Policy, PowerShell script block logging |
| Persistence | Registry Run keys, scheduled tasks, unusual services |

In a real Windows environment, many of these checks would be enforced via **Group Policy Objects (GPOs)** and validated centrally through a **SIEM**.
The CIS Windows Benchmark provides detailed remediation scripts for every failing control.
