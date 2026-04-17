# Guide 01: Windows Security Baseline

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Reading for Session 12

---

## Objective

By the end of this guide, you will be able to:

* Check and configure basic Windows security settings using PowerShell
* Identify common Windows hardening requirements from the CIS Benchmark
* Review user accounts and group memberships for security issues

---

## Setup

```console
cd guides/basic/guide-01-windows-security-baseline
docker compose up --build
docker compose run win-baseline
```

---

## Step 1: Check User Accounts

```powershell
# List all local users and their status
Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires, Description

# Check members of the Administrators group
Get-LocalGroupMember -Group "Administrators"

# Find accounts with passwords that never expire
Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} |
  Select-Object Name, PasswordNeverExpires
```

**What to look for:**

* Only expected accounts should exist
* Administrators group should have minimal members
* Service accounts may have non-expiring passwords (acceptable) — user accounts should not

---

## Step 2: Check Password Policy

```powershell
# View current password policy
net accounts

# Expected secure settings:
# Maximum password age: 90 days or less
# Minimum password length: 14 or more
# Lockout threshold: 5 or fewer attempts
```

**CIS Benchmark requirements:**

* Minimum length: 14 characters
* Lockout threshold: 5 attempts
* Lockout duration: 15+ minutes
* Password complexity: Enabled

---

## Step 3: Check Running Services

```powershell
# List all running services
Get-Service | Where-Object {$_.Status -eq "Running"} |
  Select-Object Name, DisplayName, StartType

# Check for high-risk services
$risky = @("TlntSvr", "RemoteRegistry", "SNMP", "Fax")
foreach ($svc in $risky) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s) {
    Write-Host "RISK: $svc is $($s.Status)" -ForegroundColor Red
  }
}
```

**High-risk services to disable if not needed:**

* TlntSvr (Telnet) — use SSH instead
* RemoteRegistry — disable unless required
* SNMP — disable unless required for network monitoring
* Fax — typically not needed

---

## Step 4: Check Windows Firewall

```powershell
# Check firewall profile status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Expected: All profiles Enabled, Inbound=Block
```

---

## Step 5: Check for Legacy Protocol Risks

```powershell
# Check SMBv1 (should be disabled — EternalBlue exploits this)
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Check if AutoRun is disabled (prevents USB malware)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |
  Select-Object NoDriveTypeAutoRun

# NoDriveTypeAutoRun = 255 means all drives disabled (secure)
```

---

## Step 6: Create a Baseline Security Report

```powershell
# Simple summary report
$report = @{
  TotalUsers = (Get-LocalUser).Count
  EnabledUsers = (Get-LocalUser | Where-Object {$_.Enabled}).Count
  AdminCount = (Get-LocalGroupMember -Group "Administrators").Count
  SMBv1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
  FirewallEnabled = (Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count -eq 0
}

$report.GetEnumerator() | ForEach-Object {
  Write-Host "$($_.Key): $($_.Value)"
}
```

---

## Summary

You have learned to:

* Enumerate local users and administrators
* Check password policy against CIS requirements
* Identify high-risk services
* Verify Windows Firewall configuration
* Check for legacy protocol risks (SMBv1)

These checks form the foundation of a Windows security audit.
In a real environment, these would be combined with Group Policy enforcement via domain infrastructure.
