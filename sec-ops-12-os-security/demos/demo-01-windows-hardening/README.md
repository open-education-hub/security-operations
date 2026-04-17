# Demo 01: Windows Security Hardening

## Overview

In this demo, we run a Windows-like security assessment inside a Docker container (using Wine/PowerShell Core or a simulated environment) to demonstrate Windows security baseline checks.
Students will run PowerShell scripts to audit user accounts, check firewall status, review running services, and examine common persistence locations.

## Learning Objectives

* Run basic Windows security audit commands using PowerShell
* Identify misconfigured accounts and services
* Examine Registry Run keys and scheduled tasks for potential persistence
* Compare a system's state against CIS Benchmark requirements

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-01-windows-hardening
docker compose up --build
```

The container provides a PowerShell Core environment with Windows security audit scripts.

```console
docker compose run win-audit
```

## Files

* `docker-compose.yml` — service definition
* `Dockerfile` — PowerShell Core on Linux container
* `scripts/audit_users.ps1` — user and group audit
* `scripts/audit_services.ps1` — service security check
* `scripts/audit_registry.ps1` — registry persistence check
* `scripts/audit_firewall.ps1` — firewall configuration check

## Walk-through

### Step 1: Audit User Accounts

```powershell
# Run inside the container
pwsh /scripts/audit_users.ps1
```

The script checks:

* Users with admin privileges
* Accounts with non-expiring passwords
* Disabled vs. enabled accounts

**What to look for:**

* Any unexpected admin accounts
* Non-expiring passwords on service accounts (acceptable) vs. user accounts (risk)
* Guest account enabled (should be disabled)

### Step 2: Audit Running Services

```powershell
pwsh /scripts/audit_services.ps1
```

Output example:

```text
=== Running Services ===
Name              Status  StartType  Account
----              ------  ---------  -------
wuauserv          Running Automatic  LocalSystem
WinDefend         Running Automatic  LocalSystem
TelnetService     Running Automatic  LocalSystem  *** RISK: Telnet enabled!
RemoteRegistry    Running Automatic  LocalSystem  *** RISK: Remote registry enabled!
```

**Risk items to flag:**

* Telnet (should be disabled — use SSH instead)
* Remote Registry (should be disabled)
* Any service running from unusual paths (e.g., C:\Users\, C:\Temp\)

### Step 3: Examine Registry Persistence Locations

```powershell
pwsh /scripts/audit_registry.ps1
```

This script examines the most common persistence locations:

```text
=== HKCU Run Keys ===
(None found - clean)

=== HKLM Run Keys ===
OneDriveSetup : C:\Windows\SysWOW64\OneDriveSetup.exe /thfirstsetup (NORMAL)
SecurityHealth : C:\Windows\System32\SecurityHealthSystray.exe (NORMAL)

=== HKLM Services (unusual paths) ===
(None found - clean)

=== Scheduled Tasks ===
\AdobeAcrobat\Adobe Acrobat Update Task (NORMAL - Adobe path)
\Microsoft\Windows\UpdateOrchestrator\... (NORMAL - Microsoft path)
```

**What to look for:**

* Entries pointing to C:\Temp\, C:\Users\, %APPDATA%
* Unusual process names or obfuscated paths
* Tasks running as SYSTEM from non-system directories

### Step 4: Check Firewall Configuration

```powershell
pwsh /scripts/audit_firewall.ps1
```

Output:

```text
=== Windows Firewall Profiles ===
Domain Profile:  Enabled, Inbound: Block, Outbound: Allow
Private Profile: Enabled, Inbound: Block, Outbound: Allow
Public Profile:  Enabled, Inbound: Block, Outbound: Allow

=== Potentially Risky Inbound Rules (Enabled) ===
Rule: File and Printer Sharing (SMB-In) - WARN: SMB exposed
Rule: Remote Desktop - WARN: RDP exposed - verify if needed
```

### Step 5: Generate a Simple Security Report

```powershell
# Run the full audit and save to HTML
pwsh /scripts/full_audit.ps1 -OutputPath /reports/security_report.html
```

Review the generated report highlighting:

* PASS: Controls meeting the baseline
* WARN: Controls requiring attention
* FAIL: Controls clearly failing the baseline

## Discussion Points

1. **Default configurations are insecure**: Many Windows services are enabled by default that should be disabled (Telnet, Remote Registry, NetBIOS).

1. **Registry Run keys**: Even a small malicious entry in Run keys can establish persistence that survives reboots.

1. **Service account minimization**: Services should run as least-privileged accounts (Network Service, Local Service) rather than Local System wherever possible.

1. **Scheduled task visibility**: Many legitimate applications create scheduled tasks — distinguishing legitimate from malicious requires attention to the task's executable path.

## Clean Up

```console
docker compose down
```
