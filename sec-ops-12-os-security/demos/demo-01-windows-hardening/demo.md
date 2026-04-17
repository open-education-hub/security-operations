# Demo 01: Windows Security Hardening

**Estimated time:** 30 minutes

---

## Overview

Run a Windows-like security assessment inside a Docker container using PowerShell Core.
You will audit user accounts, check firewall status, review running services, and examine common persistence locations — comparing findings against CIS Benchmark requirements.

---

## Learning Objectives

* Run basic Windows security audit commands using PowerShell
* Identify misconfigured accounts and services
* Examine Registry Run keys and scheduled tasks for potential persistence
* Compare a system's state against CIS Benchmark requirements

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-01-windows-hardening
docker compose up --build
docker compose run win-audit
```

The container provides a PowerShell Core environment with Windows security audit scripts.

---

## Step 1: Audit User Accounts

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
* Non-expiring passwords on user accounts (service accounts may be acceptable)
* Guest account enabled (should be disabled)

---

## Step 2: Audit Running Services

```powershell
pwsh /scripts/audit_services.ps1
```

Expected output:

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
* Remote Registry (should be disabled unless explicitly required)
* Services running from unusual paths (e.g., `C:\Users\`, `C:\Temp\`)

---

## Step 3: Examine Registry Persistence Locations

```powershell
pwsh /scripts/audit_registry.ps1
```

Example output:

```text
=== HKCU Run Keys ===
(None found - clean)

=== HKLM Run Keys ===
OneDriveSetup  : C:\Windows\SysWOW64\OneDriveSetup.exe  (NORMAL)
SecurityHealth : C:\Windows\System32\SecurityHealthSystray.exe  (NORMAL)

=== Scheduled Tasks ===
\AdobeAcrobat\Adobe Acrobat Update Task  (NORMAL)
\Microsoft\Windows\UpdateOrchestrator\  (NORMAL)
```

**Red flags to look for:**

* Entries pointing to `C:\Temp\`, `C:\Users\`, `%APPDATA%`
* Obfuscated process names or paths
* Tasks running as SYSTEM from non-system directories

---

## Step 4: Check Firewall Configuration

```powershell
pwsh /scripts/audit_firewall.ps1
```

Expected output:

```text
=== Windows Firewall Profiles ===
Domain Profile:  Enabled, Inbound: Block, Outbound: Allow
Private Profile: Enabled, Inbound: Block, Outbound: Allow
Public Profile:  Enabled, Inbound: Block, Outbound: Allow

=== Potentially Risky Inbound Rules (Enabled) ===
Rule: File and Printer Sharing (SMB-In)  - WARN: SMB exposed
Rule: Remote Desktop  - WARN: RDP exposed — verify if needed
```

---

## Step 5: Generate a Security Report

```powershell
pwsh /scripts/full_audit.ps1 -OutputPath /reports/security_report.html
```

Review the generated report:

* **PASS:** Controls meeting the CIS baseline
* **WARN:** Controls requiring attention
* **FAIL:** Controls clearly failing the baseline

---

## Discussion Points

1. **Default configurations are insecure**: Windows services like Telnet and Remote Registry are enabled by default on some editions and should be disabled.

1. **Registry Run keys**: Even a small malicious entry in Run keys establishes persistence that survives reboots.

1. **Service accounts**: Services should run as least-privileged accounts (Network Service, Local Service) rather than SYSTEM wherever possible.

1. **Scheduled task visibility**: Distinguishing legitimate from malicious scheduled tasks requires attention to the executable path — legitimate Microsoft tasks live under `\Microsoft\Windows\`.

---

## Clean Up

```console
docker compose down
```
