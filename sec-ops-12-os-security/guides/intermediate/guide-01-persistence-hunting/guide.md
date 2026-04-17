# Guide 01 (Intermediate): Persistence Hunting on Windows and Linux

**Level:** Intermediate

**Estimated time:** 45 minutes

**Prerequisites:** Basic guides 01–03

---

## Objective

By the end of this guide, you will be able to:

* Systematically hunt for malware persistence mechanisms on Windows and Linux
* Use both built-in OS tools and scripted approaches to identify abnormal persistence entries
* Distinguish legitimate from suspicious persistence artifacts
* Document findings as part of an incident investigation

---

## Background

Attackers establish persistence to maintain access even after reboots, credential changes, or detection of individual malicious processes.
As a SOC analyst or incident responder, recognizing persistence is critical — it tells you the attacker planned a long-term presence, not just a quick hit.

**MITRE ATT&CK Tactic:** TA0003 - Persistence

---

## Setup

```console
cd guides/intermediate/guide-01-persistence-hunting
docker compose up --build
docker compose exec hunting bash
```

The container has a pre-configured Linux system with several persistence mechanisms planted by a simulated attacker.

---

## Part 1: Linux Persistence Hunting

### 1.1 Cron Job Review

```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d/ && for f in /etc/cron.d/*; do echo "--- $f ---"; cat "$f"; done
ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.hourly/

# All user crontabs
for user in $(cut -d: -f1 /etc/passwd); do
  cron=$(crontab -l -u "$user" 2>/dev/null)
  [ -n "$cron" ] && echo "=== $user ===" && echo "$cron"
done

# AT jobs (another scheduler often overlooked)
atq 2>/dev/null
```

**Red flags:**

* Cron entries running scripts from `/tmp`, `/dev/shm`, `/var/tmp`
* Cron entries using base64 or pipe to `bash`
* Cron entries for system users (root, daemon) that you don't recognize

---

### 1.2 Systemd Service Review

```bash
# List all unit files (pay attention to non-standard paths)
systemctl list-unit-files --type=service | grep -v "vendor preset"

# Check user systemd services (per-user persistence)
ls -la /home/*/.config/systemd/user/ 2>/dev/null

# Examine suspicious service definitions
for f in /etc/systemd/system/*.service; do
  echo "=== $f ==="
  cat "$f" | grep -E "ExecStart|Description|After"
done

# Find recently modified service files
find /etc/systemd /usr/lib/systemd -name "*.service" \
  -newer /proc/1/exe 2>/dev/null
```

---

### 1.3 SSH Authorized Keys

```bash
# Review all authorized_keys files across all user home directories
find /root /home -name "authorized_keys" 2>/dev/null | while read f; do
  echo "=== $f ==="
  cat "$f"
  echo ""
done

# Check for unusual key comments (often "attacker@" or arbitrary strings)
find /root /home -name "authorized_keys" 2>/dev/null \
  -exec grep -H "." {} \;
```

Any key you cannot attribute to a known user or deployment should be removed and treated as a backdoor.

---

### 1.4 LD_PRELOAD and Library Hijacking

```console
# LD_PRELOAD hijacking — check /etc/ld.so.preload
cat /etc/ld.so.preload 2>/dev/null && echo "FOUND: /etc/ld.so.preload" || \
  echo "OK: /etc/ld.so.preload absent (expected)"

# Check current shell environment
env | grep LD_

# Check for unusual shared libraries
ldconfig -p | grep -v "/usr/lib\|/lib"
```

`/etc/ld.so.preload` should be absent or empty.
Any entry there forces loading of a library into every process — a classic rootkit technique.

---

### 1.5 PAM Module Inspection

```console
# List PAM configuration files
ls -la /etc/pam.d/
cat /etc/pam.d/sshd   # SSH login PAM config
cat /etc/pam.d/common-auth 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null

# Verify PAM library files against known-good (using package manager)
dpkg -V libpam-runtime 2>/dev/null || rpm -V pam 2>/dev/null
```

Unexpected entries in PAM configuration can log credentials or grant unauthorized access.

---

## Part 2: Windows Persistence Hunting (PowerShell)

### 2.1 Registry Run Keys

```powershell
# Check all common Registry persistence locations
$runKeys = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

foreach ($key in $runKeys) {
  Write-Host "`n=== $key ===" -ForegroundColor Cyan
  Get-ItemProperty $key -ErrorAction SilentlyContinue
}
```

**Suspicious indicators:**

* Values pointing to `%TEMP%`, `%APPDATA%\Roaming`, `C:\Users\Public\`
* Obfuscated paths or command lines with base64 encoded payloads
* Unexpected modifications to `Userinit` or `Shell` in the Winlogon key

---

### 2.2 Scheduled Tasks

```powershell
# List all non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object {
  $_.TaskPath -notlike "\Microsoft\*"
} | Select-Object TaskName, TaskPath,
  @{N='Actions'; E={$_.Actions.Execute}},
  @{N='RunAs'; E={$_.Principal.UserId}} |
  Format-Table -AutoSize

# Examine any suspicious task in detail
# Get-ScheduledTaskInfo -TaskName "TaskName"
```

---

### 2.3 Services

```powershell
# Services running from unusual paths
Get-WmiObject Win32_Service |
  Where-Object {
    $_.PathName -and
    $_.PathName -notlike "*system32*" -and
    $_.PathName -notlike "*SysWOW64*" -and
    $_.PathName -notlike "*Program Files*"
  } |
  Select-Object Name, DisplayName, PathName, StartMode, State

# Services that start automatically
Get-Service | Where-Object {$_.StartType -eq "Automatic"} |
  Select-Object Name, DisplayName, Status
```

---

### 2.4 WMI Subscriptions (Fileless Persistence)

```powershell
# Check for WMI-based persistence (often used by APTs)
$filters   = Get-WMIObject -Namespace root\subscription -Class __EventFilter
$consumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer
$bindings  = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

Write-Host "Event Filters:   $($filters.Count)"
Write-Host "Event Consumers: $($consumers.Count)"
Write-Host "Bindings:        $($bindings.Count)"

if ($filters) { $filters | Select-Object Name, Query }
if ($consumers) { $consumers | Select-Object Name, CommandLineTemplate }
```

Any WMI subscription that is not from a known security product (e.g., SCCM, antivirus) should be investigated.

---

## Persistence Hunting Checklist

| Platform | Location | Command | Risk |
|----------|---------|---------|------|
| Linux | /etc/cron.d | `ls -la /etc/cron.d/` | Cron persistence |
| Linux | ~/.config/systemd/user/ | `find /home -name "*.service"` | User systemd service |
| Linux | /root/.ssh/authorized_keys | `cat /root/.ssh/authorized_keys` | SSH backdoor |
| Linux | /etc/ld.so.preload | `cat /etc/ld.so.preload` | Library hijack |
| Windows | HKCU\...\Run | `Get-ItemProperty HKCU:\...\Run` | Login persistence |
| Windows | Scheduled Tasks | `Get-ScheduledTask` | Scheduled persistence |
| Windows | Services | `Get-WmiObject Win32_Service` | Service persistence |
| Windows | WMI Subscriptions | `Get-WMIObject __EventFilter` | Fileless persistence |

---

## Summary

Persistence hunting is a structured discipline.
The key principle: **anything that runs automatically without a user initiating it is a potential persistence mechanism**.
Systematically work through all auto-run locations on both platforms, and flag anything you cannot immediately explain.

---

## Clean Up

```console
docker compose down
```
