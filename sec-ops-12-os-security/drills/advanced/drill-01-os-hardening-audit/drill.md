# Drill 01 (Advanced) — OS Hardening Audit

## Scenario

You are a senior security engineer contracted by **HeliosBank** for a **CIS Benchmark hardening audit** of two production systems:

* **WIN-APPSERVER-01**: Windows Server 2022, running an internal .NET application and IIS
* **LNX-DBSERVER-01**: Ubuntu 22.04 LTS, running PostgreSQL 15

Both systems are scheduled for a production security review before PCI-DSS recertification.
Your job is to:

1. Audit both systems against CIS Level 1 controls
1. Document every non-conformance with evidence
1. Prioritize findings by risk (Critical / High / Medium / Low)
1. Provide remediation scripts/commands for each finding
1. Produce a formal audit report that could be submitted to a compliance officer

You must also identify **two additional findings not covered by CIS L1** that represent real-world risks in the environments described.

**Estimated time:** 75–90 minutes

**Difficulty:** Advanced

**Prerequisites:** Completed intermediate drills; knowledge of CIS Benchmarks, PCI-DSS requirements, and Windows/Linux hardening.

---

## Environment Setup

```console
docker compose up -d

# Access Windows audit environment
docker exec -it win-appserver-01 pwsh

# Access Linux audit environment
docker exec -it lnx-dbserver-01 bash
```

Load helpers:

```powershell
# In the Windows container:
. /audit/scripts/windows-audit.ps1
Start-Audit

# In the Linux container:
bash /audit/scripts/linux-audit.sh
```

---

## Part A: Windows Server 2022 Audit (WIN-APPSERVER-01)

### A1: Account and Authentication Policy

```powershell
# Check password policy
net accounts

# Check lockout policy
Get-ADDefaultDomainPasswordPolicy 2>/dev/null
net accounts /domain 2>/dev/null

# Check local password policy (non-domain)
secedit /export /cfg C:\Temp\secpol.cfg /quiet
Get-Content C:\Temp\secpol.cfg | Select-String "MinimumPasswordLength|PasswordComplexity|LockoutBadCount|LockoutDuration"

# Check guest account
Get-LocalUser -Name "Guest"
Get-LocalUser | Where-Object { $_.Enabled -eq $true }
```

**Audit tasks:**

1. Evaluate password policy against CIS L1: minimum length ≥14, complexity enabled, max age ≤365, history ≥24
1. Evaluate lockout policy: threshold ≤5, duration ≥15 min
1. Is the Guest account disabled?
1. Are there any enabled accounts without recent login activity (>90 days)?

---

### A2: Windows Services and Attack Surface

```powershell
# List running services
Get-Service | Where-Object { $_.Status -eq "Running" } | Format-Table Name, DisplayName, StartType

# Check for dangerous legacy services
Get-Service -Name "TelnetD","SNMP","Spooler","RemoteRegistry","W3SVC" -ErrorAction SilentlyContinue

# Check IIS configuration
Import-Module WebAdministration 2>/dev/null
Get-Website
Get-WebBinding

# Check SMBv1
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol

# Check WinRM
Get-WSManInstance winrm/config/listener -SelectorSet @{Address="*";Transport="HTTP"} 2>/dev/null
```

**Audit tasks:**

1. Are any dangerous legacy services running (SMBv1, Telnet, SNMP v1/2)?
1. Is the Print Spooler service enabled? (PrintNightmare risk)
1. Is IIS configured with default pages, directory browsing, or weak TLS?
1. Is WinRM configured over HTTP (unencrypted)?

---

### A3: Logging and Audit Policy

```powershell
# Check audit policy
auditpol /get /category:*

# Check PowerShell logging
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -ErrorAction SilentlyContinue

# Check Windows Firewall
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked

# Check event log sizes
Get-EventLog -List | Where-Object { $_.Log -in @("Security","Application","System") } | Select-Object Log, MaximumKilobytes
```

**Audit tasks:**

1. Is PowerShell Script Block Logging enabled?
1. Is PowerShell Transcription enabled?
1. Are audit policies set for Logon/Logoff, Account Logon, Object Access, Policy Change?
1. Is Windows Firewall enabled on all profiles with logging?
1. Are Security/Application/System log sizes sufficient (≥196MB)?

---

### A4: Credential and Privilege Protection

```powershell
# Check Credential Guard / LSA Protection
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL" -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue

# Check WDigest
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name "UseLogonCredential" -ErrorAction SilentlyContinue

# Check local admin accounts
Get-LocalGroupMember -Group "Administrators"

# Check for cached credentials limit
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
```

**Audit tasks:**

1. Is LSA Protection (RunAsPPL) enabled?
1. Is WDigest authentication disabled?
1. Is Credential Guard enabled?
1. How many users are in the local Administrators group?
1. Is the cached logon credentials count ≤1?

---

## Part B: Linux (Ubuntu 22.04) Audit (LNX-DBSERVER-01)

### B1: Filesystem and Partition Security

```bash
# Check partition options
cat /etc/fstab
mount | grep -E "nosuid|noexec|nodev"

# Check world-writable files (excluding /proc, /sys)
find / -xdev -perm -0002 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -30

# Check SUID/SGID binaries (compare against baseline)
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort

# Check sticky bit on /tmp
ls -ld /tmp /var/tmp
```

**Audit tasks:**

1. Is `/tmp` mounted with `noexec,nosuid,nodev`?
1. Is `/home` mounted with `nodev`?
1. Are there world-writable files outside of `/tmp` and `/var/tmp`?
1. List all SUID/SGID binaries and identify any non-standard ones.

---

### B2: User Accounts and PAM

```bash
# Check for accounts with UID 0 (other than root)
awk -F: '$3 == 0' /etc/passwd

# Check for accounts without passwords
awk -F: '$2 == "" || $2 == "!"' /etc/shadow 2>/dev/null || echo "Cannot read shadow"

# Check PAM password requirements
cat /etc/pam.d/common-password
cat /etc/security/pwquality.conf 2>/dev/null

# Check login.defs for password aging
grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs

# Check for login shells on service accounts
grep -v "nologin\|false" /etc/passwd | grep -v "^#"
```

**Audit tasks:**

1. Are there any non-root accounts with UID 0?
1. Are PAM password complexity requirements enabled (pam_pwquality)?
1. Does password aging comply with CIS: max 365 days, min 1 day, warn 7 days?
1. Do all service accounts have non-interactive shells?

---

### B3: SSH Hardening

```console
# Audit sshd configuration
sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|allowtcpforwarding|clientaliveinterval|usepam|protocol"

# Or read config directly
grep -v "^#" /etc/ssh/sshd_config | grep -v "^$"
ls /etc/ssh/sshd_config.d/ 2>/dev/null
```

**CIS L1 SSH requirements to check:**

* `Protocol 2` only
* `PermitRootLogin no`
* `PasswordAuthentication no` (key-based auth only)
* `MaxAuthTries 4` or less
* `X11Forwarding no`
* `AllowTcpForwarding no`
* `ClientAliveInterval 300`, `ClientAliveCountMax 3`
* `LoginGraceTime 60` or less
* `PermitEmptyPasswords no`

---

### B4: Kernel and Network Security

```console
# Check kernel sysctl hardening
sysctl -a 2>/dev/null | grep -E "randomize_va_space|ip_forward|accept_redirects|send_redirects|tcp_syncookies|log_martians|rp_filter"

# Check if UFW/iptables is active
ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -20

# Check listening services
ss -tlnp

# Check if unnecessary services are running
systemctl list-units --type=service --state=running | grep -v "@" | head -30
```

**Audit tasks:**

1. Is ASLR enabled (`randomize_va_space = 2`)?
1. Is IP forwarding disabled?
1. Are ICMP redirects rejected?
1. Are SYN cookies enabled?
1. Are martian packet logs enabled?
1. Is UFW/firewall active with a default-deny policy?

---

### B5: PostgreSQL Database Security

```console
# Check PostgreSQL configuration
cat /etc/postgresql/15/main/postgresql.conf | grep -E "listen_addresses|ssl|log_connections|log_disconnections|password_encryption|log_min_duration"

cat /etc/postgresql/15/main/pg_hba.conf

# Check PostgreSQL version and patches
psql --version 2>/dev/null

# Check if PostgreSQL runs as a dedicated non-root user
ps aux | grep postgres
```

**Audit tasks (beyond OS CIS — your "additional findings"):**

1. Does PostgreSQL listen only on localhost (or required network interface)?
1. Is `ssl = on` for encrypted connections?
1. Does `pg_hba.conf` use `scram-sha-256` or `md5`? (md5 is deprecated/weak)
1. Is PostgreSQL running as a non-root user?
1. Are connection and authentication attempts logged?

---

## Deliverables

### Required Output

Produce a structured audit report containing:

1. **Executive Summary** — one paragraph summarizing overall security posture
1. **Findings Table** — every finding with: Finding ID, Control (CIS ref), Severity, Current State, Required State, Evidence Command, Remediation Command
1. **Remediation Scripts** — PowerShell script for Windows fixes; bash script for Linux fixes
1. **Risk Prioritization** — list findings in order of risk (Critical first)
1. **Compliance Gap Assessment** — estimate PCI-DSS compliance % before and after remediation

---

## Scoring

| Section | Points | Description |
|---------|--------|-------------|
| A1 Account/Auth | 12 | All Windows account findings identified |
| A2 Services | 12 | All dangerous services and IIS issues found |
| A3 Logging | 12 | All audit/logging gaps identified |
| A4 Credentials | 12 | All credential protection gaps found |
| B1 Filesystem | 12 | All Linux filesystem findings identified |
| B2 Users/PAM | 10 | User and PAM findings correct |
| B3 SSH | 10 | All SSH hardening gaps identified |
| B4 Kernel/Network | 10 | All sysctl/firewall findings correct |
| B5 PostgreSQL | 5 | DB-specific findings identified |
| Report Quality | 5 | Executive summary, table, and scripts present |
| **Total** | **100** | |

---

## Hints

* Start with the evidence commands provided for each section before diving into remediation.
* For Windows, `secedit` and `auditpol` are the ground-truth sources; `Get-*` cmdlets read live state but may not reflect policy enforcement.
* For Linux, always use `sysctl -a` rather than just `sysctl -p` — the latter only shows custom settings, not defaults.
* PostgreSQL's `pg_hba.conf` is as security-critical as a firewall rules file.
* The "two additional findings" requirement means you must go beyond the prescribed checklist. Think like an attacker: what in the described environment is exploitable that a CIS checklist wouldn't catch?
