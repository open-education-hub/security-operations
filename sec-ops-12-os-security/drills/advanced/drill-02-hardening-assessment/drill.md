# Drill 02 (Advanced) — Hardening Assessment and CIS Benchmark

**Level:** Advanced

**Estimated time:** 75 minutes

---

## Objective

Perform a comprehensive CIS Benchmark compliance assessment on two systems (one Windows, one Linux), quantify the hardening gap, prioritize remediation by risk, and produce an executive-level security posture report.

---

## Setup

```console
cd drills/advanced/drill-02-hardening-assessment
docker compose up --build
```

Two containers start:

* `win-assessment` — PowerShell Core on Linux simulating Windows controls
* `linux-assessment` — Ubuntu 22.04 with intentional CIS deviations

Access them:

```console
docker compose exec win-assessment pwsh
docker compose exec linux-assessment bash
```

---

## Scenario

**Organization:** NorthEdge Manufacturing

**Context:** NorthEdge recently suffered a ransomware attack (XDR detected and contained it).
As part of post-incident recovery, the CISO has commissioned a full CIS Benchmark assessment of the two most common system types across their fleet: Windows workstations and Ubuntu application servers.

**Your role:** Security analyst conducting the assessment.
You must assess both platforms, quantify compliance, prioritize remediation by risk, and present findings to the CISO in a clear report.

---

## Task 1: Windows CIS Level 1 Assessment (30 checks)

Assess the simulated Windows system against the CIS Benchmark Level 1 controls.
You must check at least the following 10 categories and 30 specific controls:

### Account Policies (5 checks)

```powershell
net accounts
Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires
Get-LocalGroupMember -Group "Administrators"
```

Check:

1. Minimum password length ≥ 14?
1. Password complexity enabled?
1. Maximum password age ≤ 90 days?
1. Account lockout threshold ≤ 5?
1. Guest account disabled?

### Local Policies — Audit (5 checks)

```powershell
auditpol /get /category:*
```

Check:

1. Logon/Logoff audit enabled (success + failure)?
1. Account Logon audit enabled?
1. Object Access audit enabled?
1. Privilege Use audit enabled?
1. Process Creation audit enabled?

### Windows Firewall (3 checks)

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
```

Check:

1. Domain Profile enabled?
1. Private Profile enabled?
1. Public Profile enabled?

### Security Options (5 checks)

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
```

Check:

1. LAN Manager authentication level = 5 (NTLMv2 only)?
1. SMBv1 disabled?
1. Anonymous SID enumeration disabled?
1. AutoPlay disabled?
1. UAC enabled?

### Services (7 checks)

Check these services are disabled:

1. Telnet (TlntSvr)?
1. Remote Registry?
1. NetBIOS?
1. LLMNR?
1. WDigest authentication disabled?
1. Bluetooth (if not needed)?
1. Print Spooler (on non-print servers)?

### Software and Patching (5 checks)

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
Get-WmiObject -Class Win32_QuickFixEngineering | Measure-Object
```

Check:

1. Windows Update service enabled?
1. Automatic updates configured?
1. Last patch within 30 days?
1. No critical patches missing >30 days?
1. Windows Defender enabled and updated?

---

## Task 2: Linux CIS Level 1 Assessment (30 checks)

Assess the Ubuntu system against CIS Ubuntu 22.04 Benchmark Level 1.

### Filesystem Configuration (5 checks)

```console
findmnt /tmp
grep "noexec\|nosuid\|nodev" /etc/fstab
```

Check:

1. /tmp mounted with noexec?
1. /tmp mounted with nodev?
1. /tmp mounted with nosuid?
1. /var/tmp mounted with restrictions?
1. Sticky bit set on all world-writable directories?

### Software and Patching (3 checks)

```console
apt list --upgradable 2>/dev/null | wc -l
systemctl is-enabled unattended-upgrades
```

Check:

1. Package manager configured?
1. Unattended security upgrades enabled?
1. No outstanding critical patches?

### Authentication (7 checks)

```console
grep -E "^PermitRootLogin|^PasswordAuthentication|^MaxAuthTries|^Protocol" /etc/ssh/sshd_config
chage -l root
```

Check:

1. SSH root login disabled?
1. SSH password auth disabled?
1. SSH MaxAuthTries ≤ 3?
1. SSH Protocol 2?
1. Password expiration configured (max 365 days)?
1. Password minimum age ≥ 1 day?
1. PAM password complexity configured?

### Logging (5 checks)

```console
systemctl is-active rsyslog
systemctl is-active auditd
ls /etc/audit/rules.d/
```

Check:

1. rsyslog (or syslog-ng) running?
1. auditd running?
1. Audit rules for privileged commands?
1. Audit rules for identity files (/etc/passwd, /etc/shadow)?
1. Log files have appropriate permissions (640 or more restrictive)?

### Network Configuration (5 checks)

```console
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.tcp_syncookies
sysctl kernel.randomize_va_space
```

Check:

1. IP forwarding disabled?
1. ICMP redirects ignored?
1. SYN cookie protection enabled?
1. ASLR enabled (value = 2)?
1. Source route packets refused?

### File Permissions (5 checks)

```console
stat /etc/passwd /etc/shadow /etc/gshadow /etc/crontab
find / -perm -4000 -type f 2>/dev/null
```

Check:

1. /etc/passwd permissions = 644?
1. /etc/shadow permissions = 640?
1. /etc/gshadow permissions = 640?
1. No SUID binaries outside standard locations?
1. /etc/crontab permissions = 644?

---

## Task 3: Compliance Scoring

For both systems, calculate:

* **Compliance score:** (passed checks / total checks) × 100
* **Critical failures:** Any check at Level 1 that directly enabled the recent ransomware attack or would directly enable another attack
* **Risk-weighted score:** Weight each finding by CVSS-equivalent severity (Critical=10, High=7, Medium=4, Low=1)

Present results in a table:

| Category | Windows Score | Linux Score | Priority |
|----------|--------------|-------------|----------|
| Account Policies | X/5 | X/7 | High |
| ... | | | |
| **Total** | **X/30** | **X/30** | |

---

## Task 4: Risk-Prioritized Remediation Plan

Rank all failures by: **Risk = Likelihood × Impact**

Use this scoring:

* **Critical (immediate):** Would allow direct compromise or was a root cause of the ransomware attack
* **High (this week):** Significantly increases attack surface
* **Medium (this month):** Security improvement but not directly exploitable
* **Low (next quarter):** Best practice, minimal direct risk

For each Critical and High finding, provide:

* The specific command to fix it
* The expected compliance state after the fix
* How to verify the fix was applied

---

## Task 5: Executive Summary

Write a 1-page executive summary for the CISO covering:

1. **Overall posture:** What percentage compliant are the two system types?
1. **Most critical gaps:** The top 3 findings that create the most risk (link to the recent ransomware incident where applicable)
1. **Quick wins:** The 5 fixes that take <15 minutes and eliminate the highest risk
1. **90-day roadmap:** A phased remediation plan

**Constraint:** No technical jargon — write for a non-technical executive.

---

## Deliverable

A complete assessment report:

1. Compliance scoring table (Task 3)
1. Risk-prioritized remediation plan (Task 4)
1. Executive summary (Task 5)

See the solution in: `solutions/drill-02-solution/solution.md`
