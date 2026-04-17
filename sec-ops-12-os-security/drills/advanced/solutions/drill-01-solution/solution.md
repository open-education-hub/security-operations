# Solution: Drill 01 (Advanced) — OS Hardening Audit

## Complete Audit Report: HeliosBank Production Systems

**Audit Date:** 2024-01-15
**Systems:** WIN-APPSERVER-01 (Windows Server 2022) | LNX-DBSERVER-01 (Ubuntu 22.04)
**Framework:** CIS Benchmark Level 1

**Compliance Context:** PCI-DSS v4.0 Requirement 2 (Secure Configurations)

---

## Executive Summary

Both production systems exhibit **significant hardening deficiencies** that create material risk to HeliosBank's security posture and PCI-DSS compliance.
WIN-APPSERVER-01 has **16 non-conformances** — most critically: WDigest authentication enabled (plaintext credentials in memory), LSASS not protected, SMBv1 active, and absent credential protection controls.
LNX-DBSERVER-01 has **14 non-conformances** including: ASLR disabled, IP forwarding active, dangerous SSH settings, weak PAM password policy, and PostgreSQL configured to accept cleartext connections from any host.
Both systems are estimated at **~35% CIS L1 compliance** before remediation.

Two additional findings beyond CIS L1 were identified:

1. **IIS legacy TLS** on WIN-APPSERVER-01 accepts TLS 1.0/1.1 connections — a direct PCI-DSS v4.0 Requirement 4.2.1 violation
1. **PostgreSQL pg_hba.conf allows 0.0.0.0/0 with md5** — exposes the database to network-based brute force and uses deprecated password hashing

Estimated compliance after applying all remediation: **~92% CIS L1**.

---

## Findings Table

### Windows — WIN-APPSERVER-01

| ID | CIS Ref | Severity | Control | Current State | Required State |
|----|---------|----------|---------|---------------|----------------|
| WIN-001 | CIS 1.1.5 | High | Minimum password length | 8 characters | ≥14 characters |
| WIN-002 | CIS 1.1.2 | Medium | Maximum password age | 9999 days | ≤365 days |
| WIN-003 | CIS 1.1.4 | Medium | Password history | 10 passwords | ≥24 passwords |
| WIN-004 | CIS 1.2.1 | High | Account lockout threshold | 10 attempts | ≤5 attempts |
| WIN-005 | CIS 1.2.2 | Medium | Lockout duration | 5 minutes | ≥15 minutes |
| WIN-006 | CIS 18.3.3 | **Critical** | SMBv1 Protocol | **Enabled** | Disabled |
| WIN-007 | CIS 18.9.59 | High | Print Spooler service | Running | Stopped/Disabled |
| WIN-008 | CIS 7.2 | Medium | IIS Directory Browsing | Enabled | Disabled |
| WIN-009 | CIS 18.9.102 | High | WinRM transport | HTTP (cleartext) | HTTPS only |
| WIN-010 | CIS 18.9.100.1 | High | PS Script Block Logging | Disabled | Enabled |
| WIN-011 | CIS 18.9.100.3 | Medium | PS Transcription | Disabled | Enabled |
| WIN-012 | CIS 18.9.26.2 | Medium | Security log size | 20 MB | ≥196 MB |
| WIN-013 | CIS 2.3.11.4 | **Critical** | LSASS Protection (RunAsPPL) | Not configured | 1 (Enabled) |
| WIN-014 | CIS 2.3.11.2 | **Critical** | WDigest Authentication | **Enabled** | Disabled |
| WIN-015 | CIS 2.3.11.5 | High | Credential Guard | Disabled | Enabled |
| WIN-016 | CIS 2.3.7.1 | High | Cached Logon Credentials | 10 | ≤1 |
| WIN-017 | *(Additional)* | **Critical** | IIS TLS Version | TLS 1.0+1.1+1.2 | TLS 1.2+ only (PCI-DSS req.) |

### Linux — LNX-DBSERVER-01

| ID | CIS Ref | Severity | Control | Current State | Required State |
|----|---------|----------|---------|---------------|----------------|
| LNX-001 | CIS 1.1.2-4 | High | /tmp mount hardening | Not mounted with noexec,nosuid,nodev | Hardened tmpfs |
| LNX-002 | CIS 6.1.12 | **Critical** | World-writable files | `/opt/app/deploy.sh` (777), `/opt/app/config.db` (666) | No world-writable files outside /tmp |
| LNX-003 | CIS 6.2.3 | Medium | Service account shells | postgres, www-data-svc have `/bin/bash` | `/usr/sbin/nologin` |
| LNX-004 | CIS 5.4.1.1 | High | PASS_MAX_DAYS | 9999 | ≤365 |
| LNX-005 | CIS 5.4.1.2 | Medium | PASS_MIN_DAYS | 0 | ≥1 |
| LNX-006 | CIS 5.4.1.3 | Medium | PASS_WARN_AGE | 0 | ≥7 |
| LNX-007 | CIS 5.3.1 | High | PAM pwquality minlen | 6 | ≥14 |
| LNX-008 | CIS 5.2.10 | **Critical** | SSH PermitRootLogin | yes | no |
| LNX-009 | CIS 5.2.12 | **Critical** | SSH PasswordAuthentication | yes | no |
| LNX-010 | CIS 5.2.7 | High | SSH MaxAuthTries | 6 | ≤4 |
| LNX-011 | CIS 5.2.6 | Medium | SSH X11Forwarding | yes | no |
| LNX-012 | CIS 5.2.21 | Medium | SSH AllowTcpForwarding | yes | no |
| LNX-013 | CIS 5.2.22 | High | SSH ClientAliveInterval | 0 (disabled) | ≤300 |
| LNX-014 | CIS 1.5.2 | **Critical** | ASLR (randomize_va_space) | **0 (disabled)** | 2 |
| LNX-015 | CIS 3.1.1 | High | IP forwarding | 1 (enabled) | 0 |
| LNX-016 | CIS 3.2.2 | Medium | ICMP redirects | Accepted | Rejected |
| LNX-017 | CIS 3.3.8 | High | SYN cookies | 0 (disabled) | 1 |
| LNX-018 | CIS 3.3.1 | Medium | Martian packet logging | 0 | 1 |
| LNX-019 | *(Additional)* | **Critical** | PostgreSQL wildcard access | 0.0.0.0/0 with md5 | Restrict to app server IPs; use scram-sha-256 |

---

## Remediation Scripts

### Windows Remediation Script

```powershell
# windows-remediation.ps1
# Run as: powershell.exe -ExecutionPolicy Bypass -File windows-remediation.ps1

Write-Host "Applying Windows Server 2022 CIS L1 hardening..."

# A1: Password & Lockout Policy
net accounts /MINPWLEN:14 /MAXPWAGE:365 /UNIQUEPW:24 /LOCKOUTTHRESHOLD:5 /LOCKOUTDURATION:15

# A2: Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# A2: Disable Print Spooler
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled

# A2: Disable IIS Directory Browsing
Import-Module WebAdministration -ErrorAction SilentlyContinue
Set-WebConfigurationProperty -pspath 'IIS:\' `
    -filter 'system.webServer/directoryBrowse' -name 'enabled' -value 'False'

# A2: Remove WinRM HTTP listener
winrm delete winrm/config/listener?Address=*+Transport=HTTP 2>$null

# A3: Enable PowerShell Script Block Logging
$psRegPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psRegPath\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psRegPath\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
New-Item -Path "$psRegPath\Transcription" -Force | Out-Null
Set-ItemProperty -Path "$psRegPath\Transcription" -Name EnableTranscripting -Value 1
Set-ItemProperty -Path "$psRegPath\Transcription" -Name OutputDirectory -Value "C:\PSLogs"

# A3: Increase Security log size
wevtutil sl Security /ms:196608
wevtutil sl Application /ms:32768
wevtutil sl System /ms:32768

# A4: Disable WDigest
$wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
Set-ItemProperty -Path $wdigestPath -Name UseLogonCredential -Value 0

# A4: Enable LSASS protection (RunAsPPL)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1

# A4: Reduce cached logon credentials
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name CachedLogonsCount -Value 1

# Additional: Disable TLS 1.0 and 1.1
foreach ($tls in @("TLS 1.0","TLS 1.1")) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$tls\Server"
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name Enabled -Value 0
    Set-ItemProperty -Path $path -Name DisabledByDefault -Value 1
}

Write-Host "Windows hardening applied. A reboot is required for LSASS protection to take effect."
```

### Linux Remediation Script

```bash
#!/bin/bash
# linux-remediation.sh — Apply CIS L1 hardening to LNX-DBSERVER-01
set -euo pipefail

echo "Applying Ubuntu 22.04 CIS L1 hardening..."

# B1: /tmp hardening
if ! grep -q "^tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    mount -o remount /tmp 2>/dev/null || true
fi

# B1: World-writable file remediation
chmod o-w /opt/app/deploy.sh
chmod o-w /opt/app/config.db
chmod u-s /usr/bin/python3 2>/dev/null || true

# B2: Service account shell hardening
usermod -s /usr/sbin/nologin postgres 2>/dev/null || true
usermod -s /usr/sbin/nologin www-data-svc 2>/dev/null || true

# B2: Password aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# B2: PAM password complexity
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

# B3: SSH hardening
cat > /etc/ssh/sshd_config.d/cis-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 4
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
PermitEmptyPasswords no
EOF
sshd -t && systemctl reload sshd

# B4: Kernel hardening
cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
sysctl -p /etc/sysctl.d/99-cis-hardening.conf

# B5: PostgreSQL hardening
PGCONF="/etc/postgresql/15/main/postgresql.conf"
PGHBA="/etc/postgresql/15/main/pg_hba.conf"
if [ -f "$PGCONF" ]; then
    sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$PGCONF"
    sed -i 's/^ssl = off/ssl = on/' "$PGCONF"
    sed -i 's/^log_connections.*/log_connections = on/' "$PGCONF"
    sed -i 's/^password_encryption.*/password_encryption = scram-sha-256/' "$PGCONF"
fi
if [ -f "$PGHBA" ]; then
    sed -i 's|host.*all.*0.0.0.0/0.*md5|host    all  appuser  10.10.10.20/32  scram-sha-256|' "$PGHBA"
fi

echo "Linux hardening applied. Test each change in staging before production deployment."
```

---

## Risk Prioritization (Critical First)

1. **WIN-014 — WDigest Enabled** (Critical): Active sessions have plaintext passwords in LSASS memory. Any credential dump attack yields immediate cleartext credentials.
1. **WIN-013 — No LSASS Protection** (Critical): LSASS can be dumped by any process with `SeDebugPrivilege` or via LOLBin. Combined with WIN-014, this is the single highest-risk finding.
1. **WIN-006 — SMBv1 Enabled** (Critical): Vulnerable to EternalBlue (MS17-010/CVE-2017-0144). Justifies emergency remediation.
1. **WIN-017 — TLS 1.0/1.1 on IIS** (Critical): PCI-DSS v4.0 Req 4.2.1 violation. POODLE (CVE-2014-3566) exploitable.
1. **LNX-014 — ASLR Disabled** (Critical): Removes exploit mitigation for any memory corruption vulnerability in PostgreSQL or OS.
1. **LNX-008/009 — SSH Root Login + Password Auth** (Critical): Direct root brute-force attack surface.
1. **LNX-019 — PostgreSQL wildcard+md5** (Critical): Database reachable from any IP; MD5 trivially cracked offline; no encryption in transit.
1. **LNX-002 — World-writable /opt/app scripts** (Critical): Privilege escalation vector for any compromised process.
1. **WIN-016 — Cached Logons=10** (High): If an attacker obtains the SAM, they get 10 cached domain credential hashes.
1. **WIN-015, LNX-015, WIN-010, LNX-013**: Medium-High operational security gaps.

---

## Additional Findings (Beyond CIS L1)

### WIN-017: IIS Legacy TLS Versions

**Risk:** PCI-DSS v4.0 Requirement 4.2.1 explicitly prohibits TLS 1.0 and 1.1.
TLS 1.0 is vulnerable to POODLE (CVE-2014-3566) and BEAST (CVE-2011-3389).
As a financial institution processing card data, HeliosBank faces regulatory fines and failed QSA audits without remediation.

**Evidence:**

```text
reg query "HKLM\SYSTEM\...\SCHANNEL\Protocols\TLS 1.0\Server"
  Enabled    = 1
  DisabledByDefault = 0
```

**Remediation:** Disable TLS 1.0 and 1.1 via registry (see script above); configure cipher suites to prefer TLS 1.3 and strong TLS 1.2 cipher suites only.

### LNX-019: PostgreSQL Network Exposure with Weak Authentication

**Risk:** Combination of four weaknesses:

* `listen_addresses = '*'` — DB reachable from any network interface
* `pg_hba.conf` wildcard `0.0.0.0/0` — no source IP restriction
* `password_encryption = md5` — deprecated (broken) hash algorithm
* `ssl = off` — credentials and data in cleartext

Direct PCI-DSS violations: Req 2.2 (unnecessary services), Req 4.2 (strong cryptography), Req 8.2 (authentication).

**Evidence:**

```text
listen_addresses = '*'
host all all 0.0.0.0/0 md5
ssl = off
```

**Remediation:** See Linux remediation script; additionally: generate and install a valid SSL certificate for PostgreSQL; run `ALTER USER <user> PASSWORD '<newpass>'` to re-hash all passwords with scram-sha-256 after config change.

---

## PCI-DSS Compliance Gap Assessment

| PCI-DSS Requirement | Before | After |
|--------------------|--------|-------|
| Req 2.2: Secure Configurations | ~30% | ~90% |
| Req 4.2: Strong Cryptography (TLS) | Fail | Pass |
| Req 6.3: Secure Development | ~60% | ~90% |
| Req 8.2: Account Management | ~40% | ~85% |
| Req 8.3: Authentication Factors | ~30% | ~90% |
| Req 10.2: Audit Logging | ~20% | ~85% |
| **Overall Estimated Compliance** | **~35%** | **~90%** |
