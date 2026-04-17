# Guide 01 (Intermediate): OS Hardening — End to End

**Level:** Intermediate

**Estimated time:** 50 minutes

**Prerequisites:** Basic guides 01–03

---

## Objective

Apply a comprehensive hardening baseline to both a Windows (PowerShell) and a Linux system using structured checklists, then document the findings in a security configuration report.

---

## Setup

```console
cd guides/intermediate/guide-01-os-hardening
docker compose up --build
```

Two containers start:

* `win-hardening`: PowerShell Core environment
* `linux-hardening`: Ubuntu with pre-installed tools

---

## Part 1: Systematic Linux Hardening

### 1.1 Run the Full Audit

```console
docker compose exec linux-hardening bash

# Run Lynis with full output
lynis audit system 2>&1 | tee /tmp/lynis_results.txt

# Get the hardening index
grep "Hardening index" /tmp/lynis_results.txt
```

### 1.2 Address the Top 5 Findings

Based on Lynis output, systematically address findings in priority order:

**Finding 1: SSH root login allowed**

```console
echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/sec.conf
sshd -t && echo "SSH config valid"
```

**Finding 2: Kernel parameters not hardened**

```bash
cat > /etc/sysctl.d/99-cis.conf << 'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/99-cis.conf
```

**Finding 3: Audit daemon not running**

```bash
service auditd start || auditd -b 256

# Add baseline audit rules
cat > /etc/audit/rules.d/baseline.rules << 'EOF'
# Log sudo usage
-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged
# Log changes to passwd/shadow
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
# Log changes to sudoers
-w /etc/sudoers -p wa -k identity
# Log cron changes
-w /etc/cron.d -p wa -k schedule
EOF

augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/baseline.rules
```

**Finding 4: Password policy not enforced**

```bash
# Set PAM password requirements
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
EOF

# Set shadow password aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
```

**Finding 5: No firewall rules**

```console
# Basic UFW setup
apt-get install -y ufw 2>/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw --force enable
ufw status verbose
```

### 1.3 Re-run Audit and Compare

```console
lynis audit system 2>&1 | grep "Hardening index"
```

Document: Before score vs.
After score.

---

## Part 2: Windows Hardening Checklist

```console
docker compose exec win-hardening pwsh
```

### 2.1 Account Security

```powershell
# Check and report on account security
$issues = @()

# Check guest account
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
  $issues += "FAIL: Guest account is enabled"
} else {
  Write-Host "PASS: Guest account disabled"
}

# Check for accounts with non-expiring passwords (user accounts only)
Get-LocalUser | Where-Object {
  $_.PasswordNeverExpires -eq $true -and
  $_.Name -notin @("Administrator", "DefaultAccount", "WDAGUtilityAccount")
} | ForEach-Object {
  $issues += "WARN: $($_.Name) has non-expiring password"
}

# Report issues
if ($issues) {
  $issues | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
} else {
  Write-Host "All account checks passed" -ForegroundColor Green
}
```

### 2.2 Service Security

```powershell
# Check for high-risk services
$riskySvcs = @{
  "TlntSvr"        = "Telnet server"
  "RemoteRegistry" = "Remote Registry"
  "SNMP"           = "SNMP service"
  "W3SVC"          = "IIS (if not needed)"
}

foreach ($svc in $riskySvcs.Keys) {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($s -and $s.Status -eq "Running") {
    Write-Host "RISK: $($riskySvcs[$svc]) ($svc) is running" -ForegroundColor Red
  }
}
```

### 2.3 Firewall Verification

```powershell
# Verify all firewall profiles are enabled with correct defaults
$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
  if (-not $profile.Enabled) {
    Write-Host "FAIL: Firewall $($profile.Name) profile is DISABLED" -ForegroundColor Red
  } elseif ($profile.DefaultInboundAction -ne "Block") {
    Write-Host "WARN: $($profile.Name) profile allows inbound by default" -ForegroundColor Yellow
  } else {
    Write-Host "PASS: $($profile.Name) firewall profile configured correctly" -ForegroundColor Green
  }
}
```

### 2.4 Legacy Protocol Checks

```powershell
# Check SMBv1
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) {
  Write-Host "FAIL: SMBv1 is ENABLED - critical vulnerability" -ForegroundColor Red
} else {
  Write-Host "PASS: SMBv1 disabled" -ForegroundColor Green
}
```

---

## Part 3: Security Report Template

After completing both audits, fill in this report:

```markdown
# Security Hardening Report
Date: [DATE]
Systems: Linux (Ubuntu 22.04), Windows (Simulated)

## Linux System
- Lynis score before: [X]/100
- Lynis score after:  [Y]/100
- Issues addressed: [N]
- Remaining issues: [M]

## Windows System
- Account checks: [PASS/FAIL count]
- Service checks: [PASS/FAIL count]
- Firewall checks: [PASS/FAIL count]

## Top 3 Residual Risks
1. [Risk]

2. [Risk]
3. [Risk]

## Recommended Next Steps
1. [Action]

2. [Action]
3. [Action]
```

---

## Summary

You have applied a systematic hardening process to both Windows and Linux, measured the improvement quantitatively (Lynis score), and documented findings in a structured report.
This mirrors the process used in real security hardening projects.
