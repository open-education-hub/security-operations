# Guide 02: Linux Security Hardening with Docker

**Level:** Basic

**Estimated time:** 45 minutes

**Prerequisites:** Session 12 reading (Sections 6–9)

---

## Objective

By the end of this guide you will be able to:

* Apply CIS Benchmark Level 1 hardening to a Linux system
* Configure auditd with a production-quality ruleset
* Harden SSH using sshd_config best practices
* Apply kernel security parameters via sysctl
* Set filesystem mount options for security
* Review and minimize SUID binary exposure
* Verify PAM lockout policy

---

## Setup

```console
cd guides/basic/guide-02-linux-security-hardening
docker compose up --build
docker compose exec linux-harden bash
```

---

## Step 1: Initial Security Baseline

Before hardening, record the current state:

```bash
# Run Lynis for an initial audit score
lynis audit system --quick 2>&1 | grep -E "Hardening index|Warning|Suggestion" | head -30

# Record key metrics
echo "=== Pre-Hardening Baseline ==="
echo "SUID binary count: $(find / -perm -4000 -type f 2>/dev/null | wc -l)"
echo "World-writable files: $(find / -perm -0002 -type f -not -path '/proc/*' 2>/dev/null | wc -l)"
echo "Running services: $(systemctl list-units --type=service --state=running 2>/dev/null | grep -c running)"
echo "Listening ports: $(ss -tlnp | grep -c LISTEN)"
```

---

## Step 2: Kernel Security Parameters

```bash
# Apply security-focused sysctl settings
cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
# ========================================
# CIS Benchmark - Kernel Hardening
# ========================================

# Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Hide kernel pointers from unprivileged users
kernel.kptr_restrict = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Restrict ptrace (process debugging) to direct parent only
kernel.yama.ptrace_scope = 1

# ========================================
# Network Security
# ========================================

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Don't send redirects (not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

# Apply immediately
sysctl -p /etc/sysctl.d/99-cis-hardening.conf

# Verify
echo "=== Kernel Parameters Applied ==="
sysctl kernel.randomize_va_space kernel.kptr_restrict net.ipv4.tcp_syncookies
```

---

## Step 3: Filesystem Hardening

```bash
# Check current /tmp mount options
echo "=== Current /tmp mount ==="
mount | grep "/tmp"
cat /etc/fstab | grep /tmp

# Apply noexec, nosuid, nodev to /tmp
# In /etc/fstab (for persistent config):
# tmpfs /tmp tmpfs defaults,rw,nodev,noexec,nosuid 0 0

# For the current session (test without reboot):
mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null && \
  echo "PASS: /tmp remounted with noexec,nosuid,nodev" || \
  echo "INFO: Cannot remount /tmp in container environment"

# Verify /tmp noexec prevents execution
echo '#!/bin/bash' > /tmp/test_exec.sh
chmod +x /tmp/test_exec.sh
/tmp/test_exec.sh 2>/dev/null && echo "WARN: /tmp exec allowed" || echo "PASS: /tmp exec blocked (noexec works)"
rm -f /tmp/test_exec.sh
```

---

## Step 4: SSH Hardening

```bash
# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.original

# Apply hardened configuration
cat > /etc/ssh/sshd_config.d/99-cis-hardening.conf << 'EOF'
# ========================================
# CIS Benchmark SSH Hardening
# ========================================

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
PermitEmptyPasswords no

# Session security
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no

# Restrict users (modify for your environment)
# AllowUsers alice bob devops

# Disable weak algorithms
Protocol 2
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256,ecdh-sha2-nistp256
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Logging
LogLevel VERBOSE
EOF

# Test configuration validity
sshd -t && echo "PASS: SSH configuration syntax is valid" || echo "FAIL: SSH configuration errors"

# Show what changed
echo "=== Key Security Settings Now ==="
sshd -T 2>/dev/null | grep -E "^permitrootlogin|^passwordauthentication|^maxauthtries|^x11forwarding|^allowagentforwarding|^logingracetime"
```

---

## Step 5: Password and Account Policies

```bash
# Configure password quality (pam_pwquality)
cat > /etc/security/pwquality.conf << 'EOF'
# Minimum password length
minlen = 14

# Complexity requirements
dcredit = -1    # At least 1 digit
ucredit = -1    # At least 1 uppercase
lcredit = -1    # At least 1 lowercase
ocredit = -1    # At least 1 special character

# Prevent simple patterns
maxrepeat = 3   # Max 3 consecutive identical chars
maxclassrepeat = 4

# Check against dictionary/common passwords
dictcheck = 1
EOF

# Configure password aging in /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/'  /etc/login.defs

echo "=== Password Policy Applied ==="
grep "^PASS_" /etc/login.defs

# Lock all system accounts that shouldn't have interactive logins
echo "=== Locking system accounts ==="
for user in daemon bin sys games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
    id "$user" &>/dev/null && usermod -L "$user" 2>/dev/null && echo "  Locked: $user" || true
done
```

---

## Step 6: auditd Configuration

```bash
# Comprehensive audit rules based on CIS Benchmark
cat > /etc/audit/rules.d/99-cis-audit.rules << 'EOF'
# ========================================
# CIS Benchmark Audit Rules
# ========================================

# Delete existing rules
-D

# Buffer size
-b 8192

# Failure mode: 1=log, 2=panic (use 1 for production to avoid reboot loops)
-f 1

# ============================================================
# PRIVILEGED COMMANDS
# ============================================================
-a always,exit -F path=/usr/bin/sudo   -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-sudo
-a always,exit -F path=/usr/bin/su     -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-su
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-newgrp
-a always,exit -F path=/usr/bin/chsh   -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chsh
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# ============================================================
# IDENTITY FILES
# ============================================================
-w /etc/passwd        -p wa -k identity
-w /etc/shadow        -p wa -k identity
-w /etc/group         -p wa -k identity
-w /etc/gshadow       -p wa -k identity
-w /etc/sudoers       -p wa -k identity
-w /etc/sudoers.d/    -p wa -k identity

# ============================================================
# SSH KEYS (persistence vector)
# ============================================================
-a always,exit -F dir=/root/.ssh     -F perm=wa -k ssh-keys
-a always,exit -F dir=/home          -F filename=authorized_keys -F perm=wa -k ssh-keys

# ============================================================
# SCHEDULED JOBS (persistence vector)
# ============================================================
-w /etc/cron.d/         -p wa -k scheduled-jobs
-w /etc/cron.daily/     -p wa -k scheduled-jobs
-w /etc/cron.hourly/    -p wa -k scheduled-jobs
-w /etc/cron.monthly/   -p wa -k scheduled-jobs
-w /etc/cron.weekly/    -p wa -k scheduled-jobs
-w /etc/crontab         -p wa -k scheduled-jobs
-w /var/spool/cron/     -p wa -k scheduled-jobs

# ============================================================
# LOGIN/LOGOUT EVENTS
# ============================================================
-w /var/log/lastlog     -p wa -k logins
-w /var/run/faillock/   -p wa -k logins

# ============================================================
# NETWORK CONFIGURATION
# ============================================================
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts   -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# ============================================================
# SYSTEM FILES (immutable after applying)
# ============================================================
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/   -p wa -k sysctl

# Make rules immutable (must reboot to change — comment out for active development)
# -e 2
EOF

# Reload rules
if command -v augenrules &>/dev/null; then
    augenrules --load && echo "PASS: Audit rules loaded"
elif command -v auditctl &>/dev/null; then
    auditctl -R /etc/audit/rules.d/99-cis-audit.rules && echo "PASS: Audit rules loaded"
else
    echo "INFO: auditd not available in this environment"
fi
```

---

## Step 7: Service Minimization

```bash
# List all running services
echo "=== Currently Running Services ==="
systemctl list-units --type=service --state=running 2>/dev/null | grep -v "@"

# Services typically safe to disable on a hardened server
DISABLE_SERVICES="bluetooth avahi-daemon cups nfs-server rpcbind xinetd"

for svc in $DISABLE_SERVICES; do
    if systemctl is-active "$svc" &>/dev/null; then
        systemctl disable --now "$svc" 2>/dev/null
        echo "  Disabled: $svc"
    fi
done

# Show listening ports — attack surface
echo ""
echo "=== Listening Network Services (attack surface) ==="
ss -tlnp
```

---

## Step 8: SUID Binary Audit

```bash
# Establish and compare SUID baseline
echo "=== SUID Binary Audit ==="
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/current_suid.txt
cat /tmp/current_suid.txt

# Expected legitimate SUID binaries on Ubuntu 22.04:
cat > /tmp/expected_suid.txt << 'EOF'
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
EOF

echo "=== Unexpected SUID Binaries (investigate each) ==="
comm -23 /tmp/current_suid.txt /tmp/expected_suid.txt
```

---

## Step 9: Post-Hardening Assessment

```console
# Run Lynis again and compare score
lynis audit system --quick 2>&1 | grep -E "Hardening index|Warning" | head -20

echo ""
echo "=== Post-Hardening Summary ==="
echo "SUID binary count: $(find / -perm -4000 -type f 2>/dev/null | wc -l)"
echo "Listening ports: $(ss -tlnp | grep -c LISTEN)"
echo "Kernel ASLR: $(sysctl -n kernel.randomize_va_space 2>/dev/null)"
echo "SSH root login: $(sshd -T 2>/dev/null | grep -i permitrootlogin | awk '{print $2}')"
```

---

## Summary

You have applied a CIS Benchmark Level 1 hardening baseline:

| Category | Controls Applied |
|----------|-----------------|
| Kernel | ASLR, kptr_restrict, dmesg_restrict, TCP syncookies, no IP forward |
| Filesystem | /tmp noexec,nosuid,nodev |
| SSH | No root login, key-only auth, restricted algorithms |
| Passwords | 14-char minimum, complexity, 90-day expiry |
| Auditd | Identity, privilege, cron, SSH key monitoring |
| Services | Minimal running services |
| SUID | Baseline established, unexpected binaries flagged |

These controls form the foundation of a **secure Linux deployment**.
In production, these settings would be managed via **Ansible**, **Chef**, or **Puppet** and verified continuously via **Lynis** or **OpenSCAP**.
