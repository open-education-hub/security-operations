# Guide 02: Linux Security Baseline

**Level:** Basic

**Estimated time:** 35 minutes

**Prerequisites:** Reading for Session 12

---

## Objective

By the end of this guide, you will be able to:

* Perform a basic Linux security assessment
* Identify common security misconfigurations
* Apply basic hardening to SSH, kernel parameters, and user management
* Understand the output of a Lynis audit

---

## Setup

```console
cd guides/basic/guide-02-linux-security-baseline
docker compose up --build
docker compose run linux-baseline bash
```

---

## Step 1: User Account Review

```bash
# List all users with interactive shells (can log in)
grep -v "nologin\|false" /etc/passwd | awk -F: '{print $1, "UID:"$3, "Shell:"$7}'

# Find accounts with UID 0 (root-equivalent)
awk -F: '($3 == 0) {print $1}' /etc/passwd

# Check for empty passwords (critical vulnerability)
awk -F: '($2 == "") {print $1, "has NO PASSWORD"}' /etc/shadow 2>/dev/null || \
  echo "Run as root to check shadow file"

# Check sudo access
cat /etc/sudoers 2>/dev/null | grep -v "^#\|^$"
ls /etc/sudoers.d/ 2>/dev/null
```

---

## Step 2: SSH Configuration Check

```console
# Review sshd_config for security settings
sshd_config="/etc/ssh/sshd_config"

# Check key settings
echo "=== SSH Security Settings ==="
echo "PermitRootLogin: $(grep "^PermitRootLogin" $sshd_config || echo 'NOT SET (default: yes!)')"
echo "PasswordAuthentication: $(grep "^PasswordAuthentication" $sshd_config || echo 'NOT SET (default: yes!)')"
echo "MaxAuthTries: $(grep "^MaxAuthTries" $sshd_config || echo 'NOT SET (default: 6)')"
echo "Protocol: $(grep "^Protocol" $sshd_config || echo 'NOT SET (default: 2)')"
```

**Expected secure values:**

* `PermitRootLogin no`
* `PasswordAuthentication no`
* `MaxAuthTries 3`
* `Protocol 2` (or not set in modern SSH — Protocol 1 is removed)

---

## Step 3: Find SUID/SGID Binaries

```bash
echo "=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null

echo ""
echo "=== SGID Binaries ==="
find / -perm -2000 -type f 2>/dev/null

# Common legitimate SUID binaries (expected):
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su
# /bin/mount, /bin/umount, /usr/bin/newgrp

# ANY other SUID binary should be investigated
```

---

## Step 4: Check World-Writable Files and Directories

```console
# Find world-writable files (anyone can modify them)
find / -perm -0002 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20

# Find world-writable directories
find / -perm -0002 -type d -not -path "/proc/*" -not -path "/tmp" -not -path "/var/tmp" 2>/dev/null | head -20

# Anything outside /tmp should be flagged
```

---

## Step 5: Check Network Services

```bash
# List all listening ports and services
ss -tlnp
# or:
netstat -tlnp 2>/dev/null

# Expected output shows only necessary services
# Each service here is an attack surface - minimize!

# Check for services listening on all interfaces (0.0.0.0 or *)
ss -tlnp | grep "0.0.0.0\|\*"
# These are accessible from the network - ensure they are intentional
```

---

## Step 6: Check Log Files

```bash
# Verify critical log files exist and are not empty
for log in /var/log/syslog /var/log/auth.log; do
  if [ -f "$log" ]; then
    lines=$(wc -l < "$log")
    echo "OK: $log ($lines lines)"
  else
    echo "MISSING: $log"
  fi
done

# Check for recent authentication failures
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10

# Check for successful logins
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10
```

---

## Step 7: Apply Basic Hardening

```bash
# Apply kernel hardening parameters
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
# ASLR
kernel.randomize_va_space = 2
# Hide kernel pointers from non-root
kernel.kptr_restrict = 2
# Prevent SYN flood
net.ipv4.tcp_syncookies = 1
# No IP forwarding (not a router)
net.ipv4.ip_forward = 0
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
EOF

# Apply immediately (without reboot)
sysctl -p /etc/sysctl.d/99-hardening.conf

# Harden SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/hardening.conf
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config.d/hardening.conf
echo "LoginGraceTime 30" >> /etc/ssh/sshd_config.d/hardening.conf

# Verify syntax
sshd -t && echo "SSH config OK"
```

---

## Summary

You have learned to:

* Identify users with interactive access and root-equivalent privileges
* Review SSH configuration against security best practices
* Find SUID/SGID binaries that could enable privilege escalation
* Check for world-writable files and unnecessary network listeners
* Apply basic kernel and SSH hardening

**Next:** Guide 03 — User and Privilege Management
