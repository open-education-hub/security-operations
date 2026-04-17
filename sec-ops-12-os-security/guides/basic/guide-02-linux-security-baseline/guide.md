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
grep -v "nologin\|false" /etc/passwd | \
  awk -F: '{print $1, "UID:"$3, "Shell:"$7}'

# Find accounts with UID 0 (root-equivalent — should be only root)
awk -F: '($3 == 0) {print $1}' /etc/passwd

# Check for empty passwords (critical vulnerability)
awk -F: '($2 == "") {print $1, "has NO PASSWORD"}' /etc/shadow 2>/dev/null || \
  echo "Run as root to check shadow file"

# Review sudo access
grep -v "^#\|^$" /etc/sudoers 2>/dev/null
ls /etc/sudoers.d/ 2>/dev/null
```

---

## Step 2: SSH Configuration Check

```console
sshd_config="/etc/ssh/sshd_config"

echo "=== SSH Security Settings ==="
echo "PermitRootLogin:         $(grep "^PermitRootLogin" $sshd_config || echo 'NOT SET (default: yes!)')"
echo "PasswordAuthentication:  $(grep "^PasswordAuthentication" $sshd_config || echo 'NOT SET (default: yes!)')"
echo "MaxAuthTries:            $(grep "^MaxAuthTries" $sshd_config || echo 'NOT SET (default: 6)')"
```

**Expected secure values:**

* `PermitRootLogin no`
* `PasswordAuthentication no`
* `MaxAuthTries 3`

---

## Step 3: Find SUID/SGID Binaries

```console
echo "=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null

echo "=== SGID Binaries ==="
find / -perm -2000 -type f 2>/dev/null
```

Common legitimate SUID binaries: `/usr/bin/passwd`, `/usr/bin/sudo`, `/usr/bin/su`, `/bin/mount`, `/bin/umount`

Any additional SUID binaries should be investigated — they are common privilege escalation targets.

---

## Step 4: Check World-Writable Files and Directories

```console
# Files anyone can modify (security risk outside /tmp)
find / -perm -0002 -type f \
  -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -20

# World-writable directories (excluding /tmp which is expected)
find / -perm -0002 -type d \
  -not -path "/proc/*" -not -path "/tmp" -not -path "/var/tmp" 2>/dev/null | head -20
```

Anything world-writable outside `/tmp` should be reviewed and corrected.

---

## Step 5: Check Network Services

```console
# List all listening ports and the processes that own them
ss -tlnp

# Services listening on all interfaces (accessible from the network)
ss -tlnp | grep "0.0.0.0\|\*"
# Each one is an attack surface — ensure each is intentional
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

# Check recent authentication failures
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10

# Check recent successful logins
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10
```

---

## Step 7: Apply Basic Hardening

```bash
# Kernel hardening parameters
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Full ASLR
kernel.randomize_va_space = 2
# Hide kernel symbol addresses from non-root
kernel.kptr_restrict = 2
# SYN flood protection
net.ipv4.tcp_syncookies = 1
# No IP forwarding (this is not a router)
net.ipv4.ip_forward = 0
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
EOF

# Apply immediately (no reboot needed)
sysctl -p /etc/sysctl.d/99-hardening.conf

# SSH hardening
mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
EOF

# Verify syntax
sshd -t && echo "SSH config OK"
```

---

## Summary

You have learned to:

* Identify users with interactive access and root-equivalent privileges
* Review SSH configuration against security best practices
* Find SUID/SGID binaries that could enable privilege escalation
* Identify world-writable files and unnecessary network listeners
* Apply basic kernel and SSH hardening

**Next:** Guide 03 — User and Privilege Management
