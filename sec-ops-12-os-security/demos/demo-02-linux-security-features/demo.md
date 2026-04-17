# Demo 02: Linux Security Features

**Estimated time:** 35 minutes

---

## Overview

This demo runs a Docker Linux container with real security tools active — auditd, sudo logging, file permission analysis, SELinux/AppArmor concepts, and PAM.
You will configure and observe each security layer, generate audit events, and detect simulated attack patterns.

---

## Learning Objectives

* Configure and test file permissions and SUID binary detection
* Set up and query auditd rules for sensitive file access
* Observe sudo logging and PAM-based authentication controls
* Test iptables firewall rules
* Understand SELinux/AppArmor MAC concepts
* Use journalctl and /var/log/auth.log for security monitoring

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-02-linux-security-features
docker compose up --build
docker compose exec linux-security bash
```

---

## Step 1: Linux Identity Model — Users, Groups, and Permissions

Inside the container:

```bash
# Review user accounts
cat /etc/passwd | awk -F: '{printf "%-12s UID:%-6s GID:%-6s Shell: %s\n", $1, $3, $4, $7}'

# Check for any UID 0 accounts besides root
awk -F: '($3 == 0) {print "UID 0 ACCOUNT:", $1}' /etc/passwd

# Examine /etc/shadow structure (password hashes)
# Note: you need root to read /etc/shadow
sudo head -5 /etc/shadow | awk -F: '{
  status = ($2 == "!" || $2 == "*") ? "LOCKED" : "ACTIVE"
  printf "User: %-10s Hash prefix: %-8s Status: %s\n", $1, substr($2,1,3), status
}'
```

**Identify hash algorithms:**

```bash
# Hash prefixes in /etc/shadow:
# $1$  = MD5 (obsolete — upgrade immediately if found)
# $5$  = SHA-256
# $6$  = SHA-512 (standard)
# $y$  = yescrypt (modern, memory-hard)
# !    = account locked
# *    = no password (system account)

sudo awk -F: '{
  if ($2 ~ /^\$1\$/) print $1 ": INSECURE - MD5 hash!"
  else if ($2 ~ /^\$6\$/) print $1 ": SHA-512 (good)"
  else if ($2 ~ /^\$y\$/) print $1 ": yescrypt (excellent)"
  else if ($2 == "!" || $2 == "*") print $1 ": Locked/NoPassword (service account)"
}' /etc/shadow
```

---

## Step 2: File Permissions and SUID Audit

```console
# Understand the permission model with examples
ls -la /usr/bin/passwd /usr/bin/sudo /bin/su

# Output shows SUID bit:
# -rwsr-xr-x  /usr/bin/passwd  (s = SUID: runs as file owner = root)
# -rwsr-xr-x  /usr/bin/sudo    (SUID: needed for privilege escalation)
# -rwsr-xr-x  /bin/su          (SUID: needed for user switching)
```

```bash
# Find ALL SUID binaries on the system
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_list.txt
cat /tmp/suid_list.txt

# Count them
wc -l /tmp/suid_list.txt

# Check each against expected legitimate list
EXPECTED_SUID="/usr/bin/passwd /usr/bin/sudo /usr/bin/su /usr/bin/newgrp
               /usr/bin/chfn /usr/bin/chsh /bin/mount /bin/umount
               /usr/lib/openssh/ssh-keysign /usr/bin/pkexec"

echo "=== UNEXPECTED SUID BINARIES ==="
while IFS= read -r binary; do
    if ! echo "$EXPECTED_SUID" | grep -q "$binary"; then
        echo "  UNEXPECTED: $binary"
    fi
done < /tmp/suid_list.txt
```

```bash
# Simulate adding an SUID binary (attack scenario)
cp /usr/bin/python3 /tmp/python3_suid
chmod u+s /tmp/python3_suid
echo "SUID python3 added to /tmp"
ls -la /tmp/python3_suid

# Now show GTFOBins escape (if python3 were SUID):
echo "If python3 were SUID and world-executable:"
echo "  /tmp/python3_suid -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
echo "  This would give a root shell!"

# Clean up
rm /tmp/python3_suid
```

---

## Step 3: Configure and Test auditd

```bash
# Start auditd (may already be running)
service auditd start 2>/dev/null || auditd -b 2>/dev/null
auditctl -s   # Show current status

# Add comprehensive audit rules
# Watch critical system files
auditctl -w /etc/passwd  -p wa -k identity
auditctl -w /etc/shadow  -p wa -k identity
auditctl -w /etc/group   -p wa -k identity
auditctl -w /etc/sudoers -p wa -k identity

# Watch SSH authorized keys (persistence vector)
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh-keys 2>/dev/null
find /home -name "authorized_keys" -exec auditctl -w {} -p wa -k ssh-keys \; 2>/dev/null

# Monitor privilege escalation commands
auditctl -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -k privileged-sudo
auditctl -a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -k privileged-su

# Monitor cron modifications
auditctl -w /etc/cron.d/ -p wa -k scheduled-jobs
auditctl -w /etc/crontab -p wa -k scheduled-jobs

# Verify rules are loaded
auditctl -l
```

```bash
# GENERATE TEST EVENTS
echo "Generating test audit events..."

# 1. Trigger an identity audit event (modify /etc/group)
echo "# test comment" >> /etc/group && \
  sed -i '/# test comment/d' /etc/group
echo "  - Triggered: identity event (wrote to /etc/group)"

# 2. Trigger a sudo audit event
sudo -l >/dev/null 2>&1 || true
echo "  - Triggered: privileged-sudo event"

# SEARCH AUDIT LOG FOR EVENTS
echo ""
echo "=== Audit Events Generated ==="
ausearch -k identity -ts recent -i 2>/dev/null | tail -20
echo ""
ausearch -k privileged-sudo -ts recent -i 2>/dev/null | tail -10
```

---

## Step 4: sudo Logging and PAM

```bash
# Review sudo configuration
cat /etc/sudoers | grep -v "^#\|^$"

# Check what the current user can sudo
sudo -l

# Execute a command via sudo (generates log entry)
sudo id
sudo whoami

# Review the sudo log entry
grep "sudo" /var/log/auth.log 2>/dev/null | tail -5
# OR via journald
journalctl _COMM=sudo | tail -10
```

```bash
# Demonstrate PAM configuration
echo "=== PAM Configuration for SSH ==="
cat /etc/pam.d/sshd

echo ""
echo "=== PAM Common-Auth (shared authentication stack) ==="
cat /etc/pam.d/common-auth 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null

# Show pam_faillock status (account lockout)
echo ""
echo "=== Account Lockout Configuration ==="
grep -r "faillock\|tally" /etc/pam.d/ 2>/dev/null | head -10
```

---

## Step 5: SSH Security Configuration Review

```bash
# Review the SSH server configuration
echo "=== SSH Security Settings ==="
sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|allowagentforwarding|logingracetime|pubkeyauthentication"

# Show the configuration file directly
cat /etc/ssh/sshd_config | grep -v "^#\|^$"

# Test SSH configuration for syntax errors
sshd -t && echo "SSH config: VALID" || echo "SSH config: ERRORS FOUND"

# Show key fingerprints
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || echo "Ed25519 key not present"
ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null || echo "RSA key not present"
```

---

## Step 6: iptables Firewall

```bash
# View current firewall rules
echo "=== Current iptables Rules ==="
iptables -L -n -v --line-numbers

# Apply a basic security ruleset
echo "Applying security firewall rules..."

# Flush existing rules
iptables -F
iptables -X

# Default policies: drop inbound and forwarded, allow outbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from private ranges only
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 172.16.0.0/12 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 192.168.0.0/16 -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS (uncomment if needed)
# iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "[DROPPED] " --log-level 4
iptables -A INPUT -j DROP

echo "Rules applied:"
iptables -L INPUT -n --line-numbers

# Test: this connection should be blocked from non-private IPs
echo "Testing: connection from 203.0.113.1 (public IP) to port 22..."
iptables -C INPUT -s 203.0.113.1 -p tcp --dport 22 -j ACCEPT 2>&1 || echo "BLOCKED (as expected)"
```

---

## Step 7: SELinux/AppArmor Concepts

```bash
# Check what MAC system is available
echo "=== Mandatory Access Control Status ==="

if command -v getenforce &>/dev/null; then
    echo "SELinux: $(getenforce)"
elif command -v aa-status &>/dev/null; then
    echo "AppArmor status:"
    aa-status --synopsis 2>/dev/null || aa-status 2>/dev/null
else
    echo "No MAC system active in this container"
    echo "(SELinux/AppArmor typically run on the host, not in containers)"
fi

# Show what AppArmor profiles would look like
cat << 'EOF'
=== Example AppArmor Profile for nginx ===
/etc/apparmor.d/usr.sbin.nginx:

profile nginx /usr/sbin/nginx {
    #include <abstractions/base>
    #include <abstractions/nameservice>

    capability net_bind_service,  # Bind to port 80/443

    /usr/sbin/nginx r,            # Read the nginx binary
    /etc/nginx/** r,              # Read nginx config
    /var/log/nginx/** w,          # Write nginx logs
    /var/www/html/** r,           # Read web content

    # DENY everything else (not listed = denied)
}

# Without AppArmor: if nginx is compromised, attacker can:
#   - Read /etc/shadow
#   - Write to /etc/cron.d/
#   - Read SSH private keys

# WITH AppArmor: nginx cannot access any of those paths
EOF
```

---

## Step 8: Comprehensive Log Review

```bash
# Review auth.log for security events
echo "=== Recent Authentication Events ==="
tail -20 /var/log/auth.log 2>/dev/null

echo ""
echo "=== Failed Login Attempts (last 1 hour) ==="
grep "Failed password\|authentication failure\|FAILED" /var/log/auth.log 2>/dev/null | tail -10

echo ""
echo "=== Successful Logins ==="
grep "Accepted\|session opened" /var/log/auth.log 2>/dev/null | tail -10

echo ""
echo "=== sudo Usage ==="
grep "COMMAND" /var/log/auth.log 2>/dev/null | tail -10

# Use journald for structured queries
echo ""
echo "=== journalctl: SSH events ==="
journalctl -u ssh --no-pager | tail -10 2>/dev/null || journalctl _COMM=sshd --no-pager | tail -10 2>/dev/null
```

---

## Clean Up

```console
docker compose down
```

---

## Key Takeaways

* **SUID binaries** must be audited regularly; any non-standard SUID binary is a privilege escalation risk (GTFOBins)
* **auditd** provides kernel-level monitoring; rules for identity files, sudo, cron, and SSH keys are essential
* **sudo logging** automatically records who ran what command as whom and when
* **PAM** controls authentication flow; `pam_faillock` provides account lockout protection
* **AppArmor/SELinux** confine processes to specific file and capability access, limiting blast radius of compromised services
* **iptables** with default-drop policy ensures only explicitly allowed traffic passes
