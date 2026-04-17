# Demo 02: Linux Security Hardening

## Overview

In this demo, we run a Linux security assessment using Lynis (an open-source auditing tool) and manual checks inside a Docker container.
Students will run the full Lynis audit, review findings by category, and apply specific hardening fixes.

## Learning Objectives

* Run a comprehensive Linux security audit using Lynis
* Interpret Lynis output categories (Hardening Index, warnings, suggestions)
* Apply basic SSH and sysctl hardening
* Enable and configure auditd for security monitoring

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-02-linux-hardening
docker compose up --build
docker compose run linux-audit bash
```

## Walk-through

### Step 1: Run Lynis Audit

Inside the container:

```console
lynis audit system --quick
```

Key output sections to review:

```text
[+] System Tools
[+] Kernel
[+] Memory and Processes
[+] Users, Groups and Authentication
[+] Shells
[+] File Systems
[+] Storage
[+] NFS
[+] Name Services
[+] Ports and Packages
[+] Networking
[+] Printers and Spools
[+] Software: e-mail and messaging
[+] Software: firewalls
[+] SSH Support
[+] SNMP Support
[+] Databases
[+] LDAP Services
[+] PHP
[+] Squid Proxy Servers
[+] Logging and Files
[+] Insecure Services
[+] Banners and Identification
[+] Scheduled Tasks
[+] Accounting
[+] Time and Synchronization
[+] Cryptography
[+] Virtualization
[+] Containers
[+] Security Frameworks
[+] File Integrity
[+] System Tooling
[+] Malware
[+] File Permissions
[+] Home Directories
[+] Kernel Hardening
[+] Hardening
```

### Step 2: Review Critical Warnings

```text
Warnings found:
  W] PKGS-7392 - Installed package: telnetd (INSECURE)
  W] SSH-7408  - SSH root login allowed
  W] AUTH-9328 - Default umask in /etc/profile could be more strict (022 -> 027)
  W] KRNL-6000 - No compiler restrictions defined
```

### Step 3: Review Kernel Hardening Suggestions

```bash
# Check current kernel parameters
sysctl -a | grep -E "randomize_va|kptr|dmesg"

# Expected secure values:
# kernel.randomize_va_space = 2  (ASLR)
# kernel.kptr_restrict = 2       (hide kernel pointers)
# kernel.dmesg_restrict = 1      (restrict dmesg)

# Apply kernel hardening
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf
```

### Step 4: Harden SSH Configuration

```bash
# Backup the original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply hardening
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
X11Forwarding no
EOF

# Verify syntax
sshd -t

# Reload (in production)
# systemctl reload sshd
```

### Step 5: Enable auditd

```bash
# Start auditd
service auditd start
auditctl -s  # Show current status

# Add basic rules
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
auditctl -w /etc/sudoers -p wa -k privilege

# Trigger a monitored event
echo "test" >> /etc/motd  # This won't trigger (not monitored)
# Open a file we ARE monitoring
cat /etc/passwd > /dev/null

# Search audit log
ausearch -k identity -ts recent
```

### Step 6: Find SUID Binaries

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Expected output (legitimate SUID binaries):
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/su
# /bin/mount
# /bin/umount

# Any other SUID binaries should be investigated!
# Non-standard SUID binaries are common privilege escalation paths
```

### Step 7: Re-run Lynis and Compare

After applying hardening:

```console
lynis audit system --quick 2>&1 | grep "Hardening index"
```

Compare the hardening index before and after changes.
Aim for an index > 75.

## Discussion Points

1. **Lynis is a starting point**: A 90 hardening index doesn't mean perfectly secure — it means checked against common findings.

1. **SUID binaries**: Every SUID binary is a potential privilege escalation path. They should be minimized and regularly reviewed.

1. **SSH key-only access**: Disabling password authentication drastically reduces brute-force attack surface.

1. **auditd rules**: The rules shown are a minimal starting set. Production systems should have comprehensive rules covering all admin commands, configuration changes, and login events.

## Clean Up

```console
docker compose down
```
