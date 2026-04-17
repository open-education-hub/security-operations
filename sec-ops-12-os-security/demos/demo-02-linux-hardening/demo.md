# Demo 02: Linux Security Hardening

**Estimated time:** 30 minutes

---

## Overview

Run a comprehensive Linux security assessment using Lynis (an open-source hardening tool) and manual checks inside a Docker container.
You will run the full Lynis audit, interpret findings, apply SSH and kernel hardening, and enable auditd.

---

## Learning Objectives

* Run a comprehensive Linux security audit using Lynis
* Interpret Lynis output (Hardening Index, warnings, suggestions)
* Apply SSH and kernel hardening settings
* Enable and configure auditd for security monitoring

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-02-linux-hardening
docker compose up --build
docker compose run linux-audit bash
```

---

## Step 1: Run the Lynis Audit

Inside the container:

```console
lynis audit system --quick
```

The output covers 30+ categories.
Focus on the warning and suggestion sections:

```text
Warnings found:
  [W] PKGS-7392 - Installed package: telnetd (INSECURE)
  [W] SSH-7408  - SSH root login allowed
  [W] AUTH-9328 - Default umask too permissive (022 → use 027)
  [W] KRNL-6000 - No compiler restrictions defined
```

---

## Step 2: Apply Kernel Hardening

```bash
# Check current kernel parameters
sysctl -a | grep -E "randomize_va|kptr|dmesg"

# Apply security hardening
cat > /etc/sysctl.d/99-security.conf << 'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl -p /etc/sysctl.d/99-security.conf
```

**What each setting does:**

* `randomize_va_space = 2` — full ASLR, makes exploit code harder to position
* `kptr_restrict = 2` — hides kernel symbol addresses from unprivileged users
* `dmesg_restrict = 1` — prevents leaking kernel info via dmesg
* `tcp_syncookies = 1` — protects against SYN flood denial-of-service

---

## Step 3: Harden SSH Configuration

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

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

# Verify syntax before reload
sshd -t && echo "Config OK"
```

---

## Step 4: Enable auditd and Add Rules

```bash
# Start auditd
service auditd start
auditctl -s   # Show current rule count and status

# Add monitoring rules
auditctl -w /etc/passwd  -p wa -k identity
auditctl -w /etc/shadow  -p wa -k identity
auditctl -w /etc/sudoers -p wa -k privilege

# Trigger a monitored event to verify logging
cat /etc/passwd > /dev/null

# Search the audit log for our identity key
ausearch -k identity -ts recent
```

---

## Step 5: Find SUID Binaries

```console
# List all SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

Expected legitimate SUID binaries:

```text
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/bin/mount
/bin/umount
```

Any additional SUID binaries should be investigated — they are common privilege escalation paths.

---

## Step 6: Re-run Lynis and Compare

```console
lynis audit system --quick 2>&1 | grep "Hardening index"
```

Compare the hardening index before and after your changes.
A well-hardened system typically scores above 75.

---

## Discussion Points

1. **Lynis is a starting point**: A high hardening index indicates good baseline coverage, not complete security. Context-specific threats require additional analysis.

1. **SUID binaries**: Every SUID binary is a potential privilege escalation path. They should be minimized and regularly reviewed.

1. **SSH key-only access**: Disabling password authentication dramatically reduces brute-force attack surface.

1. **auditd comprehensiveness**: The rules demonstrated are a minimal starting set. Production systems should audit all admin commands, privilege changes, and sensitive file access.

---

## Clean Up

```console
docker compose down
```
