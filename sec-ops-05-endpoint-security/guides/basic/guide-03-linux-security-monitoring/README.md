# Guide 03: Setting Up Linux Security Monitoring with auditd

**Level:** Basic

**Time required:** 45 minutes

**Prerequisites:** Basic Linux command-line, reading.md Section 6

---

## Learning Objectives

By the end of this guide, you will be able to:

1. Install and configure `auditd` on a Linux system
1. Write security-focused audit rules for common monitoring scenarios
1. Search and analyze audit logs using `ausearch` and `aureport`
1. Identify suspicious activity patterns in Linux audit logs
1. Build a practical auditd configuration for a server

---

## Step 1: Run the Docker Lab Environment

```console
# Navigate to the demo directory
cd demos/demo-03-linux-auditd

# Start the analysis container (no privileged mode needed for log analysis)
docker-compose up --build

# For full auditd with real kernel auditing (requires privileged)
docker run --rm -it --privileged ubuntu:22.04 bash
```

---

## Step 2: Install and Start auditd

### On Ubuntu/Debian:

```console
apt-get update && apt-get install -y auditd audispd-plugins
systemctl start auditd
systemctl enable auditd
systemctl status auditd
```

### On RHEL/CentOS/Rocky:

```console
yum install audit audit-libs
systemctl start auditd
systemctl enable auditd
```

### Verify it's running:

```console
# Check status
systemctl status auditd

# Verify audit rules are loaded
auditctl -l

# Check current configuration
auditctl -s
```

---

## Step 3: Understanding auditd Configuration

### /etc/audit/auditd.conf

Key settings:

```bash
# Where to store logs
log_file = /var/log/audit/audit.log
# Maximum log file size (MB) before rotation
max_log_file = 50
# Number of log files to keep
num_logs = 5
# What to do when disk space is low
disk_full_action = SUSPEND
# What to do when disk error occurs
disk_error_action = SUSPEND
# Rate limit: max messages per second (0=no limit)
rate_limit = 0
```

### /etc/audit/rules.d/audit.rules

This is where you define what to monitor.

---

## Step 4: Core Security Monitoring Rules

### 4.1 Self-Protection Rules

These go FIRST in the rules file:

```console
# Delete all existing rules
-D

# Set kernel audit buffer size (increase if losing events)
-b 8192

# Failure mode: 0=silent, 1=printk, 2=panic
# Use 1 for most environments; 2 only for highest security (may cause outages)
-f 1

# NOTE: Add -e 2 LAST (after all other rules) to lock the config
```

### 4.2 Identity and Account Changes

```bash
# Monitor files that contain user account information
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor account modification tools
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification

# Monitor sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
```

**Why this matters:** Account creation and sudo access changes are common post-exploitation persistence techniques.

### 4.3 SSH Security

```console
# SSH server configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Authorized key files (monitor root and all user home dirs)
-w /root/.ssh/ -p wa -k ssh_authorized_keys
# For all users, use:
-a always,exit -F arch=b64 -S open -F dir=/home -F path=authorized_keys -F perm=wa -k ssh_authorized_keys
```

**Why this matters:** Adding SSH keys to authorized_keys is a common persistence technique.

### 4.4 Privilege Escalation

```console
# Monitor execution of sudo and su
-w /usr/bin/sudo -p x -k privesc
-w /usr/bin/su -p x -k privesc

# Monitor SUID/SGID bit changes (could create privilege escalation)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission_change

# Monitor setuid/setgid syscalls (process elevating its own privileges)
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privesc_syscall
```

### 4.5 Cron and Persistence

```bash
# Cron files
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Systemd service files
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /usr/lib/systemd/system/ -p wa -k systemd_persistence

# At jobs
-w /var/spool/at/ -p wa -k at_jobs
```

### 4.6 Command Execution Tracking

```console
# Track all 64-bit process executions
-a always,exit -F arch=b64 -S execve -k exec_commands

# Track all 32-bit process executions (on 64-bit systems)
-a always,exit -F arch=b32 -S execve -k exec_commands_32

# Track execution by root specifically (higher priority alerting)
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_commands
```

**Storage note:** This generates a large volume of events.
In high-traffic environments, you may want to track only execution by privileged users or from specific directories.

### 4.7 Network Monitoring

```console
# Track outbound connections (connect syscall)
-a always,exit -F arch=b64 -S connect -k network_outbound

# Track bind (listening port creation)
-a always,exit -F arch=b64 -S bind -k network_bind
```

### 4.8 Sensitive File Access

```bash
# Detect anything reading /etc/shadow (only root should do this)
-a always,exit -F arch=b64 -S open -F path=/etc/shadow -F perm=r -k shadow_access

# Detect modifications to PAM authentication configuration
-w /etc/pam.d/ -p wa -k pam_config

# Monitor kernel module loading (rootkit persistence)
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules
```

### 4.9 Lock the Configuration (Add Last)

```console
# Immutable: cannot be changed without reboot
# Add this as the LAST line in your rules file
-e 2
```

---

## Step 5: Load and Verify Rules

```console
# Apply rules immediately (without reboot)
augenrules --load

# Or load a specific file
auditctl -R /etc/audit/rules.d/audit.rules

# Verify rules are loaded
auditctl -l

# Check audit status
auditctl -s
```

---

## Step 6: Searching Audit Logs

### Basic ausearch Usage

```bash
# Search by rule key
ausearch -k identity              # Account changes
ausearch -k privesc               # Privilege escalation
ausearch -k exec_commands         # Command execution
ausearch -k ssh_authorized_keys   # SSH key changes

# Search by time (various formats)
ausearch --start today
ausearch --start "03/15/2024 14:00:00" --end "03/15/2024 15:00:00"
ausearch --start recent           # Last 10 minutes

# Search by user (login UID)
ausearch -ua 1000                 # Events by user with auid=1000
ausearch --loginuid 1000          # Same as above

# Search by executable
ausearch -x /usr/bin/sudo
ausearch -x /bin/bash

# Interpreted output (human-readable instead of raw)
ausearch -k privesc -i

# Show events with multiple conditions
ausearch -k exec_commands -ua 1000 --start today
```

### Understanding the auid Field

The `auid` (audit UID) is the **login UID** — the UID of the user who originally logged in, before any `su` or `sudo` changes.
This is critical for attribution:

```text
User jdoe (uid=1000) SSH logs in → auid=1000
jdoe runs: sudo bash → now uid=0 (root), but auid=1000 (still jdoe)
bash -c "useradd hacker" → uid=0, auid=1000

The audit log shows: uid=0 ran useradd, BUT auid=1000 (jdoe did this)
```

Special values:

* `auid=4294967295` (or `auid=-1`) = unset (system process, not started from a login session)
* `auid=0` = root logged in directly (not via sudo from another user)

### Useful ausearch Queries for Incident Response

```bash
# Who ran commands as root today?
ausearch -k root_commands --start today -i | grep -A 3 "type=EXECVE"

# What cron changes were made?
ausearch -k cron -i

# Were any new users added?
ausearch -k user_modification -i

# Did anyone access /etc/shadow?
ausearch -k shadow_access -i

# What outbound network connections were made?
ausearch -k network_outbound -i

# Show everything from a specific user
ausearch -ua 1000 --start today -i
```

---

## Step 7: Generating Reports with aureport

```bash
# Executive summary
aureport --summary

# Authentication report (all successful/failed logins)
aureport --auth

# Show only failures
aureport --failed

# Executable usage report (what programs ran, how often)
aureport --executable

# Account modification report
aureport --mods

# Network events
aureport --network

# Login/logout events
aureport --login

# Time range
aureport --summary --start today
aureport --auth --start "03/15/2024 00:00:00" --end "03/15/2024 23:59:59"
```

---

## Step 8: Practice — Analyzing the Sample Log

Use the pre-generated sample from Demo 03:

```bash
# Copy the sample log
cp demos/demo-03-linux-auditd/audit.log.sample /tmp/audit.log.sample

# Run the Python analyzer
python3 demos/demo-03-linux-auditd/analyze_audit.py \
  --file /tmp/audit.log.sample \
  --summary --detect

# Exercises:
# 1. How many failed SSH attempts occurred?
# 2. From what IP address?
# 3. What suspicious commands were executed?
# 4. Were any persistence mechanisms established?
```

---

## Step 9: Sending auditd Events to a SIEM

### Using audisp (Audit Dispatcher)

```console
# /etc/audisp/plugins.d/syslog.conf
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
```

This sends audit events to syslog, from where rsyslog/syslog-ng can forward to a SIEM.

### Using Filebeat for Auditd

```yaml
# filebeat.yml
filebeat.inputs:
  - type: auditd
    audit_rules: |
      -a always,exit -F arch=b64 -S execve -k exec

output.logstash:
  hosts: ["siem:5044"]
```

Filebeat has a native auditd module that handles kernel audit events efficiently.

---

## Summary

| Concept | Command/Config |
|---------|---------------|
| Install auditd | `apt-get install auditd` |
| Load rules | `augenrules --load` |
| View rules | `auditctl -l` |
| Search by key | `ausearch -k <key>` |
| Search by user | `ausearch -ua <uid>` |
| Reports | `aureport --auth --failed` |
| Lock config | `-e 2` (last rule) |
| auid tracking | Original login UID, survives sudo |

**Next Guide (Intermediate):** Guide 01 — EDR Investigation Workflow
