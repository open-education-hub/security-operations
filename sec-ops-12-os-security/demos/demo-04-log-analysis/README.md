# Demo 04: Log Analysis for Security Events

## Overview

In this demo, we use Docker to run a pre-populated Linux system with security event logs and analyze them to reconstruct a security incident.
Students will practice searching auth.log, auditd logs, and syslog to identify what happened, when, and by whom.

## Learning Objectives

* Parse and search Linux authentication logs
* Use ausearch and aureport for auditd log analysis
* Reconstruct the timeline of a security incident from logs
* Identify key Indicators of Compromise (IOCs) in log data

## Prerequisites

* Docker installed and running

## Setup

```console
cd demos/demo-04-log-analysis
docker compose up --build
docker compose exec log-analysis bash
```

Pre-populated log files are at `/var/log/demo/`.

## Walk-through

### Step 1: Review the Auth Log

```console
cat /var/log/demo/auth.log | head -30
```

The log shows the following events over a 2-hour period:

1. Many failed SSH login attempts from a single IP
1. A successful SSH login
1. sudo command execution
1. A new user created
1. sudo to root

### Step 2: Identify the Brute Force Attack

```console
# Count failed login attempts by source IP
grep "Failed password" /var/log/demo/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | head -10

# Output:
#  247 10.0.5.123
#    3 192.168.1.50
#    1 10.0.0.1
# ^^^ 247 failures from 10.0.5.123 = brute force attack
```

### Step 3: Find the Successful Login After the Brute Force

```console
# Find the successful login
grep "Accepted" /var/log/demo/auth.log

# Output:
# Mar 15 14:47:23 server sshd[2891]: Accepted password for www-data from 10.0.5.123 port 54321 ssh2
# ^^^ "www-data" account compromised! Attacker guessed the password.
```

**Key observation:** The `www-data` account should never be logged into interactively (it's a web server service account).
This login is immediately suspicious.

### Step 4: Trace What the Attacker Did

```console
# Search for sudo commands after the suspicious login time (14:47:23)
grep "sudo" /var/log/demo/auth.log | awk -v time="14:47:23" '$3 > time'

# Output:
# Mar 15 14:48:05 server sudo: www-data : TTY=pts/1 ; PWD=/tmp ;
#   USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash backdoor_user
# Mar 15 14:48:31 server sudo: www-data : TTY=pts/1 ; PWD=/tmp ;
#   USER=root ; COMMAND=/usr/sbin/usermod -aG sudo backdoor_user
```

**Critical findings:**

* Attacker created a new user `backdoor_user` with sudo privileges
* Commands run from `/tmp` (suspicious working directory)
* Using the `www-data` account to run sudo (means sudo was misconfigured for www-data!)

### Step 5: Check auditd Logs for File Access

```console
# Search audit log for file modifications to /etc
ausearch -f /etc/passwd --start 14:40:00 --end 15:00:00 -i

# Search for privilege escalation events
ausearch -k privileged-sudo --start 14:40:00 --end 15:00:00 -i

# Generate a timeline report
aureport --summary --start 14:40:00 --end 15:00:00
```

### Step 6: Reconstruct the Incident Timeline

Using the log evidence, build a timeline:

```text
14:23:00 - 14:47:20  Brute force attack: 247 failed SSH attempts from 10.0.5.123
14:47:23             SUCCESS: SSH login as www-data from 10.0.5.123
14:47:45             www-data runs: cat /etc/sudoers (reconnaissance)
14:48:05             www-data runs sudo: creates backdoor_user account
14:48:31             www-data runs sudo: adds backdoor_user to sudo group
14:49:12             SSH session ends
14:52:40             New SSH login as backdoor_user from 10.0.5.123
14:53:01             backdoor_user runs sudo su - (root shell)
14:53:15             root: downloads file from external IP
14:55:00             root: installs cron job in /etc/cron.d/
```

### Step 7: Identify Root Cause and Gaps

**Root cause:**

1. `www-data` had a weak (guessable) password
1. `www-data` had sudo privileges (misconfiguration)
1. No account lockout policy (247 attempts allowed)
1. SSH allowed password authentication

**Missing controls:**

* SSH key-only authentication would have prevented the brute force success
* No sudo for service accounts (www-data should not have sudo)
* Account lockout after 5 failures
* Alerting on successful logins after multiple failures (SIEM rule)

## Discussion Points

1. **Service accounts should not be interactive**: `www-data` should never SSH in. Adding `www-data` to a list of denied SSH users (`DenyUsers www-data` in sshd_config) would have prevented this.

1. **Log correlation**: The incident spans auth.log, audit.log, and syslog. Real investigations always involve correlating multiple log sources.

1. **Attacker velocity**: The attacker went from initial access (14:47) to root shell (14:53) in 6 minutes. Speed matters — this is why MTTD (mean time to detect) must be minimized.

1. **Evidence of goal**: The cron job download suggests this is the attacker establishing persistence — not just a one-time access.

## Clean Up

```console
docker compose down
```
