# Demo 04: Log Analysis for Security Events

**Estimated time:** 35 minutes

---

## Overview

Use Docker to access a pre-populated Linux system containing security event logs from a simulated breach.
You will analyze auth.log and auditd logs to reconstruct the full incident timeline — from brute-force attack through privilege escalation and persistence installation.

---

## Learning Objectives

* Parse and search Linux authentication logs
* Use `ausearch` and `aureport` for auditd log analysis
* Reconstruct the timeline of a security incident from logs
* Identify key indicators of compromise (IOCs) in log data

---

## Prerequisites

* Docker installed and running

---

## Setup

```console
cd demos/demo-04-log-analysis
docker compose up --build
docker compose exec log-analysis bash
```

Pre-populated log files are at `/var/log/demo/`.

---

## Step 1: Review the Auth Log

```console
head -30 /var/log/demo/auth.log
```

The log covers a 2-hour window with these events:

1. Many failed SSH login attempts from one IP
1. A successful SSH login
1. sudo command execution
1. A new user account created
1. sudo escalation to root

---

## Step 2: Identify the Brute-Force Attack

```console
# Count failed login attempts by source IP
grep "Failed password" /var/log/demo/auth.log | \
  awk '{print $11}' | sort | uniq -c | sort -rn | head -10
```

Expected output:

```text
 247 10.0.5.123
   3 192.168.1.50
   1 10.0.0.1
```

**247 failures from one IP = brute-force attack.** The attacker eventually succeeded.

---

## Step 3: Find the Successful Login After the Brute Force

```console
grep "Accepted" /var/log/demo/auth.log
```

Expected output:

```text
Mar 15 14:47:23 server sshd[2891]: Accepted password for www-data from 10.0.5.123 port 54321 ssh2
```

**Critical observation:** `www-data` is a web server service account — it should never SSH in interactively.
This login is immediately suspicious regardless of the brute-force context.

---

## Step 4: Trace What the Attacker Did After Login

```console
# Search for sudo commands after 14:47
grep "sudo" /var/log/demo/auth.log | awk '$3 > "14:47:23"'
```

Expected output:

```text
Mar 15 14:48:05  sudo: www-data: USER=root COMMAND=/usr/sbin/useradd -m -s /bin/bash backdoor_user
Mar 15 14:48:31  sudo: www-data: USER=root COMMAND=/usr/sbin/usermod -aG sudo backdoor_user
```

**Findings:**

* The attacker created a `backdoor_user` account with a Bash shell
* Then added it to the sudo group
* Commands were run from `/tmp` (suspicious working directory)
* `www-data` had sudo access — a misconfiguration that made this possible

---

## Step 5: Check auditd Logs for File Access

```console
# File modifications to /etc in the attack window
ausearch -f /etc/passwd --start 14:40:00 --end 15:00:00 -i

# Privilege escalation events
ausearch -k privileged-sudo --start 14:40:00 --end 15:00:00 -i

# Summary report for the window
aureport --summary --start 14:40:00 --end 15:00:00
```

---

## Step 6: Reconstruct the Incident Timeline

Using all log evidence:

```text
14:23:00 – 14:47:20  Brute force: 247 failed SSH attempts from 10.0.5.123
14:47:23             SUCCESS: SSH login as www-data from 10.0.5.123
14:47:45             www-data reads /etc/sudoers (reconnaissance)
14:48:05             www-data (sudo): creates backdoor_user
14:48:31             www-data (sudo): adds backdoor_user to sudo group
14:49:12             SSH session for www-data ends
14:52:40             New SSH login as backdoor_user from 10.0.5.123
14:53:01             backdoor_user runs: sudo su - (root shell obtained)
14:53:15             root: downloads file from external IP
14:55:00             root: installs cron job in /etc/cron.d/
```

---

## Step 7: Identify Root Causes and Missing Controls

**Root causes:**

1. `www-data` had a weak, guessable password
1. `www-data` had sudo privileges (misconfiguration)
1. No account lockout policy (247 attempts were allowed)
1. SSH accepted password authentication

**Missing controls that would have prevented this:**

* SSH key-only authentication → brute force impossible
* No sudo for `www-data` service account → privilege escalation blocked
* Account lockout after 5 failures → brute force blocked
* SIEM alert on successful login after multiple failures → faster detection

---

## Discussion Points

1. **Service accounts should not be interactive**: Add `DenyUsers www-data` in sshd_config to prevent service accounts from ever SSH-ing in.

1. **Log correlation**: This incident spans auth.log, audit.log, and syslog. Real investigations always require correlating multiple log sources.

1. **Attacker velocity**: Initial access (14:47) to root shell (14:53) took 6 minutes. Speed matters — minimizing MTTD is critical.

1. **Persistence intent**: The cron job download at the end shows the attacker establishing long-term persistence, not just a reconnaissance visit.

---

## Clean Up

```console
docker compose down
```
