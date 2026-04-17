# Drill 02 (Intermediate) — Linux Incident Response

## Scenario

You are a security analyst at **NovaTech Systems**.
At 03:47 UTC, an automated alert fired:

> **Alert**: Unusual process spawned by `nginx` — `/bin/bash` child of web worker
> **Source**: auditd rule — `execve` syscall from UID 33 (www-data)
> **Host**: `web-prod-03` (Ubuntu 22.04 LTS, production web server)

A second alert fired 12 minutes later:

> **Alert**: `root` cron job executed an unusual script
> **Source**: `/var/log/syslog` cron entry — `/tmp/.cache/update.sh`
> **Host**: `web-prod-03`

SSH logs also show a login from an unfamiliar IP `203.0.113.88` using the `deploy` service account at 03:52 UTC.

Your task is to investigate this incident by examining the evidence in the Docker container.
Determine:

1. How was the web server compromised?
1. What commands did the attacker run?
1. How did the attacker escalate from `www-data` to `root`?
1. What persistence was established?
1. What data may have been exfiltrated?
1. Build a complete attack timeline and provide remediation.

**Estimated time:** 45–60 minutes

**Difficulty:** Intermediate

**Prerequisites:** Completed basic drills; comfortable with Linux log analysis, auditd, bash forensics.

---

## Environment Setup

```console
docker compose up -d
docker exec -it linux-incident-02 bash
```

The environment contains simulated log files and artifacts matching the incident timeline.

---

## Evidence Sources Available

| Source | Location | Description |
|--------|----------|-------------|
| auth.log | `/evidence/logs/auth.log` | SSH/PAM authentication events |
| syslog | `/evidence/logs/syslog` | System events, cron, kernel |
| nginx access log | `/evidence/logs/nginx_access.log` | Web server access log |
| nginx error log | `/evidence/logs/nginx_error.log` | Web server error log |
| auditd log | `/evidence/logs/audit.log` | syscall-level audit trail |
| bash_history (www-data) | `/evidence/artifacts/www-data_history` | Commands run by www-data |
| bash_history (deploy) | `/evidence/artifacts/deploy_history` | Commands run by deploy |
| /proc snapshot | `/evidence/artifacts/proc_snapshot.txt` | Process tree at time of alert |
| wtmp/lastlog data | `/evidence/artifacts/lastlog.txt` | Login history |
| crontab exports | `/evidence/artifacts/crontabs/` | Cron jobs per user |
| filesystem timeline | `/evidence/artifacts/fs_timeline.csv` | inotify/find-based timeline |
| network snapshot | `/evidence/artifacts/ss_output.txt` | ss -tnp at alert time |
| passwd/shadow copies | `/evidence/artifacts/passwd_copy`, `/evidence/artifacts/shadow_copy` | Account state at incident time |

---

## Tasks

### Task 1: Initial Access — Web Application Exploitation

Examine the nginx logs for the attack vector.

```console
# Look for unusual HTTP methods or paths
grep -E "(POST|PUT|DELETE)" /evidence/logs/nginx_access.log | grep -v "200 -"

# Look for web shell indicators (common paths and parameters)
grep -E "(cmd=|exec=|system=|passthru=|shell=|eval=|base64_decode)" /evidence/logs/nginx_access.log

# Look for file upload patterns
grep -E "\.(php|phtml|php5|shtml)" /evidence/logs/nginx_access.log

# Check error log for PHP execution errors
cat /evidence/logs/nginx_error.log
```

**Questions:**

1. What HTTP request delivered the initial payload? (method, path, parameters)
1. Was a web shell uploaded? If so, to which path?
1. What was the attacker's source IP and user-agent string?
1. What MITRE ATT&CK technique covers the initial access?

---

### Task 2: Post-Exploitation — What Commands Were Run?

Examine auditd logs and bash history for www-data's activity.

```console
# View www-data command history
cat /evidence/artifacts/www-data_history

# Examine auditd execve calls for www-data (UID 33)
grep -A3 "uid=33" /evidence/logs/audit.log | grep "type=EXECVE"

# Look for sensitive file access
grep "uid=33" /evidence/logs/audit.log | grep "type=OPEN" | grep -E "(passwd|shadow|ssh|key)"

# Check for outbound connections
grep "uid=33" /evidence/logs/audit.log | grep "type=SOCKADDR"
```

**Questions:**

1. What system enumeration commands did the attacker run as `www-data`?
1. Were any sensitive files read (e.g., `/etc/passwd`, `/etc/shadow`, SSH keys)?
1. Was any tool downloaded from an external server? If so, what IP and what was downloaded?
1. What evidence of privilege escalation preparation is visible?

---

### Task 3: Privilege Escalation — From `www-data` to `root`

Identify how the attacker escalated privileges.

```bash
# Check sudo configuration for www-data
cat /evidence/artifacts/sudoers_export

# Check for SUID binaries that were accessed
grep "uid=33" /evidence/logs/audit.log | grep "SUID"

# Look for cron-related escalation
cat /evidence/artifacts/crontabs/root_crontab
cat /evidence/artifacts/crontabs/system_crontabs

# Check world-writable scripts called by root cron
grep "writable" /evidence/artifacts/fs_timeline.csv | head -20
```

**Questions:**

1. What privilege escalation technique was used?
1. What specific misconfiguration was exploited?
1. What is the GTFOBins technique or CVE that applies here?
1. What MITRE ATT&CK technique ID covers this escalation?

---

### Task 4: Lateral Movement — The `deploy` Account

Investigate the suspicious SSH login from `203.0.113.88`.

```console
# Examine auth.log for deploy account
grep "deploy" /evidence/logs/auth.log

# Check deploy's bash history
cat /evidence/artifacts/deploy_history

# Look for new SSH authorized keys
cat /evidence/artifacts/deploy_authorized_keys

# Check wtmp/lastlog for login timeline
cat /evidence/artifacts/lastlog.txt
```

**Questions:**

1. How was the `deploy` account accessed? (password, key, or stolen key?)
1. What is in `deploy`'s SSH `authorized_keys` file? Is anything suspicious?
1. What commands did the deploy account run?
1. Was any data copied or exfiltrated via this account?

---

### Task 5: Persistence Mechanisms

Identify all persistence mechanisms installed by the attacker.

```bash
# Check cron jobs
cat /evidence/artifacts/crontabs/root_crontab
cat /evidence/artifacts/crontabs/www-data_crontab
ls -la /evidence/artifacts/crontabs/

# Check systemd units
cat /evidence/artifacts/systemd_units.txt

# Check /etc/rc.local and init.d
cat /evidence/artifacts/rc_local

# Check for modified authorized_keys
cat /evidence/artifacts/root_authorized_keys
cat /evidence/artifacts/deploy_authorized_keys

# Look for new/modified files in startup locations
grep -E "(cron|systemd|rc\.local|profile|bashrc)" /evidence/artifacts/fs_timeline.csv
```

**Questions:**

1. What cron-based persistence was installed? (Which user, what schedule, what command?)
1. Was a systemd service created? If so, what does it do?
1. Was an SSH backdoor key added to any account?
1. Are there any modifications to shell profile files (`.bashrc`, `.profile`)?

---

### Task 6: Timeline Reconstruction and Report

Build the complete attack timeline and compile the incident report.

```console
# Use the timeline builder helper
/evidence/scripts/build-timeline.sh

# Or manually correlate:
grep "03:4[0-9]\|03:5[0-9]\|04:0[0-9]" /evidence/logs/auth.log /evidence/logs/syslog /evidence/logs/audit.log | sort
```

**Questions:**

1. What was the very first malicious event?
1. How long did it take from initial access to root privilege?
1. What data may have been exfiltrated? (List all files accessed or copied)
1. Write 5 immediate containment actions.
1. Write 5 hardening recommendations to prevent recurrence.

---

## Scoring

| Task | Points | Description |
|------|--------|-------------|
| Task 1 | 15 | Correctly identifies the web exploitation vector |
| Task 2 | 15 | Identifies post-exploitation commands and tools |
| Task 3 | 20 | Correctly identifies the privilege escalation technique |
| Task 4 | 15 | Traces lateral movement to deploy account |
| Task 5 | 20 | Finds all persistence mechanisms |
| Task 6 | 15 | Complete timeline and actionable remediation |
| **Total** | **100** | |

---

## Hints

* **Task 1**: Look for HTTP POST requests to `/upload` or admin paths. Web shells often have `cmd`, `exec`, or `system` parameters.
* **Task 2**: www-data's bash history often reveals attacker tradecraft. `wget` or `curl` downloads to `/tmp` are common.
* **Task 3**: Check if any root-owned cron job runs a script in a world-writable directory. This is "cron path hijacking" or "world-writable script abuse".
* **Task 4**: Look at the timestamps — the `deploy` SSH login happens after the attacker gained root and could read `/home/deploy/.ssh/` or copy an SSH key.
* **Task 5**: Attackers typically install 2–3 persistence mechanisms for redundancy.
