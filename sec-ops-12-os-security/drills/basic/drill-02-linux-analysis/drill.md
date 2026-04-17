# Drill 02 (Basic): Linux Permission and SUID Audit

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Session 12 reading (Sections 6–9), Guide 02

---

## Scenario

You are a security analyst who has been asked to perform a security review of a new Linux server before it goes into production.
The system was configured by a junior administrator and you need to identify any security misconfigurations.

Your focus areas:

1. File permissions and SUID binary audit
1. User account security
1. sudo configuration review
1. SSH configuration check
1. World-writable files and directories

---

## Setup

```console
cd drills/basic/drill-02-linux-analysis
docker compose up --build
docker compose exec linux-drill bash
```

---

## Investigation Tasks

### Task 1: SUID Binary Audit

```console
# Find all SUID binaries on the system
find / -perm -4000 -type f 2>/dev/null | sort
```

**Questions to answer:**

1. List all SUID binaries you found.
1. Which ones are expected/legitimate?
1. Are there any unexpected SUID binaries? Name them and explain why they are a risk.
1. How would an attacker exploit an unexpected SUID binary?

---

### Task 2: User Account Review

```console
# Review user accounts
cat /etc/passwd | awk -F: '{print $1, $3, $7}'

# Check for UID 0 accounts (other than root)
awk -F: '($3 == 0)' /etc/passwd

# Check /etc/shadow hash algorithms
sudo cat /etc/shadow | awk -F: '{print $1, $2}' | head -10
```

**Questions to answer:**

1. Are there any accounts with UID 0 besides root?
1. Are there any accounts with shell access that shouldn't have it?
1. What password hash algorithm is being used?

---

### Task 3: sudo Configuration Audit

```console
# Review sudo configuration
sudo cat /etc/sudoers
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

**Questions to answer:**

1. Which users/groups have sudo access?
1. Are there any NOPASSWD entries? Are they justified?
1. Identify the most dangerous sudo rule and explain why.

---

### Task 4: SSH Configuration Review

```console
# Check SSH daemon configuration
sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|permitemptypasswords"

# Check for authorized_keys
find /home /root -name "authorized_keys" 2>/dev/null -exec echo "=== {} ===" \; -exec cat {} \;
```

**Questions to answer:**

1. Is root login via SSH permitted?
1. Is password authentication enabled?
1. What is the MaxAuthTries setting? Is it appropriate?
1. Are there any authorized_keys files? Do you recognize the keys?

---

### Task 5: World-Writable Files and Directories

```console
# Find world-writable files (excluding /proc and /sys)
find / -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null

# Find world-writable directories
find / -perm -0002 -type d -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | grep -v "^/tmp$\|^/dev$"
```

**Questions to answer:**

1. Are there world-writable files outside of /tmp?
1. Are there world-writable directories outside expected locations?
1. What is the security risk of world-writable cron files?

---

### Task 6: Write Your Security Findings Report

Complete the following template:

```text
LINUX SECURITY REVIEW — Pre-Production Audit
System: [hostname]
Date: [today]
Analyst: [your name]

CRITICAL FINDINGS:

1. [finding] — Risk: [description] — Fix: [command]

HIGH FINDINGS:
2. [finding] — Risk: [description] — Fix: [command]

MEDIUM FINDINGS:
3. [finding] — Risk: [description] — Fix: [command]

RECOMMENDATIONS:
- [list 3-5 specific remediation steps with commands]
```

**Compare your answers to:** `solutions/drill-02-solution/solution.md`

---

## Clean Up

```console
docker compose down
```
