# Solution: Drill 02 (Basic) — Linux Security Audit

## Expected Findings on the Demo System

### Task 1: User Account Review

```console
grep -v "nologin\|false" /etc/passwd
```

**Findings (simulated):**

```text
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000::/home/ubuntu:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
backup:x:0:0::/home/backup:/bin/bash   ← UID 0!
```

**Issues:**

* `backup` account has UID 0 → FAIL (root-equivalent; should not exist)
* `deploy` account exists — needs justification; if a deployment service account, should use `/usr/sbin/nologin`

**Remediation:**

```console
# Change backup account UID (or delete if unused)
usermod -u 1002 backup
# If unused: userdel -r backup

# If deploy is a service account:
usermod -s /usr/sbin/nologin deploy
```

---

### Task 2: SSH Configuration Assessment

**Findings (simulated):**

```text
PermitRootLogin yes      ← FAIL
PasswordAuthentication yes ← FAIL
MaxAuthTries 6           ← WARN (should be 3)
X11Forwarding yes        ← WARN (should be no)
```

**Remediation:**

```console
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
EOF
sshd -t && echo "OK"
```

---

### Task 3: SUID Binaries

**Findings (simulated):**

```text
/usr/bin/passwd      ← NORMAL
/usr/bin/sudo        ← NORMAL
/usr/bin/su          ← NORMAL
/bin/mount           ← NORMAL
/bin/umount          ← NORMAL
/usr/bin/python3     ← SUSPICIOUS — python should not be SUID
/tmp/.tools/getroot  ← FAIL — attacker-planted SUID binary in /tmp
```

**Why `/usr/bin/python3` with SUID is dangerous:**
A SUID `python3` can execute commands as root:

```console
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
# This spawns a root shell
```

**Remediation:**

```console
# Remove SUID from python3
chmod u-s /usr/bin/python3

# Remove the attacker-planted binary
rm -f /tmp/.tools/getroot
```

---

### Task 4: Network Listeners

**Findings (simulated):**

```text
LISTEN  0.0.0.0:22    sshd        ← Expected
LISTEN  0.0.0.0:80    python3     ← SUSPICIOUS: web server?
LISTEN  0.0.0.0:4444  nc          ← FAIL: netcat listener — attacker backdoor
LISTEN  127.0.0.1:5432 postgres   ← OK: database only on localhost
```

**Issues:**

* Python3 web server on port 80: unexpected for a file server. Investigate.
* Netcat listener on port 4444: classic attacker backdoor.

**Remediation:**

```console
# Kill the netcat listener
kill $(ss -tlnp | grep ":4444" | awk '{print $6}' | grep -oP 'pid=\K[0-9]+')

# Investigate the Python web server
ss -tlnp | grep ":80"
```

---

### Task 5: Kernel Parameters

**Findings (simulated):**

```text
kernel.randomize_va_space = 0  ← FAIL (should be 2)
net.ipv4.ip_forward = 1        ← FAIL (should be 0 — this is not a router)
net.ipv4.tcp_syncookies = 0    ← FAIL (should be 1)
```

**Remediation:**

```console
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
EOF
sysctl -p /etc/sysctl.d/99-hardening.conf
```

---

### Task 6: Sudo Configuration

**Findings (simulated):**

```console
sudo cat /etc/sudoers
```

```text
root    ALL=(ALL:ALL) ALL
ubuntu  ALL=(ALL) NOPASSWD: ALL   ← FAIL — password bypass
deploy  ALL=(ALL) /usr/bin/find   ← FAIL — find can escalate to root
%ops    ALL=(ALL) /usr/bin/systemctl, /usr/sbin/service  ← OK
```

**Issues:**

* `ubuntu ALL=(ALL) NOPASSWD: ALL` — any user who becomes `ubuntu` gains root without a password
* `deploy` can run `/usr/bin/find` as root — `find -exec` enables shell escape to root

**GTFOBin: sudo find privilege escalation:**

```console
sudo find . -exec /bin/bash \; -quit
# Result: root shell
```

**Remediation:**

```console
# Edit /etc/sudoers with visudo — never edit directly
visudo

# Remove NOPASSWD for ubuntu; require password:
# ubuntu  ALL=(ALL) ALL

# Remove find from deploy's sudoers; assign only needed commands:
# deploy  ALL=(ALL) /usr/bin/systemctl restart myapp
```

**Additional hardening:**

```console
# Enable sudo logging via /etc/sudoers:
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output

# Restrict sudo to members of group 'sudo' only
# Ensure no other accounts have unconstrained sudo
```

---

## Audit Report Summary

| Task | Finding | Status | Remediation |
|------|---------|--------|-------------|
| Users | `backup` account has UID 0 | FAIL | Change UID or delete account |
| Users | `deploy` has interactive shell | WARN | Change shell to `/usr/sbin/nologin` |
| SSH | Root login permitted | FAIL | `PermitRootLogin no` |
| SSH | Password auth enabled | FAIL | `PasswordAuthentication no` |
| SSH | MaxAuthTries = 6 | WARN | Reduce to 3 |
| SUID | `/usr/bin/python3` has SUID | FAIL | `chmod u-s /usr/bin/python3` |
| SUID | `/tmp/.tools/getroot` is SUID | FAIL | Remove file, investigate |
| Network | Netcat listener on :4444 | FAIL | Kill process, investigate |
| Network | Python3 on :80 unexplained | WARN | Investigate and disable if unauthorized |
| Kernel | ASLR disabled | FAIL | `randomize_va_space = 2` |
| Kernel | IP forwarding enabled | FAIL | `ip_forward = 0` |
| Kernel | SYN cookies disabled | FAIL | `tcp_syncookies = 1` |
| Sudo | `ubuntu` has NOPASSWD ALL | FAIL | Require password for sudo |
| Sudo | `deploy` can sudo `find` | FAIL | Remove find; use minimal commands |

---

## MITRE ATT&CK Mapping

| Technique | ID | Finding |
|-----------|----|---------|
| Valid Accounts: Local Accounts | T1078.003 | `backup` account with UID 0 |
| Exploit Public-Facing Application | T1190 | Python3 web server on :80 |
| Command and Scripting Interpreter | T1059 | Netcat backdoor on :4444 |
| Setuid and Setgid | T1548.001 | SUID python3 / `/tmp/.tools/getroot` |
| Abuse Elevation Control Mechanism: Sudo | T1548.003 | Unconstrained sudo rules |
| Impair Defenses | T1562 | ASLR disabled (randomize_va_space=0) |
| Remote Services: SSH | T1021.004 | Root SSH login permitted |
