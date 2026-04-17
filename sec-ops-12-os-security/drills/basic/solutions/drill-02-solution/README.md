# Solution: Drill 02 — Linux Security Audit

## Expected Findings

### Task 1: User Account Audit

```console
grep -v "nologin\|false" /etc/passwd
awk -F: '($3 == 0) {print $1}' /etc/passwd
getent group sudo
```

**Expected findings:**
| Finding | Issue | Severity |
|---------|-------|---------|
| Root SSH login allowed | /etc/ssh/sshd_config: PermitRootLogin yes | High |
| www-data has sudo | /etc/sudoers: www-data ALL=(ALL) NOPASSWD:ALL | Critical |
| deploy account | Exists with shell but unknown purpose | Medium |

### Task 2: SSH Configuration

| Setting | Current Value | Expected Value | Risk |
|---------|--------------|----------------|------|
| PermitRootLogin | yes | no | High — direct root brute force |
| PasswordAuthentication | yes | no | High — brute force attack surface |
| MaxAuthTries | 6 (default) | 3 | Medium — slower brute force detection |
| X11Forwarding | yes | no | Low — X11 forwarding can be exploited |

### Task 3: SUID Binary Audit

Expected legitimate SUID binaries:

* `/usr/bin/passwd`
* `/usr/bin/sudo`
* `/usr/bin/su`
* `/bin/mount`, `/bin/umount`
* `/usr/bin/newgrp`

**Suspicious finding:**

* `/usr/local/bin/myscan` — not a standard binary, found with SUID bit set. This is a **critical finding** — investigate immediately.

```console
# Identify the suspicious binary
ls -la /usr/local/bin/myscan
file /usr/local/bin/myscan
md5sum /usr/local/bin/myscan
# Check if it's known malware or a legitimate admin tool
```

**Fix:** Remove SUID bit unless the binary requires it:

```console
chmod u-s /usr/local/bin/myscan
```

### Task 4: Network Services

```text
Port 22/tcp  - sshd (expected)
Port 80/tcp  - nginx (expected for web server)
Port 3306/tcp - mysql listening on 0.0.0.0 (RISK!)
Port 6379/tcp - redis listening on 0.0.0.0 (CRITICAL!)
```

**Findings:**
| Service | Issue | Severity | Fix |
|---------|-------|---------|-----|
| MySQL (3306) | Listening on all interfaces | High | Bind to 127.0.0.1 in my.cnf |
| Redis (6379) | Listening on all interfaces | Critical | Add `bind 127.0.0.1` to redis.conf |

Redis without authentication listening on all interfaces is a critical finding — many real ransomware attacks start by exploiting publicly accessible Redis.

### Task 5: Log Review

```console
grep "Failed password" /var/log/auth.log | tail -5
grep "Accepted" /var/log/auth.log | tail -5
grep "sudo" /var/log/auth.log | tail -10
```

**Expected finding:**

* 340 failed SSH attempts from IP 185.234.X.X in the last 4 hours (ongoing brute force)
* One successful login from 192.168.1.5 (legitimate, company VPN)
* auditd is NOT running (no audit logs) — critical gap

---

## Complete Remediation Checklist

| Priority | Finding | Command |
|----------|---------|---------|
| CRITICAL | www-data in sudoers | `visudo` → remove www-data line |
| CRITICAL | Redis on all interfaces | `echo "bind 127.0.0.1" >> /etc/redis/redis.conf; restart redis` |
| HIGH | SSH root login | `echo "PermitRootLogin no" >> /etc/ssh/sshd_config.d/sec.conf; systemctl reload sshd` |
| HIGH | MySQL on all interfaces | Add `bind-address = 127.0.0.1` to /etc/mysql/mysql.conf.d/mysqld.cnf |
| HIGH | Password auth SSH | `echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/sec.conf` |
| HIGH | Suspicious SUID binary | Investigate and remove SUID: `chmod u-s /usr/local/bin/myscan` |
| MEDIUM | No auditd | `apt install auditd; systemctl enable --now auditd` |
| MEDIUM | X11Forwarding | `echo "X11Forwarding no" >> /etc/ssh/sshd_config.d/sec.conf` |
| LOW | MaxAuthTries 6 | `echo "MaxAuthTries 3" >> /etc/ssh/sshd_config.d/sec.conf` |
