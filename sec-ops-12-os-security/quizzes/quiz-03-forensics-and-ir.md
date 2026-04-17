# Quiz 03: OS Forensics and Incident Response

**Topic:** Windows and Linux forensic artifacts, log analysis, incident timelines

**Use this quiz:** After completing Demo 03 (Windows Forensics), Demo 04 (Linux Forensics), and the intermediate guides

**Format:** Multiple choice — one correct answer unless marked `[multi]`

---

**Q1.** Windows Prefetch files (`.pf` in `C:\Windows\Prefetch\`) are useful for forensics because they:

A) Store user passwords for faster re-authentication
B) Record that a program was executed, along with a timestamp of first and last run
C) Back up the Windows registry automatically
D) Cache network traffic for performance

**Answer: B** — Prefetch files prove execution: even if the malware binary is deleted, its `.pf` file often remains, showing the program name, run count, and timestamps.

---

**Q2.** An attacker modifies a file's `mtime` (modification time) to make it appear old and blend in with system files. What is this technique called?

A) File hiding
B) Timestomping
C) Log rotation
D) Steganography

**Answer: B** — Timestomping (MITRE T1070.006) changes file timestamps to evade timeline-based detection. Defenders counter this by checking `ctime` (change time), which cannot be modified from userspace on Linux.

---

**Q3.** During a Windows incident investigation, you find the registry key:
`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` contains `"Updater" = "C:\ProgramData\svchost32.exe"`.
What does this indicate?

A) A legitimate Windows update service
B) Persistence — the executable runs every time the current user logs in
C) A Windows Defender exclusion entry
D) A recently uninstalled application

**Answer: B** — Run keys under HKCU execute the specified program at user logon. `svchost32.exe` in `C:\ProgramData\` is a red flag (legitimate svchost.exe is in `System32`). This is persistence via T1547.001.

---

**Q4.** In Linux auth.log, what does the following line indicate?
```
Jan 14 14:48:01 server sshd[4521]: Accepted password for alice from 10.0.5.123 port 54321 ssh2
```

A) alice's SSH connection was rejected
B) An SSH public key was installed for alice
C) alice successfully authenticated via password from IP 10.0.5.123
D) alice's password was changed

**Answer: C** — `Accepted password` = successful password authentication. The source IP, timestamp, and username are all clearly visible.

---

**Q5.** You are building an attack timeline. Which source of evidence would allow you to determine the exact **sequence of commands** an attacker ran after gaining SSH access?

A) Windows Event ID 4624
B) Linux `auth.log`
C) Linux `bash_history` file (or auditd execve log)
D) Network firewall logs

**Answer: C** — `bash_history` records commands typed in the shell. `auditd` with `execve` logging records every process execution (even if history is cleared). `auth.log` shows login events, not commands. Firewall logs show network flows, not shell activity.

---

**Q6.** The "order of volatility" principle in digital forensics means:

A) Collect the most valuable evidence first
B) Collect the most volatile (short-lived) evidence first, before it is lost
C) Always image the full disk before collecting RAM
D) Log files are more reliable than memory artifacts

**Answer: B** — Volatile evidence (RAM, running processes, network connections) disappears when a system is powered off. Disk contents persist. Forensic best practice is to collect from most volatile to least volatile.

---

**Q7.** `[multi]` Which of the following are **persistence mechanisms** you would look for on a compromised Linux system? Select all that apply.

A) Modified `/etc/crontab` or new files in `/etc/cron.d/`
B) New SSH keys added to `/root/.ssh/authorized_keys`
C) New entry in `/etc/passwd` with UID 0
D) Modified `/etc/hosts` file
E) New systemd service file in `/etc/systemd/system/`

**Answer: A, B, C, E** — Cron jobs, backdoor SSH keys, UID 0 accounts, and malicious systemd services are all persistence techniques. `/etc/hosts` modification is typically for redirection/pivoting, not persistence by itself.

---

**Q8.** During forensics on a Windows system, you find a Scheduled Task with the action:
`powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA...`
What should you do next?

A) Ignore it — encoded commands are normal for Windows tasks
B) Decode the Base64 payload and examine what it does
C) Delete the task immediately without analysis
D) Reboot the system to clear the task

**Answer: B** — `-EncodedCommand` is Base64-encoded PowerShell. You should decode it: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("SQBFAFgA..."))`. `SQBFAFIA` decodes to `IEX ` (Invoke-Expression) — a classic web cradle indicator.

---

**Q9.** What does Event ID **4663** in the Windows Security log indicate?

A) A new process was created
B) A user account was modified
C) An attempt was made to access an object (file/folder/registry key)
D) A service failed to start

**Answer: C** — 4663 = "An attempt was made to access an object." Used for auditing access to sensitive files, registry keys, and other securable objects.

---

**Q10.** A forensic report states: "The attacker used the `deploy` service account for lateral movement by reusing an SSH private key copied from the compromised web server." Which MITRE ATT&CK technique does this map to?

A) T1078 — Valid Accounts
B) T1110 — Brute Force
C) T1021.004 — Remote Services: SSH (with stolen key)
D) T1059 — Command and Scripting Interpreter

**Answer: C** — Using a stolen SSH key to authenticate is T1021.004 (Remote Services: SSH). T1078 (Valid Accounts) is also partially correct but T1021.004 is the more specific technique for this scenario.

---

**Bonus Q11.** During a Linux forensic investigation, you notice:
- `/var/log/auth.log` is only 12 bytes in size
- The system has been running for 6 days
- The last entry in syslog is 3 days old

What is the most likely explanation?

A) Log rotation is working correctly
B) The system has low login activity
C) An attacker truncated or wiped the log files to cover their tracks
D) journald replaced syslog

**Answer: C** — A nearly empty auth.log on a system that has been running for days with active logins is a strong indicator of log wiping. Forensic response: check journald (if available), check backup copies in `/var/log/*.1` or `.gz`, and look for file `ctime` being newer than expected.

---

**Score:** 10 questions × 1 point (Q11 is bonus) = 10 points + 1 bonus.
8–10: Strong forensics/IR fundamentals. Ready for intermediate drills.
5–7: Review the forensics demos and intermediate guides.
0–4: Re-read Session 12 Sections 10–14 before proceeding.
