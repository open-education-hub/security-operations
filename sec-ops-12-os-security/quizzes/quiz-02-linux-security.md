# Quiz 02: Linux Security Fundamentals

**Topic:** Linux permissions, hardening, auditd, and security features

**Use this quiz:** After completing Demo 02 (Linux Security Features) and Guide 02 (Linux Security Baseline/Hardening)

**Format:** Multiple choice — one correct answer unless marked `[multi]`

---

**Q1.** What does the SUID bit do on an executable file?

A) Makes the file readable by all users
B) Causes the file to run with the **owner's** permissions, not the runner's
C) Prevents the file from being deleted
D) Makes the file executable only by root

**Answer: B** — SUID (Set User ID) means the process runs with the file owner's effective UID, not the calling user's. This is how `passwd` can write to `/etc/shadow` even when run by a normal user.

---

**Q2.** You run `find / -perm -4000 -type f 2>/dev/null` and find `/usr/local/bin/python3-helper` with SUID root. Why is this dangerous?

A) Python is slow and wastes CPU
B) Any user can run Python as root, gaining full root access (GTFOBins)
C) Python SUID binaries always crash
D) SUID only matters on C binaries, not Python

**Answer: B** — Python has a simple GTFOBins exploit: `python3-helper -c "import os; os.execl('/bin/bash', 'bash', '-p')"`. This gives a root shell to any local user.

---

**Q3.** What is the purpose of `/etc/sudoers`?

A) Store user passwords in encrypted form
B) Configure which users can run which commands as root (or another user)
C) List all installed software packages
D) Define network firewall rules

**Answer: B** — `/etc/sudoers` defines sudo policy: who can run what, as whom, with or without a password.

---

**Q4.** A sudoers entry reads: `bob ALL=(root) NOPASSWD: /bin/bash`. What is the security risk?

A) Bob can run bash as himself without a password — no risk
B) Bob can get a root shell immediately with `sudo bash` without a password
C) Bob cannot run bash at all
D) NOPASSWD only applies to other users, not root

**Answer: B** — `sudo bash` as bob gives an immediate root shell. Combined with NOPASSWD, this means any attacker who compromises bob's account has instant root access.

---

**Q5.** Which file should have permissions `000` (or `640` for shadow group) and should NOT be world-readable?

A) `/etc/passwd`
B) `/etc/hosts`
C) `/etc/shadow`
D) `/etc/hostname`

**Answer: C** — `/etc/shadow` contains hashed passwords. It must not be world-readable (should be mode 640 or 000). `/etc/passwd` is intentionally world-readable (mode 644).

---

**Q6.** The auditd rule `-a always,exit -F arch=b64 -S execve -k exec_log` does what?

A) Blocks all process execution on 64-bit systems
B) Logs every program execution (execve syscall) on 64-bit processes
C) Restricts execution to only signed binaries
D) Monitors file modifications in /etc

**Answer: B** — This rule records every `execve` system call (process creation) on 64-bit programs. The `-k exec_log` key allows easy filtering with `ausearch -k exec_log`.

---

**Q7.** `[multi]` Which of the following are valid SSH hardening measures? Select all that apply.

A) `PermitRootLogin no`
B) `PasswordAuthentication no`
C) `MaxAuthTries 3`
D) `PermitEmptyPasswords yes`
E) `AllowUsers alice bob`

**Answer: A, B, C, E** — `PermitEmptyPasswords yes` is insecure (D is wrong). All others strengthen SSH: disable root login, use key auth only, limit retry attempts, and restrict to specific users.

---

**Q8.** A user's `/home/alice/.bashrc` contains the line `HISTFILE=/dev/null`. What does this do?

A) Increases the size of the bash history buffer
B) Sends bash history to a log server
C) Disables bash command history — commands are not saved
D) Makes the history file read-only

**Answer: C** — Setting `HISTFILE=/dev/null` discards all bash history. This is a common anti-forensics technique to prevent investigators from seeing what commands were run.

---

**Q9.** You find a file `/etc/cron.d/backup` with permissions `777` (world-writable). What is the attack?

A) No risk — cron files are public by design
B) Any local user can modify the cron job and inject commands that run as root
C) Root cannot read world-writable cron files
D) Cron ignores files with 777 permissions for security

**Answer: B** — A world-writable cron file in `/etc/cron.d/` is a critical misconfiguration. Any local user can overwrite it with their own command, which will then execute as the scheduled user (often root). Note: modern cron versions skip world-writable cron files — but the underlying misconfiguration is still dangerous.

---

**Q10.** What does `ausearch -k identity` return?

A) All network connections from unknown IPs
B) Audit events tagged with the `identity` key (usually modifications to `/etc/passwd`, `/etc/shadow`, `/etc/group`)
C) Failed login attempts
D) All root command executions

**Answer: B** — The `identity` auditd key is conventionally applied to rules watching `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/sudoers`. `ausearch -k identity` shows all events where those files were accessed or modified.

---

**Score:** 10 questions × 1 point each = 10 points maximum.
7–10: Strong Linux security fundamentals.
4–6: Review the Linux hardening guide and auditd documentation.
0–3: Re-read Session 12 Sections 5–9.
