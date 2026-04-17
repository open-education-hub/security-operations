# Drill 01 (Intermediate) Solution: Identify Malware Indicators in EDR Telemetry

---

## Q1 — Attack Vector Identification (3 points)

**a) Vulnerability exploited — Evidence:**

The critical evidence is the HTTP request captured in the network event at 15:58:43:

```text
GET /WebApp/upload.aspx?cmd=whoami HTTP/1.1
```

The URL parameter `?cmd=whoami` reveals that the web application has a **command injection vulnerability** — specifically, the `upload.aspx` page is passing the `cmd` parameter directly to a system command execution function without sanitization.

The subsequent process creation (16:02:11) of `powershell.exe -nop -c whoami` spawned by `w3wp.exe` confirms the injection worked — `whoami` was executed on the server.

**b) Attack vector name and CVE class:**

This is a **Web Application Command Injection** / **OS Command Injection** vulnerability.

CVE class: **CWE-78** — Improper Neutralization of Special Elements used in an OS Command
OWASP category: **A03:2021 – Injection** (previously A1 in older OWASP Top 10)

The specific pattern — a web application passing HTTP request parameters to `System.Diagnostics.Process.Start()`, `Shell.Run()`, or similar without sanitization — is trivially exploitable.

**c) Why a web server is dangerous as initial access point:**

1. **It's internet-facing** — the attacker has direct access without needing to penetrate the perimeter (no phishing, no VPN, no partner network pivot required)
1. **It runs as a service account** — typically has no MFA, no password expiry, unlimited access attempts before lockout
1. **Legitimate outbound traffic** — web servers must make outbound HTTP/HTTPS connections to APIs and update services, so outbound C2 traffic blends in
1. **Typically less monitored** — teams often focus on workstations for endpoint security, assuming servers are "safe"
1. **Gateway to internal network** — a compromised web server in the DMZ often has direct access to internal databases and application servers

---

## Q2 — Attacker Capability Assessment (3 points)

**a) First two actions — Reconnaissance:**

1. `whoami` (PID 7823) — determines what user account the web server is running as, and therefore what privileges they have. Result: `IIS APPPOOL\WebApp`.

1. DNS hostname lookup (PID 7824): `[System.Net.Dns]::GetHostEntry('')` — resolves the server's full DNS hostname. This gives the attacker the fully qualified domain name (FQDN), which reveals the domain name, internal network naming convention, and potentially the server role from its name.

These two actions answer: "Who am I?" and "Where am I?" — the first steps of any post-exploitation reconnaissance.

**b) Third network action — Web Shell Deployment:**

At 16:02:45, the attacker used IEX to download and execute `web_shell.ps1` from their C2.
This script then created `update.aspx` in the web root (`C:\inetpub\wwwroot\WebApp\`).

**Why a .aspx file in the web root is significant (persistence):**
An `.aspx` web shell is a **server-side backdoor** accessible via HTTP.
Unlike a process-based backdoor that dies when the machine reboots or the process is killed, a web shell:

* Persists as a file until explicitly deleted
* Is accessible from any internet-connected machine via a simple HTTP request
* Doesn't require a running process (IIS serves it on-demand)
* Looks like a legitimate web application file
* Can be accessed even after the original intrusion path is patched

The attacker now has **two backdoors**: the PowerShell reverse shell (process-based) AND the web shell (file-based, persistent).

**c) MITRE ATT&CK Mapping:**

| Action | MITRE Technique |
|--------|----------------|
| URL command injection | T1190 — Exploit Public-Facing Application |
| `whoami` execution | T1033 — System Owner/User Discovery |
| DNS hostname lookup | T1082 — System Information Discovery |
| Download `web_shell.ps1` via IEX | T1059.001 — PowerShell + T1105 — Ingress Tool Transfer |
| Create `update.aspx` web shell | T1505.003 — Server Software Component: Web Shell |
| `ipconfig`, `route print`, `arp -a` | T1016 — System Network Configuration Discovery |
| `net view /all /domain` | T1018 — Remote System Discovery |
| Enumerate installed software (registry) | T1082 — System Information Discovery |

---

## Q3 — Tool Analysis (2 points)

**a) nc64.exe:**

`nc64.exe` is **Netcat for Windows (64-bit)** — the classic "Swiss Army knife" network utility.
Netcat can:

* Create arbitrary TCP/UDP connections
* Listen for inbound connections
* Act as a simple file transfer tool
* Establish interactive shell sessions

In offensive security, Netcat is most commonly used to establish **reverse shells** — a connection from the victim to the attacker that provides command-line access.

VT detections at 62/72 confirm this is a known offensive tool — specifically a compiled version of Netcat commonly distributed with Kali Linux.

**b) Connection attempted:**

```text
nc64.exe → 185.234.219.47:4444 TCP outbound
```

Port 4444 is the **default Netcat/Metasploit reverse shell listener port**.
This confirms the attacker set up a Netcat/Metasploit listener on their server (185.234.219.47) at port 4444, and `nc64.exe` is connecting back to give the attacker an interactive command shell.

The `bytes_sent: 0, bytes_recv: 0` indicates the connection may have been blocked or the listener wasn't ready — but the **intent** is clear: full interactive shell access.

---

## Q4 — Privilege Analysis (2 points)

**a) IIS AppPool account privileges:**

IIS Application Pool accounts (like `IIS APPPOOL\WebApp`) are heavily restricted service accounts:

* No interactive logon rights
* No remote logon rights
* Cannot access other network shares without explicit grants
* Limited file system access (typically only the web root and temp directories)
* Cannot read LSASS or other process memory (no `SeDebugPrivilege`)
* Cannot install services
* Cannot modify registry keys outside their own profile

**b) What attacker cannot do / what they need:**

Cannot do with `IIS APPPOOL\WebApp`:

* Dump domain credentials (no access to LSASS)
* Access other systems on the network via SMB/RDP (no network credentials)
* Install persistent malware that survives reboot with SYSTEM privileges
* Read AD database or query domain controllers
* Access sensitive files owned by other users

To escalate, the attacker needs:

* A **local privilege escalation exploit** to gain `SYSTEM` or `Administrator` on `SERVER-WEB01`
* OR credential theft via a different path (e.g., finding credentials in configuration files, web.config, database connection strings)
* OR lateral movement: use the web server as a pivot to reach other systems that have misconfigured access

**MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation (if they attempt local priv esc)

---

## Q5 — IOC Extraction (3 points)

**Network Indicators:**

```text
IP Address: 185.234.219.47
  - Used for: C2, payload hosting, reverse shell listener
Ports: 80 (payload delivery), 443 (C2 HTTPS), 4444 (reverse shell)
URLs:
  http://185.234.219.47/web_shell.ps1
  http://185.234.219.47/[second stage at port 443]
```

**File Indicators:**

```text
Path: C:\Windows\Temp\nc64.exe
  MD5: CAFEBABECAFEBABECAFEBABECAFEBABE
  SHA256: DEADBEEF...
  VT: 62/72 detections

Path: C:\inetpub\wwwroot\WebApp\update.aspx  (WEB SHELL)
  MD5: A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6
  SHA256: ABCDEF1234567890...
  Note: Not in application source control — should not exist

Path: Downloaded in-memory: web_shell.ps1 (not saved to disk)
```

**Behavioral Indicators:**

```text
Parent-Child: w3wp.exe → powershell.exe (ANY — always malicious)
Parent-Child: powershell.exe → cmd.exe (with net.exe, whoami, etc.)
Pattern: IEX + DownloadString from PowerShell in IIS context
URL Pattern: /upload.aspx?cmd= (command injection probe)
Process in Temp: nc64.exe execution
```

**User Context:**

```text
Account: IIS APPPOOL\WebApp executing PowerShell and network tools
Note: Service accounts should NEVER run PowerShell or network reconnaissance commands
```

---

## Q6 — SIEM Detection Rules (4 points)

**Rule A: IIS Worker Process Spawns Child Process (Immediate Alert)**

```text
RULE A:
  Name: IIS Command Injection — w3wp Spawns Child Process
  Data Source: Sysmon Event 1 (Process Create) or Windows Event 4688
  Condition:
    ParentImage = "*\w3wp.exe"
    AND Image NOT IN (known-legitimate IIS helper processes)
    -- Specifically alert on:
    OR Image = "*\powershell.exe"
    OR Image = "*\cmd.exe"
    OR Image = "*\wscript.exe"
    OR Image = "*\cscript.exe"
  Alert Level: Critical
  False Positive Rate: Very Low
  Notes:
    w3wp.exe (IIS Worker Process) should NEVER spawn script engines in a
    production environment. The ASP.NET runtime doesn't need PowerShell.
    Any legitimate process that w3wp.exe should spawn is deterministic
    (e.g., database clients, logging tools) and can be added to an
    exclusion list. This rule will fire within seconds of successful
    command injection.
```

**Rule B: New .aspx File Created Outside Deployment Window**

```text
RULE B:
  Name: Web Shell — New ASPX File in Web Root Not From Deployment
  Data Source: Sysmon Event 11 (FileCreate) or EDR file event
  Condition:
    TargetFilename LIKE "C:\inetpub\*" AND TargetFilename LIKE "*.aspx"
    AND ProcessImage NOT IN (msdeploy.exe, robocopy.exe, xcopy.exe,
                              git.exe, [deployment tool whitelist])
    AND TimeOfDay NOT IN (maintenance_window)
  Alert Level: High
  False Positive Rate: Low (medium if deployment practices are varied)
  Notes:
    Web application files should only change during planned deployments
    using known deployment tools. A PowerShell process or cmd.exe creating
    a new .aspx file in the web root is extremely suspicious.
    Requires a deployment tool whitelist; tune based on your CI/CD pipeline.
    Even if the reverse shell is killed, this rule catches the web shell
    that provides persistent access.
```

---

## Q7 — Remediation Plan (3 points)

**Immediate Actions (0–30 minutes):**

1. **Block outbound to 185.234.219.47** at the perimeter firewall (both HTTP/80 and HTTPS/443 and 4444)

   *Why:* Cuts C2 channel and prevents any further exfiltration.

1. **Remove or WAF-block `upload.aspx`** or take the web application offline temporarily

   *Why:* The vulnerability is still present.
   The attacker can re-exploit it and re-deploy the web shell.

1. **Delete `update.aspx`** from the web root

   *Why:* This is the persistent web shell.
   As long as it exists, the attacker has backdoor access even after all other cleanup.

1. **Delete `nc64.exe`** from `C:\Windows\Temp\`

1. **Capture memory forensics / disk image** before cleanup for investigation

**Short-Term Actions (30 minutes – 4 hours):**

1. **Audit all files in the web root** against source control / deployment manifests

   Look for any other web shells not yet detected.

1. **Review IIS access logs** for the past 30 days for `upload.aspx?cmd=` patterns

   Determine: Has this been exploited before?
   What other commands were run?

1. **Review web application source code** for the command injection

   Find where `cmd` parameter is used and apply input validation / remove the functionality.

1. **Check for any new local accounts** or privilege escalation on SERVER-WEB01

**Root Cause Fix (Days 1–5):**

1. **Fix the code injection vulnerability** — never pass user input directly to system commands. Use parameterized queries, whitelist validation, or remove the feature entirely.

1. **Deploy a Web Application Firewall (WAF)** with rules blocking OS command injection patterns.

1. **Network segmentation** — SERVER-WEB01 should not have direct outbound internet access except to specific whitelisted update/monitoring endpoints. A proxy or DNS-based outbound filtering would have blocked the C2 callback.

1. **Implement Sysmon** (or EDR agent) on web servers with rules specifically for `w3wp.exe` spawning child processes.
