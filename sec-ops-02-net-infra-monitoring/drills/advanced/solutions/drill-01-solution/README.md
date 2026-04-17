# Drill 01 Solution (Advanced): Network Forensics — Volta Financial

---

## Part A: Timeline Reconstruction

### Question A1: Complete Attack Timeline

Converting UNIX timestamps:

* `1705363200` = 2024-01-15 09:00:00 UTC
* `1705365870` = 2024-01-15 09:44:30 UTC
* `1705372200` = 2024-01-15 11:30:00 UTC
* `1705372450` = 2024-01-15 11:34:10 UTC
* `1705372890` = 2024-01-15 11:41:30 UTC
* `1705380124` = 2024-01-15 13:42:04 UTC

**Full Timeline:**

```text
2024-01-15 09:00:00 UTC — INITIAL EXPLOITATION BEGINS
  Evidence: conn.log — 185.220.101.35:various → 10.0.1.10:443
  Detail: Attacker begins sending small HTTPS connections (1890 bytes out, 512 in)
          every 20 seconds — consistent with exploitation attempt or web app scanning
  Source: Zeek conn.log (CaA1B2C3D4E5 and subsequent UIDs)

2024-01-15 09:00:00 – 09:44:30 UTC — EXPLOITATION / INITIAL FOOTHOLD
  Detail: ~135 connections, each ~20s apart, ~1900 bytes out, ~510 bytes in
  Total duration: 44 minutes 30 seconds
  Attacker likely exploiting a web application vulnerability on 10.0.1.10
  The small, regular payloads suggest automated exploitation tool

2024-01-15 09:44:30 – 11:30:00 UTC — [90-MINUTE GAP]
  Detail: No connections from 185.220.101.35 during this window
  Inference: Attacker successfully compromised 10.0.1.10 and pivoted to
             post-exploitation (see below); or attacker went dormant

2024-01-15 11:30:00 UTC — REVERSE SHELL ESTABLISHED
  Evidence: conn.log UID CcA1B2C3D4E5
  10.0.1.10:56234 → 185.220.101.35:4444 (outbound from victim)
  CRITICAL: Connection lasts 1843 seconds (30+ minutes), 24.8 MB outbound
  Port 4444 = default Metasploit Meterpreter listener

2024-01-15 11:30:01 UTC — INTERNAL RECONNAISSANCE (DNS)
  Evidence: dns.log — 10.0.1.10 queries 8.8.8.8 for internal hostnames
  Queries: dc01, fileserver01, mail, backup, payroll, trading (all NXDOMAIN)
  Purpose: Attacker mapping internal network topology via DNS guessing
  Also: DNS TXT query to relay.stealdata.pw → response instructs to
        download stage 2 payload from http://185.220.101.35/implant.bin

2024-01-15 11:30:05 – 11:30:10 UTC — STAGE 2 PAYLOAD DOWNLOAD
  Evidence: http.log, files.log
  10.0.1.10 downloads: /implant.bin (2.3 MB) and /stage3.ps1 (14 KB)
  File types: binary executable + PowerShell script
  SHA256 implant.bin: a665a45920422f9d417e4867efdc4fb8a304f3e7...

2024-01-15 11:34:10 – 11:40:00 UTC — LATERAL MOVEMENT (SMB)
  Evidence: conn.log — 10.0.1.10 → 10.10.1.5, 10.10.1.6, 10.10.1.7:445
  SMB connections to three internal servers, each lasting 9–12 seconds
  Large resp_bytes (752K–892K) = files being read from these servers
  Followed by SSH scan: 24+ S0 connections to 10.10.1.x:22 (mapping SSH hosts)

2024-01-15 11:41:30 UTC — RDP LATERAL MOVEMENT TO 10.10.5.100
  Evidence: conn.log UID CeA1B2C3D4E5
  10.0.1.10 → 10.10.5.100:3389 (RDP)
  Duration: 7234 seconds (2 hours)
  891 MB bidirectional = active interactive RDP session

2024-01-15 13:42:04 – 14:42:05 UTC — DATA EXFILTRATION
  Evidence: conn.log UIDs CfA1B2C3D4E5 and CfB2C3D4E5F6
  TWO simultaneous exfiltration streams from 10.10.5.100:
  (1) 10.10.5.100 → 52.1.2.100:443 — 4.0 GB outbound (S3 bucket)
  (2) 10.10.5.100 → 185.220.101.35:443 — 4.0 GB outbound (attacker server)
  Evidence: http.log shows POST of vault.7z (4.0 GB) to backup-q4.s3.amazonaws.com
  User-Agent: python-requests/2.31 (automated script)
```

---

### Question A2: Initial Access Vector

The 45-minute period of connections from `185.220.101.35` to `10.0.1.10:443` shows:

* Connections every **20 seconds** (automated, not human)
* Payloads of **~1890 bytes outbound, ~510 bytes inbound** — very consistent
* This pattern is consistent with **exploitation of a web application** (HTTPS on port 443)

**Likely attack type:** Web application exploitation using an automated tool (e.g., Burp Suite, sqlmap, or a custom exploit).
The attacker likely:

1. Scanned and found a vulnerability (SQL injection, RCE, file upload)
1. Exploited it repeatedly (the 135+ connections may be multiple exploit attempts or stages)
1. Eventually achieved Remote Code Execution (RCE) on the web server

The small inbound payload (~510 bytes per connection) is consistent with the server returning a small response (exploit success confirmation, or file read result).

The 10.0.1.10 IP being in the 10.0.1.0/24 range suggests it is in the DMZ (web server network).

---

### Question A3: The 90-Minute Gap

**The gap (09:44 – 11:30 UTC):**

After the exploitation phase, no external connections from `185.220.101.35` are seen for 90 minutes.
This does NOT mean the attacker was inactive.
Likely explanations:

1. **The attacker established persistence and went off-network temporarily.** The web application exploit gave them code execution; they deployed a web shell or backdoor. The 90-minute gap is the attacker stepping away.

1. **The attacker was doing off-network activity:** checking their tooling, preparing stage 2 payloads (`implant.bin`, `stage3.ps1`), setting up the infrastructure for the next phase.

**What happened immediately after the gap:**

At 11:30:00, the traffic direction **reverses**: instead of the attacker connecting inbound to port 443, the **victim (`10.0.1.10`) connects outbound to `185.220.101.35:4444`**.
This is a **reverse shell** or **Meterpreter session** — the compromised web server calls home to the attacker.

This is a classic attacker technique: exploitation creates a web shell; the attacker uses the web shell to execute a Meterpreter payload; the payload opens an outbound connection to the attacker (bypassing firewalls that block inbound connections).

---

## Part B: Scope Assessment

### Question B1: Affected Internal Hosts

| Host | Evidence | What happened |
|------|---------|---------------|
| **10.0.1.10** (DMZ web server) | conn.log: initial exploitation; reverse shell to :4444; lateral movement source | Initially compromised; used as pivot point |
| **10.10.1.5** | conn.log: SMB connection from 10.0.1.10, 892 KB transferred | Files read via SMB from this server |
| **10.10.1.6** | conn.log: SMB connection from 10.0.1.10, 754 KB transferred | Files read via SMB from this server |
| **10.10.1.7** | conn.log: SMB connection from 10.0.1.10, 823 KB transferred | Files read via SMB from this server |
| **10.10.1.x (22 hosts)** | conn.log: 24+ S0 connections to port 22 | Scanned for SSH (all shown as S0 — unreachable or filtered) |
| **10.10.5.100** | conn.log: RDP session 7234s, 891 MB; exfiltration source | Likely an admin workstation; attacker had interactive access for 2 hours; used for exfiltration |

**Total directly affected hosts:** At minimum 6 known (10.0.1.10, 10.10.1.5/6/7, 10.10.5.100 + the exfiltration destination).
The 24 SSH-scanned hosts may not have been compromised (S0 = no response).

---

### Question B2: Data Exfiltration

**Yes, data was exfiltrated.**

**Evidence:**

* `http.log`: POST of `vault.7z` (4,198,305,120 bytes = **4.0 GB**) to `backup-q4.s3.amazonaws.com`
* `conn.log` CfB2: Simultaneous second stream of 4.0 GB to `185.220.101.35:443`

**Summary:**

* **File:** `vault.7z` (7-zip compressed archive — likely encrypted, hence "vault")
* **Total exfiltrated:** ~8 GB (same data sent to two destinations)
* **Destinations:**
  1. `52.1.2.100` — resolves to `backup-q4.s3.amazonaws.com` (attacker-controlled S3 bucket)
  1. `185.220.101.35` — the original attacker IP (direct exfiltration)
* **Source host:** `10.10.5.100` (the admin workstation compromised via RDP)
* **Method:** Python script (`python-requests/2.31`) — automated exfiltration
* **Duration:** ~1 hour (3601 seconds on stream 1)

The double-destination exfiltration ensures the attacker receives the data even if one channel is blocked.

---

### Question B3: DNS Queries for Internal Hostnames to External Resolver

**Purpose of the activity:**
After gaining a shell on `10.0.1.10`, the attacker ran DNS reconnaissance to map the internal network.
By querying for common internal hostnames (dc01, fileserver01, mail, backup, payroll, trading), they were trying to discover:

* The names and roles of internal servers
* Which services exist (backup server = target for ransomware; payroll = high-value data)
* Network topology for lateral movement planning

**Why querying external DNS is a security risk, even when NXDOMAIN:**

1. **Internal topology leakage:** The query `dc01.internal.volta-finance.com` reveals to Google (and anyone monitoring DNS) that Volta Financial has a host named `dc01` with an internal domain of `internal.volta-finance.com`. This exposes the internal naming convention.

1. **Attacker-controlled resolver:** If the attacker controlled a resolver at an IP the host would query (via DNS poisoning or VPN), they could return real answers pointing to malicious IP addresses — a DNS rebinding attack.

1. **DNS monitoring bypass:** By querying `8.8.8.8` instead of the corporate DNS resolver, the attacker avoids internal DNS logging and any DNS sinkholes that might block C2 domains.

1. **Evidence of compromise indicator:** Internal hostnames being queried against external DNS is an anomaly indicator in Zeek dns.log — it's a detection opportunity that should trigger an alert.

---

## Part C: Deeper Analysis

### Question C1: DNS TXT Query to relay.stealdata.pw

**What this is:** This is a **DNS C2 (Command and Control) communication channel** using DNS TXT records to transmit commands.

**The query:** `bRt7kXpY9mNq2wVs4uLe6iOa1dFh8jCg.relay.stealdata.pw` — the random-looking 32-character subdomain is a session identifier or encoded check-in token.

**The response:** `"STAGE2:download:http://185.220.101.35/implant.bin"`

* The malware on `10.0.1.10` contacted its C2 via DNS (bypassing HTTP-based detection)
* The C2 server responded with the next command: download the stage 2 payload from the attacker's server
* `STAGE2` indicates a multi-stage attack: the initial exploit was Stage 1; this is the transition to Stage 2 (persistent implant)

**Attack infrastructure:**

* `stealdata.pw` is registered by the attacker as their C2 relay domain
* The attacker controls the authoritative DNS server for `stealdata.pw`
* All DNS queries to subdomains of `stealdata.pw` go to the attacker's server

**Implication:** The attacker uses DNS as a resilient C2 channel because DNS is:

* Rarely blocked by firewalls (port 53 UDP must be open for internet access)
* Not inspected for content by basic firewalls
* Difficult to detect without DPI or Zeek-level analysis

---

### Question C2: File Hashes — What to Do

**Immediate actions with the hashes:**

1. **Search threat intelligence databases:**
   * VirusTotal: `https://www.virustotal.com/gui/file/a665a45920422f9d417e4867efdc4fb8a304f3e7abe77f9a1a76e5594d72c72b`
   * MalwareBazaar, Any.run, Hybrid-Analysis
   * MISP (if you have an organisation instance)
   * If the hash is known, get the malware family name and known TTPs

1. **Search your entire environment:**
   * Use your EDR to search all endpoints for this SHA256
   * Search Zeek files.log for the hash across all sensor data
   * This tells you if the implant was deployed elsewhere

1. **Indicator sharing:**
   * Share the hash with your ISAC (Information Sharing and Analysis Centre)
   * Create Snort/Suricata rules to detect the binary being downloaded

**What the file types suggest:**

* `implant.bin` (2.3 MB, `application/octet-stream`) = a binary executable. Likely a compiled Meterpreter stager or a custom RAT (Remote Access Tool).
* `stage3.ps1` (14 KB, `application/x-powershell`) = a PowerShell script. PowerShell is heavily used for post-exploitation (lateral movement, privilege escalation, persistence). 14 KB is a significant PowerShell script — likely contains full lateral movement/credential dumping code.

The combination is a classic two-stage attack: binary for persistence, PowerShell for operational tasks.

---

### Question C3: Connection to 185.220.101.35:4444

**What this connection represents:**
This is a **Meterpreter reverse shell** (Metasploit's primary post-exploitation framework).
The victim host (`10.0.1.10`) initiated the outbound connection to the attacker's listener on port 4444.

In a reverse shell:

* The victim calls out to the attacker (bypasses inbound firewall rules)
* Once connected, the attacker has an interactive command shell on the victim
* They can run any command, upload/download files, pivot to internal network

**Duration:** 1843 seconds = 30 minutes 43 seconds — the attacker maintained this shell for over 30 minutes, during which they:

* Ran the DNS reconnaissance queries
* Launched the SMB lateral movement
* Scanned for SSH hosts
* Likely dumped credentials from the web server

**24.8 MB outbound — why it's concerning:**
24.8 MB is unusually large for an interactive shell session.
Shell commands themselves are small.
This volume of outbound data suggests:

* The attacker ran a **credential dump** (mimikatz-style) and exfiltrated the results
* They may have read/copied sensitive files from the web server
* They may have sent reconnaissance results (network scan output, system information)

In a financial services company, the web server might have database connection strings, API keys, or cached authentication tokens that could be extracted.

---

## Part D: Incident Report

### INCIDENT REPORT
**Incident ID:** IR-2024-0042

**Severity:** P1 — Critical

**Classification:** Data Breach / Advanced Persistent Threat

**Date detected:** 2024-01-15 (retrospective discovery)

**Analyst:** [Your name]

**Status:** Contained — Investigation ongoing

---

**EXECUTIVE SUMMARY**

On Monday 15 January 2024, Volta Financial Services suffered a targeted cyber attack.
An external attacker exploited the company's public-facing web server, gained access to the internal network, and exfiltrated approximately 8 GB of data from a finance department workstation.
The attack spanned approximately 4.5 hours and affected at least 6 internal systems.
The stolen data's content is not yet confirmed but its size (~8 GB) suggests significant financial or customer data.
As financial data is likely involved, GDPR breach notification obligations must be assessed within 72 hours.

---

**TECHNICAL SUMMARY**

The attack followed a standard multi-stage pattern (Initial Access → Execution → Lateral Movement → Exfiltration):

**Phase 1 — Initial Access (09:00–09:44 UTC):** The attacker (`185.220.101.35`, a known Tor exit node associated with ransomware groups) exploited a vulnerability in the HTTPS web application running on `10.0.1.10` (DMZ web server). 135 automated exploitation attempts over 44 minutes culminated in successful Remote Code Execution.

**Phase 2 — Persistence and Execution (11:30 UTC):** Following a 90-minute pause, the compromised web server established a reverse shell to the attacker (port 4444, Metasploit Meterpreter).
The attacker used DNS C2 (`relay.stealdata.pw`) to receive commands and instructed the victim to download two payloads: a 2.3 MB binary implant and a 14 KB PowerShell script.

**Phase 3 — Reconnaissance (11:30–11:34 UTC):** The attacker queried internal hostnames via external DNS (leaking topology) and ran SMB file reads against three internal servers (`10.10.1.5`, `.6`, `.7`), extracting approximately 2.4 MB of files.

**Phase 4 — Lateral Movement (11:34–11:41 UTC):** The attacker moved from the web server to an internal admin workstation (`10.10.5.100`) via RDP, maintaining a 2-hour interactive session.

**Phase 5 — Exfiltration (13:42–14:43 UTC):** Approximately 8 GB of data (compressed as `vault.7z`) was exfiltrated from `10.10.5.100` to two external destinations: an attacker-controlled S3 bucket and the original attack IP.

---

**AFFECTED SYSTEMS**

| System | IP | Impact |
|--------|-----|--------|
| DMZ Web Server | 10.0.1.10 | Compromised; used as pivot |
| Internal File Server | 10.10.1.5/6/7 | Files accessed via SMB |
| Finance Workstation | 10.10.5.100 | Compromised; exfiltration source |

---

**IMMEDIATE CONTAINMENT ACTIONS**

Recommended (if not already done):

1. Isolate 10.0.1.10 and 10.10.5.100 from the network
1. Block 185.220.101.35 at the perimeter firewall
1. Block stealdata.pw and 52.1.2.100 at DNS and firewall
1. Reset credentials for all accounts with access to the affected systems
1. Enable MFA for all VPN and RDP access
1. Preserve memory dumps and disk images of both compromised hosts

---

**EVIDENCE PRESERVED**

* Zeek conn.log, dns.log, http.log, files.log (SHA256 hashed)
* Firewall allow/block logs
* Network PCAP (if available from sensors)
* Access: restricted to IR team; chain of custody maintained

---

**GDPR ASSESSMENT**

Volta Financial stores EU employee and customer data.
The exfiltrated `vault.7z` archive from a finance workstation is highly likely to contain personal data (customer financial records, employee data).
Under GDPR Article 33, notification to the competent supervisory authority is required within 72 hours of becoming "aware" of the breach.
The 72-hour clock started when the threat intelligence alert was received.

**Action required:** DPO notification immediately; supervisory authority notification within 72 hours; customer notification assessment (Article 34) to follow.
