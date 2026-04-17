# Drill 01 Solution: Protocol Identification

**For instructor/self-assessment use only — do not distribute before drill completion**

---

## Snippet 1 — Answer

**Protocol:** ARP (Address Resolution Protocol)

**Evidence breakdown:**

* Destination MAC `ff:ff:ff:ff:ff:ff` = Ethernet broadcast (goes to all hosts)
* Source IP (`c0 a8 01 64` = 192.168.1.100) asking about target IP (`c0 a8 01 01` = 192.168.1.1)
* Payload `00 01` = ARP opcode 1 (Request)
* `08 00` = Protocol type = IPv4; `06 04` = hardware size 6, protocol size 4
* Target MAC `00 00 00 00 00 00` = unknown (that's what is being requested)

**Full translation:** "Who has 192.168.1.1?
Tell 192.168.1.100" — this is a host trying to find the MAC address of the default gateway before sending a packet to it.

**Security assessment:** Normal

**Rationale:** ARP requests are a normal and necessary part of network operation.
Every host must resolve the MAC address of its gateway before sending traffic.

**Suspicious variations to look for:**

* Gratuitous ARP (unsolicited reply claiming a gateway IP)
* Many ARP replies for the same IP from different MACs (ARP poisoning)
* ARP from an unexpected IP/MAC combination

**Recommended action:** Ignore — this is expected behaviour.

---

## Snippet 2 — Answer

**Protocol:** TCP Port Scan (SYN scan / Nmap-style)

**Evidence breakdown:**

* Source 192.168.5.200 sends SYN to port 22 → gets RST (port closed/filtered)
* Immediately sends SYN to port 23 → gets RST
* Pattern continues sequentially through ports 24, 25, 26... 1024
* SYN-only (no ACK after SYN-ACK) — this is a **half-open/SYN scan**
* Sequential port numbers over a short time period

**Security assessment:** Malicious / Definitely suspicious

**Attack type:** Port scan / network reconnaissance
The attacker is probing which ports are open on 10.0.0.1 before planning an attack.

**Snort rule that would detect this:**

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any \
    (flags:S,!APUR; threshold: type both, track by_src, count 20, seconds 5; \
     msg:"Port Scan Detected"; sid:1000003; rev:1;)
```

**Recommended action:** **Escalate** — investigate 192.168.5.200.
Block it at the firewall.
Check whether any subsequent connections were established.

---

## Snippet 3 — Answer

**Protocol:** DNS (Domain Name System) — Type A query

**Evidence breakdown:**

* UDP destination port 53 (DNS standard port)
* Standard A record query (Host Address lookup)
* Query for `www.google.com` — a common legitimate domain
* Using Google's public resolver `8.8.8.8`

**Security assessment:** Normal (but note: using 8.8.8.8 instead of the corporate DNS server)

**Minor concern:** Querying 8.8.8.8 directly instead of the corporate DNS resolver bypasses:

* Internal DNS security policies
* DNS sinkholes (which redirect malware domains to safety)
* DNS logging at the corporate resolver

**Recommended action:** Investigate why this host is using Google DNS instead of corporate DNS.
This could indicate a misconfiguration, malware trying to avoid DNS monitoring, or shadow IT.

---

## Snippet 4 — Answer

**Protocol:** DNS Tunnelling

**Evidence breakdown:**

* DNS TXT record query (TXT records can carry arbitrary data)
* The queried domain is `xK7mN2pQ9rL4vW1eY8uI3oA6sD5fG0h.evil-domain.ru` — an extremely long, random-looking subdomain
* The response contains `ACK:cmd:whoami:result:cm9vdA==`
  * `cm9vdA==` is Base64 for `root`
  * The response structure encodes a command execution result
* Top-level domain `.ru` (Russia) — while not inherently malicious, noteworthy

**Full interpretation:** The malware on `10.10.5.23` sent a command result to its C2 server (evil-domain.ru) by encoding it in a DNS TXT query.
The C2 received it (NOERROR) and responded with acknowledgment and the next command.
This is **DNS tunnelling** used for **Command and Control**.

**Security assessment:** Malicious

**Impact:** The host at 10.10.5.23 is compromised.
The attacker ran `whoami` and got `root` — meaning they have root/administrator access.

**Recommended action:** **Immediate escalation and isolation.** Isolate 10.10.5.23 from the network immediately.
Begin incident response.
Block the domain `evil-domain.ru` at the DNS resolver and firewall.

---

## Snippet 5 — Answer

**Protocol:** FTP (File Transfer Protocol)

**Evidence breakdown:**

* TCP port 21 = FTP control channel
* Server banner: `220 ProFTPD Server ready` = FTP server
* Authentication sequence: `USER` / `PASS` commands
* Credentials `bob / p@ssw0rd123` sent in **cleartext**
* `RETR /etc/passwd` command = download `/etc/passwd` (Linux password file)

**Security assessment:** Malicious / Very suspicious

**Issues identified:**

1. **FTP transmits credentials in cleartext** — the password is visible to any network observer
1. **`/etc/passwd` retrieval** — the attacker is extracting the system's user account list, which is used for further password cracking
1. **External destination** (203.0.113.10) — internal host connecting FTP to an external server

**Recommended action:** **Immediate escalation.** Isolate the host.
Change all passwords.
Investigate what else was transferred.
Block FTP to external addresses at the firewall.
Replace FTP with SFTP.

---

## Snippet 6 — Answer

**Protocol:** RDP (Remote Desktop Protocol) over TLS — TCP port 3389

**Evidence breakdown:**

* TCP destination port 3389 = Windows Remote Desktop Protocol
* Source is internal (`10.10.1.100`) to another internal host (`10.10.2.200`)
* TLS handshake = encrypted session (content not visible)
* Duration 3 hours 22 minutes = extended interactive session
* 45 MB transferred = consistent with interactive desktop session (not large enough for bulk data transfer)

**Security assessment:** Potentially suspicious (requires context)

**Analysis:**

* Internal-to-internal RDP is sometimes legitimate (IT administration)
* However, without context: which user initiated this? Is this an authorised admin?
* The 3+ hour duration and 45 MB transfer could indicate lateral movement after compromise

**Questions to ask:**

* Is this RDP between expected hosts (admin workstation to server)?
* Is the source user authorised to RDP into the destination?
* Were there any other unusual events on either host around this time?

**Recommended action:** **Investigate** — check Active Directory logs for the RDP session.
Confirm it was authorised.
If not authorised, treat as lateral movement.

---

## Snippet 7 — Answer

**Protocol/Event:** SSH Brute Force followed by Successful Root Login

**Evidence breakdown:**

* Priority `<11>` = Severity 3 (Error), Facility 1 (user)
* 5 consecutive failed `root` login attempts from `203.0.113.50`
* Port numbers increment by 1 each attempt (12341, 12342, ...) = automated tool
* All within 5 seconds = automated brute force
* The 6th attempt **SUCCEEDED**: `Accepted password for root from 203.0.113.50`

**Security assessment:** Malicious — **Active Incident**

**Impact:** An external attacker has successfully authenticated as `root` (the most privileged user) on a web server.
This is a critical security incident.

**Recommended action:** **Critical escalation — initiate incident response immediately.**

1. Isolate the web server from the network
1. Revoke/change root credentials
1. Capture memory and disk image for forensics
1. Review all commands executed during/after the login
1. Check for persistence mechanisms (cron jobs, SSH keys added, new user accounts)
1. Block 203.0.113.50 at the firewall

---

## Snippet 8 — Answer

**Protocol:** HTTP — SQL Injection Attack

**Evidence breakdown:**

* Destination port 80 = HTTP
* URI: `id=1'+UNION+SELECT+username,password,3+FROM+users--`
  * `UNION SELECT` = UNION-based SQL injection
  * `FROM+users` = targeting the users table
  * The `--` at the end = SQL comment to terminate the original query
* User-Agent: `sqlmap/1.7.8` = **sqlmap**, an automated SQL injection tool
* Server response: `500 Internal Server Error` with a MySQL syntax error exposed
  * This confirms the application is vulnerable — the injection partially worked
* `X-Powered-By: PHP/7.4.33` = technology disclosure (also a finding)

**Security assessment:** Malicious — SQL injection attack in progress

**Impact:** The attacker appears to be using sqlmap to automate SQL injection against the internal shop application.
The 500 error suggests the application crashed rather than returning data — but sqlmap will retry with different payloads.

**Source:** `192.168.100.50` — note this is an **internal** IP address, meaning an insider or compromised internal host is conducting this attack.

**Recommended action:** **Escalate.** Block 192.168.100.50 at the firewall/proxy.
Investigate the source host.
Apply WAF rules to block sqlmap User-Agent.
Audit the shop application for SQL injection vulnerabilities.
Apply parameterised queries.

---

## Snippet 9 — Answer

**Protocol/Pattern:** HTTPS Beaconing — C2 Communication

**Evidence breakdown:**

* Connections every exactly 60 seconds = regular interval (not human behaviour)
* Every connection has identical byte counts: 256 bytes out, 512 bytes in
* All connections to the same external IP `185.220.101.50` on port 443
* All connections successfully completed (SF state)
* 24-hour pattern = malware running persistently

**Security assessment:** Malicious — Command and Control (C2) beaconing

**Analysis:**

* 185.220.101.50 is known as a TOR exit node (check threat intel)
* The **jitter-free** 60-second interval suggests an automated agent (malware)
* Human users don't access the same IP every 60 seconds for 24 hours
* Identical packet sizes suggest a fixed-size protocol (heartbeat/keep-alive with C2)

**Recommended action:** **Escalate.** Isolate `10.10.5.77`.
Block `185.220.101.50` at the firewall.
Conduct malware analysis on the host.
Review all files downloaded by the host in the past month.

---

## Snippet 10 — Answer

**Protocol/Event:** HTTPS — Possible Data Exfiltration via Cloud Storage

**Evidence breakdown:**

* NetFlow: 10.10.3.100 (Finance workstation) → 52.1.2.3 (AWS S3) port 443
* Duration: 30 seconds
* **Bytes: 4,198,305 (≈ 4 MB)** — this is the key data point
* TCP Flags: `UAPRSF` — all flags set, which is unusual
  * More importantly: the total bytes are high for 30 seconds from a workstation
* The S3 bucket is named `backup-finance-q4` — this sounds like financial data

**Security assessment:** Suspicious — possible data exfiltration, or legitimate backup

**Context needed:**

* Is there an authorised backup process from Finance workstations to S3?
* Does the employee at 10.10.3.100 have an AWS account?
* What time was this? Business hours or 2 AM?
* Has this happened before (check historical NetFlow)?

**If the transfer is not authorised:** This could be an employee exfiltrating Q4 financial data before leaving the company, or malware sending sensitive data to an attacker-controlled S3 bucket.

**Recommended action:** **Investigate.** Check if there is a legitimate business process.
Correlate with HR data (is this employee on a PIP or recently resigned?).
Review the DLP (Data Loss Prevention) logs.
If no authorised process exists, escalate as a potential insider threat.

---

## Scoring Guide

| Snippet | Key concepts tested |
|---------|-------------------|
| 1 | ARP, broadcast, Layer 2 |
| 2 | TCP flags, port scanning, SYN scan |
| 3 | DNS, protocol basics, DNS server policy |
| 4 | DNS tunnelling, C2, Base64 encoding |
| 5 | FTP cleartext auth, /etc/passwd, exfiltration |
| 6 | RDP, lateral movement, contextual analysis |
| 7 | SSH brute force, syslog, critical escalation |
| 8 | SQL injection, sqlmap, insider threat |
| 9 | C2 beaconing, Zeek conn.log analysis |
| 10 | NetFlow, data exfiltration, cloud storage |
