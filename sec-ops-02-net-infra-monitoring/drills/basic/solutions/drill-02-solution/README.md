# Drill 02 Solution: PCAP Description Analysis

**For instructor/self-assessment use only**

---

## Section A: Basic Analysis

### Question 1 Answer

**HTTP vs TLS percentage:**

* HTTP (plaintext): 49.0% of bytes
* TLS (encrypted): 44.9% of bytes

**Security implication:** Nearly half of all traffic is transmitted in cleartext.
HTTP traffic can be intercepted, read, and modified by anyone with access to the network path.
This means:

* Session cookies could be stolen (session hijacking)
* Login credentials submitted via HTTP forms are visible
* Data downloaded via HTTP can be tampered with in transit (man-in-the-middle)

For a corporate network, having 49% plaintext traffic is a significant finding.
Modern best practice is HTTPS-everywhere; any remaining HTTP should be restricted to internal-only, non-sensitive resources.

**Additional concern:** XML-over-HTTP (`HTTP/XML` — 14.7% of bytes) may indicate SOAP API calls or similar data exchange happening in cleartext.

---

### Question 2 Answer

**What is unusual:** Rows 3-9 show 24 separate UDP DNS flows, each exactly 124,800 bytes, from source port numbers incrementing sequentially (51234, 51235, 51236...).
All occur within a 30-second window.

**What this indicates:** This pattern is consistent with **automated, high-volume DNS querying**.
Normal DNS usage:

* Uses a random source port each time (not sequential)
* Does not generate 24 equally-sized flows to the same resolver in 30 seconds
* Human browsing produces varied query sizes (different domain names = different lengths)

The identical byte count (124,800 bytes = 122 KB per flow) is particularly suspicious — natural DNS traffic has variable sizes because domain names vary in length.

**Possible explanations:**

1. **DNS tunnelling:** Data is being encoded into DNS queries at a fixed rate, with each flow carrying a fixed chunk
1. **Automated reconnaissance tool:** Scripts generating DNS queries programmatically
1. **DGA malware:** Generating domains algorithmically (though DGA usually varies the subdomain length)

The combination with the TXT record queries to `c2track.net` (see Question 3) strongly suggests DNS tunnelling as the explanation.

---

### Question 3 Answer

**Attack type:** DNS Tunnelling / C2 over DNS

**Evidence:**

* Subdomains are 32 characters of seemingly random alphanumeric characters (`aKe8mNp3xQr5vLt2wZy7bDs4fGh1jCu`)
* Query type is TXT (text records — commonly used to carry arbitrary data in DNS tunnelling)
* The domain name `c2track.net` strongly implies Command and Control ("C2") infrastructure
* 361 queries to this domain (124 + 119 + 118 = 361 TXT queries alone)

**How DNS tunnelling works:**

1. Data is encoded (e.g., Base64) and split into chunks
1. Each chunk becomes a subdomain: `<encoded-data>.c2domain.net`
1. The C2 server acts as the authoritative DNS server for `c2domain.net`
1. The C2 server receives the data via DNS queries
1. Responses carry commands back in the DNS answer section

**`c2track.net` is likely:** A C2 server under the attacker's control.
The "c2" in the name is almost certainly intentional — either a test environment or a brazen attacker.

**The querying host:** Not explicitly identified in the DNS log (need to check which internal host made these queries).
The HTTP log shows `198.18.0.77` as a destination for POST requests with `go-http-client` User-Agent, which may be the same compromised host using both HTTP C2 and DNS C2.

---

## Section B: Threat Identification

### Question 4 Answer — Severity Ranking

**Ranking from most to least severe:**

**1.
(d) GET /admin/backup.zip with python-requests — CRITICAL**

* An automated tool (`python-requests`) successfully downloaded `/admin/backup.zip` from the internal web server `10.0.0.1` with HTTP 200 OK
* `backup.zip` likely contains sensitive data (database dumps, configuration files, credentials, source code)
* HTTP 200 means the download succeeded
* The internal IP `10.0.0.1` as destination suggests this is an internal admin interface — the attacker may already have internal network access
* This is **data exfiltration confirmed**

**2.
(a) HTTP traffic to 198.18.0.77 with go-http-client — HIGH**

* `go-http-client/2.0` is not a browser — this is automated software communicating over HTTP
* `/api/v2/collect` endpoint with POST method = uploading data to a remote server
* `/api/v2/cmds` endpoint with GET method = receiving commands from a remote server
* This is consistent with **HTTP-based C2 communication**
* 261 POST requests to `/collect` over 15 minutes = active exfiltration/beaconing

**3.
(c) DNS query for passwd.internal.argustech.com → 8.8.8.8 — HIGH**

* `passwd.internal.argustech.com` is an internal hostname — it should never be queried against an external DNS server
* Sending this query to `8.8.8.8` (Google DNS) means the **internal hostname was leaked to an external server**
* This reveals internal network topology to Google and to anyone monitoring DNS traffic on the path
* Could also mean an attacker is trying to resolve internal hostnames through a misconfigured DNS or testing for DNS rebinding
* The single query is suspicious — why would legitimate software query for `passwd.internal.*` at all?

**4.
(b) Self-signed certificate with RC4-MD5 on 203.0.113.50 — MEDIUM**

* RC4-MD5 has been cryptographically broken since ~2013
* Self-signed certificates provide no third-party validation
* A server using a self-signed, broken cipher suite is either very old or intentionally set up to appear secure while being weak
* This is the destination of the 42.9 MB transfer (Conversation row 1)
* However, this is lower than (d) because the connection might be legitimate (e.g., an old legacy server) — more investigation needed

---

### Question 5 Answer

**Conversation: 10.0.1.10 → 203.0.113.50:443 | 42.9 MB | 14m 52s | self-signed cert | RC4-MD5**

**Possible scenarios:**

**Scenario A (Most likely): Data exfiltration / C2 large upload**

* The host `10.0.1.10` (appears to be in the DMZ based on IP range) is connected to an external server for nearly the entire capture duration (14m 52s out of 15m)
* 42.9 MB is a significant amount — equivalent to thousands of documents or a compressed database
* Self-signed certificate means the receiving server was set up privately — not a commercial service
* RC4-MD5 is a broken cipher that no legitimate business would use — suggests either a very old server or a deliberately configured attacker infrastructure
* The sustained connection (not short bursts) is consistent with a large file transfer

**Scenario B (Less likely): Legitimate but poorly secured backup/VPN**

* Some organisations use self-signed certs for internal VPN endpoints or backup servers
* However, RC4-MD5 would be a serious misconfiguration for 2024
* 10.0.1.10 being in the DMZ (if the IP range is correct) makes this less likely

**Most likely interpretation:** Exfiltration.
A compromised DMZ server (`10.0.1.10`) is sending ~43 MB of data to an attacker-controlled server (`203.0.113.50`) using a custom HTTPS tunnel with a weak cipher.

**Supporting evidence from other logs:**

* The TLS certificate for `203.0.113.50` is self-signed and uses broken cryptography
* Multiple other C2 indicators present in the same capture (DNS tunnelling to c2track.net, HTTP C2 to 198.18.0.77)

---

### Question 6 Answer

**2,203 RST responses to SYN packets**

**Explanation:**
Looking at Conversation row 10: `203.0.113.100:33789 → 10.0.0.1:22` with TCP shows a brief connection (duration 0m 00s) — this appears to be a SYN with no response or immediate RST.

With 2,203+ RST responses and only 2,108 SYN-ACKs (suggesting ~2,204 SYN packets with no valid response), the pattern is consistent with **port scanning from 203.0.113.100** and possibly from other external sources trying to reach hosts in the 10.0.0.0 network.

Note: Conversation 10 explicitly shows `203.0.113.100 → 10.0.0.1:22` with 0 seconds duration, which is the signature of a SYN scan (SYN sent, RST received immediately — port 22 not open or filtered).

**Additional information needed:**

1. Source IPs generating the SYN packets (sort by SYN count per source)
1. Destination ports being probed (are they sequential? Random?)
1. How many distinct destination IPs were targeted?
1. Firewall logs for the same period (did the firewall block these before they reached the capture point?)

---

## Section C: Investigation Planning

### Question 7 Answer — Investigation Plan for c2track.net

**What we already know:**

* Internal host(s) making DNS TXT queries with 32-character random subdomains to `c2track.net`
* 361+ queries in 15 minutes = active campaign
* Queries going to external resolver (8.8.8.8) instead of corporate DNS = bypassing internal DNS security
* The domain `c2track.net` has A records and TXT records — it is an active DNS infrastructure
* May be correlated with HTTP C2 traffic to `198.18.0.77`

**Additional data to collect:**

1. **Which internal host generated the DNS queries?** — Filter DNS logs by source IP, cross-reference with DHCP logs
1. **When did this start?** — Review historical NetFlow/Zeek conn.log, not just this 15 minutes
1. **What do the TXT record responses contain?** — Need the full DNS response data (may have commands/data in Base64)
1. **Is 198.18.0.77 related?** — Look up this IP in threat intelligence; check if same host makes both DNS and HTTP C2 traffic
1. **What process is running?** — Need endpoint investigation (EDR logs, process list, network connections)
1. **Are there lateral movement indicators?** — Check if the compromised host connected to other internal systems

**Notification chain:**

1. Immediate: SOC Tier 2 analyst + SOC Manager
1. Within 1 hour: CISO + IT Security team
1. If data exfiltration confirmed: Legal/Compliance team, Privacy Officer (GDPR notification timeline starts)
1. If critical systems affected: Business continuity team

**Immediate containment actions:**

1. Block `c2track.net` and `198.18.0.77` at DNS resolver and firewall
1. Block `203.0.113.50` at firewall (large TLS exfiltration)
1. Isolate the source host(s) from the network (do NOT power off — preserve memory)
1. Capture memory (RAM) of the compromised host for malware analysis
1. Block outbound DNS to 8.8.8.8 and redirect to corporate DNS resolver (stops C2 channel)
1. Preserve all Zeek logs, PCAPs, and firewall logs with hash verification

---

### Question 8 Answer — Timeline

Based on the available data, the likely sequence is:

```text
TIMELINE OF EVENTS (2024-01-16)
================================

PHASE 1: Initial Compromise (before the capture — unknown time)
  - Attacker gains initial access to internal host
  - Likely via phishing or exploitation of a web application
  - Established persistence mechanism

PHASE 2: Reconnaissance (during capture — 09:47 UTC)
  - 10.0.2.5 begins automated DNS queries to 8.8.8.8
  - DNS TXT queries to c2track.net begin (C2 channel established)
  - Port scan detected: 203.0.113.100 probing 10.0.0.1:22
    (attacker mapping network / seeking new entry points)

PHASE 3: Internal Reconnaissance (09:47 – 10:00 UTC)
  - DNS query for passwd.internal.argustech.com to external resolver
    (attacker trying to enumerate internal hostnames)
  - HTTP GET to /admin/backup.zip (10.0.0.1)
    (attacker downloaded backup archive — possible credential material)

PHASE 4: Data Exfiltration (09:47 – 10:02 UTC, ongoing)
  - 10.0.1.10 → 203.0.113.50:443 [42.9 MB] — large sustained transfer
    (primary exfiltration channel via weak TLS to attacker server)
  - 10.0.2.5 → 198.18.0.77 — 261 POST requests to /api/v2/collect
    (secondary exfiltration / C2 beaconing)

PHASE 5: Command Execution (during capture)
  - 4× GET requests to /api/v2/cmds
    (attacker issuing commands to the implant)
  - DNS tunnelling continues throughout capture window
```

**Most critical event:** The 42.9 MB exfiltration to `203.0.113.50` — this represents confirmed data leaving the organisation.

---

### Question 9 Answer — Evidence Preservation and Chain of Custody

**Evidence to preserve:**

1. **Raw PCAP file** (`capture-2024-01-16-0947-1002.pcap`)
1. **Zeek log files** (conn.log, dns.log, http.log, ssl.log, files.log, notice.log)
1. **Firewall logs** (all events during the capture window ± 1 hour)
1. **DNS server logs** (queries from corporate DNS resolver)
1. **Memory dump** of the compromised host(s) (volatile evidence — collect first)
1. **Disk image** of the compromised host(s) (use write blocker)
1. **DHCP logs** (to correlate IPs with hostnames/MAC addresses)
1. **Authentication logs** (Active Directory / syslog)
1. **Endpoint logs** (EDR: process creation, network connections, file access)

**Chain of custody procedure:**

```text
Step 1: HASH EVERYTHING IMMEDIATELY
  sha256sum capture.pcap > capture.pcap.sha256
  sha256sum conn.log > conn.log.sha256
  [repeat for each file]

Step 2: DOCUMENT COLLECTION CONDITIONS
  - Who collected the evidence (name, role, employee ID)
  - Date and time of collection (UTC)
  - Where the evidence was collected from (hostname, IP, physical location)
  - What tool was used (tcpdump version, Zeek version)
  - Authorisation reference (Incident number, signed by CISO)

Step 3: COPY — NEVER WORK ON ORIGINALS
  - Store originals on write-protected media
  - Work only on verified copies
  - Verify copy hashes match originals

Step 4: ACCESS LOG
  - Record every person who accesses evidence
  - Record every analysis performed
  - Store access log alongside evidence

Step 5: STORAGE
  - Evidence drive: encrypted, access-controlled
  - Offsite backup of hashed copies
  - Lock physical media in a cabinet with key log

Step 6: LEGAL NOTIFICATION
  - If criminal prosecution is planned: involve law enforcement before further analysis
  - If regulatory (GDPR): DPA notification within 72 hours if personal data affected
```

**GDPR note:** If the exfiltrated data included personal data (employee records, customer data), GDPR Article 33 requires notification to the supervisory authority within 72 hours of becoming aware of the breach.
