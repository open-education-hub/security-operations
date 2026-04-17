# Guide 03: OSINT Tools and Techniques for Threat Intelligence

**Level:** Basic

**Estimated Time:** 40 minutes

**Goal:** Learn to use public OSINT tools for gathering threat intelligence about indicators and threat actors

---

## What is OSINT in the Security Context?

Open Source Intelligence (OSINT) in cybersecurity means collecting and analyzing publicly available information to:

* Investigate suspicious indicators (IPs, domains, file hashes)
* Research threat actors and their infrastructure
* Understand the current threat landscape
* Gather intelligence without active intrusion

**Key principle:** OSINT is passive.
You are observing and collecting public data, not actively testing or attacking systems.

---

## Fundamental OSINT Resources

### 1. VirusTotal

**What it is:** Multi-engine malware scanning and threat intelligence aggregator.

**Free capabilities:**

* Scan files (up to 32MB) against 70+ AV engines
* Look up file hashes, URLs, IPs, and domains
* View submission history and community comments
* See behavioral analysis from sandboxes
* Access "Relations" graph for pivoting

**URL:** https://www.virustotal.com

**Key things to check:**

* Detection rate (X/72 detections)
* First submission date (when was this first seen?)
* Community votes (up votes = confirmed malicious)
* Behavioral analysis (what does the malware do?)
* Relations tab (what other indicators are associated?)

**Searching by hash:**

```text
SHA256: paste the hash directly into search bar
        OR use URL: https://www.virustotal.com/gui/file/SHA256_HASH

SHA1:   https://www.virustotal.com/gui/file/SHA1_HASH
MD5:    https://www.virustotal.com/gui/file/MD5_HASH
```

**Searching by IP:**

```text
URL: https://www.virustotal.com/gui/ip-address/IP_ADDRESS
```

**Searching by domain:**

```text
URL: https://www.virustotal.com/gui/domain/DOMAIN_NAME
```

**What to do with results:**

* High detections (>10/72): Almost certainly malicious; block and investigate
* Low detections (1-5/72): Potentially malicious; investigate further
* 0 detections: Doesn't mean clean—new or evasive malware exists

---

### 2. Shodan

**What it is:** A search engine for internet-connected devices and services.

**Free capabilities:**

* Search for devices by IP, hostname, or keywords
* See open ports and services
* View banners and certificate information
* Geographic and organizational mapping

**URL:** https://www.shodan.io

**Useful searches:**

```text
# Find servers with specific banner content
"update-secure-cdn"

# Search for servers with specific SSL certificate CN
ssl:"update-secure-cdn.com"

# Search by IP
ip:198.51.100.5

# Find specific services in a country
country:DE port:4444

# Find Cobalt Strike servers (common C2)
product:"Cobalt Strike Beacon"

# Find servers with specific HTTP title
http.title:"Admin Panel" country:RU
```

**What OSINT hunters use Shodan for:**

* Identifying attacker infrastructure (C2 servers often have distinctive signatures)
* Pivoting from one C2 IP to find related servers
* Finding all servers with a specific certificate
* Discovering exposed internal services

**Important:** Never use Shodan to actively attack.
Only use it to research known-malicious infrastructure.

---

### 3. crt.sh (Certificate Transparency)

**What it is:** A public log of all SSL/TLS certificates issued, useful for discovering subdomains.

**URL:** https://crt.sh

**Usage:**

```text
Search: %.example.com   (% = wildcard)
```

This reveals:

* All subdomains that have ever had a TLS certificate
* Certificate issuers (Let's Encrypt = quick setup, common in phishing)
* Certificate dates (recently issued = possibly malicious)
* Certificate patterns (same issuer/organization across multiple malicious domains)

**Pivot technique:**
If you know one malicious domain, search for related certificates:

1. Find the malicious domain's certificate at crt.sh
1. Note the issuer and any common organizational fields
1. Search for other certificates with the same fields
1. You may find additional malicious infrastructure

---

### 4. URLScan.io

**What it is:** An online service that scans URLs, takes screenshots, and analyzes web content.

**URL:** https://urlscan.io

**Free capabilities:**

* Scan a URL (creates a public record)
* View historical scans
* See: screenshot, DOM content, HTTP headers, linked domains, IPs
* Redirect chains

**Usage for threat intelligence:**

* Investigate phishing sites without visiting them directly
* See what domains/IPs a suspicious URL loads from
* Find related domains from the same phishing kit

**Search examples:**

```text
# Search for pages containing specific text
page.title:"Login - SecureBank"

# Find pages loading from a specific domain
domain:update-secure-cdn.com

# Find pages submitted from a specific IP
ip:198.51.100.5

# Find pages with specific HTML content
page.body:"malware_c2_string"
```

---

### 5. WHOIS Lookup

**What it is:** Registration information for domain names.

**Free tools:**

* https://www.whois.com
* https://lookup.icann.org
* Command line: `whois domain.com`

**What to look for:**

* Registrar (GoDaddy, NameCheap, Porkbun - common in malicious domains)
* Registration date (very new = suspicious)
* Registrant information (often privacy-protected)
* Name servers (some bulletproof hosting has distinctive NS)
* Expiration date (short-term registrations = temporary infrastructure)

**WHOIS via command line:**

```console
whois suspicious-domain.com

# Key fields to examine:
# Registrar: (who registered it?)
# Created Date: (how old is it?)
# Updated Date: (recently modified?)
# Name Server: (what DNS service?)
# Registrant Organization: (who owns it, if not privacy-protected)
```

---

### 6. MITRE ATT&CK

**What it is:** The comprehensive knowledge base of adversary tactics, techniques, and procedures.

**URL:** https://attack.mitre.org

**For threat intelligence use:**

**Researching a threat actor:**

1. https://attack.mitre.org/groups/
1. Find the group (APT28, FIN7, Lazarus, etc.)
1. View their techniques, tools, and references

**Researching a technique:**

1. https://attack.mitre.org/techniques/enterprise/
1. Find the technique (T1059.001, T1003.001, etc.)
1. Read: Description, Sub-techniques, Procedure examples, Detection guidance, Data sources

**Looking up a malware family:**

1. https://attack.mitre.org/software/
1. Find malware by name (Cobalt Strike, Mimikatz, etc.)
1. See: Techniques it implements, Groups that use it, References

---

### 7. AlienVault OTX (Open Threat Exchange)

**What it is:** Community-driven threat intelligence platform with free API.

**URL:** https://otx.alienvault.com

**Free features:**

* Indicator reputation lookup (IP, domain, hash, URL)
* "Pulses" - community-created threat intelligence reports
* ATT&CK mapping
* Free API (register for key)

**Searching OTX:**

```python
# Install: pip install OTXv2
from OTXv2 import OTXv2, IndicatorTypes

# Free API key from otx.alienvault.com
otx = OTXv2("your-free-otx-api-key")

# Look up an IP
indicators = otx.get_indicator_details_full(
    IndicatorTypes.IPv4,
    "198.51.100.5"
)

# Look up a domain
domain_info = otx.get_indicator_details_full(
    IndicatorTypes.DOMAIN,
    "malicious-domain.example.com"
)

# Look up a file hash
file_info = otx.get_indicator_details_full(
    IndicatorTypes.FILE_HASH_SHA256,
    "sha256_hash_here"
)

# Get recent pulses related to a topic
pulses = otx.search_pulses("ransomware")
```

---

## OSINT Workflow for Indicator Investigation

When you receive a suspicious indicator, follow this process:

```text
Receive Indicator (IP/Domain/Hash/URL)
            │
            ▼
    Step 1: VirusTotal lookup
    - Detection rate?
    - First seen?
    - Behavioral analysis?
            │
            ▼
    Step 2: Context lookup
    - IP → Shodan (what services run on this IP?)
    - Domain → WHOIS (how old? who registered?)
    - Domain → crt.sh (what subdomains exist?)
    - URL → URLScan (what does the page look like?)
            │
            ▼
    Step 3: OTX / Community lookup
    - Has this been reported before?
    - What campaigns is it associated with?
    - Any related indicators?
            │
            ▼
    Step 4: ATT&CK mapping
    - If malware identified: find software page
    - What techniques does it use?
    - What groups use it?
            │
            ▼
    Step 5: Document findings
    - Import to MISP
    - Add context and TLP marking
    - Share with relevant stakeholders
```

---

## OSINT for Domain Investigation: Worked Example

Let's trace through investigating `update-secure-cdn[.]com`:

### Step 1: Initial Assessment

**WHOIS:**

```console
whois update-secure-cdn.com

# Results (fictional example):
# Registrar: NameCheap
# Created Date: 2024-02-20 (3 weeks ago - SUSPICIOUS)
# Registrant: PRIVACY PROTECTED
# Name Server: ns1.bulletproof-hosting.ru
#              ns2.bulletproof-hosting.ru
# (SUSPICIOUS: known bulletproof hosting NS)
```

**Assessment so far:** Very new domain, privacy-protected, bulletproof hosting nameservers.
High suspicion.

### Step 2: VirusTotal

Search for the domain at VirusTotal:

* Detection: 15/87 vendors flagging as malicious
* Community: 4 malicious votes
* First seen in VT: 2024-02-22 (2 days after registration)
* Resolutions: Points to IP 192.0.2.15

**Assessment:** Confirmed malicious by community intelligence.

### Step 3: Certificate Transparency

At crt.sh, search `%.update-secure-cdn.com`:

```text
Subdomains found:
- cdn.update-secure-cdn.com
- api.update-secure-cdn.com
- auth.update-secure-cdn.com

All certificates issued by Let's Encrypt, all within 1 day of domain registration.
```

**Assessment:** Rapid infrastructure setup suggests automated/organized attack.

### Step 4: URLScan

Search urlscan.io for `update-secure-cdn.com`:

* Page screenshot shows: Blank page (C2 server, not a phishing site)
* Loads no external resources
* No HTML content (just a C2 listening server)
* HTTP response: 403 Forbidden to browser requests

**Assessment:** C2 infrastructure (not phishing, but command-and-control).

### Step 5: Shodan

Search Shodan for the IP (192.0.2.15):

```text
Port 443: HTTPS, certificate issued to "update-secure-cdn.com"
Port 80: HTTP, redirect to 443
Port 50050: Open! (Cobalt Strike Team Server default port!)

ASN: AS12345 - Bulletproof Hosting Provider
Country: Netherlands
```

**Assessment:** This is almost certainly a Cobalt Strike C2 server.

### Step 6: Document and Share

Create a MISP event:

* Event Info: "Cobalt Strike C2 - update-secure-cdn.com"
* Tags: TLP:AMBER, MITRE T1071.001, kill-chain:command-and-control
* Add attributes: IP, domain, certificate hash
* Share with your ISAC community

---

## OSINT Operational Security

When conducting OSINT research, maintain operational security:

**Do:**

* Use a dedicated, isolated research machine or VM
* Research through a non-attributable network (VPN or Tor for sensitive research)
* Use browser profiles isolated from personal/work browsing
* Be aware that visiting malicious URLs can trigger downloads or tracking

**Don't:**

* Visit suspected malicious URLs directly without isolation
* Submit company files to VirusTotal (your hash is now public)
* Use work credentials or accounts for OSINT research
* Accidentally tip off the attacker (some C2 servers log who views them)

**Tool to safely investigate URLs:**

```console
# URLScan does the visiting for you - safe
# Or use AnyRun / Hybrid Analysis online sandboxes
# Or use Browserling for isolated browser sessions
```

---

## Building Your OSINT Toolkit

Bookmark and register for these free services:

| Tool | URL | Register? | API? |
|------|-----|-----------|------|
| VirusTotal | virustotal.com | Yes | Yes (free) |
| Shodan | shodan.io | Yes | Yes (free, limited) |
| crt.sh | crt.sh | No | Yes |
| URLScan | urlscan.io | Yes | Yes |
| OTX | otx.alienvault.com | Yes | Yes (free) |
| MITRE ATT&CK | attack.mitre.org | No | Yes (STIX) |
| Abuse.ch URLhaus | urlhaus.abuse.ch | No | Yes |
| MalwareBazaar | bazaar.abuse.ch | No | Yes |
| AnyRun | any.run | Yes | Yes (free, limited) |

---

## Summary

You have learned to:

1. Use VirusTotal for multi-engine indicator reputation lookup
1. Use Shodan to identify attacker infrastructure
1. Use Certificate Transparency (crt.sh) to discover infrastructure
1. Use URLScan for safe URL investigation
1. Use WHOIS for domain registration intelligence
1. Use OTX for community threat intelligence
1. Apply a systematic workflow for indicator investigation
1. Maintain operational security during OSINT research

**Key takeaways:**

* No single tool tells the complete story—use multiple sources
* Context (age, registration, hosting, community reports) is as important as detections
* Always document your findings with sources and confidence levels
* Import findings into MISP to preserve and share intelligence
* OSINT is the foundation of all threat intelligence work

---

*Next: Guide 04 (Intermediate) - Conducting a Hypothesis-Driven Hunt*
