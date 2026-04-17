# Session 02: Network Infrastructure and Security Monitoring Tools

**Estimated reading time:** 2 hours

**Level:** Beginner

**Prerequisites:** Basic understanding of what a computer network is; completion of Session 01

---

## Table of Contents

1. [Network Topology Fundamentals](#1-network-topology-fundamentals)
1. [Key Network Components](#2-key-network-components)
1. [The TCP/IP Stack and Key Protocols](#3-the-tcpip-stack-and-key-protocols)
1. [Introduction to Network Security Monitoring Tools](#4-introduction-to-network-security-monitoring-tools)
1. [Monitoring Approaches: Flow-Based vs. Packet-Based](#5-monitoring-approaches-flow-based-vs-packet-based)
1. [Collecting Network Traffic: TAPs and SPAN Ports](#6-collecting-network-traffic-taps-and-span-ports)
1. [Log Formats: Syslog, NetFlow, and PCAP](#7-log-formats-syslog-netflow-and-pcap)
1. [Legal Considerations for Packet Capture](#8-legal-considerations-for-packet-capture)
1. [Putting It All Together: The NSM Cycle](#9-putting-it-all-together-the-nsm-cycle)
1. [References and Further Reading](#10-references-and-further-reading)

---

## 1. Network Topology Fundamentals

Before you can monitor a network for threats, you must understand its layout — what devices exist, how they are connected, and which zones serve which purposes.
Network architects group devices into **zones** based on trust level and function.
Understanding these zones is the first step toward deciding *where* to place monitoring sensors.

### 1.1 Local Area Network (LAN)

A **Local Area Network (LAN)** is a collection of devices connected within a single physical location — an office floor, a building, or a campus.
LANs are usually administered by a single organisation, connected via Ethernet switches, and protected by a perimeter firewall from the wider internet.

Key characteristics:

* High bandwidth, low latency (typically 1 Gbps–10 Gbps links)
* Devices trust each other more than external systems
* Flat LANs (no segmentation) are a significant security risk: one compromised host can reach all others

**Security implication:** Because internal traffic is often trusted and not inspected closely, lateral movement after a breach can go undetected for months.
East-west monitoring (internal traffic between hosts) is as important as north-south monitoring (traffic crossing the perimeter).

### 1.2 Wide Area Network (WAN)

A **Wide Area Network (WAN)** connects geographically distributed sites — e.g., a company's headquarters to its branch offices or cloud providers.
WAN links are typically leased from telecommunications carriers (MPLS, SD-WAN) or traverse the public internet using encrypted tunnels.

From a monitoring perspective, WAN links are:

* Narrower than internal links (bandwidth is expensive)
* Potentially traversed by both legitimate and malicious traffic
* A good place to capture traffic entering or leaving the organisation

### 1.3 Demilitarised Zone (DMZ)

The **DMZ** is a network segment that sits between the internet and the internal LAN.
It hosts services that must be accessible from the internet — web servers, email gateways, DNS resolvers, and VPN concentrators — while limiting their access to the internal network.

```text
Internet ──── [Firewall Outer] ──── DMZ ──── [Firewall Inner] ──── LAN
```

The DMZ is one of the highest-value monitoring locations because:

* Servers here are directly exposed to the internet and are frequent attack targets
* Attackers who compromise a DMZ host will attempt to pivot inward
* Detecting unusual outbound connections from DMZ servers is a critical detection opportunity

### 1.4 Virtual Private Network (VPN)

A **VPN** encrypts traffic between two endpoints over an untrusted network.
Organisations use VPNs for:

* **Remote access VPN:** Employees connecting from home to corporate resources
* **Site-to-site VPN:** Linking branch offices to headquarters over the internet

From a monitoring perspective, VPN traffic presents a challenge: the payload is encrypted before entering your network.
Monitoring must occur either:

1. At the VPN concentrator's internal interface (after decryption), or
1. Using metadata and flow records that do not require payload inspection

### 1.5 Network Segmentation and VLANs

Modern networks use **VLANs (Virtual Local Area Networks)** to logically segment traffic on shared physical infrastructure.
For example:

* VLAN 10: Finance department
* VLAN 20: Engineering department
* VLAN 30: Guest Wi-Fi

Traffic between VLANs must pass through a Layer 3 device (router or multilayer switch), providing a natural chokepoint for monitoring.
A well-segmented network gives you:

* **Containment:** A breach in the Guest VLAN cannot directly reach Finance
* **Monitoring clarity:** Unexpected inter-VLAN traffic stands out as anomalous

### 1.6 Management Network

A **Management Network** (also called an Out-of-Band management network) is a dedicated network used exclusively for administering network devices — configuring routers, accessing console ports, running SNMP.
It is kept separate from production traffic to:

* Prevent attackers from using production traffic paths to compromise infrastructure
* Ensure management access even during an attack or outage
* Limit who can reach management interfaces

---

## 2. Key Network Components

Understanding the function of each component helps you determine what data it can provide for monitoring, and what its failure or compromise would mean.

### 2.1 Routers

A **router** operates at Layer 3 (Network layer) of the OSI model and forwards packets between different networks based on IP addresses.
Routers maintain routing tables and make forwarding decisions for each packet.

**Security relevance:**

* Routers can generate **NetFlow** records — summaries of who talked to whom, for how long, and how much data was transferred
* Routers can filter traffic using Access Control Lists (ACLs) — basic packet filtering
* Compromised routers can silently redirect traffic (a technique used in BGP hijacking attacks)

### 2.2 Switches

A **switch** operates at Layer 2 (Data link layer) and forwards frames between hosts on the same LAN segment, using MAC addresses.
Modern switches are "smart" — they maintain a MAC address table and send frames only to the correct port.

**Security relevance:**

* Switches can be configured with **SPAN (Switched Port ANalyzer)** ports to copy traffic for monitoring (see Section 6)
* **ARP poisoning** attacks exploit switches to redirect traffic
* Unmanaged or misconfigured switches are invisible to network management, making monitoring difficult

### 2.3 Firewalls

A **firewall** enforces access control policies between network zones.
It can operate at different layers:

| Type | Layer | What it inspects |
|------|-------|-----------------|
| Packet filter | L3/L4 | IP addresses, ports, protocol |
| Stateful firewall | L4 | Connection state (TCP handshake) |
| Application-layer firewall (WAF) | L7 | HTTP methods, URLs, payloads |
| Next-Generation Firewall (NGFW) | L3–L7 | All of the above + user identity, TLS inspection |

**Security relevance:** Firewall logs are a primary data source for Security Operations.
They show:

* Blocked connection attempts (potential reconnaissance or attack)
* Allowed connections (what traffic your policy permits)
* Policy violations (traffic that shouldn't exist)

### 2.4 Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)

An **IDS** passively monitors network traffic and generates alerts when it detects patterns matching known attacks or policy violations.
An **IPS** does the same but can also actively block malicious traffic.

| Feature | IDS | IPS |
|---------|-----|-----|
| Traffic inspection | Yes | Yes |
| Alert generation | Yes | Yes |
| Blocking capability | No | Yes |
| Deployment mode | Out-of-band (passive) | Inline (active) |
| Risk if it fails | Misses threats | Can block legitimate traffic |

**Key distinction from firewalls:**

* A firewall enforces a policy based on source/destination/port
* An IDS/IPS looks at the *content* of packets for attack patterns (signatures) or abnormal behavior (anomaly detection)

### 2.5 Proxies and Load Balancers

A **proxy** sits between clients and servers, forwarding requests on the client's behalf.
Security proxies (e.g., Squid, Zscaler) can:

* Inspect HTTP/HTTPS traffic (with TLS interception)
* Block access to malicious URLs
* Log all web requests for auditing

A **load balancer** distributes traffic across multiple servers for availability and performance.
From a monitoring standpoint, load balancers can:

* Terminate TLS connections, making inspection easier
* Log connection metadata

---

## 3. The TCP/IP Stack and Key Protocols

Network monitoring tools capture and analyse packets.
To make sense of what you see, you must understand the protocols those packets implement.

### 3.1 The TCP/IP Model

The TCP/IP model (also called the Internet model) describes networking in four layers:

```text
┌─────────────────────────────────┐
│  Application Layer              │  HTTP, DNS, SMTP, SSH, FTP
├─────────────────────────────────┤
│  Transport Layer                │  TCP, UDP
├─────────────────────────────────┤
│  Internet Layer                 │  IP, ICMP, ARP
├─────────────────────────────────┤
│  Network Access (Link) Layer    │  Ethernet, Wi-Fi
└─────────────────────────────────┘
```

Each layer adds a **header** that wraps the data from the layer above — a process called **encapsulation**.
When you capture a packet, you see all these headers stacked together.

Example: An HTTP request to a web server is encapsulated as:

```text
[Ethernet Frame]
  └─ [IP Packet]
       └─ [TCP Segment]
            └─ [HTTP Request]
```

### 3.2 IP (Internet Protocol)

IP provides logical addressing and routing.
Key fields for security analysts:

* **Source IP / Destination IP:** Who is talking to whom
* **TTL (Time to Live):** How many hops remain before the packet is discarded. An unusually low TTL may indicate the packet has travelled a long path (or someone is manipulating it)
* **Protocol:** What transport protocol is used (6=TCP, 17=UDP, 1=ICMP)
* **Flags:** Fragmentation flags — unusual fragmentation can indicate evasion attempts

### 3.3 TCP (Transmission Control Protocol)

TCP provides reliable, ordered, connection-oriented communication.
It uses a **three-way handshake** before data transfer:

```text
Client          Server
  |──── SYN ────►|
  |◄── SYN-ACK ──|
  |──── ACK ────►|
  |─── DATA ────►|
  |◄── DATA ─────|
  |──── FIN ────►|
  |◄── FIN-ACK ──|
```

**Security-relevant TCP flags:**

| Flag | Meaning | Attack relevance |
|------|---------|-----------------|
| SYN | Initiate connection | SYN floods |
| RST | Reset connection | Port scanning (RST means port closed) |
| FIN | Close connection | FIN scans to evade detection |
| URG | Urgent data | Sometimes used in evasion |
| PSH | Push data to application | |
| ACK | Acknowledge receipt | |

A **SYN scan** (used by Nmap) sends SYN packets and observes responses without completing the handshake.
Many IDS signatures detect large volumes of SYN packets to many ports as a port scan.

### 3.4 UDP (User Datagram Protocol)

UDP is connectionless and does not guarantee delivery.
It is used where speed matters more than reliability:

* DNS queries (UDP/53)
* DHCP (UDP/67,68)
* VoIP (RTP over UDP)
* Some tunnelling protocols

**Security relevance:** UDP is used in many amplification DDoS attacks (DNS amplification, NTP amplification) where small queries elicit large responses.

### 3.5 DNS (Domain Name System) — Port 53

DNS translates human-readable domain names (e.g., `example.com`) into IP addresses.
Nearly every internet-bound connection starts with a DNS query.

**Why DNS matters for security monitoring:**

* **DNS is ubiquitous and rarely blocked** — attackers use it for C2 (Command and Control) communication via DNS tunnelling
* **Newly registered or rarely seen domains** often indicate malicious activity
* **High-volume DNS queries** to a single domain may indicate DGA (Domain Generation Algorithm) malware
* **Unexpected DNS servers** (not your corporate resolvers) may indicate DNS hijacking
* **NXDOMAIN responses** in high volume suggest C2 beaconing to non-existent domains

Key DNS record types to know:

* `A` — IPv4 address for a domain
* `AAAA` — IPv6 address
* `MX` — Mail server for a domain
* `TXT` — Text records (used in SPF, DKIM, DMARC for email security)
* `PTR` — Reverse lookup (IP → domain)

### 3.6 HTTP and HTTPS — Ports 80 and 443

HTTP is the foundation of the web.
HTTPS is HTTP over TLS (Transport Layer Security).

**Key HTTP fields for security analysts:**

| Field | Security relevance |
|-------|-------------------|
| Method (GET/POST/PUT) | POST to unusual endpoints may indicate data exfiltration |
| URI/URL | Paths with `../` may indicate path traversal; long query strings may indicate SQLi |
| User-Agent | Unusual or missing User-Agent strings may indicate automated tools or malware |
| Host header | Virtual host routing; used in request smuggling attacks |
| Referer | Shows which page linked to this request |
| X-Forwarded-For | Original client IP when traffic passes through a proxy |
| Response codes | 401/403 may indicate brute force; 500 may indicate injection attempts |

**HTTPS challenge:** TLS encryption protects confidentiality but hides content from inspection.
Modern monitoring strategies use:

1. **TLS metadata** (certificate subject, JA3/JA3S fingerprints) — still visible even in encrypted traffic
1. **TLS inspection/interception** at a proxy (requires certificate authority deployment)
1. **Behavioural analysis** of encrypted traffic patterns (duration, volume, timing)

### 3.7 FTP (File Transfer Protocol) — Ports 20/21

FTP transfers files in cleartext, including credentials.
It uses two channels:

* **Control channel (port 21):** Commands and responses
* **Data channel (port 20 or ephemeral):** Actual file data

**Security relevance:** FTP transmits passwords in plaintext.
Monitoring FTP traffic can capture credentials.
Most organisations replace FTP with SFTP (SSH-based) or FTPS (FTP over TLS), but legacy FTP use persists.
Detecting FTP on internal networks is often a finding in security audits.

### 3.8 SSH (Secure Shell) — Port 22

SSH provides encrypted terminal access and file transfer (SCP, SFTP).
It replaced Telnet and rlogin.

**Security relevance:**

* SSH brute-force attacks are extremely common — logs will show thousands of failed authentication attempts from internet hosts
* **Port forwarding** via SSH can create covert tunnels that bypass firewalls
* Attackers who gain a foothold may use SSH for lateral movement
* Watch for SSH connections from unexpected sources or to unusual ports

### 3.9 SMTP (Simple Mail Transfer Protocol) — Port 25/587

SMTP delivers email between mail servers.
Submissions from mail clients use port 587 (with authentication).

**Security relevance:**

* Phishing and malware distribution occur via email
* **Open relays** (SMTP servers that relay mail from anyone) are exploited by spammers
* Detecting large volumes of outbound SMTP may indicate a compromised host sending spam
* SMTP authentication failures suggest brute-force or credential stuffing attacks
* Email headers (`Received:`, `X-Originating-IP:`) can trace the path of a message

### 3.10 ARP (Address Resolution Protocol)

ARP maps IP addresses to MAC addresses on a LAN.
It operates at Layer 2 and has no authentication.

**ARP Poisoning / ARP Spoofing:**
An attacker sends forged ARP replies, associating their MAC address with the IP of a legitimate host (such as the default gateway).
This causes traffic intended for that host to flow through the attacker instead — a **man-in-the-middle (MitM)** attack.

Detection: Look for multiple ARP replies claiming the same IP address, or for an IP address changing its MAC address unexpectedly.

---

## 4. Introduction to Network Security Monitoring Tools

**Network Security Monitoring (NSM)** is the practice of collecting and analysing network data to detect and respond to threats.
This section introduces the primary tools used in this session.

### 4.1 Wireshark

**Wireshark** is the most widely used network protocol analyser.
It captures packets in real time or reads saved PCAP files and provides a graphical interface for deep packet inspection.

**Key features:**

* Deep dissection of hundreds of protocols
* Display filters to isolate traffic of interest (e.g., `http.response.code == 404`)
* Follow TCP/UDP streams to reconstruct conversations
* Statistics tools: protocol hierarchy, conversations, I/O graphs, expert info
* Export objects (extract files transferred over HTTP, SMB, etc.)

**When to use Wireshark:**

* Investigating a specific suspicious connection in detail
* Reconstructing an attack after the fact from a PCAP file
* Understanding how a protocol works
* Forensic analysis of captured traffic

**Limitations:**

* Not suitable for high-volume network monitoring (not designed to handle 10 Gbps+ continuously)
* Single analyst tool — not built for team correlation or alerting
* Large PCAP files are slow to navigate

**Install (Docker — see Demo 01):**

```console
docker run --rm -it --net=host linuxserver/wireshark
```

### 4.2 Zeek (formerly Bro)

**Zeek** is a network analysis framework designed for high-throughput, long-term network monitoring.
Unlike Wireshark, Zeek does not provide a GUI — it parses network traffic and generates structured log files suitable for ingestion into a SIEM or analysis with command-line tools.

**Key features:**

* Generates rich per-protocol logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `notice.log`, and many more
* Highly extensible via scripts (the Zeek scripting language)
* Supports custom protocol dissectors
* Designed to run on high-speed networks (10 Gbps+)

**Example Zeek log entry (conn.log):**

```text
ts          uid         id.orig_h    id.orig_p  id.resp_h    id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1693000000  CaBcDe12345 192.168.1.5  54321      93.184.216.34 443       tcp    ssl      1.234     1024        8192        SF
```

**When to use Zeek:**

* Continuous network monitoring at the perimeter or key internal chokepoints
* Generating logs for a SIEM
* Detecting anomalies in protocol behaviour
* File extraction and hash recording

**Comparison with Wireshark:**

| Feature | Wireshark | Zeek |
|---------|-----------|------|
| Interface | GUI | Command line / logs |
| Use case | Deep packet inspection | Long-term monitoring |
| Output | PCAP, decoded packets | Structured log files |
| Throughput | Limited | High (10+ Gbps) |
| Learning curve | Low | Medium-High |
| Alerting | No | Yes (via notices) |

### 4.3 Snort

**Snort** is the most widely deployed open-source Intrusion Detection and Prevention System (IDS/IPS).
It uses a rule-based signature detection engine to identify known attack patterns.

**Architecture:**

1. **Packet decoder** — parses packet headers
1. **Preprocessors** — normalise protocols, reassemble streams, detect anomalies
1. **Detection engine** — matches packets against rules
1. **Output plugins** — write alerts to files, syslog, databases

**A Snort rule has two parts:**

```text
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; \
  threshold: type threshold, track by_src, count 5, seconds 60; \
  sid:1000001; rev:1;)
```

* **Rule header:** `alert tcp any any -> $HOME_NET 22` — action, protocol, source, destination
* **Rule options:** `msg`, `threshold`, `sid`, `rev` — metadata and detection logic

**When to use Snort:**

* Detecting known attack signatures in real time
* Blocking attacks in inline (IPS) mode
* Protecting specific network segments

### 4.4 Suricata

**Suricata** is a modern, multi-threaded IDS/IPS/NSM engine.
It is largely compatible with Snort rules but offers additional features:

* **Multi-threading:** Utilises multiple CPU cores, supporting 10–40 Gbps+
* **Protocol identification:** Identifies protocols independent of port number (e.g., detects HTTP on port 8080)
* **File extraction:** Can extract and hash files transferred over HTTP, FTP, SMTP
* **Lua scripting:** Complex detection logic
* **EVE JSON output:** Structured JSON logs suitable for SIEM ingestion
* **TLS/SSL logging:** Logs certificate details without full decryption

Suricata is increasingly preferred over Snort in modern deployments due to its performance and output quality.

### 4.5 tcpdump

**tcpdump** is a command-line packet capture tool.
It is available on virtually every Unix/Linux system and is often the first tool available during incident response.

**Common tcpdump commands:**

```bash
# Capture all traffic on eth0
tcpdump -i eth0

# Capture traffic to/from a specific host
tcpdump -i eth0 host 192.168.1.100

# Capture traffic on port 80
tcpdump -i eth0 port 80

# Write to a PCAP file for later analysis
tcpdump -i eth0 -w capture.pcap

# Read from a PCAP file
tcpdump -r capture.pcap

# Verbose output showing all headers
tcpdump -i eth0 -v -X
```

**BPF (Berkeley Packet Filter):** tcpdump uses BPF syntax for filtering.
Key operators:

* `host 1.2.3.4` — traffic to or from an IP
* `port 443` — traffic on port 443
* `net 192.168.0.0/24` — traffic to or from a subnet
* `src` / `dst` — source or destination qualifiers
* `and`, `or`, `not` — Boolean operators

### 4.6 NetworkMiner

**NetworkMiner** is a Windows-based network forensic analyser focused on passively reconstructing sessions and extracting artefacts from PCAP files:

* Reconstructs files transferred over HTTP, SMB, FTP
* Extracts credentials sent in cleartext
* Identifies hosts and their operating systems via passive OS fingerprinting
* Reconstructs email messages (SMTP, POP3, IMAP)

NetworkMiner is particularly useful during incident response for quickly identifying what was transferred over the network.

---

## 5. Monitoring Approaches: Flow-Based vs. Packet-Based

There are two fundamental approaches to network monitoring.
Understanding the trade-offs is essential for designing a monitoring strategy.

### 5.1 Packet-Based Monitoring (Full Packet Capture)

**Full packet capture (FPC)** records every byte of every packet traversing a network link.
The captured data is stored in PCAP files.

**Advantages:**

* Maximum forensic fidelity — you can reconstruct exactly what happened
* Supports deep protocol analysis and file extraction
* Can be replayed through IDS engines at a later time

**Disadvantages:**

* Extremely high storage requirements — a 1 Gbps link generates ~450 GB/hour of data
* Privacy concerns — captures payload data including passwords, documents, emails
* Requires significant processing power to capture at wire speed
* Not practical for very high-speed links (100 Gbps+)

**Use cases:**

* DMZ or critical server segments where traffic volume is manageable
* Forensic investigation after an incident
* Short-duration captures for troubleshooting

### 5.2 Flow-Based Monitoring

**Network flows** are summaries of network conversations.
Instead of capturing every byte, a flow record captures metadata: who talked to whom, which protocol, how many bytes, when and for how long.

**NetFlow** (Cisco) is the dominant flow standard.
A NetFlow record contains:

* Source and destination IP addresses
* Source and destination ports
* Protocol
* Number of packets and bytes
* Start and end timestamps
* TCP flags

**IPFIX** (IP Flow Information Export) is the IETF standard based on NetFlow v9.

**sFlow** is a sampling-based alternative (samples 1 in N packets rather than recording all flows).

**Advantages:**

* Vastly reduced storage requirements (~1000x smaller than FPC)
* Can scale to very high-speed links
* Sufficient for detecting many attack types (beaconing, DDoS, lateral movement)
* No payload capture — reduces privacy concerns

**Disadvantages:**

* No payload — cannot reconstruct transferred files
* Cannot detect payload-based attacks without an additional IDS
* Sampling (in sFlow) may miss low-volume attacks

**Comparison summary:**

| Aspect | Full Packet Capture | Flow-Based |
|--------|--------------------|--------------------|
| Storage per 1 Gbps | ~450 GB/hr | ~1–10 MB/hr |
| Forensic fidelity | High | Low–Medium |
| Payload inspection | Yes | No |
| Attack detection | Full | Limited to metadata |
| Privacy risk | High | Low |
| Typical retention | Days to weeks | Months to years |

### 5.3 Hybrid Approach

Most mature security operations centres use a hybrid approach:

* **Flow records** everywhere for baseline visibility and anomaly detection
* **Full packet capture** at critical chokepoints (DMZ, data centre access) with shorter retention
* **IDS/IPS** inline or out-of-band for signature-based detection
* **Protocol logs** (from Zeek) as a middle ground — structured data without full payload

---

## 6. Collecting Network Traffic: TAPs and SPAN Ports

Before you can analyse network traffic, you must be able to *see* it.
There are two primary methods for obtaining a copy of traffic for monitoring tools.

### 6.1 Network TAPs

A **Network TAP (Test Access Point)** is a hardware device inserted into a network link that creates a passive copy of all traffic passing through it.

```text
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Router  ├────┤  TAP     ├────┤ Firewall │
└──────────┘    └────┬─────┘    └──────────┘
                     │
                     ▼
               ┌──────────┐
               │ Sensor   │
               │(Zeek/IDS)│
               └──────────┘
```

**Advantages of TAPs:**

* **Passive and transparent** — the TAP does not introduce latency or become a single point of failure
* **Captures everything** — including errors and malformed frames that switches may drop
* **Cannot be detected or bypassed** by attackers on the monitored link
* Works with full-duplex links (separate TX and RX streams can be merged)

**Types of TAPs:**

* **Passive optical TAP:** Uses a prism to split fibre optic signals — no power required, zero latency
* **Active TAP:** Required for copper (Ethernet) links; requires power but has failsafe bypass
* **Aggregating TAP:** Merges full-duplex traffic onto a single monitoring port

**Disadvantage:** Requires physical installation and cannot be reconfigured remotely.

### 6.2 SPAN Ports (Port Mirroring)

A **SPAN (Switched Port ANalyzer) port**, also called a mirror port, is a software feature on a managed switch that copies traffic from one or more ports (or VLANs) to a designated monitoring port.

```text
Switch
┌──────────────────────────────┐
│  Port 1 ─── Workstation A   │
│  Port 2 ─── Workstation B   │  ← Traffic from Port 1 & 2
│  Port 3 ─── Server          │    mirrored to Port 24
│  ...                         │
│  Port 24 ─── Sensor (IDS)   │
└──────────────────────────────┘
```

**Advantages of SPAN:**

* No hardware cost — uses existing switch infrastructure
* Remotely configurable
* Can mirror specific VLANs or ports

**Limitations of SPAN:**

* **Oversubscription:** If the combined mirrored traffic exceeds the SPAN port bandwidth, packets are dropped silently
* **CPU overhead:** On some switches, SPAN sessions consume switch CPU
* **Drops errors:** Most switches drop malformed frames before mirroring
* **Limited sessions:** Switches typically support only 2–4 concurrent SPAN sessions
* **Detectable by attackers** who compromise the switch

### 6.3 RSPAN and ERSPAN

* **RSPAN (Remote SPAN):** Allows traffic mirroring across multiple switches in a network (between switches)
* **ERSPAN (Encapsulated RSPAN):** Encapsulates mirrored traffic in GRE tunnels, enabling monitoring of traffic from remote sites

### 6.4 Choosing Between TAPs and SPAN

| Consideration | TAP | SPAN |
|--------------|-----|------|
| Cost | Higher (hardware) | Lower (free on managed switches) |
| Reliability | Highest | Good |
| Traffic fidelity | All frames including errors | Drops errors; may drop under load |
| Flexibility | Fixed (physical) | Configurable remotely |
| Recommended for | Critical links, forensic use | Internal monitoring, lab use |

**Best practice:** Use physical TAPs on links that carry critical or high-volume traffic (internet uplinks, data centre interconnects).
Use SPAN ports for internal segments and development/lab environments.

---

## 7. Log Formats: Syslog, NetFlow, and PCAP

Effective monitoring requires understanding the format of the data you are collecting and how to process it.

### 7.1 Syslog

**Syslog** (RFC 5424) is the standard logging protocol for network devices, servers, and security appliances.
A syslog message contains:

* **Facility:** Category of the source (e.g., `kern` for kernel, `auth` for authentication, `daemon` for daemons)
* **Severity:** 0 (Emergency) to 7 (Debug)
* **Timestamp**
* **Hostname / Source**
* **Message body**

**Example syslog message (firewall block):**

```text
<134>Jan 15 14:23:45 fw-01 kernel: [BLOCKED] IN=eth0 OUT=eth1 \
  SRC=203.0.113.50 DST=192.168.10.5 PROTO=TCP SPT=54321 DPT=22 \
  FLAGS=SYN
```

The `<134>` is the Priority value: `134 = Facility(16) * 8 + Severity(6)`.
Facility 16 = local use 0; Severity 6 = Informational.

**Syslog severity levels:**

| Level | Value | Description |
|-------|-------|-------------|
| Emergency | 0 | System is unusable |
| Alert | 1 | Action must be taken immediately |
| Critical | 2 | Critical condition |
| Error | 3 | Error condition |
| Warning | 4 | Warning condition |
| Notice | 5 | Normal but significant |
| Informational | 6 | Informational message |
| Debug | 7 | Debug-level message |

**Syslog transport:**

* **UDP/514** — Traditional, unreliable (messages can be lost)
* **TCP/514** — Reliable delivery
* **TCP/6514 (TLS)** — Encrypted and authenticated (recommended)

**CEF (Common Event Format):** An extension to syslog used by many security products (ArcSight, etc.):

```text
CEF:0|Cisco|ASA|9.14|106023|Deny TCP|5|src=203.0.113.50 spt=54321 \
  dst=192.168.10.5 dpt=22 proto=TCP
```

### 7.2 NetFlow

**NetFlow** was developed by Cisco and is now an industry standard.
A flow collector (e.g., ntopng, NFDUMP, Elastic) receives flow records exported by routers and switches.

**NetFlow v5 record fields:**

```text
srcaddr  - Source IP address
dstaddr  - Destination IP address
nexthop  - Next hop router
input    - SNMP input interface
output   - SNMP output interface
dpkts    - Packets in the flow
doctets  - Bytes in the flow
first    - SysUptime at start of flow
last     - SysUptime at end of flow
srcport  - Source port
dstport  - Destination port
tcp_flags - TCP flags (union of all)
prot     - IP Protocol (6=TCP, 17=UDP)
tos      - Type of Service
src_as   - Source Autonomous System
dst_as   - Destination Autonomous System
```

**NetFlow v9 / IPFIX** are template-based, allowing custom fields.

**Analysing NetFlow with nfdump:**

```console
# Show top 10 talkers
nfdump -r /var/flow/nfcapd.current -s srcip/bytes -n 10

# Show all flows to port 443
nfdump -r /var/flow/nfcapd.current "dst port 443"

# Show flows larger than 100MB
nfdump -r /var/flow/nfcapd.current "bytes > 100000000"
```

### 7.3 PCAP (Packet Capture)

**PCAP** (libpcap format) is the standard file format for storing captured packets.
The file contains:

* A global header (magic number, timestamps precision, link layer type)
* A sequence of packet records (each with a timestamp, captured length, original length, and raw bytes)

**Tools that read/write PCAP:**

* Wireshark / tshark
* tcpdump
* Zeek
* Snort / Suricata
* NetworkMiner

**PcapNG** (PCAP Next Generation) is the modern format that supports:

* Multiple network interfaces in a single file
* Packet comments and annotations
* Better timestamp precision
* Packet loss counters

**Working with PCAP files:**

```console
# Extract HTTP traffic from a PCAP
tshark -r capture.pcap -Y "http" -w http_only.pcap

# Extract all URIs from HTTP traffic
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.uri

# Convert PCAP to text
tcpdump -r capture.pcap -A -n

# Get statistics from a PCAP
capinfos capture.pcap
```

### 7.4 Structured Logging: JSON and ECS

Modern monitoring platforms prefer structured log formats. **Elastic Common Schema (ECS)** is a standardised field naming convention for log data:

```json
{
  "@timestamp": "2024-01-15T14:23:45.000Z",
  "event.action": "network-connection-blocked",
  "source.ip": "203.0.113.50",
  "source.port": 54321,
  "destination.ip": "192.168.10.5",
  "destination.port": 22,
  "network.protocol": "tcp",
  "rule.name": "Block inbound SSH"
}
```

Suricata's EVE JSON output and Zeek's JSON log format both support ECS-compatible output.

---

## 8. Legal Considerations for Packet Capture

Packet capture is a powerful investigative technique, but it must be conducted within legal and ethical boundaries.

### 8.1 Why Legal Considerations Matter

Packet capture records the content of communications — including private messages, passwords, and personal data.
Depending on jurisdiction and context, capturing this data without authorisation can constitute:

* A criminal offence (wiretapping laws)
* A civil liability (privacy torts)
* A violation of employment law or labour regulations
* A breach of contract with employees or customers

### 8.2 Authorisation and Consent

**In a corporate environment:**

* **Acceptable Use Policies (AUPs)** inform employees that network monitoring may occur. Signed AUPs typically provide implied consent for monitoring corporate network traffic.
* **Written authorisation** from senior management (CISO, Legal, HR) should be obtained before conducting an investigation.
* Monitoring should be proportionate and limited to what is necessary for the stated purpose.

**Legal principle:** Just because you *can* capture traffic does not mean you *should*.
Capture the minimum data necessary for the investigation.

**In a service provider environment:** Telecommunications operators face additional legal obligations around interception (e.g., CALEA in the US, Lawful Intercept standards in the EU).

### 8.3 GDPR Considerations (EU)

The **General Data Protection Regulation (GDPR)** treats IP addresses and network metadata as personal data when they can be linked to identifiable individuals.

Key GDPR implications for network monitoring:

| GDPR Principle | Monitoring Implication |
|---------------|------------------------|
| Lawfulness, fairness, transparency | Must have a legal basis (legitimate interest, contract, legal obligation). Employees must be informed. |
| Purpose limitation | Traffic captured for security purposes should not be repurposed for performance management |
| Data minimisation | Do not capture more than necessary. Prefer flow data over full packet capture when sufficient. |
| Storage limitation | Define and enforce retention periods. Raw PCAPs should not be kept indefinitely. |
| Data subject rights | Employees may request access to or deletion of their personal data |
| Data breach notification | If captured traffic is accessed without authorisation, this is itself a data breach |

**Article 6 legal bases applicable to monitoring:**

* **Legitimate interests (Article 6(1)(f))** — protecting the organisation's network and assets is a legitimate interest, provided it does not override employee rights
* **Legal obligation (Article 6(1)(c))** — certain sectors (financial, healthcare) have legal obligations to monitor for fraud or data breaches

### 8.4 Chain of Custody for Digital Evidence

If packet captures may be used as evidence in legal proceedings (e.g., prosecution of an insider threat), strict **chain of custody** procedures must be followed:

1. **Document everything:** Record when capture started/stopped, who authorised it, which interface was used, what tool was used, where files were stored
1. **Preserve integrity:** Calculate and record cryptographic hashes (MD5, SHA-256) of PCAP files immediately after capture
1. **Access control:** Limit who can access raw evidence files; log all access
1. **Write protection:** Use write blockers when duplicating evidence; never work on original copies
1. **Storage:** Store evidence on dedicated, secured media with documented access logs
1. **Continuity:** Maintain an unbroken record of who had possession of evidence from collection to court

**Example chain of custody record:**

```text
Evidence Item: network_capture_2024-01-15.pcap
Collection date: 2024-01-15 14:30 UTC
Collected by: J. Smith (Senior Analyst)
Authorisation: Incident #2024-0042, approved by CISO
Interface captured: eth2 (internet uplink)
Duration: 14:00–14:30 UTC
SHA-256: a3b4c5d6e7f8... [full hash]
Storage: Evidence drive E:\cases\2024-0042\ (write-protected)
Access log: See E:\cases\2024-0042\access.log
```

### 8.5 Practical Guidelines

* **Always operate under written authorisation**
* **Inform your legal team** before conducting investigations that may involve employee monitoring
* **Use the minimum capture needed** — apply BPF filters to capture only relevant traffic where possible
* **Set retention limits** — define how long captures are kept and automate deletion
* **Separate security data from HR/disciplinary processes** to avoid improper data use
* **Document your methodology** so that investigations can withstand scrutiny

---

## 9. Putting It All Together: The NSM Cycle

Network Security Monitoring is not a set of tools — it is a continuous process.
The **NSM Cycle** consists of three phases:

```text
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  COLLECTION │ ───► │   ANALYSIS  │ ───► │   RESPONSE  │
│             │      │             │      │             │
│ TAPs, SPAN  │      │ Wireshark   │      │ Block/alert │
│ Zeek, IDS   │      │ Zeek logs   │      │ Hunt threat │
│ NetFlow     │      │ Snort alerts│      │ Improve     │
└─────────────┘      └─────────────┘      └─────────────┘
       ▲                                          │
       └──────────────────────────────────────────┘
                    Continuous improvement
```

### Phase 1: Collection

Deploy sensors at strategic network chokepoints:

* **Internet perimeter:** TAP or SPAN on the WAN uplink; deploy Zeek and Suricata
* **DMZ:** Monitor all traffic entering and leaving the DMZ
* **Internal segments:** Flow-based monitoring (NetFlow) for lateral movement detection
* **Critical assets:** Full packet capture near databases, finance systems, PII repositories

### Phase 2: Analysis

Data collected from sensors is sent to a **SIEM (Security Information and Event Management)** system for correlation and alerting.
Analysts review:

* IDS alerts generated by signature matches
* Zeek connection logs for anomalies (unusual ports, large transfers, new hosts)
* DNS logs for DGA activity or tunnelling
* Flow records for beaconing patterns

**Triage:** Not every alert is a real attack.
Analysts must distinguish:

* **True positives:** Real attacks (require response)
* **False positives:** Legitimate traffic matching a rule (require rule tuning)
* **True negatives:** Normal traffic correctly not alerted
* **False negatives:** Attacks that were not detected (require detection improvement)

### Phase 3: Response

When a real threat is confirmed:

1. Contain the affected host/segment
1. Collect full packet captures of ongoing activity
1. Preserve evidence following chain of custody procedures
1. Analyse the scope of compromise
1. Remediate (patch, rebuild, rotate credentials)
1. Document lessons learned to improve detection

---

## 10. References and Further Reading

### Essential Books

1. **Sanders, C. & Smith, J. (2013). *Applied Network Security Monitoring: Collection, Detection, and Analysis*. Syngress.**

   *The definitive guide to NSM.
   Covers the full lifecycle from sensor deployment to investigation.
   Required reading for anyone working in network security operations.*

1. **Chappell, L. (2012). *Wireshark Network Analysis: The Official Wireshark Certified Network Analyst Study Guide*. Protocol Analysis Institute.**

   *Comprehensive Wireshark reference covering filters, statistics, and protocol analysis.*

1. **Bejtlich, R. (2004). *The Tao of Network Security Monitoring: Beyond Intrusion Detection*. Addison-Wesley.**

   *Foundational work on NSM philosophy and practice by one of the field's pioneers.*

1. **Corelight. (2023). *The Zeek Book*. Available at https://book.zeek.org**

   *The official guide to Zeek scripting and deployment.*

1. **Caswell, B., Beale, J. & Baker, A. (2007). *Snort IDS and IPS Toolkit*. Syngress.**

   *Comprehensive guide to Snort rule writing and tuning.*

### Online Resources

* **Wireshark Documentation:** https://www.wireshark.org/docs/
* **Zeek Documentation:** https://docs.zeek.org/
* **Snort Rules Reference:** https://www.snort.org/documents
* **Suricata Documentation:** https://suricata.readthedocs.io/
* **SANS NSM Course (SEC503):** https://www.sans.org/courses/network-intrusion-detection/
* **NIST SP 800-94: Guide to IDS and IPS:** https://csrc.nist.gov/publications/detail/sp/800-94/final
* **RFC 3954 (NetFlow v9):** https://www.rfc-editor.org/rfc/rfc3954
* **RFC 7011 (IPFIX):** https://www.rfc-editor.org/rfc/rfc7011
* **RFC 5424 (Syslog):** https://www.rfc-editor.org/rfc/rfc5424
* **GDPR text (EU):** https://gdpr-info.eu/

### Practice Resources

* **Malware Traffic Analysis (PCAP exercises):** https://www.malware-traffic-analysis.net/
* **PacketLife PCAP challenges:** https://packetlife.net/captures/
* **Zeek sample logs and scripts:** https://github.com/zeek/zeek
* **Snort community rules:** https://www.snort.org/downloads/#rule-downloads

---

*End of Session 02 Reading.
Proceed to the entry quiz to test your baseline knowledge, then work through the demos and guides.*
