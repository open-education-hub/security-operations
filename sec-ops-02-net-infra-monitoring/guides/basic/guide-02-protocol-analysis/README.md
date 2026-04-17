# Guide 02: Protocol Analysis — Identifying Protocols and Security-Relevant Fields

**Level:** Beginner

**Duration:** 60–90 minutes

**Tools:** Docker, tshark, Wireshark

**Format:** Reference guide with hands-on exercises

---

## Introduction

Every packet you capture is an instance of one or more **protocols**.
A protocol defines the format and rules for communication between systems.
To be effective as a security analyst, you need to:

1. Quickly identify which protocol is in use from packet headers
1. Know which fields in each protocol are security-relevant
1. Recognise patterns that indicate normal vs. suspicious behaviour

This guide covers the protocols you will encounter most frequently in a SOC environment.

---

## Setup: Lab Environment

```bash
mkdir protocol-lab && cd protocol-lab
mkdir -p capture scripts

cat > docker-compose.yml << 'EOF'
version: '3.8'
networks:
  proto-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.31.0.0/24

services:
  dns-server:
    image: andyshinn/dnsmasq
    networks:
      proto-net:
        ipv4_address: 172.31.0.53
    cap_add: [NET_ADMIN]
    command: --no-daemon --log-queries

  web-server:
    image: nginx:alpine
    networks:
      proto-net:
        ipv4_address: 172.31.0.80

  traffic-gen:
    image: alpine:3.18
    networks:
      proto-net:
        ipv4_address: 172.31.0.100
    depends_on: [web-server, dns-server]
    command: >
      sh -c "apk add --no-cache curl wget bind-tools netcat-openbsd 2>/dev/null &&
      sleep 3 && while true; do
        curl -s -o /dev/null http://web-server/;
        nslookup example.com 172.31.0.53;
        nslookup nonexistent123.example 172.31.0.53 2>/dev/null;
        wget -q -O /dev/null http://web-server/;
        nc -z web-server 80;
        nc -z web-server 22 2>/dev/null;
        nc -z web-server 443 2>/dev/null;
        sleep 5;
      done"

  capture:
    image: nicolaka/netshoot
    network_mode: "service:web-server"
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./capture:/capture
    command: tcpdump -i eth0 -s 0 -w /capture/protocols.pcap
EOF

docker compose up -d
sleep 60
docker compose stop capture
```

---

## Part 1: Ethernet and ARP

### 1.1 Ethernet Frame Analysis

Every packet on a local network starts with an Ethernet frame header.

Filter in Wireshark: `eth` or just look at any packet.

Key fields:

```text
Ethernet II
├── Destination MAC: ff:ff:ff:ff:ff:ff  ← Broadcast (or specific host)
├── Source MAC: 02:42:ac:1f:00:64       ← Hardware address of sender
└── Type: 0x0800 (IPv4) | 0x0806 (ARP) | 0x86DD (IPv6)
```

**Security relevance:**

* MAC addresses identify network interface cards
* MAC spoofing — changing your MAC to impersonate another device — is possible but detectable
* Broadcast traffic (`ff:ff:ff:ff:ff:ff`) goes to all hosts on the LAN

### 1.2 ARP Analysis

Apply filter: `arp`

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses.

```text
Address Resolution Protocol (request)
├── Opcode: 1 (request) | 2 (reply)
├── Sender MAC: 02:42:ac:1f:00:64
├── Sender IP: 172.31.0.100
├── Target MAC: 00:00:00:00:00:00  ← Unknown (that's what we're asking)
└── Target IP: 172.31.0.80         ← Who has this IP?
```

**Normal ARP traffic pattern:**

```text
Host A → Broadcast: "Who has 172.31.0.80? Tell 172.31.0.100"
Host B → Host A: "172.31.0.80 is at 02:42:ac:1f:00:50"
```

**ARP Poisoning (attack pattern):**

```text
Attacker → Broadcast: "172.31.0.1 is at AA:BB:CC:DD:EE:FF" (lying!)
Attacker → Host A:    "172.31.0.1 is at AA:BB:CC:DD:EE:FF" (lying!)
```

**Detection indicators:**

* Multiple hosts claiming the same IP address
* Gratuitous ARP (unsolicited ARP reply) for the gateway IP
* Rapid ARP traffic — hundreds of ARP packets per second

```console
# Count ARP packets by sender
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "arp" \
  -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -rn
```

---

## Part 2: IP Protocol Analysis

Apply filter: `ip` (to see all IPv4 packets)

### 2.1 Key IP Header Fields

```text
Internet Protocol Version 4
├── Version: 4
├── Header Length: 20 bytes
├── DSCP: 0x00 (normal) | 0x28 (DSCP AF11) | etc.
├── Total Length: 152
├── Identification: 0x3a4b
├── Flags: Don't Fragment (DF)
├── Fragment Offset: 0
├── Time to Live: 64     ← OS indicator
├── Protocol: 6 (TCP) | 17 (UDP) | 1 (ICMP)
├── Header Checksum: 0x1234
├── Source: 172.31.0.100
└── Destination: 172.31.0.80
```

### 2.2 TTL as an Operating System Indicator

| Default TTL | Typical OS |
|-------------|-----------|
| 64 | Linux, macOS, modern Android |
| 128 | Windows |
| 255 | Cisco routers, some Unix systems |
| 254 | Solaris, AIX |

Each hop (router) decrements TTL by 1.
If you receive a packet with TTL=57, the source is likely a Linux system ~7 hops away (64-7=57).

**Security use:** A sudden TTL change for a known host may indicate the traffic is now coming from a different machine (e.g., after ARP poisoning).

```console
# Show TTL values for all packets
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap \
  -T fields -e ip.src -e ip.dst -e ip.ttl \
  | head -20
```

### 2.3 IP Fragmentation

Large packets may be fragmented into smaller pieces.
Fragmentation is used legitimately but also in:

* **Teardrop attacks:** Malformed fragments that crash vulnerable OS TCP/IP stacks
* **IDS evasion:** Splitting attack payloads across fragments so no single fragment matches a signature

Filter: `ip.flags.mf == 1` (More Fragments flag) or `ip.frag_offset > 0`

---

## Part 3: TCP Protocol Analysis

Apply filter: `tcp`

### 3.1 TCP Three-Way Handshake

Every TCP connection starts with this exchange:

```text
Client                  Server
  │                        │
  │──── SYN ─────────────►│  "Can we talk? (Seq=1000)"
  │                        │
  │◄─── SYN-ACK ───────────│  "Yes. (Seq=5000, Ack=1001)"
  │                        │
  │──── ACK ─────────────►│  "Acknowledged. (Ack=5001)"
  │                        │
  │──── DATA ────────────►│  Application data
  │◄─── DATA ──────────────│
  │                        │
  │──── FIN ─────────────►│  "I'm done."
  │◄─── FIN-ACK ───────────│
```

Filter for only SYN packets (connection attempts):

```text
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

Filter for connection resets:

```text
tcp.flags.rst == 1
```

### 3.2 TCP Flag Combinations in Security Context

| Flag(s) | Normal use | Attack/scan implication |
|---------|-----------|------------------------|
| SYN only | Connection initiation | Port scanning (SYN scan) |
| SYN + many RST responses | — | Scanner finding closed ports |
| FIN only (no data) | — | FIN scan (stealthy port scanning) |
| NULL (no flags) | — | NULL scan (stealthy) |
| URG + PSH + FIN | — | XMAS scan (all flags set) |
| RST in response to SYN | Port closed | Normal for port scan |
| Many SYN, no ACK response | — | SYN flood (DoS attack) |

### 3.3 Port Number Analysis

Port numbers tell you which application protocol is likely in use:

```console
# List all destination ports and their frequency
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap \
  -T fields -e ip.dst -e tcp.dstport \
  | sort | uniq -c | sort -rn | head -20
```

| Port | Protocol | Security notes |
|------|----------|---------------|
| 21 | FTP | Cleartext, password visible |
| 22 | SSH | Encrypted; brute force target |
| 23 | Telnet | Cleartext — should never be used |
| 25 | SMTP | Email delivery; open relays dangerous |
| 53 | DNS | UDP/TCP; DNS tunnelling attack vector |
| 80 | HTTP | Cleartext web; should be HTTPS |
| 110 | POP3 | Email retrieval (cleartext) |
| 143 | IMAP | Email retrieval |
| 443 | HTTPS | Encrypted web traffic |
| 445 | SMB | Windows file sharing; WannaCry target |
| 1433 | MS SQL | Database — should never be internet-facing |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote Desktop; frequent attack target |
| 8080 | HTTP alt | Often used by attacker C2, proxies |
| 4444 | — | Default Metasploit listener port |

> **Rule of thumb:** Any unknown high port (>1024) in use on a server is worth investigating.

---

## Part 4: DNS Analysis

Apply filter: `dns`

### 4.1 DNS Query/Response Structure

A DNS query:

```text
Domain Name System (query)
├── ID: 0x1234  ← Transaction ID (matches query to response)
├── Flags: Standard query, RD (Recursion Desired)
├── Questions: 1
│   └── example.com: type A, class IN
└── Answers: 0  ← Empty in a query
```

A DNS response:

```text
Domain Name System (response)
├── ID: 0x1234  ← Same as query
├── Flags: Standard query response, No error
├── Questions: 1
├── Answers: 1
│   └── example.com: type A, class IN, addr 93.184.216.34
└── Additional records: ...
```

### 4.2 DNS Security Analysis

```bash
# Extract all DNS queries
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type

# Find NXDOMAIN responses (domain not found)
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap \
  -Y "dns.flags.rcode == 3" \
  -T fields -e ip.src -e dns.qry.name

# Look for unusually long domain names (DGA indicator)
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name \
  | awk 'length($0) > 50 {print length($0), $0}' | sort -rn
```

**Suspicious DNS patterns:**

| Pattern | Possible cause |
|---------|---------------|
| NXDOMAIN in high volume | DGA malware, beaconing |
| DNS queries to non-corporate resolvers | DNS hijacking, shadow IT |
| Long random-looking subdomains | DNS tunnelling |
| TXT record queries | DNS tunnelling (data in TXT records) |
| MX record queries from workstations | Spam bot, malware recon |
| PTR queries for internal IPs to external DNS | Misconfiguration, leaking internal topology |

### 4.3 DNS Tunnelling Indicator

Legitimate DNS traffic has short query names (e.g., `google.com`, `windows.com`).

DNS tunnelling encodes data in subdomains:

```text
# Normal DNS query
query: www.google.com  (15 chars)

# DNS tunnel query (data encoded in subdomain)
query: SGVsbG8gV29ybGQhCg.evil-c2.com  (35 chars of base64 + domain)
```

Apply filter: `dns` and look at `dns.qry.name` field lengths.

---

## Part 5: HTTP Analysis

Apply filter: `http`

### 5.1 HTTP Request Fields

```text
Hypertext Transfer Protocol
├── Request Method: GET | POST | PUT | DELETE | HEAD | OPTIONS
├── Request URI: /index.html
├── Request Version: HTTP/1.1
├── Host: www.example.com
├── User-Agent: Mozilla/5.0 ...
├── Accept: text/html,application/xhtml+xml
├── Accept-Encoding: gzip, deflate, br
├── Cookie: session=abc123; auth=xyz789
└── Authorization: Basic YWxpY2U6cGFzc3dvcmQ=  ← BASE64!
```

### 5.2 Decoding Base64 HTTP Basic Auth

If you see an `Authorization: Basic ...` header, the credentials are Base64 encoded:

```console
# Decode Base64 credentials
echo "YWxpY2U6cGFzc3dvcmQ=" | base64 -d
# Output: alice:password
```

```console
# Extract all Authorization headers from PCAP
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "http.authorization" \
  -T fields -e ip.src -e http.host -e http.authorization
```

### 5.3 HTTP Response Analysis

```text
HTTP/1.1 200 OK
├── Status Code: 200 OK
├── Content-Type: text/html; charset=UTF-8
├── Content-Length: 1234
├── Server: Apache/2.4.51  ← Version fingerprinting!
├── Set-Cookie: session=abc123; Secure; HttpOnly
└── X-Powered-By: PHP/8.1  ← Technology disclosure
```

**Security-relevant response codes:**

| Code | Meaning | Security relevance |
|------|---------|-------------------|
| 200 | OK | Normal |
| 301/302 | Redirect | Could redirect to malicious site |
| 401 | Unauthorised | Authentication required — may indicate brute force |
| 403 | Forbidden | Access denied — may indicate path traversal attempt |
| 404 | Not Found | Missing resource — may indicate scanning |
| 500 | Server Error | Crash — may indicate successful injection |
| 503 | Service Unavailable | Overloaded — may indicate DoS |

```console
# Count HTTP response codes
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "http.response" \
  -T fields -e http.response.code \
  | sort | uniq -c | sort -rn
```

### 5.4 HTTP Security Analysis Exercises

```bash
# Find all user agents (tool fingerprinting)
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "http.user_agent" \
  -T fields -e ip.src -e http.user_agent \
  | sort | uniq

# Find POST requests (possible credential submission or data upload)
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "http.request.method==POST" \
  -T fields -e ip.src -e http.host -e http.request.uri -e http.file_data

# Find suspicious URIs (path traversal, SQLi patterns)
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/protocols.pcap -Y "http.request.uri" \
  -T fields -e ip.src -e http.request.uri \
  | grep -E "\.\./|UNION|SELECT|<script|eval\("
```

---

## Part 6: Protocol Identification Quick Reference

When you see an unknown packet, use this systematic approach:

**Step 1:** Look at the IP destination port

* Is it a well-known port? (See table in Part 3.3)
* If not, what does the application layer look like?

**Step 2:** Check the payload (packet bytes pane)

* Does it start with printable text? (HTTP, SMTP, FTP, Telnet)
* Does it have a binary magic number? (e.g., PDF starts with `%PDF`, ZIP with `PK`)
* Is it all zeros or random-looking? (May be encrypted)

**Step 3:** Look at connection patterns

* Is it one-to-one, or broadcast?
* How long is the connection?
* How many bytes?

**Step 4:** Use Wireshark's automatic protocol detection

* Wireshark identifies most protocols automatically
* Look at the Protocol column and the dissected fields in the packet details

### Quick Protocol Cheat Sheet

| Visible in payload | Protocol |
|-------------------|---------|
| `GET / HTTP/1.` | HTTP |
| `HTTP/1.1 200` | HTTP Response |
| `SSH-2.0-OpenSSH` | SSH |
| `220 mail.` | SMTP greeting |
| `EHLO` / `MAIL FROM:` | SMTP |
| `220 FTP server` | FTP |
| `USER alice` / `PASS ` | FTP auth |
| `+OK` / `-ERR` | POP3 |
| Binary with `\x16\x03` | TLS/SSL |
| `\x00\x00\x00\x00` query header | DNS (binary format) |

---

## Summary

Key protocol analysis skills developed in this guide:

1. **ARP:** Detect poisoning by watching for IP-MAC conflicts
1. **IP:** Use TTL to fingerprint OS; watch for fragmentation anomalies
1. **TCP:** Interpret flag combinations to identify scans and DoS
1. **Port numbers:** Know common service ports and suspicious values
1. **DNS:** Detect DGA, tunnelling, and unauthorized resolvers
1. **HTTP:** Find credentials, reconnaissance, and injection attempts

---

## Next Steps

* **Guide 03:** Network Log Formats — understand syslog and NetFlow
* **Drill 01:** Protocol Identification — apply these skills in 10 exercises
* **Demo 04:** Snort IDS — see how these protocol patterns become detection rules
