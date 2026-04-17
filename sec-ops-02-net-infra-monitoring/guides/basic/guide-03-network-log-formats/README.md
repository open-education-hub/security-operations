# Guide 03: Network Log Formats — Syslog, NetFlow, and PCAP

**Level:** Beginner

**Duration:** 45–60 minutes

**Tools:** Docker, Docker Compose

**Format:** Reference guide with hands-on exercises

---

## Introduction

Network security monitoring relies on collecting and analysing **logs** from network devices.
Understanding log formats is essential because:

1. Different tools generate different formats
1. You need to know what fields are available before writing detection rules
1. SIEM systems require properly parsed logs to correlate events
1. Evidence quality depends on what data your logs contain

This guide covers the three fundamental log formats in network security monitoring:

* **Syslog** — the universal logging protocol for network devices
* **NetFlow/IPFIX** — flow-based summaries of network conversations
* **PCAP** — raw packet captures (covered in depth in Guides 01 and 02)

---

## Part 1: Syslog

### 1.1 What is Syslog?

Syslog (RFC 5424) is the standard logging protocol that network devices, servers, and security appliances use to send log messages to a central log collector (syslog server).

Almost every security appliance — firewalls, IDS, VPN concentrators, routers — can send logs via syslog.

### 1.2 Syslog Message Structure

A syslog message has this structure:

```text
<PRIORITY>TIMESTAMP HOSTNAME APPLICATION[PID]: MESSAGE BODY
```

Example (firewall block log):

```text
<134>Jan 15 14:23:45 fw-corp kernel: [FW-BLOCK] IN=eth0 OUT=eth1 \
SRC=203.0.113.50 DST=10.10.1.5 LEN=60 PROTO=TCP SPT=54321 DPT=22 \
FLAGS=SYN WINDOW=29200
```

Breaking this down:

* `<134>` — Priority value (see below)
* `Jan 15 14:23:45` — Timestamp (RFC 3164 format)
* `fw-corp` — Hostname of the sending device
* `kernel` — Process/application name
* `[FW-BLOCK]` — Custom tag
* Everything after `:` — The message body

### 1.3 Priority Calculation

The `<134>` in the example is calculated as:

```text
Priority = (Facility × 8) + Severity

134 = (16 × 8) + 6 = 128 + 6

Facility 16 = "local0" (local use 0)
Severity 6  = "Informational"
```

**Facility values (device category):**

| Value | Facility | Common use |
|-------|---------|------------|
| 0 | kern | Linux kernel |
| 1 | user | User-level messages |
| 2 | mail | Mail system |
| 3 | daemon | System daemons |
| 4 | auth | Authentication |
| 5 | syslog | Syslog daemon |
| 10 | authpriv | Private authentication |
| 16–23 | local0–local7 | Locally defined |

**Severity values:**

| Value | Name | Description | Example |
|-------|------|-------------|---------|
| 0 | Emergency | System unusable | Kernel panic |
| 1 | Alert | Immediate action needed | Disk full |
| 2 | Critical | Critical condition | Hardware failure |
| 3 | Error | Error condition | Failed login |
| 4 | Warning | Warning condition | Config error |
| 5 | Notice | Normal but significant | User login |
| 6 | Informational | Informational | System startup |
| 7 | Debug | Debug messages | Trace output |

### 1.4 Syslog Formats in Practice

**RFC 3164 (legacy BSD syslog):** Used by most older network devices

```text
<134>Jan 15 14:23:45 firewall KERN-5-UPDOWN: Interface GigabitEthernet0/0, changed state to up
```

**RFC 5424 (modern syslog):** Structured, with explicit fields

```text
<134>1 2024-01-15T14:23:45.000Z firewall kernel - - - Interface state up
```

**CEF (Common Event Format):** Used by HP ArcSight and many security tools

```text
CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|THREAT|5|src=203.0.113.50 spt=54321 dst=10.10.1.5 dpt=22 proto=TCP act=block
```

**LEEF (Log Event Extended Format):** Used by IBM QRadar

```text
LEEF:2.0|Cisco|ASA|9.14|106023|devTime=Jan 15 2024 14:23:45|src=203.0.113.50|dst=10.10.1.5|proto=TCP
```

### 1.5 Running a Syslog Lab

```bash
mkdir syslog-lab && cd syslog-lab

cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  # Syslog server (receives and stores logs)
  syslog-server:
    image: linuxserver/syslog-ng:latest
    container_name: syslog-server
    ports:
      - "514:514/udp"
      - "601:601/tcp"
    volumes:
      - ./syslog-config:/config
      - ./syslog-logs:/var/log/syslog-ng
    environment:
      - PUID=1000
      - PGID=1000

  # Log generator (simulates a firewall sending syslog messages)
  log-generator:
    image: alpine:3.18
    depends_on: [syslog-server]
    command: >
      sh -c "apk add --no-cache socat 2>/dev/null && sleep 3 && while true; do
        echo '<134>Jan 15 14:23:45 fw-01 kernel: [FW-BLOCK] SRC=203.0.113.50 DST=10.10.1.5 PROTO=TCP DPT=22' \
          | socat - UDP:syslog-server:514;
        echo '<86>Jan 15 14:23:46 fw-01 kernel: [FW-ALLOW] SRC=10.10.1.5 DST=8.8.8.8 PROTO=UDP DPT=53' \
          | socat - UDP:syslog-server:514;
        echo '<11>Jan 15 14:23:47 auth-srv sshd[1234]: Failed password for root from 203.0.113.50 port 12345 ssh2' \
          | socat - UDP:syslog-server:514;
        sleep 5;
      done"
EOF

docker compose up -d
sleep 15
docker compose logs log-generator
```

### 1.6 Parsing Syslog Messages

Key fields to extract from firewall syslog messages:

```console
# Sample firewall syslog message
MSG='<134>Jan 15 14:23:45 fw-01 kernel: [FW-BLOCK] IN=eth0 SRC=203.0.113.50 DST=10.10.1.5 PROTO=TCP SPT=54321 DPT=22'

# Extract source IP using awk
echo "$MSG" | grep -oP 'SRC=\K[0-9.]+'

# Extract destination port
echo "$MSG" | grep -oP 'DPT=\K[0-9]+'

# Extract action (BLOCK or ALLOW)
echo "$MSG" | grep -oP '\[FW-\K\w+'
```

### 1.7 Important Syslog Messages to Monitor

| Message pattern | Security meaning |
|----------------|-----------------|
| `Failed password for` | SSH brute force attempt |
| `Accepted password for root` | Successful root login (very suspicious) |
| `BLOCK` / `DENY` firewall action | Blocked connection attempt |
| `accepted` firewall action + unusual port | Allowed unexpected connection |
| `Invalid user` | Username enumeration |
| `Connection closed by authenticating user` | Possible credential stuffing |
| `sudo: ... COMMAND=` | Privilege escalation event |

---

## Part 2: NetFlow

### 2.1 What is NetFlow?

NetFlow is Cisco's network flow protocol (now standardised as IPFIX, RFC 7011).
Instead of capturing every packet, NetFlow summarises network conversations into **flow records**.

A **flow** is a unidirectional sequence of packets with the same:

* Source IP
* Destination IP
* Source port
* Destination port
* Layer 3 protocol (TCP/UDP/ICMP)

### 2.2 NetFlow Record Fields

**NetFlow v5 record (fixed format):**

```text
Field           Type    Description
─────────────────────────────────────────────────────────
srcaddr         IPv4    Source IP address
dstaddr         IPv4    Destination IP address
nexthop         IPv4    Next hop router
input           uint16  SNMP input interface index
output          uint16  SNMP output interface index
dpkts           uint32  Packets in this flow
doctets         uint32  Bytes in this flow
first           uint32  SysUptime when flow started
last            uint32  SysUptime when flow ended
srcport         uint16  Source port (or ICMP type/code)
dstport         uint16  Destination port
tcp_flags       uint8   Union of all TCP flags seen
prot            uint8   IP Protocol (6=TCP, 17=UDP, 1=ICMP)
tos             uint8   IP TOS field
src_as          uint16  Source Autonomous System number
dst_as          uint16  Destination AS number
src_mask        uint8   Source IP subnet mask bits
dst_mask        uint8   Destination IP subnet mask bits
```

**NetFlow v9/IPFIX** is template-based — the exporter sends a template record first defining which fields it will export.

### 2.3 Reading NetFlow with nfdump

```bash
# Start a NetFlow collector
mkdir netflow-lab && cd netflow-lab
mkdir -p flows

cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  # NetFlow collector and analysis
  nfcapd:
    image: pschiffe/nfdump:latest
    container_name: netflow-collector
    ports:
      - "2055:2055/udp"
    volumes:
      - ./flows:/flows
    command: nfcapd -T all -l /flows -p 2055 -D

  # Flow viewer
  nfdump:
    image: pschiffe/nfdump:latest
    container_name: netflow-viewer
    volumes:
      - ./flows:/flows:ro
    entrypoint: ["nfdump"]
    profiles: [view]
EOF

docker compose up -d nfcapd
```

Query flows with nfdump:

```bash
# Show all flows (last capture file)
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current -o extended

# Show top 10 source IPs by bytes
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current \
  -s srcip/bytes -n 10

# Show all flows to a specific destination port
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current \
  "dst port 443"

# Show flows larger than 100MB (possible data exfiltration)
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current \
  "bytes > 100000000"

# Show flows in a time range
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current \
  -t 2024-01-15.14:00:00-2024-01-15.15:00:00

# Show flows with specific TCP flags (SYN only — possible scan)
docker compose run --rm nfdump \
  nfdump -r /flows/nfcapd.current \
  "flags S and not flags AFRPU"
```

### 2.4 NetFlow Analysis for Security

**Detecting port scanning:**

```console
# Find sources with connections to many unique destination ports
nfdump -r /flows/nfcapd.current -s dstport/flows -n 50 \
  "proto tcp and src ip 203.0.113.50"
```

**Detecting beaconing (C2 communication):**
Beaconing creates flows with:

* Regular time intervals between flows
* Similar byte counts per flow
* Consistent destination IP and port

```console
# Show all flows from a suspect host ordered by time
nfdump -r /flows/nfcapd.current \
  "src ip 10.10.5.50" \
  -o extended | sort -k3
```

**Detecting data exfiltration:**
Exfiltration shows large flows going *outbound*:

```console
# Large flows going to the internet (bytes > 50MB)
nfdump -r /flows/nfcapd.current \
  "bytes > 50000000 and not dst net 10.0.0.0/8"
```

### 2.5 NetFlow vs. PCAP Comparison

For the same 1-hour window on a 100 Mbps link:

| Metric | Full PCAP | NetFlow |
|--------|-----------|---------|
| Data volume | ~45 GB | ~50 MB |
| Payload content | Yes | No |
| Can reconstruct sessions | Yes | No |
| Can detect port scans | Yes | Yes |
| Can detect beaconing | Yes | Yes |
| Can detect data exfil | Yes | Volume only |
| Privacy sensitive | Very high | Lower |
| Long-term retention practical | Difficult | Easy (months) |

---

## Part 3: PCAP Format Deep Dive

### 3.1 PCAP File Structure

A PCAP file (libpcap format) has this binary structure:

```text
┌──────────────────────────────────────┐
│  Global Header (24 bytes)            │
│  ├── Magic Number: 0xd4c3b2a1        │  ← Identifies PCAP format
│  ├── Major Version: 2                │
│  ├── Minor Version: 4                │
│  ├── Timezone Offset: 0              │
│  ├── Timestamp Accuracy: 0           │
│  ├── Snapshot Length: 65535          │  ← Max bytes per packet
│  └── Link-Layer Header Type: 1       │  ← 1=Ethernet
├──────────────────────────────────────┤
│  Packet Record 1                     │
│  ├── Timestamp (seconds)             │
│  ├── Timestamp (microseconds)        │
│  ├── Captured Length: 152            │  ← Bytes in this record
│  ├── Original Length: 152            │  ← Original packet size
│  └── Packet Data (152 bytes)         │  ← Raw packet bytes
├──────────────────────────────────────┤
│  Packet Record 2                     │
│  └── ...                             │
└──────────────────────────────────────┘
```

The **magic number** `0xd4c3b2a1` (or `0xa1b2c3d4` in big-endian) identifies the file as PCAP.
PcapNG files start with `0x0A0D0D0A`.

### 3.2 Useful capinfos Commands

```bash
# Get a summary of the PCAP file
capinfos capture.pcap

# Sample output:
# File name: capture.pcap
# File type: Wireshark/tcpdump/... - pcap
# File encapsulation: Ethernet
# Number of packets: 1847
# File size: 248987 bytes
# Data size: 245873 bytes
# Capture duration: 90.123456 seconds
# Start time: Mon Jan 15 14:23:45 2024
# End time: Mon Jan 15 14:25:15 2024
# Data byte rate: 2729.43 bytes/sec
# Data bit rate: 21835.45 bits/sec
# Average packet size: 133.15 bytes
# Average packet rate: 20.50 packets/sec
# SHA256 hash: a3b4c5d6e7f8...
```

### 3.3 Splitting and Merging PCAP Files

```console
# Split large PCAP into 100MB chunks
editcap -c 100000 large.pcap split

# Split by time (one file per hour)
editcap -A "2024-01-15 14:00:00" -B "2024-01-15 15:00:00" capture.pcap hour1.pcap

# Merge multiple PCAP files (sorted by timestamp)
mergecap -w combined.pcap file1.pcap file2.pcap file3.pcap

# Extract a subset by time
editcap -A "2024-01-15 14:23:00" -B "2024-01-15 14:25:00" capture.pcap incident.pcap
```

### 3.4 Calculating PCAP Hashes for Chain of Custody

```bash
# Calculate SHA-256 hash (for evidence integrity)
sha256sum capture.pcap > capture.pcap.sha256
cat capture.pcap.sha256

# Verify integrity later
sha256sum -c capture.pcap.sha256
# capture.pcap: OK  ← File has not been modified
# capture.pcap: FAILED  ← File has been altered!
```

---

## Part 4: Comparing Log Formats Side by Side

The same network event — a blocked SSH connection attempt — as seen in three formats:

### 4.1 As Syslog (from firewall):

```text
<134>Jan 15 14:23:45 fw-01 kernel: [FW-BLOCK] IN=eth0 OUT=eth1 \
MAC=02:42:ac:00:00:01:02:42:ac:00:00:02:08:00 SRC=203.0.113.50 \
DST=10.10.1.5 LEN=60 TOS=0x00 PREC=0x00 TTL=116 ID=12345 DF \
PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
```

**What you can see:** IP addresses, ports, protocol, TCP flags, action taken, interface

**What you cannot see:** Whether a connection was established; what data was sent

### 4.2 As NetFlow record:

```text
Date flow start    Duration  Proto    Src IP Addr:Port    Dst IP Addr:Port    Flags  Tos  Packets  Bytes  Flows
2024-01-15 14:23:45.000    0.000 TCP    203.0.113.50:54321 ->  10.10.1.5:22     .S....  0      1       60      1
```

**What you can see:** Connection metadata, direction, byte count, TCP flags

**What you cannot see:** Whether connection succeeded; packet content

### 4.3 As Zeek conn.log entry:

```text
ts           uid          id.orig_h    id.orig_p id.resp_h  id.resp_p proto service duration orig_bytes resp_bytes conn_state
1705328625.0 CBW123abc456 203.0.113.50 54321     10.10.1.5  22        tcp   ssh     -         -          -          S0
```

**What you can see:** All NetFlow fields PLUS connection state (S0 = SYN sent, no response = blocked)

**What you cannot see:** Packet content

### 4.4 As Wireshark/PCAP:

```text
Frame 1: 60 bytes
Ethernet: Src=02:42:ac:14:00:64, Dst=02:42:ac:14:00:02
IP: 203.0.113.50 → 10.10.1.5, TTL=116, Proto=TCP
TCP: 54321 → 22, Flags=SYN, Seq=1234567890, Win=29200
  [No payload — SYN packet has no application data]
```

**What you can see:** Everything — every bit of every header

**Storage cost:** ~60 bytes per packet (vs. ~100 bytes for the NetFlow record — similar for a single packet, but PCAP stores ALL packets)

---

## Part 5: Hands-On Exercises

### Exercise 5.1: Syslog Parsing

Parse the following syslog message manually:

```text
<38>Jan 15 14:30:00 authserver sshd[9876]: Accepted publickey for admin from 10.10.5.20 port 62345 ssh2: RSA SHA256:abc123
```

Questions:

1. What is the Priority value? What facility and severity does it decode to?
1. Which host sent this log message?
1. What authentication method was used?
1. Is this event suspicious? What context would help you decide?

### Exercise 5.2: NetFlow Interpretation

Given this NetFlow data:

```text
Date flow start          Duration  Proto  Src IP:Port         Dst IP:Port       Flags  Pkts  Bytes
2024-01-15 02:15:00.000  0.001     TCP    10.10.5.55:49234 -> 8.8.8.8:53        .S....    1     40
2024-01-15 02:15:01.000  0.001     TCP    10.10.5.55:49235 -> 8.8.8.8:53        .S....    1     40
2024-01-15 02:15:02.000  0.001     TCP    10.10.5.55:49236 -> 8.8.8.8:53        .S....    1     40
2024-01-15 02:15:03.000  0.001     TCP    10.10.5.55:49237 -> 8.8.8.8:53        .S....    1     40
[... continues every second for 10 minutes ...]
```

Questions:

1. Why is DNS traffic going to port 53 via TCP instead of UDP?
1. The flows show only SYN flags (.S....) — what does this mean?
1. What does the pattern (one flow per second, same size) suggest?
1. What would you do next to investigate?

### Exercise 5.3: Format Selection

For each scenario, which log format would provide the most value?

1. An incident responder needs to recover the exact file that was downloaded by malware
1. The security team wants to detect beaconing behaviour over the past 30 days
1. A firewall administrator wants to audit all blocked connections last week
1. An analyst needs to determine if a host was port-scanned from an external IP last month

---

## Summary

| Format | Best for | Storage | Contains payload |
|--------|---------|---------|-----------------|
| PCAP | Full forensic detail, file recovery | Very high | Yes |
| Zeek logs | Per-protocol summaries, long-term monitoring | Medium | No |
| NetFlow | Traffic volume, beaconing, long-term | Low | No |
| Syslog | Device events, authentication, policy | Very low | No |

In a well-designed NSM architecture, you collect **all four** and use each for its strengths.

---

## Next Steps

* **Guide 01 (Intermediate): Zeek Analysis** — advanced Zeek log analysis
* **Drill 02:** PCAP Analysis — apply format knowledge in a practical scenario
* **Demo 02:** Zeek Installation — see Zeek logs generated from real traffic
