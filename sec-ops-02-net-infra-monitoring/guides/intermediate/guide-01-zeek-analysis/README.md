# Guide 01 (Intermediate): Zeek for Network Security Monitoring

**Level:** Intermediate

**Duration:** 90–120 minutes

**Tools:** Docker, Zeek, zeek-cut, jq

**Prerequisites:** Completion of Demo 02 (Zeek Installation), Guide 01 (Wireshark)

---

## Introduction

This guide takes you beyond basic Zeek log exploration into practical security monitoring workflows.
You will learn to:

* Conduct structured threat hunts using Zeek logs
* Detect common attack patterns: port scans, DNS tunnelling, lateral movement, beaconing
* Write Zeek scripts that generate custom detections
* Enrich Zeek logs with threat intelligence
* Correlate across multiple log files to reconstruct an attack timeline

---

## Setup: Lab Environment

```bash
mkdir zeek-intermediate && cd zeek-intermediate
mkdir -p logs pcap scripts intel

# Download a more complex sample PCAP (mix of normal and suspicious traffic)
# This PCAP contains: normal web browsing, a port scan, DNS queries, SSH attempts
cat > generate-traffic.sh << 'SCRIPT'
#!/bin/bash
# This script generates a realistic mix of network traffic
# Run this inside a Docker network to populate the PCAP

echo "Generating normal traffic..."
for i in $(seq 1 20); do
  curl -s -o /dev/null http://web-server/ --max-time 2
  nslookup google.com dns-server > /dev/null 2>&1
  sleep 2
done

echo "Generating suspicious traffic (SSH brute force)..."
for i in $(seq 1 10); do
  nc -z -w1 ssh-server 22
done

echo "Generating DGA-like DNS queries..."
for domain in $(cat /dev/urandom | tr -dc 'a-z' | fold -w 12 | head -5); do
  nslookup "${domain}.example.com" dns-server > /dev/null 2>&1
done

echo "Generating beaconing (regular connection pattern)..."
for i in $(seq 1 20); do
  curl -s -o /dev/null http://web-server/beacon --max-time 1
  sleep 30
done &

echo "Traffic generation complete."
SCRIPT
chmod +x generate-traffic.sh
```

Create the docker-compose for this lab:

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'
networks:
  zeek-int-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24

services:
  web-server:
    image: nginx:alpine
    networks:
      zeek-int-net:
        ipv4_address: 172.25.0.10

  traffic-gen:
    image: alpine:3.18
    networks:
      zeek-int-net:
        ipv4_address: 172.25.0.100
    depends_on: [web-server]
    command: >
      sh -c "apk add --no-cache curl bind-tools netcat-openbsd 2>/dev/null &&
      sleep 3 &&
      for i in \$(seq 1 30); do
        curl -s -o /dev/null http://172.25.0.10/;
        sleep 2;
      done &
      for i in \$(seq 1 15); do
        nc -z -w1 172.25.0.10 22 2>/dev/null;
        nc -z -w1 172.25.0.10 3389 2>/dev/null;
      done &
      wait"

  capture:
    image: nicolaka/netshoot
    network_mode: "service:web-server"
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./pcap:/pcap
    command: tcpdump -i eth0 -s 0 -w /pcap/lab-traffic.pcap

  zeek:
    image: zeek/zeek:latest
    volumes:
      - ./pcap:/pcap:ro
      - ./logs:/logs
      - ./scripts:/scripts:ro
      - ./intel:/intel:ro
    working_dir: /logs
    command: zeek -C -r /pcap/lab-traffic.pcap /scripts/
    profiles: [analyse]
EOF
```

Run the environment and capture traffic:

```console
docker compose up -d web-server traffic-gen capture
sleep 90
docker compose stop capture
docker compose run --rm zeek
```

---

## Part 1: Systematic Log Analysis

A structured approach to analysing Zeek logs for security incidents:

### 1.1 The Five-Step Analysis Process

```text
Step 1: Get the big picture (conn.log statistics)
Step 2: Identify anomalies (unusual ports, states, sizes)
Step 3: Drill into specific protocols (dns, http, ssl)
Step 4: Correlate across logs (link conn.log UID to http.log)
Step 5: Build timeline
```

### Step 1: Get the Big Picture

```bash
cd logs

# How many connections total?
wc -l conn.log

# What are the top destination ports?
zeek-cut id.resp_p proto < conn.log \
  | sort | uniq -c | sort -rn | head -20

# What are the top source IPs by connection count?
zeek-cut id.orig_h < conn.log \
  | sort | uniq -c | sort -rn | head -10

# How much data was transferred?
zeek-cut orig_bytes resp_bytes < conn.log \
  | awk 'NF==2 {orig+=$1; resp+=$2} END \
    {printf "Outbound: %d MB\nInbound: %d MB\n", orig/1048576, resp/1048576}'
```

### Step 2: Identify Anomalies

```bash
# Find connections that were NOT successfully completed
# (S0=SYN no response, REJ=rejected, RSTO/RSTR=reset)
zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < conn.log \
  | grep -v '\bSF\b' | grep -v '\bS1\b'

# Find very long connections (> 1 hour — possible persistent access)
zeek-cut ts id.orig_h id.resp_h id.resp_p duration < conn.log \
  | awk '$5 > 3600 {print}'

# Find very large transfers (> 100MB outbound — possible exfiltration)
zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes < conn.log \
  | awk '$5 > 100000000 {print}'

# Find connections to unusual high ports (>1024 and not in common list)
zeek-cut id.orig_h id.resp_h id.resp_p proto < conn.log \
  | awk '$3 > 1024 && $3 != 8080 && $3 != 8443 && $4 == "tcp" {print}' \
  | sort | uniq -c | sort -rn
```

### Step 3: Drill into Specific Protocols

#### DNS Threat Hunting

```bash
# All unique domains queried
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head -30

# NXDOMAIN responses (domain not found)
zeek-cut ts id.orig_h query rcode_name < dns.log \
  | awk '$4 == "NXDOMAIN" {print}' | head -30

# Detect potential DNS tunnelling: long/random-looking subdomains
zeek-cut query < dns.log \
  | awk '{
      # Count dots (subdomains)
      n = split($1, parts, ".");
      # Get the leftmost label length
      if (length(parts[1]) > 30) print length(parts[1]), $1
    }' | sort -rn | head -20

# Identify DNS queries going to non-standard resolvers
zeek-cut id.resp_h < dns.log | sort | uniq -c | sort -rn
# Any resolver that is NOT your corporate DNS server is suspicious

# Find TXT record queries (common in DNS tunnelling)
zeek-cut query qtype_name < dns.log \
  | awk '$2 == "TXT" {print}'
```

#### HTTP Threat Hunting

```bash
# Unusual user agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn

# Requests returning server errors (possible injection attempts)
zeek-cut id.orig_h host uri status_code < http.log \
  | awk '$4 >= 500 {print}'

# Find suspicious URI patterns
zeek-cut host uri < http.log \
  | grep -E '\.\.\/|union.+select|<script|eval\(|base64_decode'

# Large POST requests (possible file upload or data exfil)
zeek-cut method uri request_body_len < http.log \
  | awk '$1 == "POST" && $3 > 10000 {print}'

# Find non-browser user agents
zeek-cut id.orig_h user_agent < http.log \
  | grep -iv 'mozilla\|chrome\|safari\|firefox\|edge' \
  | sort | uniq

# Check for command-and-control patterns (very regular connections)
zeek-cut ts id.orig_h host uri < http.log \
  | awk '{print substr($1,1,5), $2, $3}' \
  | sort | uniq -c | sort -rn
```

#### SSL/TLS Analysis

```bash
# List all TLS versions in use (find TLS 1.0/1.1)
zeek-cut version < ssl.log | sort | uniq -c | sort -rn

# Find self-signed or invalid certificates
zeek-cut server_name validation_status < ssl.log \
  | grep -v 'ok' | sort | uniq

# JA3 fingerprinting (if available) — identifies TLS client
zeek-cut ja3 ja3s < ssl.log | sort | uniq -c | sort -rn

# Find certificate details
zeek-cut server_name cert_chain_fuids < ssl.log \
  | head -20
# Then join with x509.log using the FUID
```

### Step 4: Correlate Using UIDs

Every connection in Zeek has a unique identifier (UID).
This UID appears in conn.log AND in any protocol-specific log for that connection.

```bash
# Find the UID of an interesting connection
zeek-cut ts uid id.orig_h id.resp_h id.resp_p < conn.log \
  | grep "172.25.0.100" | head -5

# Use that UID to find the corresponding HTTP request
UID="CaBcDe12345"
grep "$UID" http.log
grep "$UID" ssl.log
grep "$UID" files.log

# Script to get full picture of a connection by UID
zeek_lookup_uid() {
    local uid="$1"
    echo "=== conn.log ==="
    grep "$uid" conn.log
    echo "=== http.log ==="
    grep "$uid" http.log 2>/dev/null
    echo "=== dns.log ==="
    grep "$uid" dns.log 2>/dev/null
    echo "=== ssl.log ==="
    grep "$uid" ssl.log 2>/dev/null
    echo "=== files.log ==="
    grep "$uid" files.log 2>/dev/null
}
```

### Step 5: Build a Timeline

```console
# Combine all log events for a specific host and sort by time
cat conn.log http.log dns.log ssl.log 2>/dev/null \
  | grep "172.25.0.100" \
  | zeek-cut ts \
  | sort -n \
  | awk '{printf "%s\n", strftime("%H:%M:%S", int($1))}'
```

---

## Part 2: Detecting Specific Attack Patterns

### 2.1 Detecting Port Scanning

A port scan creates many connections from one source to many destination ports, most resulting in REJ or S0 states.

```bash
# Count REJ and S0 connections per source IP
zeek-cut id.orig_h conn_state < conn.log \
  | awk '($2 == "REJ" || $2 == "S0") {count[$1]++}
         END {for (ip in count) print count[ip], ip}' \
  | sort -rn | head -10

# Show which ports were probed by the scanner
zeek-cut id.orig_h id.resp_p conn_state < conn.log \
  | awk '$1 == "172.25.0.100" && ($3 == "REJ" || $3 == "S0") {print $2}' \
  | sort -n | tr '\n' ',' | sed 's/,$/\n/'
```

Expected output for a port scan:

```text
245 172.25.0.100
Port probed: 1,2,3,...,22,...,80,...,443,...
```

### 2.2 Detecting Beaconing (C2 Communication)

Malware beaconing creates regular, short connections at fixed intervals.

```bash
# Get all connections from a host to a specific destination,
# sorted by time, and calculate intervals between them
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes < conn.log \
  | awk '$2 == "10.10.5.100" && $3 == "185.220.101.50"' \
  | awk 'NR>1 {printf "Interval: %.1f sec, Bytes: %s\n", $1-prev, $5} {prev=$1}'

# Detect beaconing: host making many same-sized connections to same dest
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes < conn.log \
  | awk '{key=$1":"$2":"$3; size[$1":"$2":"$3"#"$4]++; total[key]++}
         END {for (k in total) if (total[k] > 10) {
           print total[k], "connections:", k
         }}' | sort -rn
```

### 2.3 Detecting Lateral Movement

Internal hosts connecting to each other on administrative ports (RDP/3389, SSH/22, WMI/445) may indicate lateral movement.

```bash
# Find internal-to-internal connections on administrative ports
zeek-cut id.orig_h id.resp_h id.resp_p proto service < conn.log \
  | awk '
    # Both source and dest are in 10.10.0.0/16
    $1 ~ /^10\.10\./ && $2 ~ /^10\.10\./ &&
    ($3 == 22 || $3 == 3389 || $3 == 445 || $3 == 5985 || $3 == 5986)
    {print}
  ' | sort | uniq

# Find hosts accessing many other internal hosts (possible scanner/worm)
zeek-cut id.orig_h id.resp_h < conn.log \
  | awk '$1 ~ /^10\.10\./ && $2 ~ /^10\.10\./' \
  | sort -u \
  | awk '{count[$1]++} END {for (h in count) print count[h], h}' \
  | sort -rn | head -10
```

### 2.4 Detecting SSH Brute Force

```console
# Count SSH connection attempts per source IP
zeek-cut id.orig_h id.resp_p conn_state < conn.log \
  | awk '$2 == 22 {count[$1]++}
         END {for (ip in count) if (count[ip] > 5) print count[ip], ip}' \
  | sort -rn

# Cross-reference with auth.log (if available)
# Zeek itself doesn't log SSH auth outcomes — use Zeek + syslog together
```

---

## Part 3: Writing Zeek Detection Scripts

### 3.1 Basic Script Structure

Every Zeek script responds to **events**.
Common events:

```zeek
# Connection established
event connection_established(c: connection) { ... }

# DNS request/response
event dns_request(c: connection, msg: dns_msg, query: string, ...) { ... }
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, ...) { ... }

# HTTP request
event http_request(c: connection, method: string, ...) { ... }

# TLS/SSL handshake
event ssl_established(c: connection) { ... }
```

### 3.2 Script: Detect SSH Brute Force

```bash
cat > scripts/ssh-brute-force.zeek << 'EOF'
# Detect SSH brute force based on connection rate
# Generates a notice when more than 5 SSH connections are seen
# from the same source IP within 60 seconds

module SSHBruteForce;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force
    };

    # Threshold: connections per time window
    const threshold: count = 5 &redef;
    const time_window: interval = 60sec &redef;
}

# Track SSH connection attempts per source IP
global ssh_attempts: table[addr] of count &default=0 &create_expire=60sec;

event connection_state_remove(c: connection)
{
    # Only look at TCP port 22 (SSH)
    if (c$id$resp_p != 22/tcp) return;

    # Increment counter for this source IP
    ++ssh_attempts[c$id$orig_h];

    # Check if threshold exceeded
    if (ssh_attempts[c$id$orig_h] >= threshold)
    {
        NOTICE([$note=SSH_Brute_Force,
                $conn=c,
                $msg=fmt("SSH brute force from %s: %d attempts in 60s",
                         c$id$orig_h, ssh_attempts[c$id$orig_h]),
                $identifier=cat(c$id$orig_h),
                $suppress_for=10min]);
    }
}
EOF
```

### 3.3 Script: Detect Long DNS Names (DGA)

```bash
cat > scripts/dga-detection.zeek << 'EOF'
# Detect potential DGA (Domain Generation Algorithm) malware
# by looking for unusually long or random-looking domain names

module DGADetection;

export {
    redef enum Notice::Type += {
        Possible_DGA_Domain
    };

    const min_label_length: count = 20 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
{
    # Skip if query is empty
    if (|query| == 0) return;

    # Split domain into labels
    local labels = split_string(query, /\./);

    # Check the leftmost label (subdomain)
    if (|labels| > 0)
    {
        local subdomain = labels[0];

        # Flag if subdomain is very long (DGA indicator)
        if (|subdomain| >= min_label_length)
        {
            NOTICE([$note=Possible_DGA_Domain,
                    $conn=c,
                    $msg=fmt("Long DNS subdomain from %s: %s (%d chars)",
                             c$id$orig_h, query, |subdomain|),
                    $identifier=query,
                    $suppress_for=1hr]);
        }
    }
}
EOF
```

### 3.4 Script: Log Connections to Threat Intelligence IPs

```bash
# Create a threat intelligence file (bad IPs)
cat > intel/bad-ips.txt << 'EOF'
#fields indicator  indicator_type  meta.source     meta.desc
203.0.113.50  Intel::ADDR  ThreatFeed-1  Known C2 server
198.51.100.99 Intel::ADDR  ThreatFeed-1  Malware dropper
192.0.2.100   Intel::ADDR  ThreatFeed-2  TOR exit node
EOF

cat > scripts/load-intel.zeek << 'EOF'
# Load threat intelligence from file
# This script causes Zeek to generate Intel framework notices
# when it sees traffic to/from IPs in the intel file

@load base/frameworks/intel

redef Intel::read_files += {
    "/intel/bad-ips.txt"
};
EOF
```

### 3.5 Running Scripts

```bash
# Run Zeek with all scripts
docker compose run --rm zeek sh -c \
  "zeek -C -r /pcap/lab-traffic.pcap \
   /scripts/ssh-brute-force.zeek \
   /scripts/dga-detection.zeek \
   /scripts/load-intel.zeek"

# Check notice.log for generated alerts
cat logs/notice.log

# Filter by notice type
grep "SSH_Brute_Force" logs/notice.log
grep "DGA" logs/notice.log
grep "Intel" logs/notice.log
```

---

## Part 4: Zeek JSON Output

For SIEM integration, Zeek can output logs in JSON format.

### 4.1 Enable JSON Output

```console
cat > scripts/json-output.zeek << 'EOF'
# Configure JSON log output
redef LogAscii::use_json = T;
EOF

# Run Zeek with JSON output
docker compose run --rm zeek sh -c \
  "zeek -C -r /pcap/lab-traffic.pcap /scripts/json-output.zeek"
```

### 4.2 Processing JSON Logs with jq

```bash
# Pretty print first connection record
docker run --rm -v "$(pwd)/logs:/logs" \
  stedolan/jq < /logs/conn.log 'first'

# Filter connections by destination port 22
cat logs/conn.log | \
  docker run --rm -i stedolan/jq 'select(."id.resp_p" == 22)'

# Extract specific fields as CSV
cat logs/http.log | \
  docker run --rm -i stedolan/jq -r \
  '[.ts, ."id.orig_h", .host, .uri, .status_code] | @csv'

# Count connections per destination port
cat logs/conn.log | \
  docker run --rm -i stedolan/jq -sr \
  '[.[] | ."id.resp_p"] | group_by(.) | map({port: .[0], count: length}) | sort_by(.count) | reverse | .[0:10]'
```

---

## Part 5: Zeek in a Production NSM Architecture

### 5.1 Deployment Modes

**Standalone:** Single Zeek instance on a sensor connected to a TAP or SPAN port

* Suitable for: Links up to ~1 Gbps
* Simple to deploy and manage

**Cluster mode:** Multiple worker nodes + manager + logger

* Suitable for: High-speed links (10 Gbps+)
* Load balances packet processing across multiple CPUs/machines

```text
                    ┌─────────────┐
         TAP        │   Manager   │  (coordinates workers)
          │         └──────┬──────┘
          ▼                │
   ┌─────────────┐  ┌──────┴──────┐
   │    Proxy    │  │   Logger    │  (writes log files)
   └──────┬──────┘  └─────────────┘
          │
     ┌────┴────┐
     │         │
  Worker1   Worker2   (process packets in parallel)
```

### 5.2 Sending Zeek Logs to a SIEM

Zeek logs are written to files.
To ship them to a SIEM:

**Option 1: Filebeat (Elastic)**

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/zeek/*.log
    fields:
      source: zeek
    json.keys_under_root: true  # If using JSON output
output.elasticsearch:
  hosts: ["https://siem:9200"]
```

**Option 2: Logstash**

```text
input {
  file {
    path => "/var/log/zeek/conn.log"
    codec => "json"
  }
}
filter {
  if [_path] == "conn" {
    date { match => ["ts", "UNIX"] }
  }
}
output {
  elasticsearch { hosts => ["siem:9200"] }
}
```

---

## Summary and Key Commands Reference

```bash
# The most important zeek-cut commands

# Overview of all connections
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state < conn.log

# Find failed connections
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | grep -E 'S0|REJ|RSTO|RSTR'

# DNS queries with NXDomain
zeek-cut ts id.orig_h query rcode_name < dns.log | awk '$4=="NXDOMAIN"'

# HTTP requests with suspicious status
zeek-cut host uri status_code < http.log | awk '$3>=400'

# SSL issues
zeek-cut server_name version validation_status < ssl.log | grep -v ok

# Files transferred
zeek-cut mime_type filename md5 sha256 < files.log
```

---

## Next Steps

* **Drill 01 (Intermediate):** Write Snort rules for 5 attack scenarios
* **Drill 02 (Intermediate):** Design a network monitoring strategy
* **Advanced Drill 01:** Network forensics — reconstruct an attack from Zeek logs + PCAP
