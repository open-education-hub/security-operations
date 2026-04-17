# Demo 02: Zeek Installation and PCAP Analysis

**Level:** Beginner–Intermediate

**Duration:** 30–45 minutes

**Tools:** Docker, Docker Compose, Zeek 6.x
**Learning objectives:**

* Run Zeek in a Docker container
* Analyse a PCAP file with Zeek and understand its output logs
* Interpret the most important Zeek log files: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`
* Use Zeek's `zeek-cut` utility to extract specific fields
* Understand how Zeek logs compare to raw PCAP data

---

## Prerequisites

* Docker and Docker Compose installed
* Completion of Demo 01 (Wireshark basics)
* Basic familiarity with Linux command line and JSON

---

## Background

**Zeek** (formerly Bro) is a network analysis framework that reads packet data and produces structured log files for each protocol it sees.
Unlike Wireshark, which gives you raw packets, Zeek gives you *events* and *summaries* that are much easier to search and ingest into a SIEM.

For example, instead of digging through 10,000 packets to find all HTTP requests, Zeek produces a `http.log` file with one line per request, containing the timestamp, client IP, server IP, URI, status code, and more.

### Key Zeek log files

| Log file | Content |
|----------|---------|
| `conn.log` | Every TCP/UDP/ICMP connection (duration, bytes, state) |
| `dns.log` | All DNS queries and responses |
| `http.log` | All HTTP requests (method, URI, user-agent, response code) |
| `ssl.log` | TLS/SSL connections (certificate subject, version, cipher) |
| `files.log` | Files transferred (hash, MIME type, size) |
| `notice.log` | Zeek's built-in detections and anomaly notices |
| `weird.log` | Protocol anomalies and unexpected behaviour |
| `x509.log` | Certificate details from TLS connections |

---

## Step 1: Project Structure

```console
mkdir zeek-demo && cd zeek-demo
mkdir -p logs pcap scripts
```

```text
zeek-demo/
├── docker-compose.yml
├── logs/           # Zeek output logs appear here
├── pcap/           # Place PCAP files here for analysis
└── scripts/        # Custom Zeek scripts (optional)
```

---

## Step 2: Obtain a Sample PCAP File

We will use a publicly available PCAP that contains realistic traffic including HTTP, DNS, and some suspicious activity.

```console
# Download a sample PCAP from Zeek's test suite
curl -L -o pcap/sample.pcap \
  "https://github.com/zeek/zeek/raw/master/testing/btest/Traces/get.trace"
```

Alternatively, use the PCAP generated in Demo 01:

```console
cp ../demo-01-wireshark-basics/capture/demo-capture.pcap pcap/sample.pcap
```

Or generate a fresh capture using the included client (see the `generate-traffic` service in docker-compose.yml).

---

## Step 3: Docker Compose Configuration

See `docker-compose.yml` in this directory.
It provides:

* `zeek-analyse`: Runs Zeek against a PCAP file and writes logs to `./logs/`
* `zeek-live`: Runs Zeek on a live Docker network interface (advanced)
* `generate-traffic`: Generates HTTP+DNS traffic for live capture demo
* `zeek-shell`: Interactive shell for exploring Zeek commands

---

## Step 4: Analyse the PCAP with Zeek

Run Zeek against the sample PCAP:

```console
docker compose run --rm zeek-analyse
```

This will:

1. Start the Zeek container
1. Mount `./pcap/` and `./logs/` into the container
1. Run: `zeek -C -r /pcap/sample.pcap`
1. Write all log files to `/logs/` (which is `./logs/` on your host)

After it completes (a few seconds), check the output:

```console
ls -la logs/
```

Expected output:

```text
total 128
-rw-r--r-- 1 root root  2341 Jan 15 14:30 conn.log
-rw-r--r-- 1 root root   891 Jan 15 14:30 dns.log
-rw-r--r-- 1 root root  1024 Jan 15 14:30 http.log
-rw-r--r-- 1 root root   456 Jan 15 14:30 ssl.log
-rw-r--r-- 1 root root   234 Jan 15 14:30 files.log
-rw-r--r-- 1 root root    78 Jan 15 14:30 packet_filter.log
-rw-r--r-- 1 root root   123 Jan 15 14:30 weird.log
```

---

## Step 5: Exploring conn.log

The `conn.log` is the foundation of Zeek analysis.
It records every network connection.

```console
# View the header and first few lines
docker compose run --rm zeek-shell head -5 /logs/conn.log
```

The first line of every Zeek log is the field names:

```text
#separator \x09
#set_separator ,
#empty_field (empty)
#unset_field -
#path conn
#open 2024-01-15-14-30-00
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
#types  time   string  addr    port    addr    port    enum    string  interval count   count   string
```

Then each data line contains the actual connection record.
Use `zeek-cut` to extract specific fields:

```bash
# Extract timestamp, source IP, dest IP, dest port, bytes transferred
docker compose run --rm zeek-shell \
  zeek-cut ts id.orig_h id.resp_h id.resp_p service orig_bytes resp_bytes conn_state \
  < /logs/conn.log

# Find all connections that are NOT in the SF (successfully finished) state
docker compose run --rm zeek-shell sh -c \
  "zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state < /logs/conn.log | grep -v 'SF'"

# Find long-duration connections (possible beaconing/C2)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut ts id.orig_h id.resp_h duration < /logs/conn.log | sort -k4 -rn | head -10"
```

### Connection states explained

| State | Meaning |
|-------|---------|
| `SF` | Normal established and closed connection |
| `S0` | SYN sent, no response (port scan, firewall block) |
| `S1` | SYN+SYN-ACK, no final ACK |
| `REJ` | SYN sent, RST received (port closed) |
| `RSTO` | Connection reset by originator |
| `RSTR` | Connection reset by responder |
| `OTH` | No SYN seen — connection in progress at capture start |

> **Security note:** A large number of `S0` or `REJ` connections from a single source is a strong indicator of **port scanning**.

---

## Step 6: Exploring dns.log

```bash
# View all DNS queries
docker compose run --rm zeek-shell \
  zeek-cut ts id.orig_h query qtype_name rcode_name answers \
  < /logs/dns.log

# Find all NXDOMAIN responses (queried domains that don't exist)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut query rcode_name < /logs/dns.log | grep NXDOMAIN"

# Count unique domains queried
docker compose run --rm zeek-shell sh -c \
  "zeek-cut query < /logs/dns.log | sort | uniq -c | sort -rn"
```

> **Security note:** A host generating many NXDOMAIN responses may be running **DGA (Domain Generation Algorithm)** malware that tries random domain names to reach its C2 server.

---

## Step 7: Exploring http.log

```bash
# View all HTTP requests
docker compose run --rm zeek-shell \
  zeek-cut ts id.orig_h id.resp_h method host uri status_code user_agent \
  < /logs/http.log

# Find all non-200 responses
docker compose run --rm zeek-shell sh -c \
  "zeek-cut host uri status_code < /logs/http.log | awk '\$3 != 200'"

# Find interesting user-agents (possible malware or tools)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut user_agent < /logs/http.log | sort | uniq -c | sort -rn"

# Find large POST requests (possible data exfiltration)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut method uri request_body_len < /logs/http.log | awk '\$1 == \"POST\" && \$3 > 1000'"
```

---

## Step 8: Exploring ssl.log

```bash
# View TLS connection details
docker compose run --rm zeek-shell \
  zeek-cut ts id.orig_h id.resp_h server_name version cipher cert_chain_fuids \
  < /logs/ssl.log

# Find self-signed certificates (no validation chain — suspicious)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut server_name validation_status < /logs/ssl.log | grep -v 'ok'"

# Find old TLS versions (TLS 1.0/1.1 — security risk)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut version server_name < /logs/ssl.log | grep -E 'TLSv10|TLSv11'"
```

---

## Step 9: Exploring files.log

```console
# View all files seen in the capture
docker compose run --rm zeek-shell \
  zeek-cut ts source conn_uids mime_type filename md5 sha256 \
  < /logs/files.log

# Find executable files (potential malware delivery)
docker compose run --rm zeek-shell sh -c \
  "zeek-cut mime_type filename < /logs/files.log | grep -E 'exe|dll|application/x-'"
```

---

## Step 10: Live Network Monitoring with Zeek

For live monitoring (rather than PCAP analysis), start the full environment:

```console
docker compose up -d generate-traffic zeek-live
```

Watch Zeek logs in real time:

```console
# Follow the connection log as it grows
docker compose exec zeek-live tail -f /logs/conn.log | \
  docker compose exec -T zeek-live zeek-cut ts id.orig_h id.resp_h id.resp_p service

# Or use the built-in zeek-cut streaming
docker compose exec zeek-live sh -c \
  "tail -f /logs/http.log | zeek-cut ts id.orig_h host uri status_code"
```

---

## Step 11: Comparing Wireshark and Zeek Output

For the same traffic, compare what each tool produces:

| Question | Wireshark approach | Zeek approach |
|----------|--------------------|---------------|
| What IPs talked to each other? | Statistics → Conversations | `zeek-cut id.orig_h id.resp_h < conn.log` |
| What HTTP pages were requested? | Filter: `http.request` | `zeek-cut uri < http.log` |
| Were there any suspicious domains? | Filter: `dns` | `zeek-cut query rcode_name < dns.log` |
| What files were transferred? | File → Export Objects → HTTP | `zeek-cut mime_type filename < files.log` |
| Was TLS inspection possible? | Only metadata visible | `zeek-cut server_name version < ssl.log` |

---

## Step 12: Writing a Simple Zeek Script

Zeek is scriptable.
Create a simple script to detect HTTP requests to unusual ports:

```bash
cat > scripts/detect-http-unusual-port.zeek << 'EOF'
# Detect HTTP traffic on non-standard ports (not 80 or 8080)
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if (c$id$resp_p != 80/tcp && c$id$resp_p != 8080/tcp &&
        c$id$resp_p != 8000/tcp)
    {
        print fmt("[NOTICE] HTTP on unusual port %d: %s requested %s",
                  c$id$resp_p, c$id$orig_h, original_URI);
    }
}
EOF
```

Run Zeek with the custom script:

```console
docker compose run --rm zeek-shell \
  zeek -C -r /pcap/sample.pcap /scripts/detect-http-unusual-port.zeek
```

---

## Clean Up

```console
docker compose down -v
rm -rf logs/ pcap/
```

---

## Key Takeaways

* Zeek transforms raw packets into structured, per-protocol **log files**
* `conn.log` is the master log — every connection appears here
* `dns.log`, `http.log`, `ssl.log` provide protocol-specific details
* `zeek-cut` extracts specific fields from Zeek's tab-separated logs
* Connection states (SF, S0, REJ) provide quick insight into scan and attack activity
* Zeek is designed for **long-term monitoring**, not interactive packet inspection
* Zeek scripts extend detection capabilities with custom event handlers

---

## Exercises

1. In `conn.log`, find all connections with state `S0` or `REJ`. What might these indicate?
1. In `dns.log`, list all unique domains queried. Are any suspicious?
1. In `http.log`, what User-Agent strings appear? Are they what you expected?
1. Run Zeek against the Demo 01 capture. How do the results compare to your Wireshark analysis?
1. Modify the custom script to also log the destination IP when detecting HTTP on unusual ports.

---

## References

* Zeek Documentation: https://docs.zeek.org/
* The Zeek Book: https://book.zeek.org/
* Zeek log fields reference: https://docs.zeek.org/en/master/script-reference/log-files.html
