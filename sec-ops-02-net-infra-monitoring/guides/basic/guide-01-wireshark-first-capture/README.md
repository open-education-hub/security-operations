# Guide 01: Your First Packet Capture with Wireshark

**Level:** Beginner

**Duration:** 60–90 minutes

**Tools:** Docker, Docker Compose, Wireshark / tshark

**Format:** Step-by-step guided walkthrough

---

## Introduction

This guide walks you through capturing and analysing network traffic using Wireshark in a Docker-based lab environment.
By the end, you will be able to:

* Set up a Docker network lab for packet capture
* Capture live traffic using tcpdump and save it to PCAP format
* Open and navigate a PCAP file in Wireshark
* Use display filters to find specific traffic
* Reconstruct TCP conversations using "Follow Stream"
* Export captured files and statistics

This guide builds on Demo 01.
If you have already completed Demo 01, some steps here will be familiar — this guide goes deeper into the analysis.

---

## Part 1: Setting Up the Lab

### 1.1 Prerequisites Check

Before starting, verify your environment:

```console
# Check Docker is installed and running
docker --version
docker compose version
docker ps  # Should return empty list or running containers

# Check available disk space (you need at least 2 GB)
df -h .
```

### 1.2 Create the Lab Environment

```console
mkdir wireshark-lab && cd wireshark-lab
mkdir -p capture web
```

Create a web page that will be served by our lab server:

```bash
cat > web/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wireshark Lab Server</title>
</head>
<body>
    <h1>Wireshark Lab — NSM Training</h1>
    <p>This page is used for packet capture exercises.</p>
    <p>When you request this page, your browser sends an HTTP GET request
    that you can observe in your packet capture.</p>
</body>
</html>
EOF

cat > web/login.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Login Page</title></head>
<body>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
</body>
</html>
EOF
```

Create the Docker Compose file:

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'
networks:
  lab-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24

services:
  web:
    image: nginx:alpine
    networks:
      lab-net:
        ipv4_address: 172.30.0.2
    volumes:
      - ./web:/usr/share/nginx/html:ro

  client:
    image: alpine:3.18
    networks:
      lab-net:
        ipv4_address: 172.30.0.10
    depends_on: [web]
    command: >
      sh -c "apk add --no-cache curl wget 2>/dev/null && sleep 3 &&
      while true; do
        curl -s -o /dev/null http://web/;
        curl -s -o /dev/null http://web/login.html;
        curl -s -d 'username=alice&password=secret123' http://web/login;
        wget -q -O /dev/null http://web/index.html 2>&1;
        sleep 8;
      done"

  capture:
    image: nicolaka/netshoot
    network_mode: "service:web"
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./capture:/capture
    command: tcpdump -i eth0 -s 0 -w /capture/lab.pcap tcp
EOF
```

Start the environment:

```console
docker compose up -d
```

Let it run for 60–90 seconds to accumulate traffic:

```console
sleep 90
docker compose stop capture
```

Verify the PCAP was created:

```console
ls -lh capture/lab.pcap
# Expected: 10 KB – 500 KB depending on traffic volume
```

---

## Part 2: Basic Wireshark Navigation

### 2.1 Opening a PCAP File

**If Wireshark is installed on your host:**

```console
wireshark capture/lab.pcap
```

**Using tshark (command-line, always available via Docker):**

```console
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark tshark -r /data/lab.pcap -q -z io,phs
```

### 2.2 The Three-Pane View

When Wireshark opens, you see:

```text
┌─────────────────────────────────────────────────────────┐
│ FILTER BAR: [                              ] Apply Clear │
├──────────────────────────────────────────────────────────┤
│ PACKET LIST PANE                                         │
│ No. | Time   | Source       | Destination  | Proto| Info │
│   1 | 0.0000 | 172.30.0.10  | 172.30.0.2   | TCP  | SYN  │
│   2 | 0.0001 | 172.30.0.2   | 172.30.0.10  | TCP  | SA   │
│   3 | 0.0001 | 172.30.0.10  | 172.30.0.2   | TCP  | A    │
│   4 | 0.0002 | 172.30.0.10  | 172.30.0.2   | HTTP | GET /│
│   5 | 0.0010 | 172.30.0.2   | 172.30.0.10  | HTTP | 200  │
│   ...                                                    │
├─────────────────────────────────────────────────────────┤
│ PACKET DETAILS PANE (when you click a packet)            │
│  ▼ Frame 4: 152 bytes on wire                            │
│  ▼ Ethernet II, Src: 02:42:ac:1e:00:0a                  │
│  ▼ Internet Protocol Version 4                           │
│    Source: 172.30.0.10, Destination: 172.30.0.2         │
│    TTL: 64, Protocol: 6 (TCP)                            │
│  ▼ Transmission Control Protocol                         │
│    Src Port: 54321, Dst Port: 80                         │
│    Flags: PSH, ACK                                       │
│  ▼ Hypertext Transfer Protocol                           │
│    GET /index.html HTTP/1.1\r\n                          │
│    Host: web\r\n                                        │
│    User-Agent: curl/7.88.0\r\n                          │
├─────────────────────────────────────────────────────────┤
│ PACKET BYTES PANE                                        │
│ 0000: 02 42 ac 1e 00 02 02 42  ac 1e 00 0a 08 00 45 00  │
│ 0010: 00 94 00 01 40 00 40 06  ...                       │
└─────────────────────────────────────────────────────────┘
```

**Practice:** Click on the first TCP SYN packet.
Expand each protocol layer in the details pane.
Can you find:

* The source and destination MAC addresses?
* The source and destination IP addresses?
* The TCP source and destination ports?
* The TCP flags (which flags are set)?

### 2.3 Colour Coding

Wireshark uses colours to highlight different traffic:

* **Light blue:** DNS
* **Light green:** HTTP
* **Dark green:** TCP (general)
* **Yellow:** ARP
* **Red/Black:** TCP errors (retransmissions, resets)
* **Light purple:** ICMP

These colours can be customised under View → Coloring Rules.

---

## Part 3: Display Filters

Display filters are the most powerful navigation tool in Wireshark.
They narrow what is shown without deleting any packets.

### 3.1 Basic Filter Syntax

```text
# By protocol
http
dns
tcp
udp
icmp
arp

# By IP address
ip.addr == 172.30.0.10         # Packets to OR from this IP
ip.src == 172.30.0.10          # Packets FROM this IP
ip.dst == 172.30.0.2           # Packets TO this IP

# By port
tcp.port == 80
tcp.dstport == 80
tcp.srcport == 80

# By TCP flags
tcp.flags.syn == 1             # All SYN packets
tcp.flags.syn == 1 and tcp.flags.ack == 0   # Only SYN (not SYN-ACK)
tcp.flags.rst == 1             # All RST packets

# Combining filters
http and ip.src == 172.30.0.10
tcp and (tcp.port == 80 or tcp.port == 443)
not arp                        # Exclude ARP

# By content (string in payload)
http.request.uri contains "login"
http.request.method == "POST"
```

### 3.2 Filter Exercises

Apply each filter and note what you observe:

**Exercise 3.2.1:** Apply `tcp.flags.syn == 1 and tcp.flags.ack == 0`

* How many SYN packets are there?
* Each SYN represents the *start* of a new TCP connection. What destinations are being connected to?

**Exercise 3.2.2:** Apply `http.request`

* How many HTTP requests were made?
* What URIs were requested? (Look in the Info column)

**Exercise 3.2.3:** Apply `http.request.method == "POST"`

* Are there any POST requests?
* What URI are they going to?
* Click on a POST packet and expand the HTTP layer. Can you see the POST body?

**Exercise 3.2.4:** Apply `tcp.flags.rst == 1`

* RST packets indicate an abruptly closed connection. Do you see any?
* What does this tell you?

---

## Part 4: Following TCP Streams

Wireshark can reconstruct entire TCP conversations from individual packets.

### 4.1 Follow a TCP Stream

1. Find any HTTP GET request in the packet list
1. Right-click on the packet
1. Select **Follow → TCP Stream**

A new window appears showing the full conversation:

```text
GET / HTTP/1.1
Host: web
User-Agent: curl/7.88.0
Accept: */*

HTTP/1.1 200 OK
Server: nginx/1.25.3
Date: Mon, 15 Jan 2024 14:30:00 GMT
Content-Type: text/html
Content-Length: 278

<!DOCTYPE html>
<html lang="en">
...
```

* **Red text** = traffic from client to server
* **Blue text** = traffic from server to client

### 4.2 Finding Cleartext Credentials

Since the client container sends a POST to `/login` with `username=alice&password=secret123`, you should be able to find this in the capture.

1. Apply filter: `http.request.method == "POST"`
1. Click on the POST packet
1. In the packet details, expand **Hypertext Transfer Protocol**
1. Look for the **HTML Form URL Encoded** section

Or use Follow TCP Stream to see the full login transaction:

```text
POST /login HTTP/1.1
Host: web
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=alice&password=secret123
```

> **Security observation:** HTTP carries form data in cleartext, including passwords. Anyone with access to the network can see these credentials. This is why HTTPS is mandatory for any page that handles authentication.

### 4.3 Exercises

**Exercise 4.3.1:** Find the POST request with login credentials.
What is the username and password?

**Exercise 4.3.2:** Find an HTTP 404 Not Found response (the client tries to fetch a page that doesn't exist).
What URI triggered the 404?

**Exercise 4.3.3:** Right-click on any HTTP response and choose Follow → TCP Stream.
Can you read the HTML content of the response?

---

## Part 5: Statistics and Analysis

### 5.1 Protocol Hierarchy

Go to **Statistics → Protocol Hierarchy**.

This shows the breakdown of traffic by protocol as a percentage of total bytes and packets.
For our lab, you should see:

```text
Protocol        Packets %    Bytes %
Ethernet        100%         100%
  IPv4          ~98%         ~98%
    TCP         ~98%         ~98%
      HTTP      ~70%         ~80%
        Data    ~20%         ~30%
```

### 5.2 Conversations

Go to **Statistics → Conversations → TCP tab**.

This shows each TCP connection as a row with:

* Source and destination IP/port
* Number of packets in each direction
* Total bytes transferred
* Duration

Sort by bytes descending — which connection transferred the most data?

### 5.3 I/O Graph

Go to **Statistics → I/O Graph**.

This shows traffic volume over time.
You should see periodic spikes every ~8 seconds (when the client generates traffic) with quiet periods in between.

This pattern — regular bursts at fixed intervals — is characteristic of **beaconing** behaviour seen in malware communicating with C2 servers.

### 5.4 Using tshark for Statistics

```bash
# Protocol hierarchy
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap -q -z io,phs

# TCP conversations
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap -q -z conv,tcp

# All HTTP request URIs
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap -Y "http.request" \
  -T fields -e http.request.method -e http.request.uri \
  -e http.user_agent

# Extract POST body content
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap -Y "http.request.method==POST" \
  -T fields -e http.file_data
```

---

## Part 6: Exporting Data

### 6.1 Export Packets (Filtered Subset)

To save only HTTP packets to a new PCAP:

```console
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap \
  -Y "http" \
  -w /data/http-only.pcap

ls -lh capture/http-only.pcap
```

### 6.2 Export HTTP Objects

Wireshark can extract files transferred over HTTP directly from a PCAP.
In the GUI:

**File → Export Objects → HTTP**

This shows a list of all HTTP-transferred files (HTML, images, scripts) that you can save to disk.
This is invaluable when investigating malware distribution via HTTP.

### 6.3 Export Packet Details as CSV

```bash
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/lab.pcap \
  -T fields \
  -e frame.number \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport \
  -e http.request.method \
  -e http.request.uri \
  -E header=y \
  -E separator=, \
  -E quote=d \
  -Y "http.request" \
  > capture/http-requests.csv

cat capture/http-requests.csv
```

---

## Part 7: Comparing Filters — Security Investigation Workflow

Imagine you received an alert: "Possible credential harvesting on IP 172.30.0.10".
Work through this investigation:

**Step 1:** Show all traffic from the suspect IP

```text
ip.src == 172.30.0.10
```

Count packets, identify all destination IPs.

**Step 2:** Look for authentication-related traffic

```text
ip.src == 172.30.0.10 and http.request.method == "POST"
```

**Step 3:** Follow the POST stream to see credentials

**Step 4:** Check response codes

```text
ip.src == 172.30.0.10 and http.response.code >= 400
```

Were there many errors, suggesting credential stuffing?

**Step 5:** Look at timing
Open **Statistics → I/O Graph** filtered to `ip.addr == 172.30.0.10`.
Is the traffic regular (automated) or irregular (human)?

**Step 6:** Write your findings:

```text
INVESTIGATION FINDINGS
======================
Suspect IP: 172.30.0.10
Finding: HTTP POST requests to /login with cleartext credentials
Credentials observed: alice / secret123
Traffic pattern: Automated (regular interval, 8s)
Assessment: Automated credential testing tool
Recommendation: Block source IP; investigate source host
```

---

## Clean Up

```console
docker compose down -v
rm -rf capture/ web/
```

---

## Summary

You have learned to:

* Capture live network traffic using tcpdump in Docker
* Navigate Wireshark's three-pane interface
* Apply display filters to isolate relevant traffic
* Follow TCP streams to reconstruct conversations
* Find cleartext credentials in HTTP traffic
* Generate protocol statistics and conversation summaries
* Conduct a basic security investigation workflow

---

## Next Steps

* **Guide 02:** Protocol Analysis — go deeper into individual protocols
* **Guide 03:** Network Log Formats — learn Syslog, NetFlow, and how logs complement PCAPs
* **Drill 01:** Protocol Identification — test your knowledge with 10 log/packet snippets
