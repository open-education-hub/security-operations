# Demo 01: Wireshark Basics — Installation and First Packet Capture

**Level:** Beginner

**Duration:** 30–45 minutes

**Tools:** Docker, Docker Compose, Wireshark (containerised)
**Learning objectives:**

* Install and launch Wireshark using Docker (no host installation required)
* Perform a live packet capture on a Docker network
* Navigate the Wireshark interface: packet list, packet details, packet bytes
* Apply basic display filters to isolate traffic of interest
* Follow a TCP stream to reconstruct a conversation

---

## Prerequisites

* Docker and Docker Compose installed on your machine
* Basic familiarity with the Linux command line
* Completion of the session reading (Sections 3 and 4.1)

---

## Background

Wireshark is a **packet analyser** — it captures raw packets from a network interface and lets you inspect every field of every protocol header.
In this demo, we will:

1. Spin up a small Docker network with a web server and a client
1. Capture traffic generated between those containers
1. Analyse the captured packets using tcpdump inside the container (producing a PCAP)
1. Open the PCAP in Wireshark for analysis

> **Why Docker?** Installing Wireshark directly on your machine is possible, but requires elevated privileges and varies by OS. Docker gives us a reproducible environment and avoids modifying your host system.

---

## Step 1: Project Structure

Create a working directory and navigate into it:

```console
mkdir wireshark-demo && cd wireshark-demo
```

The directory will contain:

```text
wireshark-demo/
├── docker-compose.yml
├── capture/          # PCAP files will be written here
└── web/
    └── index.html    # Simple web page served by nginx
```

Create the directories:

```console
mkdir -p capture web
```

Create a simple web page:

```bash
cat > web/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>NSM Demo Server</title></head>
<body>
  <h1>Network Security Monitoring Lab</h1>
  <p>This page is served for packet capture demonstration purposes.</p>
  <p>Session: SO-02 | Tool: Wireshark</p>
</body>
</html>
EOF
```

---

## Step 2: Docker Compose Configuration

The `docker-compose.yml` below defines three services on a custom network:

* **web**: An nginx web server
* **client**: A container that generates HTTP traffic
* **capture**: A tcpdump container that writes traffic to a PCAP file

---

## Step 3: Start the Environment

```console
docker compose up -d
```

Expected output:

```text
[+] Running 4/4
 ✔ Network wireshark-demo_demo-net  Created
 ✔ Container web                    Started
 ✔ Container capture                Started
 ✔ Container client                 Started
```

Verify all containers are running:

```console
docker compose ps
```

---

## Step 4: Generate Traffic

The client container will automatically generate HTTP requests every 5 seconds.
You can also trigger requests manually:

```bash
# Open a shell in the client container
docker compose exec client sh

# Make several HTTP requests
for i in $(seq 1 10); do
  wget -q -O /dev/null http://web/
  sleep 1
done

exit
```

You can also generate more interesting traffic patterns:

```bash
# Simulate a basic scan (SYN to closed ports — useful for IDS demos)
docker compose exec client sh -c "for p in 22 23 25 80 443 3306 5432; do \
  nc -z -w1 web \$p 2>/dev/null && echo 'open: '\$p || echo 'closed: '\$p; done"
```

---

## Step 5: Capture Traffic with tcpdump

The `capture` container is already running tcpdump.
Check what it's writing:

```console
# View live tcpdump output
docker compose logs -f capture
```

Stop the capture after generating enough traffic:

```console
docker compose stop capture
```

The PCAP file is in the `capture/` directory on your host:

```console
ls -lh capture/
# demo-capture.pcap  (typically 10-100 KB for a short capture)
```

---

## Step 6: Analyse the PCAP with Wireshark (GUI)

### Option A: Wireshark installed on your host

If you have Wireshark installed:

```console
wireshark capture/demo-capture.pcap
```

### Option B: tshark (command-line Wireshark) via Docker

```console
docker run --rm -v "$(pwd)/capture:/data" \
  linuxserver/wireshark \
  tshark -r /data/demo-capture.pcap
```

### Option C: tshark analysis (recommended for this demo)

Use tshark to explore the capture in the terminal:

```bash
# Count packets by protocol
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap \
  -q -z io,phs

# List all unique IP conversations
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap \
  -q -z conv,ip

# Extract all HTTP request URIs
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap \
  -Y "http.request" \
  -T fields -e ip.src -e http.request.method -e http.request.uri

# Show TCP handshakes (SYN packets only)
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap \
  -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport
```

---

## Step 7: Understanding the Wireshark Interface

When you open the PCAP in Wireshark, you see three panes:

```text
┌─────────────────────────────────────────────────────────┐
│  PACKET LIST PANE                                       │
│  No. | Time  | Source  | Destination | Protocol | Info  │
│  1   | 0.000 | 172.20.0.3 | 172.20.0.2 | TCP    | SYN   │
│  2   | 0.001 | 172.20.0.2 | 172.20.0.3 | TCP    | SYN-ACK│
│  3   | 0.001 | 172.20.0.3 | 172.20.0.2 | TCP    | ACK   │
│  4   | 0.002 | 172.20.0.3 | 172.20.0.2 | HTTP   | GET / │
│  ...                                                    │
├─────────────────────────────────────────────────────────┤
│  PACKET DETAILS PANE (click a packet to expand)        │
│  ▼ Frame 4: 152 bytes on wire                          │
│    ▼ Ethernet II                                        │
│      Src: 02:42:ac:14:00:03                            │
│      Dst: 02:42:ac:14:00:02                            │
│    ▼ Internet Protocol Version 4                       │
│      Source: 172.20.0.3                                │
│      Destination: 172.20.0.2                           │
│      TTL: 64, Protocol: TCP                            │
│    ▼ Transmission Control Protocol                     │
│      Src Port: 54321, Dst Port: 80                     │
│      Flags: PSH, ACK                                   │
│    ▼ Hypertext Transfer Protocol                       │
│      GET / HTTP/1.0\r\n                               │
│      Host: web\r\n                                    │
├─────────────────────────────────────────────────────────┤
│  PACKET BYTES PANE                                      │
│  0000  02 42 ac 14 00 02 02 42  ac 14 00 03 08 00 ...  │
│  0010  45 00 00 94 ...                                 │
└─────────────────────────────────────────────────────────┘
```

### Key fields to identify:

**Ethernet frame:**

* `Src MAC` and `Dst MAC` — hardware addresses

**IP packet:**

* `Source IP` and `Destination IP`
* `TTL` — time to live (64 means Linux host, 128 means Windows)
* `Protocol` — 6=TCP, 17=UDP

**TCP segment:**

* `Src Port` and `Dst Port`
* `Flags` — SYN/SYN-ACK/ACK/PSH/FIN/RST
* `Seq` and `Ack` numbers

**HTTP layer:**

* `Method` (GET/POST)
* `URI` (path requested)
* `Host` header
* Response `Status Code`

---

## Step 8: Applying Display Filters

Display filters in Wireshark narrow down which packets are shown.
They do **not** delete packets from the capture.

```text
# Show only HTTP traffic
http

# Show only traffic to/from a specific IP
ip.addr == 172.20.0.2

# Show only TCP SYN packets (start of connections)
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Show HTTP requests with a specific URI
http.request.uri contains "/"

# Show responses with HTTP 200 OK
http.response.code == 200

# Show large TCP segments (possible data exfiltration)
tcp.len > 1000

# Combine filters with 'and', 'or', 'not'
http and ip.src == 172.20.0.3
```

### Exercise: Try these filters

1. Apply `tcp.flags.syn == 1` — how many new connections were established?
1. Apply `http.request` — how many HTTP requests were made?
1. Click on one HTTP GET packet and follow the stream: **Right-click → Follow → TCP Stream**. What do you see?

---

## Step 9: Following a TCP Stream

Right-click on any HTTP packet and select **Follow → TCP Stream**.
This reconstructs the entire conversation:

```text
GET / HTTP/1.0
Host: web
User-Agent: Wget/1.34
Accept: */*
Connection: close

HTTP/1.1 200 OK
Server: nginx/1.25.3
Date: Mon, 15 Jan 2024 14:23:45 GMT
Content-Type: text/html
Content-Length: 195

<!DOCTYPE html>
<html>
...
```

The **red text** is traffic from the client; **blue text** is from the server.
This view makes it easy to see exactly what was communicated.

---

## Step 10: Export Statistics

Under the **Statistics** menu, explore:

* **Protocol Hierarchy:** What percentage of traffic is each protocol?
* **Conversations:** Which IP pairs exchanged the most data?
* **I/O Graphs:** Traffic volume over time
* **Expert Information:** Wireshark-detected issues (retransmissions, resets, etc.)

Using tshark:

```console
# Protocol hierarchy
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap -q -z io,phs

# Top conversations by bytes
docker compose run --rm tshark \
  tshark -r /data/demo-capture.pcap -q -z conv,tcp
```

---

## Clean Up

```console
docker compose down -v
rm -rf capture/
```

---

## Key Takeaways

* Wireshark/tcpdump captures **raw packets** at the network interface level
* Every packet contains multiple protocol layers (Ethernet → IP → TCP → HTTP)
* **Display filters** isolate packets of interest without modifying the capture
* **Follow TCP Stream** reconstructs full application-layer conversations
* For automated or high-volume analysis, use `tshark` (command-line) instead of the GUI
* PCAP files can be shared and re-analysed — they are the "source of truth" in network investigations

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No packets captured | Check `docker compose ps` — is the capture container running? |
| Permission denied on capture/ directory | Run `chmod 777 capture/` |
| tshark not found | Use `docker compose run --rm tshark ...` as shown |
| PCAP file is empty (0 bytes) | Ensure traffic was generated before stopping capture |

---

## Next Steps

* Proceed to **Demo 02** to see how Zeek analyses the same traffic and generates structured logs
* Try **Guide 01** for a deeper walkthrough of Wireshark's features
* Challenge: modify the `client` service to generate DNS queries and HTTP POST requests, then find them in Wireshark
