# Final Practice Quiz — Session 02: Practical Assessment

**Purpose:** Assess practical understanding of hands-on session content

**Format:** 5 short-answer questions + 2 long-answer questions

**Time limit:** 45 minutes

**Instructions:** Write your answers in full sentences.
Short-answer questions require 2–5 sentences.
Long-answer questions require a structured response of 200–400 words each.

---

## Short-Answer Questions (10 points each)

### Question 1

You run the following `tshark` command against a PCAP file:

```console
tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport
```

The output shows 1,247 lines, all with the same source IP (`203.0.113.45`) connecting to many different destination ports on `10.0.1.0/24` hosts.

a) What activity does this output describe?
b) Write a Snort rule that would detect and alert on this activity.
c) What TWO Zeek log files would contain evidence of this activity, and which `conn_state` value would you search for?

---

### Question 2

Explain the difference between these two Zeek connection states observed in `conn.log`:

| conn_state | id.orig_h | id.resp_h | id.resp_p | proto |
|------------|-----------|-----------|-----------|-------|
| SF         | 10.10.1.5 | 8.8.8.8   | 443       | tcp   |
| S0         | 10.10.1.5 | 8.8.8.8   | 4444      | tcp   |

a) What happened for the `SF` state connection?
b) What happened for the `S0` state connection?
c) Which of these is more suspicious and why?

---

### Question 3

A junior analyst has written the following Syslog query to find successful root logins:

```text
grep "root" /var/log/auth.log
```

Identify two problems with this approach and write an improved command that:

1. Filters specifically for **successful** authentication
1. Includes only the `root` username
1. Shows the timestamp and source IP

---

### Question 4

You are setting up a Docker-based Zeek sensor to monitor a small lab network.
Your `docker-compose.yml` starts Zeek with:

```text
command: zeek -C -r /pcap/capture.pcap
```

a) What does the `-C` flag do?
b) What does the `-r` flag do (vs. `-i`)?
c) After running this command, you see `conn.log` but no `http.log`.
Name TWO possible reasons why `http.log` was not generated.

---

### Question 5

Match each tool to its PRIMARY use case (one tool may have multiple use cases — choose the BEST primary match):

| Tool | Primary Use Case |
|------|----------------|
| Wireshark | ? |
| Zeek | ? |
| Snort | ? |
| tcpdump | ? |
| NetworkMiner | ? |

Choose from:

* (a) Rule-based real-time intrusion detection/prevention
* (b) Command-line packet capture and basic filtering
* (c) Generating structured per-protocol log files for long-term monitoring
* (d) GUI-based deep packet inspection and protocol analysis
* (e) Reconstructing files and extracting artefacts from PCAP files

---

## Long-Answer Questions (25 points each)

### Question 6

**Scenario:**
You receive an alert from your SIEM: "High volume of DNS queries to unusual domains from 10.10.5.77".
You open Zeek's `dns.log` and find the following entries (abbreviated):

```text
ts             id.orig_h   id.resp_h  query                                             qtype  rcode
1705372200.0   10.10.5.77  8.8.8.8    mNpq9rLt3vWx7uYe2sOf5aHj.relay.badactor.net      TXT    NOERROR
1705372201.0   10.10.5.77  8.8.8.8    oQrs0sNu4wXy8vZf3tPg6bIk.relay.badactor.net      TXT    NOERROR
[... 200 more similar entries over 10 minutes ...]
1705372800.0   10.10.5.77  8.8.8.8    payroll.acme-internal.corp                        A      NXDOMAIN
1705372801.0   10.10.5.77  8.8.8.8    dc01.acme-internal.corp                           A      NXDOMAIN
1705372802.0   10.10.5.77  8.8.8.8    backup.acme-internal.corp                         A      NXDOMAIN
```

Write a structured investigation response covering:

1. **What is happening?** Identify and name the attack technique(s) you see
1. **Evidence analysis:** Explain what each type of DNS query tells you about the attacker's actions
1. **Immediate actions:** What do you do in the next 15 minutes?
1. **Containment:** What firewall/DNS changes do you make?
1. **How could this have been detected sooner?** What monitoring improvements would help?

---

### Question 7

**Design Question:**
A small e-commerce company (50 employees, 1 physical office, 1 cloud-hosted web application) asks you to design a basic network security monitoring setup.
Their constraints are:

* Budget: €5,000/year for tools and infrastructure
* Staff: 1 part-time IT person (2 hours/day for security tasks)
* Infrastructure: Managed switch (supports SPAN), FortiGate firewall, internet connection (500 Mbps)
* Data: Customer payment card data (PCI-DSS scope), employee personal data (GDPR)

Design a practical monitoring solution that:

1. Identifies which 3 log sources are most valuable given their constraints
1. Specifies what tools to use (must be open source or very low cost)
1. Describes where to place monitoring sensors
1. Explains what automated alerts to configure
1. Considers PCI-DSS and GDPR compliance requirements

Justify every decision in terms of the specific constraints provided.

---

## Scoring Guide

| Component | Points | Criteria |
|-----------|--------|---------|
| Q1 (Short) | 10 | 3-4 pts per sub-part: correctness, specificity |
| Q2 (Short) | 10 | 3-4 pts per sub-part: accurate state explanation |
| Q3 (Short) | 10 | 5 pts per problem identified; correct grep command |
| Q4 (Short) | 10 | 3-4 pts per sub-part; Docker/Zeek knowledge |
| Q5 (Short) | 10 | 2 pts per correct match |
| Q6 (Long) | 25 | 5 pts per section; accuracy and completeness |
| Q7 (Long) | 25 | 5 pts per requirement; realistic and justified |
| **Total** | **100** | |

Passing: 65/100

---

## Answer Key

### Q1 Answers

**a)** This output describes a **TCP SYN port scan** (specifically a half-open/stealth scan).
The source IP `203.0.113.45` is sending SYN packets to many different ports on the `10.0.1.0/24` network, trying to discover which ports are open.
The fact that there are 1,247 lines suggests a large number of port/host combinations were probed.

**b)** Snort rule:

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any \
    (msg:"TCP SYN Port Scan Detected"; \
     flags:S,!APUR; \
     threshold: type both, track by_src, count 20, seconds 5; \
     sid:1000003; rev:1; \
     classtype:attempted-recon; priority:2;)
```

**c)** Two Zeek log files:

1. `conn.log` — search for `conn_state == "S0"` (SYN sent, no response) or `conn_state == "REJ"` (SYN sent, RST received = port closed)
1. `notice.log` — if Zeek's scan detection policy is loaded, scan events are written here

---

### Q2 Answers

**a) SF state:** The connection to `8.8.8.8:443` was **Successfully Finished** (SF).
Both sides completed the TCP handshake, exchanged data, and closed the connection cleanly with FIN/ACK.
This is entirely normal HTTPS traffic.

**b) S0 state:** The connection to `8.8.8.8:4444` shows **SYN sent but no response received** (S0).
The client attempted to initiate a TCP connection but the server either didn't respond, or the traffic was blocked by a firewall before reaching the destination.

**c)** The `S0` connection to port 4444 is more suspicious.
Port 4444 is the default Metasploit Meterpreter listener port — it has essentially no legitimate use.
The S0 state could mean the malware tried to establish a reverse shell to an attacker's server but was blocked by a firewall.
This should be investigated immediately.

---

### Q3 Answers

**Problems:**

1. `grep "root"` matches any line containing the word "root" — this includes failed logins, logout events, sudo commands, cron jobs running as root, etc. It generates many false positives.
1. The command doesn't distinguish between failed and successful authentication.

**Improved command:**

```console
grep "Accepted.*for root" /var/log/auth.log | \
    awk '{print $1, $2, $3, $NF, $(NF-3)}'
```

Or more precisely:

```console
grep -P "Accepted (password|publickey) for root from" /var/log/auth.log
```

This matches only "Accepted" (successful) authentication events for the root user, and the `from` keyword captures the source IP that follows.

---

### Q4 Answers

**a)** The `-C` flag tells Zeek to **ignore bad/invalid checksums** in packets.
This is necessary because virtualised environments (Docker, VMware) sometimes generate packets with incorrect checksums (due to checksum offloading to the NIC).
Without `-C`, Zeek would skip these packets and miss traffic.

**b)** `-r /pcap/capture.pcap` tells Zeek to **read from a PCAP file** (offline mode).
The `-i eth0` flag (alternative) tells Zeek to listen on a **live network interface** (online mode).
The `-r` flag is for post-incident analysis; `-i` is for continuous monitoring.

**c)** Two reasons why `http.log` might not be generated:

1. **No HTTP traffic in the capture** — if the capture only contains DNS, TLS, or other non-HTTP traffic, Zeek won't create an `http.log` (it only creates log files for protocols it actually sees)
1. **HTTP not running on port 80** — Zeek uses port 80 as the default for HTTP detection. If HTTP traffic uses a non-standard port (8080, 8000), Zeek may not identify it as HTTP without a `DPD::ports` configuration change

---

### Q5 Answers

| Tool | Primary Use Case |
|------|----------------|
| Wireshark | (d) GUI-based deep packet inspection and protocol analysis |
| Zeek | (c) Generating structured per-protocol log files for long-term monitoring |
| Snort | (a) Rule-based real-time intrusion detection/prevention |
| tcpdump | (b) Command-line packet capture and basic filtering |
| NetworkMiner | (e) Reconstructing files and extracting artefacts from PCAP files |

---

### Q6 Model Answer (abbreviated — see full solution in session materials)

**What is happening:** Two attack techniques are visible:

1. **DNS Tunnelling / C2 via DNS** — 200+ TXT record queries with random-looking 32-character subdomains to `relay.badactor.net`. This is a compromised host communicating with a C2 server via DNS.
1. **Internal Reconnaissance via DNS** — Queries for internal hostnames (payroll, dc01, backup) going to external resolver `8.8.8.8`. The attacker is mapping the internal network.

**Evidence analysis:** The TXT queries encode data in subdomains; NOERROR means the C2 server received them.
The NXDOMAIN queries for internal hostnames reveal the attacker is using DNS to fingerprint what services exist internally.

**Immediate actions:** Isolate `10.10.5.77`.
Check which user/process is generating DNS queries (endpoint investigation).
Preserve all Zeek logs.

**Containment:** Block `relay.badactor.net` at DNS resolver.
Block port 53 UDP to `8.8.8.8` — force all DNS through corporate resolver.
Block outbound DNS TXT queries at firewall.

**Earlier detection:** A Zeek script checking subdomain length (>25 chars) would have detected this.
A rule blocking outbound DNS to non-corporate resolvers would have prevented the bypass.

---

### Q7 Model Answer (abbreviated)

**Three most valuable log sources:**

1. **Firewall logs (FortiGate)** — already available, covers all traffic. Provides connection allow/deny, URL filtering for cloud WAF.
1. **Zeek on SPAN port** — one sensor covers all traffic; structured logs. Most value per euro.
1. **Web application access logs** — directly in PCI-DSS scope; captures customer-facing attacks.

**Tools (all free/open source):**

* Zeek (free) on a Raspberry Pi 4 or cheap VM connected to SPAN port
* Wazuh (free) to collect FortiGate syslog + Zeek logs
* Wazuh dashboard for alerts

**Sensor placement:**

* SPAN port on managed switch → Zeek sensor
* FortiGate syslog → Wazuh server

**Automated alerts (3 critical for PCI-DSS):**

1. Any connection attempt to database ports (3306, 5432, 1433) from non-application IP
1. HTTP 500 errors in web app logs (possible injection)
1. Authentication failures > 10 in 5 minutes

**PCI-DSS and GDPR:** Zeek+Wazuh supports PCI-DSS Req 10 (logging) and Req 11.4 (IDS).
For GDPR: minimise capture scope, don't log payment card numbers in cleartext, document the legitimate interest basis.
With only 1 part-time person, focus alerts on the highest-risk scenarios and automate as much as possible.
