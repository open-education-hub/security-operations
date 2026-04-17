# Demo 04: Snort IDS — Introduction, Rule Writing, and Alert Generation

**Level:** Beginner–Intermediate

**Duration:** 45–60 minutes

**Tools:** Docker, Docker Compose, Snort 3
**Learning objectives:**

* Run Snort 3 in a Docker container in IDS mode
* Understand the structure of a Snort rule
* Write basic rules for common attack scenarios
* Generate traffic that triggers alerts and interpret Snort's output
* Understand the difference between IDS (detection only) and IPS (inline blocking)

---

## Prerequisites

* Docker and Docker Compose installed
* Completion of Demo 01 (Wireshark) and Demo 02 (Zeek)
* Basic understanding of TCP/IP protocols from the reading material

---

## Background

**Snort** is a rule-based Intrusion Detection System.
It reads packets (live or from a PCAP file) and compares them against a set of **rules**.
When a packet matches a rule, Snort generates an **alert**.

Unlike Zeek, which produces logs for *all* traffic, Snort is focused on detecting *specific threats* defined in its ruleset.
This makes Snort:

* **Efficient** — only alerts on what you tell it to watch for
* **Precise** — rules can be tuned to minimise false positives
* **Dependent on rule quality** — it cannot detect attacks that have no matching rule

### Snort 3 vs. Snort 2

This demo uses **Snort 3**, which differs from Snort 2 in several ways:

* Lua-based configuration (not the old `snort.conf`)
* Multi-threaded processing
* Improved protocol normalisation
* Better performance and maintainability

The rule syntax remains largely the same.

---

## Step 1: Project Structure

```console
mkdir snort-demo && cd snort-demo
mkdir -p rules logs pcap
```

```text
snort-demo/
├── docker-compose.yml
├── snort.lua              # Main Snort 3 configuration
├── rules/
│   └── local.rules        # Custom rules you will write
├── logs/                  # Alert output goes here
└── pcap/                  # PCAP files for offline analysis
```

---

## Step 2: Snort Configuration File

Create the main Snort configuration:

```bash
cat > snort.lua << 'EOF'
-- Snort 3 configuration for the SO-02 demo
-- This is a minimal configuration suitable for learning

-- Define the home network (our protected network)
HOME_NET = '172.22.0.0/24'
EXTERNAL_NET = '!HOME_NET'

-- Include the IPS module
ips =
{
    -- Use rules from our local rules file
    include = 'rules/local.rules',
    -- Enable all built-in rule groups
    enable_builtin_rules = true,
}

-- Output: unified2 format and fast alert text
alert_fast =
{
    file = true,
    packet = false,
}

-- Log packets that trigger alerts
output =
{
    -- Write alerts to /logs/alert_fast.txt
}

-- Normalise common protocols for better detection
normalizer = {}

-- Network inspection
stream =
{
    tcp_cache = { max_sessions = 256000 },
    udp_cache = { max_sessions = 128000 },
}

-- Protocol decoders
stream_tcp =
{
    policy = 'os-linux',
}
EOF
```

---

## Step 3: Understanding Snort Rule Syntax

A Snort rule has two components: the **rule header** and **rule options**.

```text
ACTION  PROTO  SRC_IP  SRC_PORT  DIRECTION  DST_IP  DST_PORT  (OPTIONS)
```

### Rule header breakdown:

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 22
│     │   │             │   │   │         │
│     │   │             │   │   │         └─ Dest port
│     │   │             │   │   └─ Dest IP (variable)
│     │   │             │   └─ Direction (-> = one-way, <> = bidirectional)
│     │   │             └─ Source port (any = all ports)
│     │   └─ Source IP (variable meaning external)
│     └─ Protocol (tcp, udp, icmp, ip)
└─ Action (alert, drop, log, pass, reject)
```

### Rule options (between parentheses):

| Option | Example | Meaning |
|--------|---------|---------|
| `msg` | `msg:"SSH Brute Force"` | Alert message |
| `content` | `content:"GET"` | Match literal bytes in payload |
| `nocase` | `nocase` | Case-insensitive content match |
| `offset` | `offset:0` | Start searching at byte offset |
| `depth` | `depth:4` | Only search within first N bytes |
| `pcre` | `pcre:"/User-Agent: curl/i"` | Perl regex match |
| `threshold` | `threshold: type threshold, track by_src, count 5, seconds 60` | Rate-based detection |
| `flags` | `flags:S` | Match specific TCP flags |
| `dsize` | `dsize:>1000` | Match based on data size |
| `sid` | `sid:1000001` | Unique rule ID (must be > 1,000,000 for custom rules) |
| `rev` | `rev:1` | Rule revision number |
| `classtype` | `classtype:attempted-recon` | Alert classification |
| `priority` | `priority:2` | Alert priority (1=high) |

---

## Step 4: Writing Your First Rules

Create your local rules file:

```bash
cat > rules/local.rules << 'EOF'
# =============================================================
# SO-02 Demo: Local Snort Rules
# Author: Security Operations Master Class
# Date: 2024-01-15
# =============================================================

# ─────────────────────────────────────────────────────────────
# RULE 1: Detect SSH connection attempts from external hosts
# ─────────────────────────────────────────────────────────────
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 \
    (msg:"SSH Connection Attempt from External Host"; \
     flow:to_server,established; \
     sid:1000001; rev:1; \
     classtype:attempted-admin; priority:2;)

# ─────────────────────────────────────────────────────────────
# RULE 2: Detect SSH brute force (5 attempts in 60 seconds)
# ─────────────────────────────────────────────────────────────
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 \
    (msg:"SSH Brute Force Attempt"; \
     flow:to_server; \
     flags:S; \
     threshold: type threshold, track by_src, count 5, seconds 60; \
     sid:1000002; rev:1; \
     classtype:attempted-admin; priority:1;)

# ─────────────────────────────────────────────────────────────
# RULE 3: Detect Nmap SYN scan (large number of SYNs, no ACKs)
# ─────────────────────────────────────────────────────────────
alert tcp $EXTERNAL_NET any -> $HOME_NET any \
    (msg:"Possible Nmap SYN Port Scan"; \
     flags:S,!APUR; \
     threshold: type both, track by_src, count 20, seconds 5; \
     sid:1000003; rev:1; \
     classtype:attempted-recon; priority:2;)

# ─────────────────────────────────────────────────────────────
# RULE 4: Detect cleartext FTP authentication
# ─────────────────────────────────────────────────────────────
alert tcp $HOME_NET any -> any 21 \
    (msg:"FTP Cleartext Authentication Detected"; \
     flow:to_server,established; \
     content:"PASS "; offset:0; depth:5; \
     sid:1000004; rev:1; \
     classtype:policy-violation; priority:2;)

# ─────────────────────────────────────────────────────────────
# RULE 5: Detect HTTP request with SQL injection signature
# ─────────────────────────────────────────────────────────────
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
    (msg:"HTTP SQL Injection Attempt - UNION SELECT"; \
     flow:to_server,established; \
     content:"UNION"; nocase; \
     content:"SELECT"; nocase; distance:0; within:20; \
     http_uri; \
     sid:1000005; rev:1; \
     classtype:web-application-attack; priority:1;)

# ─────────────────────────────────────────────────────────────
# RULE 6: Detect suspicious User-Agent (curl tool)
# ─────────────────────────────────────────────────────────────
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
    (msg:"HTTP Request with curl User-Agent"; \
     flow:to_server,established; \
     content:"User-Agent: curl"; nocase; \
     sid:1000006; rev:2; \
     classtype:policy-violation; priority:3;)

# ─────────────────────────────────────────────────────────────
# RULE 7: Detect ICMP ping sweep (reconnaissance)
# ─────────────────────────────────────────────────────────────
alert icmp $EXTERNAL_NET any -> $HOME_NET any \
    (msg:"ICMP Ping Sweep - Possible Reconnaissance"; \
     itype:8; \
     threshold: type both, track by_src, count 5, seconds 3; \
     sid:1000007; rev:1; \
     classtype:attempted-recon; priority:2;)

# ─────────────────────────────────────────────────────────────
# RULE 8: Detect outbound DNS queries for unusually long domains
# (potential DGA malware)
# ─────────────────────────────────────────────────────────────
alert udp $HOME_NET any -> any 53 \
    (msg:"DNS Query for Suspiciously Long Domain - Possible DGA"; \
     content:"|01 00 00 01|"; offset:2; depth:4; \
     dsize:>100; \
     sid:1000008; rev:1; \
     classtype:bad-unknown; priority:2;)

EOF
```

---

## Step 5: Start the Environment

```console
docker compose up -d
```

Verify Snort started correctly:

```console
docker compose logs snort-ids
```

Expected output (no errors):

```text
--== Initializing Snort ==--
...
        ,,_     -*> Snort! <*-
       o"  )~   Version 3.x.x
        ''''    By Martin Roesch & The Snort Team
...
Snort successfully validated the configuration (with 0 warnings).
```

---

## Step 6: Generate Traffic to Trigger Alerts

Open a second terminal and watch alerts in real time:

```console
# Watch Snort alert file
docker compose exec snort-ids tail -f /logs/alert_fast.txt
```

Now generate traffic that should trigger your rules:

### Trigger Rule 1 — SSH Connection Attempt:

```console
docker compose exec attacker sh -c \
    "nc -z -w2 172.22.0.2 22 && echo 'Connected' || echo 'No response'"
```

### Trigger Rule 3 — Port Scan:

```bash
docker compose exec attacker sh -c \
    "for p in \$(seq 1 100); do nc -z -w1 172.22.0.2 \$p; done"
```

### Trigger Rule 5 — SQL Injection:

```console
docker compose exec attacker sh -c \
    "curl -s 'http://172.22.0.2/search?q=1+UNION+SELECT+username,password+FROM+users'"
```

### Trigger Rule 6 — curl User-Agent:

```console
docker compose exec attacker sh -c \
    "curl -s http://172.22.0.2/"
```

### Trigger Rule 7 — ICMP Sweep:

```bash
docker compose exec attacker sh -c \
    "for i in \$(seq 1 10); do ping -c1 172.22.0.\$i 2>/dev/null; done"
```

---

## Step 7: Interpreting Alert Output

Example alert output from `alert_fast.txt`:

```text
01/15-14:23:45.123456 [**] [1:1000005:1] "HTTP SQL Injection Attempt - UNION SELECT" [**] \
[Classification: Web Application Attack] [Priority: 1] {TCP} \
203.0.113.50:54321 -> 172.22.0.2:80
```

Breaking down this alert:

* `01/15-14:23:45.123456` — Timestamp
* `[1:1000005:1]` — Generator ID : Rule SID : Revision
* `"HTTP SQL Injection Attempt..."` — Rule message
* `[Classification: Web Application Attack]` — classtype
* `[Priority: 1]` — priority (1 = highest)
* `203.0.113.50:54321 -> 172.22.0.2:80` — Source and destination

---

## Step 8: Offline PCAP Analysis

Snort can analyse a saved PCAP file instead of live traffic:

```console
# Download a sample PCAP with known attack traffic
# (Use your Demo 01 capture or any PCAP file)
cp ../demo-01-wireshark-basics/capture/demo-capture.pcap pcap/

# Run Snort against the PCAP
docker compose run --rm snort-pcap-analyse
```

---

## Step 9: Rule Tuning — Reducing False Positives

After running Snort, you may notice alerts that are not real attacks.
For example, Rule 1006 (curl User-Agent) will fire for legitimate internal tools.

To tune rules, you have several options:

**Option 1: Suppress by source IP (known legitimate source)**

```text
# Add to rules/local.rules
suppress gen_id 1, sig_id 1000006, track by_src, ip 10.0.0.0/8
```

**Option 2: Change action from `alert` to `pass` for specific traffic**

```text
pass tcp 10.10.0.0/8 any -> $HOME_NET 80 \
    (msg:"Whitelist internal curl"; \
     content:"User-Agent: curl"; nocase; \
     sid:2000001; rev:1;)
```

**Option 3: Raise the threshold**

```text
# Change count from 5 to 20 for the SSH brute force rule
threshold: type threshold, track by_src, count 20, seconds 60;
```

---

## Step 10: IDS vs. IPS Mode

This demo runs Snort in **IDS mode** (passive monitoring — alerts only, no blocking).

To run in **IPS mode** (inline — can block traffic):

1. Change `alert` to `drop` in rule actions
1. Deploy Snort **inline** on a network bridge (between two interfaces)
1. In docker-compose.yml, use `--daq afpacket` with bridge interfaces

**Warning:** IPS mode can block legitimate traffic if rules are not well-tuned.
Always run in IDS mode first and tune rules before enabling blocking.

```text
IDS Mode:
  Traffic → [Mirror/SPAN] → Snort → Alert (traffic continues unaffected)

IPS Mode (inline):
  Traffic → [Snort inline] → Forward/Drop → Destination
```

---

## Clean Up

```console
docker compose down -v
rm -rf logs/ pcap/
```

---

## Key Takeaways

* Snort uses **signature-based detection** — it only detects what rules tell it to
* Rules have a header (action, protocol, IPs, ports) and options (content, flags, thresholds)
* `alert` is the most common action in IDS mode; `drop` is used in IPS mode
* **Threshold** options prevent alert floods for rate-based attacks
* Rule tuning (suppression, whitelisting) reduces false positives
* SID numbers above 1,000,000 are reserved for local/custom rules
* Snort complements Zeek: Snort detects known attacks, Zeek provides full network context

---

## Exercises

1. Write a rule to detect Telnet (port 23) connections from outside.
1. Modify rule 1000005 to also detect `OR 1=1` in SQL injection payloads.
1. What would happen if you changed `alert` to `drop` in rule 1000003? What are the risks?
1. The attacker container uses IP `172.22.0.100`. How would you suppress all alerts from this IP during testing?
1. Open the generated alerts in Wireshark alongside the raw PCAP. Can you find the matching packet for each alert?

---

## References

* Snort 3 Documentation: https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_v3_User_Manual.pdf
* Snort Rule Writing Guide: https://www.snort.org/documents
* Emerging Threats Rules (community Snort rules): https://rules.emergingthreats.net/
* Talos Intelligence (Cisco): https://www.talosintelligence.com/
