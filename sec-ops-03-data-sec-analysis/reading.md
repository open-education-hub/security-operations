# Session 03: Data Categories and Analysis

**Estimated reading time:** ~120 minutes

**Level:** Intermediate

**Prerequisites:** Session 01 (SOC Fundamentals), Session 02 (Threat Landscape)

---

## Table of Contents

1. [Why Data is the Foundation of Security Operations](#1-why-data-is-the-foundation)
1. [Security Data Source Categories](#2-security-data-source-categories)
1. [Data Normalization and Formats](#3-data-normalization-and-formats)
1. [Log Aggregation and Collection Infrastructure](#4-log-aggregation-and-collection-infrastructure)
1. [SIEM-Based Analysis](#5-siem-based-analysis)
1. [Indicators of Compromise (IOCs)](#6-indicators-of-compromise-iocs)
1. [Threat Intelligence Integration](#7-threat-intelligence-integration)
1. [Tactical vs Strategic Threat Intelligence](#8-tactical-vs-strategic-threat-intelligence)
1. [Data Retention and Compliance](#9-data-retention-and-compliance)
1. [Putting It All Together: The Analysis Pipeline](#10-putting-it-all-together)
1. [Key Takeaways](#11-key-takeaways)
1. [References and Further Reading](#12-references-and-further-reading)

---

## 1. Why Data is the Foundation

Every security operation — whether detecting an intrusion, investigating a breach, or hunting for hidden threats — begins and ends with data.
Before an analyst can say "we were compromised," they must answer a deceptively simple question: *What happened, and what evidence do we have?*

Security data serves three primary roles:

| Role | Description | Example |
|------|-------------|---------|
| **Detection** | Identify malicious activity in real time or near real time | Firewall log shows port scan from external IP |
| **Investigation** | Reconstruct the timeline and scope of an incident | Endpoint logs confirm lateral movement |
| **Compliance** | Prove that controls are operating as required | Audit logs showing all privileged access |

The challenge is not a lack of data.
Modern organizations generate staggering volumes of log events — a mid-sized enterprise can produce hundreds of millions of events per day.
The challenge is *collecting the right data*, *normalizing it into a usable form*, and *analyzing it efficiently* enough to find the signal in the noise.

This session covers the full pipeline: from raw log generation at the source, through normalization and aggregation, to correlation and enrichment in a SIEM, and finally to the output that analysts act on — alerts, dashboards, and threat intelligence feeds.

---

## 2. Security Data Source Categories

Security data comes from many places.
A mature SOC collects from all of them.
Each source category has distinct characteristics: different formats, different fidelity, different coverage gaps.

### 2.1 Endpoint Data

Endpoints — workstations, servers, laptops — generate some of the most valuable security telemetry because they record exactly what code ran, which files were touched, and which network connections were made.

**Windows Event Logs** are the primary endpoint source on Windows systems.
Key event IDs include:

| Event ID | Description | Security Relevance |
|----------|-------------|-------------------|
| 4624 | Successful logon | Baseline user activity, lateral movement |
| 4625 | Failed logon | Brute-force detection |
| 4648 | Logon with explicit credentials | Pass-the-hash, credential misuse |
| 4688 | Process creation | Malware execution, living-off-the-land |
| 4698 | Scheduled task created | Persistence mechanism |
| 4720 | User account created | Privilege escalation |
| 7045 | New service installed | Persistence, rootkit installation |
| 4104 | PowerShell script block | Script-based attacks |

> **Tip:** Default Windows audit policy is insufficient for security monitoring. You must enable advanced audit policy and Sysmon (System Monitor) to capture process creation, network connections, and file hash data. See the [Sysmon configuration guide by SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) as a starting baseline.

**Sysmon** (part of Sysinternals) extends Windows logging significantly.
With a well-tuned configuration, Sysmon captures:

* Process creation with command-line arguments and parent process information
* Network connection events with process name and remote IP/port
* File creation and deletion events
* Registry modifications
* DNS query logging (Sysmon v11+)

**Linux Audit Logs** (`/var/log/audit/audit.log`) provide similar depth on Linux systems.
The `auditd` daemon monitors system calls and can track file access, privilege escalation, and network connections.
Common rules monitor writes to `/etc/passwd`, execve system calls, and changes to sudoers files.

**EDR (Endpoint Detection and Response)** platforms (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) sit on top of the OS and provide pre-processed, enriched telemetry — process trees, behavioral signals, and file hash lookups — in a format already suitable for ingestion into a SIEM or data lake.

### 2.2 Network Telemetry

Network data captures communication between systems.
It operates independently of the endpoint — even if an attacker wipes endpoint logs, the network capture remains.

**Full Packet Capture (PCAP)** is the most complete form but the least scalable.
A 10 Gbps link generates ~4.3 TB per hour of raw PCAP.
Organizations typically deploy taps and span ports only at key chokepoints (internet egress, DMZ boundaries) and retain data for 24–72 hours before rolling over.

**NetFlow / IPFIX** provides flow-level metadata: source IP, destination IP, source port, destination port, protocol, byte count, packet count, and start/end timestamps.
A single flow record summarizes an entire TCP connection, compressing a 10 Gbps link to approximately 1–2% of raw PCAP volume.
NetFlow is the standard for long-term network behavioral analysis.

**Zeek (formerly Bro)** occupies the middle ground.
It processes packets and emits structured log files covering:

* `conn.log`: Connection summaries (similar to NetFlow)
* `dns.log`: DNS queries and responses
* `http.log`: HTTP transactions with URIs, user agents, response codes
* `ssl.log`: TLS handshake details, certificate subjects, JA3 fingerprints
* `files.log`: File transfers with MD5/SHA1/SHA256 hashes
* `weird.log`: Protocol anomalies

Zeek logs are written as TSV or JSON, making them directly ingestible into ELK or Splunk.
The combination of Zeek + Suricata (IDS signatures on the same tap) is a common open-source NSOC baseline.

**Firewall and Proxy Logs** are the most commonly collected network sources because they already exist in most environments:

* Next-generation firewalls (Palo Alto, Fortinet, Check Point) log allow/deny decisions with application identification
* Web proxies log all HTTP/HTTPS URLs, user agents, and response codes
* Both provide coarse-grained visibility without full packet analysis

### 2.3 Application Logs

Applications generate logs that reveal what users did inside the system — which is critical for detecting insider threats and post-exploitation activity that blends in with legitimate use.

**Web Application Logs** (Apache access logs, NGINX logs, IIS W3C format) capture:

* Client IP address
* HTTP method (GET/POST/PUT/DELETE)
* Request URI
* HTTP response code
* Bytes transferred
* User-Agent string
* Referrer

Patterns such as HTTP 404 storms (directory brute-forcing), abnormal user agents, SQL syntax in URIs, and large POST bodies to unusual endpoints are red flags visible only from application logs.

**Database Audit Logs** (MySQL general query log, PostgreSQL `pg_audit`, Microsoft SQL Server audit) record queries and can detect SQL injection, unauthorized data exports (large SELECT *), and privilege abuse.

**Custom Application Logs** — internal applications, microservices, APIs — should follow structured logging standards (JSON is preferred) and include fields like user ID, session ID, action performed, and the IP of the client.
A mature application security program includes log review in the secure development lifecycle (SDLC).

### 2.4 Authentication and Identity Logs

Authentication logs are among the most critical data sources for detecting credential-based attacks, which account for the majority of breaches (Verizon DBIR consistently places credential theft in the top attack vectors).

**Active Directory / LDAP Logs:**

* Domain controller security event logs (Event IDs 4624, 4625, 4768, 4769, 4771) record all authentication attempts against the domain
* Kerberos ticket granting service (TGS) requests (4769) can reveal Kerberoasting attacks — when an attacker requests service tickets to crack offline
* LDAP queries for enumeration appear in directory service logs

**VPN and Remote Access Logs:**

* Successful and failed authentications, with source IP
* Session duration and data volume — a VPN session downloading gigabytes of data at 2 AM is unusual
* Geographic anomalies: user logging in from Romania immediately after a login from New York

**Cloud Identity Logs:**

* Azure AD Sign-In logs (available in the Azure portal and exportable to Log Analytics)
* AWS CloudTrail records all API calls including IAM logins, role assumptions, and console authentication
* Google Workspace Admin logs record logins, file access, sharing, and admin changes

**Multi-Factor Authentication (MFA) Logs:**

* MFA success/failure logs reveal push-bombing attacks (repeated push notifications to exhaust the user) and MFA fatigue
* Sudden enrollment of new MFA devices may indicate account takeover

### 2.5 DNS Records

DNS is described by security practitioners as "the log source that sees everything." Almost every network communication begins with a DNS query, and DNS logs therefore provide a comprehensive record of which domains were resolved from which host at what time.

**Why DNS matters:**

* Command and control (C2) malware phones home to attacker-controlled domains
* Data exfiltration via DNS tunneling encodes stolen data inside DNS queries
* Newly registered domains used in phishing can be detected by checking domain age
* Fast-flux networks (C2 infrastructure that rapidly changes DNS records) are detectable from resolution patterns

**Data to collect:**

* Recursive resolver logs (corporate DNS server logs, or passive DNS feeds from the ISP/cloud provider)
* DNS Security (DNSSEC) validation failures
* NXDomain (non-existent domain) responses — a high NXDomain rate from a single host suggests DGA (Domain Generation Algorithm) malware

**Key DNS IOC types:**

* High-entropy domain names (DGA): `a3bc4d.evil.com`
* Unusually long hostnames (DNS tunneling): `encodeddata.attacker.com`
* TXT record queries (data exfiltration channel)
* Queries to known sinkholed domains

### 2.6 Cloud Logs

Cloud environments have their own logging ecosystem, distinct from traditional on-premises sources but equally critical as organizations migrate workloads.

**AWS CloudTrail:**

* Records every AWS API call: who called what, from where, at what time
* Key events: `ConsoleLogin`, `AssumeRole`, `CreateUser`, `AttachUserPolicy`, `PutBucketPolicy`, `DescribeInstances`
* CloudTrail data events capture S3 object-level access — useful for detecting data exfiltration from buckets
* Must be explicitly enabled for each region; organizations often miss regions they don't think they use

**AWS VPC Flow Logs:**

* Equivalent of NetFlow for VPC networking
* Records traffic between EC2 instances, Lambda, and external endpoints
* Key fields: source/destination IP, port, protocol, bytes, packets, action (ACCEPT/REJECT)

**Azure Monitor / Azure AD:**

* Azure Activity Log: resource creation, deletion, role assignment changes
* Azure AD Sign-In logs: authentications to all Azure AD-integrated applications
* Microsoft Sentinel natively ingests these sources

**GCP Cloud Audit Logs:**

* Admin Activity logs: always on, cannot be disabled
* Data Access logs: must be enabled; record API calls that read configuration or user-provided data
* System Event logs: automatic actions by Google infrastructure

**Kubernetes Audit Logs:**

* API server audit log records all requests to the Kubernetes control plane
* Detects: unauthorized pod creation, container escapes via privileged containers, RBAC abuse, secret enumeration

---

## 3. Data Normalization and Formats

Collecting logs from dozens of sources creates an immediate problem: every source uses a different format.
A firewall log looks nothing like a Windows event log, which looks nothing like an AWS CloudTrail record.
Before analysis, these disparate formats must be normalized into a common schema.

### 3.1 Why Normalization Matters

Without normalization, writing a correlation rule that spans multiple data sources requires knowing the exact field names used by each source:

* Fortinet firewall calls the source IP `srcip`
* Palo Alto calls it `src`
* Windows Event Log calls it `IpAddress`
* Zeek calls it `id.orig_h`
* Sysmon calls it `SourceIp`

A normalized schema maps all these to a single field (e.g., `src_ip`), allowing a single query or rule to run across all sources simultaneously.

### 3.2 Common Event Format (CEF)

**CEF (Common Event Format)** was developed by ArcSight (now Micro Focus) and has become a widely-used standard for log forwarding, particularly over syslog.

A CEF message has the following structure:

```text
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Real-world example** (firewall deny event):

```text
CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|Traffic Deny|5|
  rt=1680000000000 src=192.168.1.100 dst=198.51.100.1
  spt=54321 dpt=443 proto=TCP act=deny
  cs1=untrust-zone cs1Label=DestinationZone
```

**CEF field breakdown:**

* `CEF:0` — CEF version 0
* `Palo Alto Networks` — Device vendor
* `PAN-OS` — Device product
* `10.1` — Device version
* `TRAFFIC` — Signature/rule ID
* `Traffic Deny` — Human-readable name
* `5` — Severity (0–10)
* Extension fields follow as `key=value` pairs

**Standard CEF extension fields:**

| CEF Key | Description |
|---------|-------------|
| `src` | Source IP address |
| `dst` | Destination IP address |
| `spt` | Source port |
| `dpt` | Destination port |
| `proto` | Protocol |
| `act` | Action taken |
| `msg` | Free-text message |
| `rt` | Receipt time (Unix epoch milliseconds) |
| `suser` | Source username |
| `duser` | Destination username |
| `fname` | Filename |
| `fsize` | File size |
| `cs1`–`cs6` | Custom string fields (vendor-specific) |

CEF is primarily used as a transport format (syslog over UDP/TCP to a collector) and is widely supported by SIEMs for parsing.

### 3.3 JSON Log Format

**JSON (JavaScript Object Notation)** has become the dominant structured log format in modern systems, particularly cloud services, microservices, and observability platforms.
Its advantages over CEF include:

* Native support in virtually all programming languages
* Nested structures (arrays, objects within objects)
* Human-readable and machine-parseable
* Compatible with ElasticSearch, Splunk HEC, CloudWatch, etc.

**Example: AWS CloudTrail record (JSON)**

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAIEXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/analyst",
    "accountId": "123456789012",
    "userName": "analyst"
  },
  "eventTime": "2024-03-15T14:23:01Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "sourceIPAddress": "203.0.113.42",
  "userAgent": "aws-cli/2.15.0",
  "requestParameters": {
    "bucketName": "company-financial-reports",
    "key": "Q4-2023-earnings.xlsx"
  },
  "responseElements": null,
  "requestID": "EXAMPLE123",
  "eventID": "unique-event-id",
  "readOnly": true,
  "resources": [{
    "ARN": "arn:aws:s3:::company-financial-reports/Q4-2023-earnings.xlsx",
    "accountId": "123456789012",
    "type": "AWS::S3::Object"
  }]
}
```

**Example: Zeek HTTP log (JSON format)**

```json
{
  "ts": 1710500000.123,
  "_path": "http",
  "uid": "Cgx5Jk2KD7EXAMPLE",
  "id.orig_h": "192.168.1.50",
  "id.orig_p": 54321,
  "id.resp_h": "203.0.113.10",
  "id.resp_p": 80,
  "method": "POST",
  "host": "malicious-c2.example.com",
  "uri": "/update",
  "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)",
  "request_body_len": 2048,
  "response_body_len": 128,
  "status_code": 200,
  "resp_mime_types": ["text/plain"]
}
```

### 3.4 Field Unification and Schema Standards

Several open standards exist for defining a common field schema across data sources:

**Elastic Common Schema (ECS):**

* Developed by Elastic for the ELK stack
* Defines field names, data types, and allowed values
* Key field groups: `@timestamp`, `event.*`, `host.*`, `network.*`, `user.*`, `process.*`, `file.*`
* Widely adopted beyond ELK; supported by Beats agents and Logstash

**OSSEM (Open Source Security Events Metadata):**

* Community project defining a data dictionary for security events
* Maps Windows event IDs, Sysmon events, Linux audit logs to standard fields
* Useful for documentation and building parsers

**Splunk CIM (Common Information Model):**

* Splunk's schema standard, used by Splunk apps and correlation searches
* Data models: Authentication, Network Traffic, Endpoint, Web, etc.
* Data must be mapped to CIM fields for Splunk ES correlation rules to work

**Example field mapping across schemas:**

| Source Field | ECS Field | Splunk CIM Field | CEF Key |
|-------------|-----------|-----------------|---------|
| `IpAddress` (Win) | `source.ip` | `src_ip` | `src` |
| `ProcessName` (Win) | `process.name` | `process` | `sproc` |
| `id.orig_h` (Zeek) | `source.ip` | `src_ip` | `src` |
| `srcip` (Fortinet) | `source.ip` | `src_ip` | `src` |

### 3.5 Timestamping and Time Synchronization

Time is foundational to log analysis.
An investigation that requires correlating events across ten systems is impossible if those systems' clocks drift by minutes from each other.

**Best practices:**

* All systems must synchronize to NTP (Network Time Protocol). Use a hierarchical NTP topology with reliable stratum-1 or stratum-2 sources.
* Log timestamps should use **UTC** (Coordinated Universal Time), not local time. Local time creates confusion during daylight saving time transitions and across geographic zones.
* Timestamps should include sub-second precision where possible (`2024-03-15T14:23:01.843Z`)
* ISO 8601 format is preferred for human readability; Unix epoch (seconds since 1970-01-01T00:00:00Z) is preferred for machine processing

**The risk of time drift:** A 5-minute clock drift between two systems can make a causal relationship appear as coincidence.
If an attacker pivots from System A to System B, System A's logs may show the attack at 14:03 while System B (with a drifted clock) shows the corresponding logon at 13:58 — appearing to precede the attack event.

---

## 4. Log Aggregation and Collection Infrastructure

### 4.1 Collection Architecture Patterns

Before logs can be analyzed, they must be collected and forwarded to a central platform.
The architecture for doing this varies by scale:

**Agent-based collection:** A lightweight agent runs on each host and ships logs to a central collector or directly to the SIEM.
Examples:

* Splunk Universal Forwarder (forwards data to Splunk indexers)
* Elastic Beats (Filebeat, Winlogbeat, Auditbeat) forward to Logstash or Elasticsearch
* Fluentd / Fluent Bit forward to ELK, Splunk, or cloud platforms
* NXLog is cross-platform and commonly used for Windows Event Log forwarding

**Syslog forwarding:** Devices without agent support (firewalls, routers, IoT devices) forward logs using the syslog protocol (RFC 5424) over UDP port 514 or TCP/TLS port 6514 to a central syslog server.
Rsyslog and syslog-ng are the standard Linux syslog daemons.

**API pull collection:** Cloud services expose APIs for log retrieval.
A collector polls the API on a schedule and ingests new events.
AWS CloudTrail delivers to S3 buckets; Azure Monitor exports to Event Hub; Google Cloud Logging streams to Pub/Sub.

**SNMP traps and WMI:** Legacy protocols still used in network operations; less common in security monitoring due to limited detail and reliability.

### 4.2 Elasticsearch and the ELK Stack

The **ELK stack** — Elasticsearch, Logstash, Kibana — is the dominant open-source SIEM/log management platform.
It has evolved into the **Elastic Stack** with the addition of Beats and other components.

**Elasticsearch:**

* A distributed, document-oriented search and analytics engine based on Apache Lucene
* Stores data as JSON documents in indices; indices are sharded across cluster nodes for horizontal scalability
* Supports full-text search, field-level queries, aggregations, and time-series analysis
* Data streams (indices with time-based rollover) are used for log data
* **Key concept:** Data is indexed at ingest time, making search very fast but requiring schema decisions upfront

**Logstash:**

* Data processing pipeline: ingests from multiple inputs, applies filters to parse/transform/enrich, outputs to one or more destinations
* **Inputs:** beats, tcp, syslog, http, s3, kafka, jdbc, and dozens more
* **Filters:**
  * `grok`: Parse unstructured text using named regex patterns
  * `date`: Parse timestamps and set `@timestamp`
  * `mutate`: Rename, remove, convert field types
  * `geoip`: Add geolocation data from IP addresses
  * `dns`: Resolve IP to hostname
  * `json`: Parse embedded JSON strings
* **Outputs:** elasticsearch, s3, kafka, file, email, pagerduty
* Logstash is CPU-intensive; Fluent Bit is a lighter-weight alternative for simple pipelines

**Kibana:**

* Visualization and query interface for Elasticsearch
* **Discover:** Ad-hoc log search with filtering and field selection
* **Dashboards:** Pre-built or custom visualizations (time charts, pie charts, maps)
* **Lens:** Drag-and-drop analytics builder
* **Elastic Security:** Built-in SIEM with detection rules, timeline investigation, and case management (powered by Elasticsearch under the hood)
* **KQL (Kibana Query Language):** Simple query language for filtering: `event.code: 4625 AND source.ip: 192.168.0.0/16`
* **EQL (Event Query Language):** Sequence-based detection language, e.g., detecting process creation followed by network connection

**Example Logstash pipeline for Windows Event Logs:**

```ruby
input {
  beats {
    port => 5044
    type => "winlog"
  }
}

filter {
  if [type] == "winlog" {
    # Parse Windows Event Log XML
    if [winlog][event_id] == 4625 {
      mutate {
        add_tag => ["failed_logon"]
        add_field => { "alert_type" => "authentication_failure" }
      }
    }
    # GeoIP enrichment
    if [source][ip] {
      geoip {
        source => "[source][ip]"
        target => "[source][geo]"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "security-winlog-%{+YYYY.MM.dd}"
  }
}
```

### 4.3 Splunk

**Splunk** is the leading commercial SIEM platform.
Unlike ELK (which indexes data at ingest), Splunk uses a **late-binding schema** (also called schema-on-read): raw data is stored compressed, and field extraction happens at search time.
This provides flexibility — you can add new field extractions to historical data without re-indexing.

**Splunk Architecture:**

* **Search Head:** Handles user queries, distributes searches, renders results
* **Indexer:** Receives, parses, and stores data in compressed form
* **Universal Forwarder:** Lightweight agent that tails files and forwards to indexers
* **Heavy Forwarder:** Can parse and filter data before forwarding; runs on a full Splunk instance
* **Deployment Server:** Manages forwarder configurations at scale

**Splunk Processing Language (SPL)** is Splunk's query language.
Key concepts:

```spl
# Basic search - all failed logons in last 24 hours
index=windows EventCode=4625 earliest=-24h

# Count by source IP (identify brute-force sources)
index=windows EventCode=4625
| stats count by src_ip
| where count > 10
| sort -count

# Identify accounts targeted in brute force
index=windows EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5

# Rare process execution (hunting)
index=sysmon EventCode=1
| stats count by CommandLine
| where count < 3
| sort count
```

**Splunk Data Models and CIM:**
Data models define the schema for data stored in Splunk.
The Common Information Model (CIM) provides a standard set of data models:

* `Authentication` — logon events
* `Network_Traffic` — firewall, flow data
* `Endpoint` — process, file system events
* `Web` — web server and proxy logs
* `Intrusion_Detection` — IDS/IPS alerts

Mapping your data to CIM enables the use of pre-built Splunk Enterprise Security (ES) correlation rules and community apps (like Splunk Security Essentials).

---

## 5. SIEM-Based Analysis

### 5.1 What a SIEM Does

A **Security Information and Event Management (SIEM)** system is the analytical backbone of a SOC.
It combines:

* **Security Information Management (SIM):** Long-term log storage, compliance reporting, historical search
* **Security Event Management (SEM):** Real-time event correlation, alerting

The SIEM ingests normalized events from all data sources and applies **correlation rules** — logical conditions that, when met, generate an alert for analyst review.

### 5.2 Correlation Rules

A correlation rule is a logical condition applied to event data to detect security-relevant patterns.
Effective rules balance:

* **True positive rate:** Does the rule fire when the attack actually happens?
* **False positive rate:** Does the rule fire on benign activity?

A rule that is too broad generates so many false positives that analysts become desensitized — this is **alert fatigue** and it is one of the primary operational challenges in a SOC.

**Rule types:**

**Threshold rules:** Fire when a count exceeds a limit within a time window.

```text
IF count(EventCode=4625) > 10 WITHIN 5 minutes FROM same src_ip
THEN alert "Possible Brute Force"
```

**Sequence rules:** Detect ordered sequences of events (multi-step attacks).

```text
IF EventCode=4624 (successful logon)
  FOLLOWED BY EventCode=4698 (scheduled task created)
  WITHIN 10 minutes
  BY same user
THEN alert "Logon followed by persistence"
```

**Aggregation rules:** Look for statistical anomalies.

```text
IF user connects to > 20 unique hosts within 1 hour
THEN alert "Possible lateral movement"
```

**Baseline deviation rules:** Compare current activity to historical baseline.

```text
IF bytes_out > (baseline_bytes_out * 3) FOR user
THEN alert "Data exfiltration candidate"
```

### 5.3 Building Detection Logic: The Kill Chain Approach

Rather than writing rules for individual events, skilled detection engineers map rules to attacker actions in the **Cyber Kill Chain** or **MITRE ATT&CK** framework.
This ensures coverage of complete attack sequences rather than isolated indicators.

**Example: Detecting a spear-phishing campaign leading to a foothold**

| Kill Chain Stage | Observable | Detection Rule |
|-----------------|-----------|----------------|
| Delivery | Phishing email with attachment | Email gateway logs: attachment with macro + external sender |
| Exploitation | Office macro executes | Sysmon Event 1: Word/Excel spawning cmd.exe or PowerShell |
| Installation | Malware writes to disk | Sysmon Event 11: File creation in `%APPDATA%` by Office process |
| C2 | Malware phones home | Zeek/proxy: Unusual beacon pattern, DGA domain |
| Actions on Objectives | Data staging | File system: Large .zip creation in unusual directory |

Each stage can be detected independently, but correlated together they form a high-confidence multi-stage alert.

### 5.4 SIEM Dashboards

Dashboards provide situational awareness — a visual summary of the current security posture.
A well-designed SIEM dashboard shows:

**Operational dashboards (for analysts):**

* Open alerts by severity and status
* Top alerting rules over the last 24 hours
* Event volume by source (identifies gaps in log ingestion)
* Failed authentication attempts by geography
* Top network destinations by volume (exfiltration monitoring)

**Executive dashboards (for management):**

* Mean time to detect (MTTD) and mean time to respond (MTTR) trends
* Total alerts generated vs. investigated vs. escalated
* Compliance-relevant metrics (e.g., privileged access review)
* Vulnerability count trends from integrated scanner

### 5.5 Alert Triage Workflow

When a SIEM fires an alert, the analyst follows a structured triage process:

1. **Review the alert details:** What rule triggered? What data did it match? What is the severity?
1. **Gather context:** Look up the source IP, user, or host in asset inventory. Is this a known privileged account? A production server? A recently onboarded employee?
1. **Pivot to raw data:** Look at the surrounding log context — what happened before and after the event that triggered the alert?
1. **Enrich with threat intelligence:** Is the IP or domain in any TI feeds? Does the file hash match a known malware sample?
1. **Determine true vs. false positive:** Based on context and enrichment, does this look like real malicious activity?
1. **Take action:** Close as false positive (with a note), escalate to Tier 2, or open an incident ticket.

---

## 6. Indicators of Compromise (IOCs)

An **Indicator of Compromise (IOC)** is a piece of evidence found in a network or on a system that indicates a system may have been compromised.
IOCs are artifacts left behind by attackers that can be used for detection, hunting, and blocking.

### 6.1 IP Addresses

An IP address IOC is a specific IP known to be associated with malicious activity.
It may be:

* A known C2 server IP
* A scanning host from a botnet
* A TOR exit node used in attacks

**Limitations:**

* IPs are easily changed (attackers use bulletproof hosting, CDNs, cloud VMs)
* IPs are shared (blocking a TOR exit node may block legitimate researchers)
* IP-based IOCs have a very short useful lifespan (hours to days)

**Usage:** Block at the firewall (outbound traffic to known C2 IPs), alert in SIEM when internal hosts communicate with them.

### 6.2 File Hashes

A file hash is a cryptographic fingerprint of a malicious file.
MD5, SHA1, and SHA256 are the most common formats.
SHA256 is preferred due to MD5 and SHA1 collision vulnerabilities.

**Example:**

```text
SHA256: 44d88612fea8a8f36de82e1278abb02f
        (this is an EICAR test file hash)
```

**Strengths:**

* Extremely specific — a hash uniquely identifies a file
* High-confidence (low false positive rate) when matched

**Limitations:**

* Trivial for attackers to change: recompile, repack, or XOR the binary
* Many malware families recompile for every campaign (polymorphic malware)
* Hash-based detection is defeated by slight binary modifications

**Implication:** Hash-based detection is best used for **known-bad confirmation** (you found a file — is this a known malware sample?) rather than as a primary detection mechanism.

### 6.3 Domain Names

Domain IOCs include C2 domains, phishing domains, and malware distribution sites.
Domain-based detection is more durable than IP-based (attackers often change IPs but keep domains longer).

**Types:**

* Explicit domains: `malware-c2.ru`
* Wildcard domains: `*.evil-cdn.net`
* Domain patterns (DGA): Algorithmic domains generated by malware (e.g., `xkqjwvbz.com`) — detected by entropy analysis rather than explicit blocklists

**Detection methods:**

* DNS RPZ (Response Policy Zones): Block DNS resolution of malicious domains at the resolver level
* Proxy/DNS log alerting: Alert when internal hosts resolve or communicate with IOC domains
* Passive DNS: Historical record of domain-to-IP mappings, useful for infrastructure pivoting

### 6.4 User Agents

HTTP User-Agent strings identify the browser or application making a request.
Malware using HTTP for C2 often uses:

* Default User-Agent strings from their HTTP library (e.g., `python-requests/2.28.0`)
* Hardcoded static strings that match common browsers but don't match browser behavior patterns
* Legitimate-looking but low-frequency User-Agents that real users rarely use

**Example indicators:**

* `curl/7.68.0` — rare from workstations, may indicate scripted activity
* `Go-http-client/1.1` — Golang-based malware or tools
* `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)` — very old IE string, unlikely from modern systems
* PowerShell Empire's default User-Agent: `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko`

**Detection:** Search proxy logs for rare or anomalous User-Agent strings, particularly from internal hosts.

### 6.5 Filenames and Paths

Malware often uses consistent filenames or is dropped to predictable locations:

* `svchost32.exe` (masquerading as legitimate svchost.exe)
* Files in `C:\Windows\Temp\`, `%APPDATA%\Roaming\`, or `C:\ProgramData\`
* Filenames with double extensions: `invoice.pdf.exe`
* Randomly-named executables in temp directories

**Usage:** Endpoint detection rules, EDR file creation alerts, SIEM searches against Sysmon file creation events.

### 6.6 IOC Formats and Sharing Standards

**STIX (Structured Threat Information eXpression):**

* JSON-based standard for representing threat intelligence objects
* Core objects: Indicator, Malware, Attack Pattern, Threat Actor, Campaign, Tool, Vulnerability
* Relationships: `malware --uses--> attack-pattern`, `threat-actor --uses--> malware`
* Current version: STIX 2.1

**TAXII (Trusted Automated eXchange of Indicator Information):**

* Transport protocol for sharing STIX data between organizations
* RESTful API with collections; clients pull updates from servers
* MISP, Anomali, and many commercial TI platforms expose TAXII feeds

**Simple formats:**

* Plain text lists of IPs, domains, hashes (used in firewall blacklists, DNS RPZ)
* CSV files with IOC + metadata
* MISP's native JSON format

---

## 7. Threat Intelligence Integration

### 7.1 What is Threat Intelligence?

**Cyber Threat Intelligence (CTI)** is evidence-based knowledge about an existing or emerging threat that can be used to make informed security decisions.
It answers: *Who is attacking us?
How?
Why?
What are the indicators?*

CTI is distinguished from raw data by its analytical value:

* **Data:** `IP 203.0.113.5 connected to port 443`
* **Information:** `IP 203.0.113.5 is hosted in a country with known cybercrime activity`
* **Intelligence:** `IP 203.0.113.5 is operated by threat actor APT-X, which targets financial institutions using spear-phishing followed by banking trojan deployment. Confidence: HIGH. Based on: 3 previous campaigns, shared TTP patterns, infrastructure overlap.`

### 7.2 MISP (Malware Information Sharing Platform)

**MISP** is an open-source threat intelligence platform designed for sharing, storing, and analyzing IOCs and threat intelligence.
It is used by ISACs (Information Sharing and Analysis Centers), CERTs, and private organizations globally.

**MISP core concepts:**

* **Event:** A collection of attributes related to a single threat incident, campaign, or malware sample
* **Attribute:** A single IOC or piece of intelligence (IP, domain, hash, etc.) within an event
* **Tag:** Labels applied to events and attributes for classification (TLP, MITRE ATT&CK, kill chain stage)
* **Galaxy:** Higher-level threat actor, malware family, or attack pattern knowledge base (links to MITRE ATT&CK)
* **Organisation:** Each MISP instance is operated by an organization; trust levels control what is shared between organizations

**TLP (Traffic Light Protocol):**

* `TLP:RED` — Not for disclosure; recipient-only
* `TLP:AMBER` — Limited disclosure; recipient organization only
* `TLP:GREEN` — Community-wide; can be shared broadly within the security community
* `TLP:WHITE` (now `TLP:CLEAR`) — Public disclosure allowed

**MISP API usage (Python):**

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

# Connect to MISP instance
misp = PyMISP('https://misp.example.org', 'YOUR_API_KEY')

# Search for events containing a specific IP
result = misp.search(value='203.0.113.5', type_attribute='ip-dst')

for event in result:
    print(f"Event UUID: {event.uuid}")
    print(f"Event Info: {event.info}")
    print(f"Threat Level: {event.threat_level_id}")
    for attr in event.attributes:
        print(f"  {attr.type}: {attr.value}")

# Add a new IOC to an event
event = MISPEvent()
event.info = "Phishing Campaign - March 2024"
attr = event.add_attribute('ip-dst', '198.51.100.42')
attr.add_tag('misp-galaxy:threat-actor="Lazarus Group"')
misp.add_event(event)
```

**MISP feeds:**
MISP supports subscribing to external threat intelligence feeds:

* AlienVault OTX
* Feodo Tracker (botnet C2 IPs)
* URLhaus (malware distribution URLs)
* Abuse.ch
* CIRCL (Computer Incident Response Center Luxembourg)

These feeds are automatically imported and available as searchable attributes.

### 7.3 VirusTotal

**VirusTotal** is a web service that analyzes files, URLs, domains, and IP addresses against 70+ antivirus engines and dozens of other security tools.
It is operated by Google.

**Key capabilities:**

* File scanning: Submit a file (up to 650MB) for multi-engine AV scan
* URL/domain scanning: Check reputation and content of URLs
* Hash lookup: Query whether a file hash is known without submitting the file
* Graph relationships: Visualize relationships between files, URLs, domains, IPs
* YARA rules: Search VirusTotal corpus for files matching YARA patterns

**VirusTotal API (v3):**

```python
import requests

API_KEY = "YOUR_VT_API_KEY"
BASE_URL = "https://www.virustotal.com/api/v3"

def lookup_hash(file_hash):
    """Look up a file hash on VirusTotal."""
    url = f"{BASE_URL}/files/{file_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        name = data['data']['attributes'].get('meaningful_name', 'Unknown')
        print(f"File: {name}")
        print(f"Malicious: {stats['malicious']}/{stats['malicious'] + stats['undetected']}")
        return data
    elif response.status_code == 404:
        print("Hash not found in VirusTotal")
    else:
        print(f"Error: {response.status_code}")

def lookup_domain(domain):
    """Look up a domain on VirusTotal."""
    url = f"{BASE_URL}/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        cats = data['data']['attributes'].get('categories', {})
        print(f"Domain: {domain}")
        print(f"Malicious: {stats['malicious']}")
        print(f"Suspicious: {stats['suspicious']}")
        print(f"Categories: {cats}")
        return data

# Usage
lookup_hash("44d88612fea8a8f36de82e1278abb02f3524ec74")
lookup_domain("malicious-domain.example.com")
```

**Rate limits:** Free accounts are limited to 4 requests/minute and 500 requests/day.
Commercial licenses provide higher limits and access to advanced features (retrohunt, livehunt).

### 7.4 Commercial Threat Intelligence Feeds

Beyond MISP and VirusTotal, many organizations subscribe to commercial TI platforms:

| Platform | Strengths |
|----------|-----------|
| **Recorded Future** | Machine learning analysis, real-time intelligence from dark web and open web |
| **Mandiant Threat Intelligence** | Deep research on APT groups, attribution confidence |
| **CrowdStrike Falcon Intelligence** | Actor profiles, campaign tracking, integration with Falcon platform |
| **Palo Alto Unit 42** | Malware analysis, threat actor profiling |
| **IBM X-Force** | Vulnerability intelligence, global threat data |
| **Anomali ThreatStream** | Feed aggregation and operationalization platform |

Commercial feeds provide value beyond raw IOCs: context, attribution, analyst reports, and direct integration with SIEMs and firewalls.

---

## 8. Tactical vs Strategic Threat Intelligence

Threat intelligence exists on a spectrum from highly technical and operational to broad and strategic.
Understanding this spectrum helps organizations consume intelligence appropriately.

### 8.1 Tactical Intelligence

**Tactical (Technical) Intelligence** is actionable, machine-readable data used by security tools to detect and block specific threats *right now*.

**Characteristics:**

* High volume, short lifespan (hours to weeks)
* Specific and concrete: IPs, hashes, domains, YARA rules, Snort signatures
* Consumed by: firewalls, SIEMs, EDR platforms, DNS resolvers, email gateways
* Production: automated feeds, malware analysis sandboxes, honeynet data

**Examples:**

* A list of 5,000 IP addresses associated with an active malware botnet
* SHA256 hashes of a new ransomware variant
* Snort rule to detect a specific exploit's network signature
* YARA rule matching the unique string constants in a new RAT

**Limitation:** Tactical IOCs go stale quickly.
An attacker who burns an IP simply rotates to a new one.
Pure tactical intelligence becomes a game of whack-a-mole.

### 8.2 Operational Intelligence

**Operational Intelligence** describes *how* attacks are conducted: the tools, techniques, and procedures (TTPs) used by a specific threat actor or campaign.

**Characteristics:**

* Medium lifespan (weeks to months)
* Describes attack patterns rather than specific artifacts
* Consumed by: SOC analysts, incident responders, threat hunters
* Format: MITRE ATT&CK techniques, campaign reports, malware analysis reports

**Examples:**

* "APT-X typically uses spear-phishing with weaponized Office documents, deploys a custom RAT that communicates over HTTPS to domains with .ru TLDs"
* "This ransomware campaign uses RDP brute-force for initial access, deploys Cobalt Strike for lateral movement, then deploys ransomware after 3–5 days"

**Value:** TTPs are harder to change than IOCs.
Even if an attacker changes their C2 IPs and recompiles their malware, they are less likely to change their fundamental tradecraft (e.g., spear-phishing with macros, LSASS credential dumping, using legitimate admin tools for lateral movement).

### 8.3 Strategic Intelligence

**Strategic Intelligence** informs executive decision-making and long-term security investment.

**Characteristics:**

* Long lifespan (months to years)
* Non-technical, narrative format
* Consumed by: CISOs, board members, risk management teams
* Format: Analyst reports, threat landscape assessments, geopolitical risk analysis

**Examples:**

* "Nation-state actors from [country] are increasingly targeting energy sector infrastructure in [region] in the context of ongoing geopolitical tensions"
* "Ransomware attacks against healthcare organizations increased 48% in 2023; average ransom demand is $1.5M"
* "Supply chain attacks are an emerging vector; organizations should increase scrutiny of third-party software and update their vendor risk management program"

**Value:** Helps organizations prioritize security investments, understand their threat model, and make risk-informed decisions about controls.

### 8.4 The Intelligence Lifecycle

Intelligence is not a product — it is a process.
The **intelligence lifecycle** describes how raw data becomes actionable intelligence:

```text
1. Planning & Direction

   ├── Define intelligence requirements (what do we need to know?)
   └── Prioritize based on organization's threat model

2. Collection
   ├── Technical feeds (OSINT, commercial, ISAC)
   └── Internal observations (honeypots, incident reports)

3. Processing
   ├── Parse and normalize raw data
   └── Deduplicate, filter false positives

4. Analysis
   ├── Contextualize indicators
   ├── Identify patterns and actor attribution
   └── Assess confidence and relevance

5. Dissemination
   ├── Push IOCs to detection systems
   ├── Brief relevant teams (operational, strategic)
   └── Share with community (MISP, ISAC) where appropriate

6. Feedback
   └── Did the intelligence help? Were detections accurate?
       → Informs next planning cycle
```

---

## 9. Data Retention and Compliance

### 9.1 Why Retention Policies Matter

Log data serves dual purposes: security analysis and compliance.
These two drivers often impose different — and sometimes conflicting — retention requirements.

**Security analysis perspective:**

* Longer retention enables investigation of incidents that weren't detected immediately
* APTs (Advanced Persistent Threats) may lurk for months before being discovered; investigating requires historical logs
* Threat hunting often queries 30–90 days of data to find historical patterns
* Typical security-driven retention: 90 days online (fast query), 12–24 months archived

**Compliance perspective:**

* Many regulations mandate specific retention periods
* Deletion of logs may constitute evidence tampering during a legal investigation
* Some regulations restrict *where* data can be stored (data residency)

### 9.2 Key Regulatory Requirements

**GDPR (General Data Protection Regulation)** — EU:

* Personal data in logs (IP addresses, usernames, session tokens) may be subject to GDPR
* No specific retention period mandated for security logs, but principle of **data minimization** applies: retain only what is necessary for the specified purpose
* **Right to erasure** ("right to be forgotten") can conflict with log retention — addresses this by defining legitimate security interest as a lawful basis for retention
* **Practical approach:** Anonymize or pseudonymize personal data in logs after the security retention period expires, rather than deleting the entire log record

**HIPAA (Health Insurance Portability and Accountability Act)** — USA:

* Audit logs for systems containing PHI (Protected Health Information) must be retained for **6 years**
* Covers: login/logout events, data access, modifications, transmissions

**PCI DSS (Payment Card Industry Data Security Standard)**:

* Audit logs must be retained for at least **12 months**
* At least 3 months must be immediately available (online)
* Applies to systems in the cardholder data environment (CDE)

**SOX (Sarbanes-Oxley Act)** — USA:

* Financial audit records: **7 years**
* Covers IT controls for financial reporting systems

**NIS2 Directive** — EU:

* Requires essential entities to maintain audit logs for **at least 3 years**
* Logs from security monitoring must be available for competent authority review

### 9.3 Practical Data Retention Architecture

A tiered storage approach balances cost, performance, and compliance:

```text
Hot Tier (0–90 days):
├── Fully indexed, fast query (sub-second for simple queries)
├── Stored on SSD or high-performance NVMe
├── Used for: daily operations, incident response, threat hunting
└── Cost: High ($$$)

Warm Tier (90 days – 12 months):
├── Partially indexed or summary indexed
├── Stored on HDD or object storage with query layer
├── Used for: incident investigation beyond 90 days, compliance audit
└── Cost: Medium ($$)

Cold/Archive Tier (12 months – 7+ years):
├── Compressed, not indexed (restore required for query)
├── Stored on object storage (S3, Azure Blob, GCS) or tape
├── Used for: legal holds, regulatory audit, forensic investigation
└── Cost: Low ($)
```

**Splunk SmartStore:** Offloads older indexes to S3-compatible object storage while maintaining searchability.

**Elasticsearch ILM (Index Lifecycle Management):** Automatically moves indices through hot → warm → cold → delete phases based on age.

### 9.4 Log Integrity

Log data used as evidence must be demonstrably unmodified.
Integrity mechanisms include:

* **Write-once storage:** WORM (Write Once Read Many) storage prevents modification after writing
* **Cryptographic hashing:** Compute SHA256 hash of each log file daily; store hashes in a separate system
* **Digital signatures:** Sign log batches with a private key; verify with the corresponding public key
* **Centralized logging:** Logs forwarded off the endpoint immediately cannot be tampered with after the fact (even if the endpoint is compromised)
* **Audit trails for the audit system:** Who accessed, modified, or deleted logs from the logging platform?

---

## 10. Putting It All Together: The Analysis Pipeline

The following end-to-end pipeline describes how a single real-world attack scenario — a user opening a phishing email and installing malware — would be detected and analyzed using the tools and concepts from this session.

### Scenario: Phishing to C2 Beacon

**T+0:00** — User `jsmith` on host `WORKSTATION-042` opens a malicious Word document.
The macro runs `powershell.exe -EncodedCommand <base64>`.

**Log sources activated:**

1. **Sysmon Event 1** (process creation): Word spawned `powershell.exe` with suspicious encoded command
1. **Sysmon Event 3** (network connection): `powershell.exe` makes an outbound HTTPS connection to `update-services.net`
1. **Zeek http.log**: DNS query for `update-services.net` resolves to `198.51.100.22`
1. **DNS log**: NXDOMAIN responses as DGA variants are tried before the successful resolution

**Detection pipeline:**

1. Sysmon events forwarded by Winlogbeat → Logstash (field normalization, GeoIP enrichment) → Elasticsearch
1. Zeek logs forwarded by Filebeat → Elasticsearch
1. Elastic Security rule fires: "Office application spawned scripting engine"
1. Second correlation: Script engine made network connection within 60 seconds of process creation

**Enrichment:**

* MISP lookup: `update-services.net` is tagged as C2 infrastructure for `TrojanDownloader:Win32/Emotet`
* VirusTotal: Domain registered 3 days ago, 12/90 vendors flag as malicious
* GeoIP: C2 IP resolves to a hosting provider in Eastern Europe

**Alert generated and triaged:**

* Tier 1 analyst reviews the alert with all context pre-populated
* Confirms: Office macro → PowerShell → Outbound connection to known-bad domain + newly registered domain → Emotet C2
* Escalates to Tier 2 as confirmed compromise
* Incident response initiated: host isolated via EDR, MISP event created to share IOCs with ISAC

**Post-incident:**

* IOCs added to MISP, shared with community
* Detection rule refined based on the specific Emotet macro technique
* Retention: All logs retained under 90-day hot tier; a legal hold tag extends retention to 7 years (litigation risk)

---

## 11. Key Takeaways

* **Collect broadly, normalize consistently.** Gaps in log collection are gaps in visibility. The most dangerous blind spot is the source you don't know you're missing.

* **Normalization enables cross-source correlation.** Without a common schema, correlation rules must be written separately for every data source. Standards like ECS, CIM, and CEF solve this at scale.

* **Time is everything.** UTC timestamps with millisecond precision and synchronized clocks are prerequisites for meaningful multi-source correlation.

* **IOCs are perishable.** IP-based and hash-based IOCs have lifespans measured in hours. Prioritize detection based on adversary TTPs (MITRE ATT&CK), not just known-bad indicators.

* **Context transforms alerts into intelligence.** An alert without context is noise. An alert enriched with asset information, threat intelligence, and historical behavior becomes actionable intelligence.

* **Alert fatigue is a real threat.** Poorly tuned rules that generate high false positive rates erode analyst effectiveness. Quality over quantity in detection engineering.

* **Retention is a security control.** You cannot investigate what you cannot search. Plan data retention with both security analysis requirements and regulatory obligations in mind.

---

## 12. References and Further Reading

### Books

* **Monnappa K A** — *Learning Malware Analysis* (Packt, 2018) — Chapter 1 covers tools for analyzing malware artifacts, relevant to the endpoint log analysis discussed in this session.
* **Chris Sanders and Jason Smith** — *Applied Network Security Monitoring: Collection, Detection, and Analysis* (No Starch Press, 2013) — The definitive practical guide to NSM; Chapters 3–6 directly cover the log collection and analysis techniques in this session.
* **Richard Bejtlich** — *The Practice of Network Security Monitoring* (No Starch Press, 2013) — Classic text on deploying NSM infrastructure with open-source tools.
* **Joseph Muniz and Aamir Lakhani** — *Security Operations Center: Building, Operating, and Maintaining Your SOC* (Cisco Press, 2015)

### Online Resources

* **Splunk Documentation** — Splunk Search Reference, Common Information Model (CIM), Enterprise Security Correlation Searches — https://docs.splunk.com
* **Elastic Security Documentation** — ECS specification, detection rules library — https://www.elastic.co/guide/en/security/current/index.html
* **MISP Project** — Official documentation, API reference — https://www.misp-project.org/documentation/
* **MITRE ATT&CK Framework** — Adversary tactics and techniques database — https://attack.mitre.org
* **Sigma Rules** — Community repository of generic SIEM detection rules in a vendor-neutral format — https://github.com/SigmaHQ/sigma
* **Sysmon documentation (Microsoft)** — https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
* **Zeek documentation** — https://docs.zeek.org

### Standards

* **ArcSight CEF Standard** — Common Event Format specification (HP ArcSight, v25)
* **Elastic Common Schema (ECS) specification** — https://www.elastic.co/guide/en/ecs/current/index.html
* **STIX 2.1 specification** — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
* **TAXII 2.1 specification** — https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html

### Tools Referenced

| Tool | Description | URL |
|------|-------------|-----|
| Splunk Free | SIEM platform (500MB/day free) | https://www.splunk.com/en_us/download.html |
| Elasticsearch + Kibana | Open-source search and analytics | https://www.elastic.co/downloads |
| MISP | Open-source TI platform | https://www.misp-project.org |
| Zeek | Network security monitor | https://zeek.org |
| Sysmon | Windows system monitor | https://docs.microsoft.com/sysinternals |
| Sigma | Generic SIEM rule format | https://github.com/SigmaHQ/sigma |
| VirusTotal | File/URL reputation service | https://www.virustotal.com |

---

*End of Session 03 Reading Material*

*Next: [Session 04 — Incident Response Fundamentals](../sec-ops-04-incident-response/reading.md)*
