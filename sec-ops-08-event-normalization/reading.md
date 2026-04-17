# Session 08: Event Correlation and Normalization

**Estimated reading time: ~2 hours**

---

## Table of Contents

1. [The Normalization Problem: Why Heterogeneous Logs Break Detection](#1-the-normalization-problem)
1. [Log Formats: A Taxonomy](#2-log-formats-a-taxonomy)
1. [Field Mapping and Normalization Techniques](#3-field-mapping-and-normalization-techniques)
1. [Parsing Tools](#4-parsing-tools)
1. [Event Correlation Concepts](#5-event-correlation-concepts)
1. [Correlation Rule Types](#6-correlation-rule-types)
1. [Rule Languages](#7-rule-languages)
1. [False Positive Management](#8-false-positive-management)
1. [Correlation Platforms: SIEM vs UEBA vs XDR](#9-correlation-platforms)
1. [Building a Detection Library](#10-building-a-detection-library)
1. [ATT&CK-Based Detection Coverage Measurement](#11-attck-based-detection-coverage)
1. [References](#12-references)

---

## 1. The Normalization Problem

### 1.1 The Modern SOC Log Landscape

A typical enterprise Security Operations Center (SOC) ingests logs from dozens—sometimes hundreds—of distinct source types: Windows Event Logs, Linux auditd records, firewall deny messages, web access logs, DNS query logs, VPN authentication logs, cloud trail events, EDR telemetry, and more.
Each of these sources was designed by a different vendor, for a different purpose, at a different point in time.
The result is a landscape of wildly inconsistent log formats.

Consider the same conceptual event—a failed authentication attempt—expressed by three different systems:

**Linux PAM (syslog):**

```text
Dec 14 07:42:01 webserver01 sshd[3822]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
```

**Windows Security Event Log (XML):**

```xml
<EventID>4625</EventID>
<TimeCreated SystemTime="2024-12-14T07:42:01.000Z"/>
<Computer>WORKSTATION01</Computer>
<Data Name="SubjectUserName">-</Data>
<Data Name="TargetUserName">admin</Data>
<Data Name="IpAddress">192.168.1.45</Data>
<Data Name="IpPort">54321</Data>
<Data Name="FailureReason">%%2313</Data>
```

**Cisco ASA Firewall:**

```text
Dec 14 2024 07:42:01: %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.45/54321 (192.168.1.45/54321) to inside:10.0.0.5/22 (10.0.0.5/22)
```

These three messages relate to the same underlying activity, but the source IP field is named differently (`from`, `IpAddress`, none), the timestamp format differs, the user is represented differently, and the event itself conveys different layers of the same activity.

### 1.2 Why This Matters for Detection

Detection rules operate on field values.
A correlation rule that looks for `src_ip = "192.168.1.45"` will only fire if the field is actually named `src_ip` in all ingested records.
Without normalization:

* Rules must be duplicated for each source format (multiplicative complexity).
* Cross-source correlation (e.g., "same IP seen in firewall deny AND authentication failure") becomes nearly impossible.
* Analysts waste time mentally translating field names during investigations.
* Reporting and dashboards require format-specific queries.

Normalization solves this by establishing a **common schema** to which all ingested events are mapped.
Once events are normalized, a single rule covers all sources, cross-source correlation works naturally, and analyst experience is consistent regardless of the originating system.

### 1.3 Normalization vs. Parsing

These terms are sometimes conflated but represent distinct operations:

| Operation | Definition | Example |
|-----------|------------|---------|
| **Parsing** | Extracting structured fields from a raw unstructured string | Extracting `src_ip=192.168.1.45` from a syslog message |
| **Normalization** | Mapping extracted fields to a common schema with standardized names and types | Renaming `src_ip` → `source.ip` (ECS) |
| **Enrichment** | Adding context not present in the original event | Adding `source.geo.country` by GeoIP lookup on `source.ip` |

All three steps are typically chained together in a log processing pipeline.

---

## 2. Log Formats: A Taxonomy

### 2.1 Raw Syslog (RFC 3164 / RFC 5424)

Syslog is the oldest and most widespread log transport protocol on Unix-like systems.
It defines a message structure but leaves the actual message payload entirely to the application.

**RFC 3164 format:**

```text
<PRI>TIMESTAMP HOSTNAME TAG: MSG
<13>Dec 14 07:42:01 webserver01 sshd[3822]: Failed password for...
```

**RFC 5424 format (structured data):**

```text
<165>1 2024-12-14T07:42:01.003Z webserver01 sshd 3822 - [exampleSDID@32473 iut="3"] Failed password...
```

The `PRI` value encodes **Facility** (bits 3–7) and **Severity** (bits 0–2).
Common severity values:

| Value | Keyword | Meaning |
|-------|---------|---------|
| 0 | emerg | System is unusable |
| 1 | alert | Action must be taken immediately |
| 2 | crit | Critical conditions |
| 3 | err | Error conditions |
| 4 | warning | Warning conditions |
| 5 | notice | Normal but significant |
| 6 | info | Informational |
| 7 | debug | Debug-level messages |

**Challenges:** The message body is a free-form string.
Parsing requires application-specific patterns.
Different applications using the same syslog facility produce completely different message structures.

### 2.2 CEF: Common Event Format (ArcSight / Micro Focus)

CEF was created by ArcSight (now Micro Focus) to provide a structured log format that maps easily into SIEM systems.
It is widely supported by network devices, security appliances, and applications.

**CEF format:**

```text
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example:**

```text
CEF:0|Cisco|ASA|9.8|106023|Deny IP due to Land Attack|8|src=192.168.1.45 spt=54321 dst=10.0.0.5 dpt=22 proto=TCP act=deny cs1=policy_name cs1Label=PolicyName
```

Key fields in the CEF extension:

* `src` / `dst` — source and destination IP
* `spt` / `dpt` — source and destination port
* `act` — action taken
* `msg` — human-readable message
* `cs1`–`cs6`, `cn1`–`cn3` — custom string/number fields with labels

**Strengths:** Widely supported, predictable structure, easier to parse than free-form syslog.

**Weaknesses:** Fixed set of standard fields; custom fields (`cs1`–`cs6`) are overloaded and not self-documenting without context.

### 2.3 LEEF: Log Event Extended Format (IBM QRadar)

IBM developed LEEF for use with QRadar.
It is conceptually similar to CEF but uses different delimiters and has some structural differences.

**LEEF format:**

```text
LEEF:Version|Vendor|Product|Version|EventID|[delimiter]key=value\tkey=value...
```

**Example (LEEF 1.0):**

```text
LEEF:1.0|Cisco|ASA|9.8|106023|src=192.168.1.45	dst=10.0.0.5	spt=54321	dpt=22	proto=TCP
```

**Example (LEEF 2.0, custom delimiter):**

```text
LEEF:2.0|Cisco|ASA|9.8|106023|^|src=192.168.1.45^dst=10.0.0.5^spt=54321^dpt=22
```

LEEF 2.0 allows a custom key-value delimiter to handle values that contain tabs.
The delimiter is specified as the 6th pipe-delimited field in the header.

**Key difference from CEF:** LEEF uses tabs (or a custom delimiter) between key-value pairs; CEF uses spaces.
LEEF also has a distinct attribute vocabulary (e.g., `usrName` vs CEF's `suser`).

### 2.4 ECS: Elastic Common Schema

ECS is an open-source log schema developed by Elastic.
Unlike CEF and LEEF (which are transport/serialization formats), ECS is purely a **field naming and typing convention** for structured (JSON) events stored in Elasticsearch.

ECS organizes fields into **field sets** (namespaces):

| Field Set | Example Fields |
|-----------|---------------|
| `base` | `@timestamp`, `message`, `tags`, `labels` |
| `event` | `event.kind`, `event.category`, `event.type`, `event.outcome` |
| `source` | `source.ip`, `source.port`, `source.user.name` |
| `destination` | `destination.ip`, `destination.port` |
| `user` | `user.name`, `user.id`, `user.domain` |
| `host` | `host.name`, `host.ip`, `host.os.type` |
| `process` | `process.name`, `process.pid`, `process.command_line` |
| `network` | `network.protocol`, `network.transport`, `network.direction` |
| `file` | `file.path`, `file.hash.sha256`, `file.size` |
| `url` | `url.full`, `url.domain`, `url.path` |
| `dns` | `dns.question.name`, `dns.question.type` |
| `threat` | `threat.indicator.type`, `threat.tactic.name` |

**ECS categorization model:** Every event should have:

* `event.kind`: `alert`, `event`, `metric`, `state`, `pipeline_error`, `signal`
* `event.category`: `authentication`, `file`, `network`, `process`, `registry`, `web`...
* `event.type`: `access`, `change`, `connection`, `creation`, `deletion`, `end`, `error`, `info`, `start`
* `event.outcome`: `success`, `failure`, `unknown`

This allows generic queries like "show me all failed authentication events" regardless of source.

**Example normalized authentication failure:**

```json
{
  "@timestamp": "2024-12-14T07:42:01.000Z",
  "event.kind": "event",
  "event.category": ["authentication"],
  "event.type": ["start"],
  "event.outcome": "failure",
  "source.ip": "192.168.1.45",
  "source.port": 54321,
  "destination.ip": "10.0.0.5",
  "destination.port": 22,
  "user.name": "admin",
  "host.name": "webserver01",
  "process.name": "sshd",
  "process.pid": 3822
}
```

### 2.5 OCSF: Open Cybersecurity Schema Framework

OCSF is a newer, vendor-neutral, community-driven schema framework launched in 2022 by AWS, Splunk, IBM, CrowdStrike, and others.
It is more prescriptive than ECS, defining not just field names but entire **event class taxonomies**.

**OCSF key concepts:**

* **Event Classes**: Numbered categories (e.g., 1001 = File System Activity, 3001 = Network Activity, 4001 = Security Finding)
* **Profiles**: Reusable field groupings that can be mixed into any event class
* **Observables**: Normalized representation of indicators (IP, hash, URL, etc.)
* **Activity IDs**: Numeric codes for specific actions within a class

**Example OCSF Authentication event (class 3002):**

```json
{
  "class_uid": 3002,
  "class_name": "Authentication",
  "activity_id": 1,
  "activity_name": "Logon",
  "time": 1734161121000,
  "status_id": 2,
  "status": "Failure",
  "src_endpoint": {
    "ip": "192.168.1.45",
    "port": 54321
  },
  "dst_endpoint": {
    "ip": "10.0.0.5",
    "port": 22
  },
  "user": {
    "name": "admin"
  },
  "auth_protocol_id": 99,
  "auth_protocol": "SSH"
}
```

**OCSF vs ECS:** ECS is optimized for Elastic Stack adoption; OCSF is designed as a true cross-vendor standard.
OCSF has a richer taxonomy and explicit activity codes, making it better suited for multi-vendor SIEM/XDR environments.
ECS has broader current tooling adoption.

### 2.6 Format Comparison Matrix

| Feature | Raw Syslog | CEF | LEEF | ECS | OCSF |
|---------|-----------|-----|------|-----|------|
| Schema strictness | None | Moderate | Moderate | High | Very High |
| Serialization | Text | Text (key=value) | Text (key=value) | JSON | JSON |
| Transport agnostic | Yes | Yes (over syslog) | Yes (over syslog) | Yes | Yes |
| Field vocabulary | None | ~50 standard | ~50 standard | ~400+ | ~500+ |
| Taxonomy | None | Severity-based | Severity-based | Category+Type | Class+Activity |
| Vendor support | Universal | Wide | QRadar-centric | Elastic-centric | Growing |
| Open standard | RFC | Proprietary | Proprietary | Open Source | Open Source |

---

## 3. Field Mapping and Normalization Techniques

### 3.1 The Normalization Pipeline

A normalization pipeline typically consists of these stages:

```text
Raw Event → Parsing → Type Casting → Field Renaming → Derived Fields → Enrichment → Storage
```

1. **Parsing**: Extract key-value pairs or structured fields from the raw string
1. **Type casting**: Convert strings to appropriate types (int, date, boolean, IP)
1. **Field renaming**: Map source-specific names to schema-standard names
1. **Derived fields**: Compute new fields (e.g., `event.outcome` from status code)
1. **Enrichment**: Add context (GeoIP, threat intelligence, asset lookup)

### 3.2 Field Mapping Tables

Organizations typically maintain explicit mapping tables documenting how each source field translates to the normalized schema.
Example mapping table (SSH auth failure):

| Source Field | Source Format | Normalized Field (ECS) | Type | Notes |
|-------------|---------------|----------------------|------|-------|
| `hostname` in syslog header | Syslog | `host.name` | keyword | |
| `timestamp` in syslog header | Syslog | `@timestamp` | date | Parse with strptime |
| `from <IP>` in message | Syslog/PAM | `source.ip` | ip | Regex extraction |
| `port <N>` in message | Syslog/PAM | `source.port` | integer | Regex extraction |
| `user <name>` in message | Syslog/PAM | `user.name` | keyword | |
| `process[pid]` in syslog | Syslog | `process.name`, `process.pid` | keyword, integer | Split on `[` |

### 3.3 Multi-Source Field Conflicts

When normalizing multiple sources, field conflicts arise.
Common conflict types:

**Semantic conflicts**: Different sources use the same field name for different purposes.

* Resolution: Always check source-specific documentation before mapping.

**Cardinality conflicts**: One source has a scalar value, another has an array.

* ECS solution: Many ECS fields are defined as arrays (e.g., `event.category` is always an array).

**Precision conflicts**: Timestamp precision varies (second vs. millisecond vs. microsecond).

* Resolution: Always store as milliseconds since epoch or ISO8601 with full precision.

**IP representation conflicts**: IPv4 mapped to IPv6 (`::ffff:192.168.1.45`).

* Resolution: Normalize to dotted-decimal IPv4 when possible; treat mapped addresses consistently.

### 3.4 Conditional Normalization

Some normalization decisions depend on the event content.
This requires conditional logic in the normalization pipeline:

```ruby
# Logstash pipeline example
if [event_id] == "4625" {
  mutate { add_field => { "[event][outcome]" => "failure" } }
  mutate { add_field => { "[event][category]" => ["authentication"] } }
} else if [event_id] == "4624" {
  mutate { add_field => { "[event][outcome]" => "success" } }
  mutate { add_field => { "[event][category]" => ["authentication"] } }
}
```

### 3.5 Normalization Testing

Always test normalization logic with a corpus of sample events:

1. **Unit tests**: Verify each individual parser with known input/output pairs.
1. **Integration tests**: Verify the full pipeline end-to-end.
1. **Regression tests**: Ensure changes don't break existing normalizations.
1. **Coverage metrics**: Track what percentage of ingested events successfully normalize vs. fail to parse.

A common metric is the **parse failure rate**: the percentage of events that could not be parsed by any configured pattern.
High failure rates indicate missing parsers or format changes from upstream sources.

---

## 4. Parsing Tools

### 4.1 Logstash and Grok Patterns

Logstash is the "L" in the ELK/Elastic Stack.
It is a data processing pipeline tool that reads events from inputs, transforms them through filters, and writes to outputs.

**Grok** is Logstash's primary text-parsing filter.
It uses named regular expression patterns to extract fields from unstructured text.
Grok patterns follow the syntax `%{PATTERN_NAME:field_name:type}`.

**Built-in grok patterns (selection):**

| Pattern | Regex | Example Match |
|---------|-------|---------------|
| `IP` | `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` | `192.168.1.45` |
| `INT` | `(?:[+-]?(?:[0-9]+))` | `3822` |
| `WORD` | `\b\w+\b` | `admin` |
| `DATA` | `.*?` | any string (non-greedy) |
| `GREEDYDATA` | `.*` | any string (greedy) |
| `TIMESTAMP_ISO8601` | ISO8601 pattern | `2024-12-14T07:42:01Z` |
| `SYSLOGTIMESTAMP` | syslog timestamp | `Dec 14 07:42:01` |
| `HOSTNAME` | hostname chars | `webserver01` |
| `USERNAME` | username chars | `jdoe` |

**Example Logstash configuration for SSH log parsing:**

```ruby
filter {
  grok {
    match => {
      "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:host_name} %{WORD:process_name}\[%{INT:process_pid:int}\]: %{GREEDYDATA:syslog_message}"
    }
    tag_on_failure => ["_grokparsefailure_syslog_header"]
  }

  if "sshd" in [process_name] {
    grok {
      match => {
        "syslog_message" => [
          "Failed password for invalid user %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int}",
          "Failed password for %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int}",
          "Accepted password for %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int}"
        ]
      }
      tag_on_failure => ["_grokparsefailure_ssh"]
    }
  }

  # Normalize to ECS
  mutate {
    rename => {
      "host_name"   => "[host][name]"
      "process_name" => "[process][name]"
      "process_pid" => "[process][pid]"
      "src_ip"      => "[source][ip]"
      "src_port"    => "[source][port]"
      "user_name"   => "[user][name]"
    }
  }

  if "Failed" in [syslog_message] {
    mutate {
      add_field => {
        "[event][outcome]" => "failure"
        "[event][category]" => "authentication"
      }
    }
  }

  date {
    match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
    target => "@timestamp"
    timezone => "UTC"
  }
}
```

**Grok Debugger**: Elastic provides an online Grok Debugger at `https://grokdebug.herokuapp.com` and it is also available in Kibana Dev Tools.

### 4.2 Fluentd

Fluentd is a CNCF-graduated log collector focused on reliability and a plugin-based architecture.
It is written in Ruby (with C extensions for performance-critical parts) and is particularly popular in Kubernetes environments.

**Key Fluentd concepts:**

* **Sources** (`<source>`): Where logs come from (tail, forward, http, syslog)
* **Filters** (`<filter>`): Transform events in-flight (record_transformer, parser, grep)
* **Match** (`<match>`): Where logs go (elasticsearch, s3, kafka, stdout)
* **Buffer**: Reliable delivery with configurable batching

**Example Fluentd configuration for SSH log normalization:**

```xml
<source>
  @type tail
  path /var/log/auth.log
  pos_file /var/log/fluentd/auth.log.pos
  tag auth.sshd
  <parse>
    @type regexp
    expression /^(?<syslog_time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?<hostname>\S+) (?<process>\w+)\[(?<pid>\d+)\]: (?<message>.*)$/
    time_key syslog_time
    time_format "%b %d %H:%M:%S"
  </parse>
</source>

<filter auth.sshd>
  @type record_transformer
  enable_ruby true
  <record>
    event_category "authentication"
    event_outcome ${record["message"].include?("Failed") ? "failure" : "success"}
    source_ip ${record["message"].match(/from (\d+\.\d+\.\d+\.\d+)/)&.captures&.first}
  </record>
</filter>

<match auth.**>
  @type elasticsearch
  host localhost
  port 9200
  index_name security-logs
  <buffer>
    @type file
    path /var/log/fluentd/buffer/auth
    flush_mode interval
    flush_interval 5s
    retry_max_times 5
  </buffer>
</match>
```

### 4.3 Vector

Vector (from Datadog) is a high-performance observability data pipeline written in Rust.
It is increasingly popular for high-throughput log ingestion due to its performance characteristics.

**Key Vector concepts:**

* **Sources**: Input configurations (file, syslog, kafka, http, kubernetes_logs)
* **Transforms**: Processing (remap/VRL, filter, reduce, route)
* **Sinks**: Outputs (elasticsearch, s3, kafka, splunk_hec)

Vector uses **VRL (Vector Remap Language)**, a purpose-built functional language for event transformation:

```toml
# vector.toml
[sources.auth_logs]
  type = "file"
  include = ["/var/log/auth.log"]

[transforms.parse_syslog]
  type = "remap"
  inputs = ["auth_logs"]
  source = '''
    . = parse_syslog!(string!(.message))
    .event.category = ["authentication"]

    if contains(string!(.message), "Failed") {
      .event.outcome = "failure"
    } else if contains(string!(.message), "Accepted") {
      .event.outcome = "success"
    }

    # Extract source IP
    match = parse_regex(.message, r'from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)')
    if is_ok(match) {
      .source.ip = match.ip
      .source.port = to_int!(match.port)
    }
  '''

[sinks.elasticsearch]
  type = "elasticsearch"
  inputs = ["parse_syslog"]
  endpoint = "http://localhost:9200"
  index = "security-logs-%Y.%m.%d"
```

### 4.4 Splunk: props.conf and transforms.conf

Splunk uses a configuration file-based approach to parsing and field extraction.
The two key configuration files are `props.conf` (source type properties) and `transforms.conf` (field transformations).

**props.conf**: Defines how Splunk handles each source type — timestamp extraction, line breaking, and which field extractions to apply.

```ini
# props.conf
[sshd_auth]
TIME_PREFIX = ^
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 20
TRANSFORMS-sshd = extract_sshd_fields
REPORT-sshd_normalization = sshd_to_ecs
```

**transforms.conf**: Defines regex-based field extractions and lookup tables.

```ini
# transforms.conf
[extract_sshd_fields]
REGEX = (?:Failed|Accepted) password for (?:invalid user )?(?P<user_name>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)
FORMAT = user_name::$1 src_ip::$2 src_port::$3
WRITE_META = true

[sshd_to_ecs]
REGEX = (Failed|Accepted) password
FORMAT = event_outcome::$1
WRITE_META = true
```

**SPL field aliasing**: Splunk also supports field aliasing to provide normalized field names:

```ini
[sshd_auth]
FIELDALIAS-source_ip = src_ip AS source.ip
FIELDALIAS-user = user_name AS user.name
```

### 4.5 Choosing a Parsing Tool

| Criteria | Logstash | Fluentd | Vector | Splunk |
|----------|----------|---------|--------|--------|
| Performance | Moderate (JVM) | Good | Excellent (Rust) | Good |
| Plugin ecosystem | Very large | Large | Growing | Very large |
| Config complexity | Moderate | Low-Moderate | Low-Moderate | High (conf files) |
| Best for | Elastic Stack | Kubernetes | High throughput | Splunk customers |
| Grok support | Native | Via plugin | Via VRL | Via regex |
| Memory footprint | High (JVM) | Low | Very Low | Moderate |

---

## 5. Event Correlation Concepts

### 5.1 What Is Correlation?

**Event correlation** is the process of analyzing multiple individual log events in relation to each other to identify patterns that are significant for security.
A single log event is rarely sufficient to determine a security incident; correlation reveals intent, behavior, and attack sequences that are invisible in individual events.

Analogy: A single frame from a security camera shows a person in a hallway.
Correlation across multiple cameras and time windows shows that person entered through the back, visited the server room, and left with a USB drive — a narrative invisible in any single frame.

### 5.2 Temporal Correlation

**Temporal correlation** analyzes events based on time relationships.
Key temporal concepts:

**Time windows**: A correlation rule evaluates events only within a defined time interval.
A "brute force" rule might count failed logins within a 5-minute window.

```text
Rule: If COUNT(event.outcome=failure) WHERE event.category=authentication
      AND source.ip = X WITHIN 5 minutes > 10 → ALERT
```

**Event sequencing**: Events must occur in a specific order.
For example:

1. Reconnaissance scan
1. Exploitation attempt
1. Successful shell access

**Temporal proximity**: Events from different sources must occur within a time threshold of each other to be considered related.
Configuring the right window is critical — too narrow causes missed detections; too wide causes false correlations.

**Time zone handling**: All events in a correlation engine must be in the same timezone (typically UTC).
This is a common source of bugs in log pipelines.

### 5.3 Statistical Correlation

**Statistical correlation** identifies deviations from established baselines.
It requires a learning or baselining phase.

**Frequency analysis**: Count events per unit time and alert on spikes.

* A DNS server querying 100 domains/second is normal; 10,000/second may indicate data exfiltration via DNS tunneling.

**Volume anomalies**: Data transfer amounts deviating from baseline.

* A workstation transferring 500MB to an external IP at 2 AM when it normally transfers <10MB/day.

**Ratio analysis**: Relationships between event types.

* A high ratio of failed-to-successful logins indicates brute forcing.
* A high ratio of NXDOMAIN responses to total DNS queries indicates domain generation algorithm (DGA) activity.

**Cardinality anomalies**: Unusual numbers of distinct values.

* A single source IP connecting to 100+ distinct destination ports in 1 minute (port scan).
* A user account authenticating from 20 distinct IP addresses in one hour (credential stuffing or account sharing).

### 5.4 Behavioral Correlation

**Behavioral correlation** builds a model of "normal" behavior for an entity (user, host, service) and alerts when behavior deviates significantly.
This is the domain of **UEBA (User and Entity Behavior Analytics)**.

**Behavioral baselines capture:**

* Typical working hours (time-of-day patterns)
* Typical accessed resources
* Typical network destinations
* Typical data transfer volumes
* Typical peer group behavior (other users with similar roles)

**Behavioral models:**

* **Peer group analysis**: Compare user's behavior to peers with similar job functions.
* **Time-series models**: Statistical models of activity over time (moving average, EWMA).
* **Machine learning models**: Clustering, isolation forests, autoencoders for anomaly detection.

**Risk scoring**: UEBA systems typically produce a numeric **risk score** per entity that aggregates signals from multiple behavioral anomalies.
No single anomaly triggers an alert; instead, the accumulated risk score exceeds a threshold.

### 5.5 Correlation Challenges

**Event ordering**: Network latency and processing delays mean events arrive out of order.
Correlation engines must either wait (introducing latency) or handle late arrivals (increasing complexity).

**Event enrichment timing**: Enriching events with threat intelligence or GeoIP data takes time.
Correlation that depends on enriched fields may miss events that haven't been enriched yet.

**Scalability**: At enterprise scale, a correlation engine may process millions of events per second.
Naive O(n²) correlation algorithms are computationally infeasible.

**Schema drift**: Source systems change their log formats over time, silently breaking parsers and normalization logic without obvious failures.

---

## 6. Correlation Rule Types

### 6.1 Single-Event Rules

Single-event rules evaluate each event independently.
They trigger on a specific combination of field values in one event.

**Examples:**

* Any event with `event.id = 4688` (Windows process creation) where `process.name = "mimikatz.exe"`
* Any DNS query where `dns.question.name` matches a known-bad domain

**Advantages:** Simple, low-latency, no state required.

**Limitations:** Easily bypassed by attackers who know the rule (rename the tool, vary the command).

```yaml
# Sigma single-event rule example
title: Mimikatz Execution
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\mimikatz.exe'
  condition: selection
```

### 6.2 Multi-Event Rules (Aggregation)

Multi-event rules aggregate events over time.
They trigger when the count of matching events exceeds a threshold within a time window.

**Examples:**

* More than 5 failed login attempts from the same IP within 2 minutes
* More than 100 DNS queries from a single host within 1 minute

**Key parameters:**

* **Group-by field**: The field used to group events (e.g., `source.ip`)
* **Count threshold**: The number of events that triggers the alert
* **Time window**: The period over which events are counted

```splunk
# Splunk SPL multi-event rule
index=auth sourcetype=linux_secure "Failed password"
| bucket _time span=2m
| stats count as fail_count by _time, src_ip
| where fail_count > 5
```

### 6.3 Time-Window Rules

Time-window rules look for specific events occurring within a time window, potentially across different sources or entities.

**Sliding window**: The window "slides" forward in time; each new event triggers re-evaluation.

**Tumbling window**: Fixed, non-overlapping time windows; events are evaluated once per window interval.

**Session window**: A window that extends as long as events keep arriving (with a gap timeout to close the window).

**Example: Login from unusual location within short time of normal login**

```text
IF user.name = X AND source.geo.country_iso_code != baseline_country
   AND EXISTS (successful_login for X within last 1 hour from baseline_country)
THEN alert "impossible travel"
```

### 6.4 Sequence-Based Rules (Attack Chains)

Sequence rules require events to occur in a specific order.
They are used to detect multi-stage attack chains (ATT&CK Kill Chain phases).

**Example: Lateral movement sequence**

```text
Step 1: Process execution event: net.exe or whoami.exe (Discovery)
Step 2 (within 5 min): SMB connection from same host to different internal host
Step 3 (within 5 min): Successful authentication on target host
→ ALERT: Suspected lateral movement
```

**Implementation considerations:**

* Sequence rules require stateful processing (tracking which steps have been observed per entity).
* The entity key (e.g., `host.name`) ties the sequence together.
* Partial sequences should be tracked in memory/cache with TTL.
* Late-arriving events can invalidate completed sequences or extend pending ones.

### 6.5 Baseline Deviation Rules

Baseline deviation rules compare current activity to a historical baseline.

```text
IF today's_bytes_out_for_user > (7day_avg + 3 * 7day_stddev)
THEN alert "unusual data transfer volume"
```

These rules require:

1. A baselining period (typically 7–30 days of historical data)
1. A chosen statistical model (mean+stddev, percentile, ML model)
1. Periodic baseline refresh to account for gradual legitimate change

---

## 7. Rule Languages

### 7.1 Sigma

Sigma is an **open, vendor-neutral rule format** for SIEM correlation rules.
Think of it as "Snort for logs" — a standard language that can be compiled/transpiled to queries in any SIEM's native language.

**Sigma rule structure:**

```yaml
title: Suspicious PowerShell Encoded Command
id: c7e91a02-d771-4a6d-a700-42587e0b1095
status: experimental
description: Detects suspicious PowerShell execution with encoded command argument
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: SecurityTeam
date: 2024/12/14
modified: 2024/12/14
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'powershell'
      - '-enc'
  selection_base64:
    CommandLine|re: '[A-Za-z0-9+/]{100,}={0,2}'
  condition: selection and selection_base64
falsepositives:
  - Legitimate software using encoded PowerShell commands
  - Administrative scripts
level: high
```

**Sigma compilation**: The `sigma` tool (or `pySigma`) compiles Sigma rules to:

* Splunk SPL
* Elasticsearch KQL/Lucene
* Microsoft Sentinel KQL
* Chronicle YARA-L
* QRadar AQL
* Sumo Logic
* ...and more

**Converting a Sigma rule to Splunk SPL:**

```console
sigma convert -t splunk -p splunk_windows rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml
```

### 7.2 KQL: Kusto Query Language (Microsoft)

KQL is Microsoft's query language used in:

* Microsoft Sentinel (SIEM)
* Microsoft Defender XDR
* Azure Monitor / Log Analytics

KQL has a pipeline syntax similar to Unix pipes:

```kusto
// Detect brute force: >10 failed logins in 5 minutes from same IP
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailCount = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by IpAddress, bin(TimeGenerated, 5m)
| where FailCount > 10
| project TimeGenerated, IpAddress, FailCount, FirstSeen, LastSeen
| order by FailCount desc
```

**KQL correlation with join:**

```kusto
// Correlate failed logins followed by successful login (brute force success)
let failed_logins = SecurityEvent
| where EventID == 4625
| summarize FailCount = count() by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where FailCount > 5;

SecurityEvent
| where EventID == 4624
| join kind=inner failed_logins on TargetUserName, IpAddress
| project TimeGenerated, TargetUserName, IpAddress, FailCount
| extend Alert = "Brute Force Success"
```

### 7.3 SPL: Splunk Processing Language

SPL is Splunk's search and analytics language.
It uses a pipe-delimited command syntax.

**Basic search with aggregation:**

```splunk
index=security sourcetype=WinEventLog:Security EventCode=4625
| eval time_bucket = floor(_time/300)*300
| stats count as fail_count by time_bucket, src_ip, user
| where fail_count > 10
| eval alert_time = strftime(time_bucket, "%Y-%m-%d %H:%M:%S")
| table alert_time, src_ip, user, fail_count
| sort -fail_count
```

**Transaction-based correlation (session building):**

```splunk
index=security (EventCode=4625 OR EventCode=4624)
| transaction user startswith="EventCode=4625" endswith="EventCode=4624" maxspan=10m maxpause=2m
| where eventcount > 5
| eval outcome = if(eventcount > 5 AND EventCode="4624", "brute_force_success", "brute_force_attempt")
```

**Correlation across multiple sources with join:**

```splunk
index=firewall action=blocked
| rename src AS remote_ip
| join type=inner remote_ip [
    search index=authentication failed=true
    | rename source_ip AS remote_ip
    | stats count as auth_failures by remote_ip
    | where auth_failures > 3
  ]
| table _time, remote_ip, auth_failures
```

### 7.4 YARA-L (Google Chronicle / SecOps)

YARA-L is Google Chronicle's rule language, designed specifically for large-scale, multi-event correlation over security telemetry.

**YARA-L 2.0 rule structure:**

```text
rule rule_name {
  meta:
    // Rule metadata
  events:
    // Event patterns to match
  match:
    // Variables to group events by
  condition:
    // Logical condition to trigger alert
}
```

**Example YARA-L brute force rule:**

```yara-l
rule brute_force_followed_by_success {
  meta:
    author = "SecurityTeam"
    description = "Detects brute force attack followed by successful login"
    severity = "HIGH"
    mitre_attack_tactic = "Credential Access"
    mitre_attack_technique = "T1110"

  events:
    $failed.metadata.event_type = "USER_LOGIN"
    $failed.metadata.vendor_name = "Microsoft"
    $failed.security_result.action = "BLOCK"
    $failed.principal.ip = $src_ip
    $failed.target.user.userid = $username

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.ip = $src_ip
    $success.target.user.userid = $username

  match:
    $src_ip, $username over 10m

  condition:
    #failed > 5 and $success
}
```

**YARA-L vs other languages:**

* YARA-L is optimized for petabyte-scale historical search (Chronicle stores years of data).
* The `match ... over` clause natively handles time windowing.
* YARA-L 2.0 added `outcome` section for computing derived fields in the alert.

### 7.5 Language Comparison

| Feature | Sigma | KQL | SPL | YARA-L |
|---------|-------|-----|-----|--------|
| Portability | Excellent (compiles to others) | Microsoft only | Splunk only | Chronicle only |
| Multi-event | Via aggregation | Native (join, summarize) | Native (transaction, join) | Native (match..over) |
| Time windows | Via sigma rules | `ago()`, `bin()` | `bucket`, `maxspan` | `match..over` |
| Learning curve | Low | Moderate | Moderate | Moderate-High |
| Community rules | Very large | Growing | Large | Limited |
| Open source | Yes | No (query language is open) | No | No |

---

## 8. False Positive Management

### 8.1 The False Positive Problem

A false positive is an alert that fires on legitimate, benign activity.
In security operations, false positives are not merely inconvenient — they are operationally dangerous:

* **Alert fatigue**: Analysts become desensitized to alerts and stop investigating them carefully.
* **Cost**: Each false positive requires analyst time to investigate and close.
* **Opportunity cost**: Time spent on false positives is time not spent on real threats.
* **Trust erosion**: Excessive false positives cause teams to disable detection rules, creating blind spots.

The goal is not zero false positives (which would require extremely loose rules that also miss real threats) but a **manageable false positive rate** — typically targeting <10% of alerts being true positives in a mature SOC, with the goal of improving over time.

### 8.2 Tuning Strategies

**Threshold tuning**: Adjust the count/time threshold of aggregation rules.

* Start conservative (low threshold = more alerts), then increase as false positives are identified.
* Use percentile analysis to set thresholds that exclude the bulk of normal activity.

```splunk
# Find the distribution of login failure counts to inform threshold setting
index=security EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip
| stats perc50(count), perc90(count), perc95(count), perc99(count) by src_ip
```

**Scope narrowing**: Add additional conditions to reduce false positive scope.

```yaml
# Before (too broad - fires on all encoded PS)
detection:
  selection:
    CommandLine|contains: '-encodedCommand'

# After (narrowed - excludes known-good software paths)
detection:
  selection:
    CommandLine|contains: '-encodedCommand'
  filter_legitimate:
    Image|startswith:
      - 'C:\Program Files\ManagementSoftware\'
      - 'C:\Windows\System32\WindowsPowerShell\'
    ParentImage|endswith: '\svchost.exe'
  condition: selection and not filter_legitimate
```

**Time-based filtering**: Many legitimate processes run during business hours; suspicious activity often occurs outside these windows.

```splunk
| where hour(_time) < 7 OR hour(_time) > 19
| where NOT (dayofweek(_time) >= 2 AND dayofweek(_time) <= 6)  # Mon-Fri business hours
```

### 8.3 Whitelisting and Allowlisting

**Static whitelists**: Predefined lists of known-good values (IPs, hostnames, user accounts, hashes) that are excluded from alerting.

```yaml
# Sigma rule with whitelist
detection:
  selection:
    EventID: 4648
  filter_service_accounts:
    SubjectUserName|endswith: '$'  # Computer accounts
  filter_known_tools:
    ProcessName|endswith:
      - '\mstsc.exe'
      - '\TeamViewer.exe'
  condition: selection and not 1 of filter_*
```

**Dynamic whitelists (lookup tables)**: Regularly updated lists from authoritative sources (IT asset management, HR system, change management).

```splunk
# Splunk lookup-based whitelist
index=security EventCode=4625
| lookup authorized_scanners src_ip OUTPUT is_scanner
| where isnull(is_scanner) OR is_scanner != "true"
```

**Contextual whitelisting**: Instead of whitelisting an IP globally, whitelist it only for specific behaviors.

* "Vulnerability scanner 10.0.1.100 is allowed to generate port scan alerts but not brute force alerts."

### 8.4 Contextual Enrichment for FP Reduction

Enriching events with context before alerting allows more precise filtering:

**Asset context**: Is the destination host a server (expected to receive connections) or a workstation (unexpected)?

**User context**: Is this user in the IT admin group (expected privileged behavior) or a regular user?

**Threat intelligence context**: Is the source IP known-bad (elevate priority) or known-good (CDN, scanner)?

**Time context**: Is this activity occurring during a scheduled maintenance window?

**Change management context**: Is there an active change ticket that explains this behavior?

### 8.5 False Negative Management

The flip side of false positives: **false negatives** (missed real attacks) are the more dangerous failure mode.
Tuning rules too aggressively to eliminate false positives risks introducing false negatives.

**Balancing approach:**

1. Never whitelist based on `user.name` alone — attackers can impersonate any user.
1. Prefer narrow `filter_*` conditions over broad whitelist patterns.
1. Log all suppressed events (even if no alert fires) for retrospective analysis.
1. Regularly review whitelists — "authorized scanner" IPs change, service accounts get compromised.
1. Test rules against red team/purple team activity to verify they fire on real attacks.

### 8.6 Rule Maturity Model

| Stage | FP Rate | Description |
|-------|---------|-------------|
| Experimental | Very high | New rule, not yet tuned |
| Development | High | Under active tuning |
| Testing | Moderate | Validated against test environment |
| Stable | Low | Tuned, deployed in production |
| Deprecated | N/A | Replaced by better rule |

Sigma uses this maturity model in the `status` field of rules.

---

## 9. Correlation Platforms

### 9.1 SIEM: Security Information and Event Management

A SIEM is a platform that collects, stores, and correlates security event data from across the environment.
Core SIEM capabilities:

* **Log collection and normalization**: Ingest from diverse sources, parse to common schema
* **Long-term retention**: Store events for compliance (often 1–7 years)
* **Real-time correlation**: Apply detection rules to event streams
* **Alerting**: Generate and route alerts to analysts
* **Case management integration**: Feed alerts to ticketing/SOAR platforms
* **Dashboards and reporting**: Operational and compliance reporting

**Leading SIEM platforms:**

| Platform | Vendor | Query Language | Notes |
|----------|--------|----------------|-------|
| Splunk Enterprise Security | Splunk/Cisco | SPL | Market leader, most mature |
| Microsoft Sentinel | Microsoft | KQL | Cloud-native, Azure-integrated |
| IBM QRadar | IBM | AQL | Strong network analytics |
| Google Chronicle | Google | YARA-L/UDM | Petabyte-scale, flat-rate |
| Elastic Security | Elastic | EQL/KQL | Open source core, SIEM on top |
| LogRhythm SIEM | LogRhythm | — | Strong automation |
| Exabeam | Exabeam | — | UEBA-first SIEM |

### 9.2 UEBA: User and Entity Behavior Analytics

UEBA platforms specialize in detecting anomalous behavior using machine learning models that go beyond simple threshold-based rules.
UEBA addresses the insider threat and compromised account detection use case, where the attacker is operating within normal access patterns.

**UEBA vs SIEM correlation:**
| Aspect | SIEM | UEBA |
|--------|------|------|
| Detection approach | Rule-based | Behavior-based (ML) |
| Baseline required | No | Yes (days–weeks) |
| Insider threat detection | Weak | Strong |
| Zero-day detection | Weak | Moderate |
| Explainability | High (rule fired) | Moderate (anomaly scored) |
| False positive rate | Variable | Can be high during baselining |
| Alert volume | Often high | Lower (risk score aggregation) |

Modern SIEMs increasingly embed UEBA capabilities: Exabeam, Splunk ES + UEBA, Microsoft Sentinel with ML, etc.

### 9.3 XDR: Extended Detection and Response

XDR is a newer platform category that integrates telemetry from endpoints, networks, cloud, email, and identity into a unified detection and response platform.
XDR vendors typically include:

* Native endpoint sensor (EDR)
* Network detection integration
* Cloud workload monitoring
* Email security integration
* Identity/IAM integration
* Automated response capabilities

**SIEM vs XDR:**
| Aspect | SIEM | XDR |
|--------|------|-----|
| Primary use case | Compliance + detection | Detection + response |
| Data breadth | All log sources | Curated security telemetry |
| Out-of-box detection | Rules required | Vendor-provided AI detection |
| Response automation | Via SOAR integration | Native automated response |
| Analyst experience | Query-heavy | Guided investigation |
| Data retention | Long-term (compliance) | Shorter (operational) |
| Openness | High (ingest anything) | Moderate (own sensors preferred) |

**The SIEM + XDR hybrid model**: Many mature SOCs run both — XDR for rapid detection and response across the endpoint/network/cloud stack, SIEM for compliance log retention, custom rules, and integration with legacy sources the XDR doesn't cover.

---

## 10. Building a Detection Library

### 10.1 Detection-as-Code

Treating detection rules as code enables:

* **Version control**: Track who changed what and why.
* **Peer review**: Detection logic reviewed before deployment.
* **Automated testing**: Rules validated against sample events.
* **CI/CD pipeline**: Automated deployment to production SIEM.
* **Rollback**: Easily revert rules that cause alert storms.

**Repository structure:**

```text
detection-rules/
├── rules/
│   ├── windows/
│   │   ├── credential_access/
│   │   ├── lateral_movement/
│   │   └── persistence/
│   ├── linux/
│   │   ├── privilege_escalation/
│   │   └── execution/
│   ├── network/
│   └── cloud/
├── tests/
│   ├── unit/
│   └── integration/
├── parsers/
├── lookups/
└── pipelines/
```

### 10.2 Rule Lifecycle Management

Each rule should have documented metadata:

```yaml
# Example rule metadata
id: "DET-2024-0042"
title: "Suspicious Service Installation"
description: "Detects installation of a new Windows service with suspicious characteristics"
author: "analyst@company.com"
created: 2024-12-14
modified: 2024-12-14
version: "1.2"
status: stable
mitre_attack:
  - tactic: Persistence
    technique: T1543.003
data_sources:
  - Windows Security Event Log (Event ID 7045)
  - Sysmon Event ID 11
testing_notes: "Validated against Atomic Red Team T1543.003"
tuning_history:
  - date: 2024-12-14
    change: "Added filter for SYSTEM-installed services to reduce FPs"
    analyst: "analyst@company.com"
```

### 10.3 Testing Rules Before Deployment

**Unit testing with sample events:**

```python
# pytest-based rule testing example
def test_brute_force_rule_fires_on_10_failures():
    events = [make_auth_failure_event() for _ in range(11)]
    result = run_rule("brute_force_detection", events, window="5m")
    assert result.triggered == True
    assert result.alert_count == 1

def test_brute_force_rule_does_not_fire_on_5_failures():
    events = [make_auth_failure_event() for _ in range(5)]
    result = run_rule("brute_force_detection", events, window="5m")
    assert result.triggered == False
```

**Integration testing with Atomic Red Team**: Use Atomic Red Team (Red Canary) test cases to validate that detection rules fire on actual attack technique simulations.

```console
# Run an Atomic Red Team test for T1059.001
Invoke-AtomicTest T1059.001 -TestNumbers 1
# Then verify the SIEM fired the expected alert
```

**Regression testing**: Before deploying a modified rule, run it against a corpus of historical "golden" events (known-true-positive and known-true-negative events) and verify the expected outcome.

### 10.4 Rule Prioritization

Not all detections are equal.
Prioritize rules by:

1. **Coverage of high-risk ATT&CK techniques**: Focus first on techniques used in recent threat campaigns against your sector.
1. **Signal-to-noise ratio**: High-fidelity rules (low FP rate) get priority in analyst queues.
1. **Response time criticality**: Ransomware deployment should trigger immediate response; insider threat can tolerate more investigation time.
1. **Data availability**: Rules requiring data sources you don't have are useless; build parsers first.

**Priority matrix:**

```text
HIGH fidelity + HIGH severity → P1: Immediate automated response
HIGH fidelity + LOW severity  → P3: Queue for analyst review
LOW fidelity + HIGH severity  → P2: Notify analyst, investigate
LOW fidelity + LOW severity   → P4: Log, suppress unless context changes
```

---

## 11. ATT&CK-Based Detection Coverage Measurement

### 11.1 The MITRE ATT&CK Framework

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of adversary behaviors derived from real-world observations.
It provides:

* **Tactics**: The adversary's goal (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact)
* **Techniques**: How the adversary achieves the goal (e.g., T1059 — Command and Scripting Interpreter)
* **Sub-techniques**: More specific variants (e.g., T1059.001 — PowerShell)
* **Procedures**: Specific usage of a technique by a known threat actor

### 11.2 Coverage Mapping

By tagging each detection rule with the ATT&CK techniques it covers, you can generate a **coverage heatmap** that visualizes your detection posture.

```yaml
# Sigma rule with ATT&CK tags
tags:
  - attack.execution           # Tactic
  - attack.t1059.001          # Technique
  - attack.t1059              # Parent technique
```

**Coverage levels:**

* **Technique coverage**: Do you have at least one rule for this technique?
* **Sub-technique coverage**: Do you cover all sub-techniques?
* **Procedure coverage**: Do you detect the specific TTP used by relevant threat actors?
* **Data source coverage**: Do you have the data sources required to detect this technique?

### 11.3 ATT&CK Navigator

The ATT&CK Navigator is a web-based tool for annotating ATT&CK matrices with coverage data.
You can:

* Import a JSON layer file with technique scores and colors
* Visualize coverage gaps
* Compare coverage before/after adding new rules
* Overlay threat actor profiles to prioritize detection investment

**Generating a coverage layer from Sigma rules:**

```console
# Using sigma tooling to generate ATT&CK Navigator layer
sigma list --tags attack.* rules/ | \
  python3 generate_navigator_layer.py > coverage_layer.json
```

### 11.4 Detection Gap Analysis

A detection gap analysis compares your current detection coverage against a target — typically the techniques used by threat actors relevant to your industry.

**Process:**

1. Identify relevant threat actor groups (use MITRE ATT&CK Groups database, industry threat reports).
1. Extract the techniques used by those actors.
1. Map your existing detection rules to techniques.
1. Identify gaps: techniques used by relevant actors where you have no detection.
1. Prioritize gap filling based on technique prevalence and potential impact.

**Example gap analysis for ransomware:**

```text
Ransomware-relevant techniques:
T1486 - Data Encrypted for Impact          → COVERED (file encryption detection)
T1490 - Inhibit System Recovery            → COVERED (vssadmin/bcdedit rule)
T1059.001 - PowerShell                     → COVERED (encoded PS rule)
T1078 - Valid Accounts                     → PARTIAL (has threshold rule, missing behavioral)
T1021.002 - SMB/Admin Shares               → GAP (no detection)
T1057 - Process Discovery                  → GAP (no process enumeration detection)

Priority: Implement SMB/Admin Shares detection next (T1021.002)
```

---

## 12. References

### Standards and Schemas

* IETF RFC 3164: The BSD Syslog Protocol. https://datatracker.ietf.org/doc/html/rfc3164
* IETF RFC 5424: The Syslog Protocol. https://datatracker.ietf.org/doc/html/rfc5424
* Elastic Common Schema (ECS) Documentation. https://www.elastic.co/guide/en/ecs/current/
* Open Cybersecurity Schema Framework (OCSF). https://schema.ocsf.io/
* ArcSight Common Event Format (CEF). Micro Focus Security Community.

### Tools and Platforms

* Logstash Reference. https://www.elastic.co/guide/en/logstash/current/
* Fluentd Documentation. https://docs.fluentd.org/
* Vector Documentation. https://vector.dev/docs/
* Splunk Search Reference. https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

### Rule Languages and Frameworks

* Sigma Project. https://github.com/SigmaHQ/sigma
* MITRE ATT&CK Framework. https://attack.mitre.org/
* ATT&CK Navigator. https://mitre-attack.github.io/attack-navigator/
* Google Chronicle YARA-L. https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview
* Kusto Query Language (KQL). https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/

### Detection Engineering

* Detection Engineering with Sigma. Florian Roth, Thomas Patzke. (GitHub: SigmaHQ)
* Atomic Red Team. https://github.com/redcanaryco/atomic-red-team
* The Detection Maturity Level (DML) Model. Ryan Stillions. http://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html
* Palantir's Alerting and Detection Strategy (ADS) Framework. https://github.com/palantir/alerting-detection-strategy-framework

### Research Papers

* Liao, X., et al. (2016). Acing the IOC Game: Toward Automatic Discovery and Analysis of Open-Source Cyber Threat Intelligence. CCS.
* Sommer, R., & Paxson, V. (2010). Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. IEEE S&P.
* Milajerdi, S.M., et al. (2019). HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows. IEEE S&P.
