# Guide 02: Mapping Fields to ECS / CEF Normalized Format

**Level:** Basic

**Estimated time:** 30 minutes

**Goal:** Build a field mapping table and apply it in a Logstash normalization pipeline

---

## Why Field Normalization Matters

After parsing a log event, you have a set of field names specific to that source:

| Source | Field Name | Meaning |
|--------|-----------|---------|
| Linux PAM | `from` | Source IP of connecting client |
| Windows Security | `IpAddress` | Source IP of connecting client |
| Cisco ASA CEF | `src` | Source IP of connecting client |
| Palo Alto firewall | `src` | Source IP of connecting client |
| AWS CloudTrail | `sourceIPAddress` | Source IP of connecting client |

Five different field names for the same concept.
A correlation rule that searches for `source.ip = "203.0.113.42"` only works if all five have been normalized to `source.ip`.

---

## The ECS Field Hierarchy

ECS uses dot-notation namespaces:

```text
<namespace>.<field_name>
```

For nested structures:

```text
<namespace>.<subnamespace>.<field_name>
```

**Key ECS namespaces for security events:**

```text
@timestamp              Canonical event timestamp (always UTC)
message                 Human-readable log message
event.kind              alert | event | metric | state
event.category          authentication | file | network | process | web
event.type              access | change | connection | creation | start | end
event.outcome           success | failure | unknown
event.code              Source-specific event code (e.g., "4625")
event.severity          Numeric severity (0–100 scale)

source.ip               Source IP address
source.port             Source port
destination.ip          Destination IP
destination.port        Destination port

host.name               Hostname of the reporting system
host.os.type            windows | linux | macos | unix

user.name               Username
user.id                 User identifier (UID, SID)
user.domain             Domain or realm

process.name            Process executable name
process.pid             Process ID (integer)
process.command_line    Full command line
process.parent.name     Parent process name

network.protocol        Application protocol (ssh, http, dns)
network.transport       Transport protocol (tcp, udp)
network.direction       inbound | outbound | internal | external | unknown

file.path               Full file path
file.name               File name only
file.hash.sha256        SHA-256 hash

url.full                Full URL
url.domain              Hostname portion
url.path                Path portion

dns.question.name       Queried domain name
dns.question.type       Record type (A, AAAA, MX, TXT)

cloud.provider          aws | azure | gcp
cloud.region            Cloud region identifier
cloud.account.id        Cloud account/subscription ID
```

---

## Building a Field Mapping Table

### Step 1: Identify Source Fields

First, collect sample events from each source and list all the fields they produce after parsing.

**SSH syslog (after grok):**

```text
syslog_ts, hostname, program, pid, action, username, src_ip, src_port, ssh_proto
```

**Windows Security Event 4625 (after XML extraction):**

```text
event_id, time_created, computer, target_user, target_domain, src_ip, src_port, logon_type, failure_reason
```

**CEF firewall (after CEF parsing):**

```text
cef_version, vendor, product, device_version, sig_id, event_name, severity,
ext_src, ext_dst, ext_spt, ext_dpt, ext_proto, ext_act, ext_msg
```

### Step 2: Map to ECS

| Source | Source Field | ECS Field | Type | Transformation |
|--------|-------------|-----------|------|----------------|
| SSH syslog | `syslog_ts` | `@timestamp` | date | Parse with strptime |
| SSH syslog | `hostname` | `host.name` | keyword | Direct rename |
| SSH syslog | `program` | `process.name` | keyword | Direct rename |
| SSH syslog | `pid` | `process.pid` | integer | Rename + cast |
| SSH syslog | `src_ip` | `source.ip` | ip | Rename |
| SSH syslog | `src_port` | `source.port` | integer | Rename + cast |
| SSH syslog | `username` | `user.name` | keyword | Rename |
| SSH syslog | `"sshd"` literal | `network.protocol` | keyword | Static value |
| SSH syslog | `action == "Failed"` | `event.outcome = "failure"` | keyword | Conditional |
| Win 4625 | `time_created` | `@timestamp` | date | Parse ISO8601 |
| Win 4625 | `computer` | `host.name` | keyword | Rename |
| Win 4625 | `target_user` | `user.name` | keyword | Rename |
| Win 4625 | `target_domain` | `user.domain` | keyword | Rename |
| Win 4625 | `src_ip` | `source.ip` | ip | Rename |
| Win 4625 | `src_port` | `source.port` | integer | Rename + cast |
| Win 4625 | `event_id == 4625` | `event.outcome = "failure"` | keyword | Conditional |
| CEF FW | `timestamp` | `@timestamp` | date | Parse syslog ts |
| CEF FW | `ext_src` | `source.ip` | ip | Rename |
| CEF FW | `ext_dst` | `destination.ip` | ip | Rename |
| CEF FW | `ext_spt` | `source.port` | integer | Rename + cast |
| CEF FW | `ext_dpt` | `destination.port` | integer | Rename + cast |
| CEF FW | `ext_proto` | `network.transport` | keyword | Rename, lowercase |
| CEF FW | `ext_act == "Deny"` | `event.outcome = "failure"` | keyword | Conditional |
| CEF FW | `severity` | `event.severity` | integer | Map: 8-10→high, etc |

---

## Implementing the Mapping in Logstash

### Method 1: `mutate rename`

The simplest case — field exists with a different name:

```ruby
mutate {
  rename => {
    "src_ip"   => "[source][ip]"
    "src_port" => "[source][port]"
    "username" => "[user][name]"
    "hostname" => "[host][name]"
    "program"  => "[process][name]"
    "pid"      => "[process][pid]"
  }
  convert => {
    "[source][port]"  => "integer"
    "[process][pid]"  => "integer"
  }
}
```

### Method 2: `mutate add_field` for Static/Derived Values

For fields that don't come from the source but are derived:

```ruby
mutate {
  add_field => {
    "[event][kind]"     => "event"
    "[event][category]" => "authentication"
    "[ecs][version]"    => "8.12.0"
    "[network][protocol]" => "ssh"
  }
}
```

### Method 3: Conditional Field Setting

When the ECS value depends on the content of a source field:

```ruby
# Set event.outcome based on action keyword
if [action] == "Failed" or [action] == "Invalid" {
  mutate { add_field => { "[event][outcome]" => "failure" } }
} else if [action] == "Accepted" {
  mutate { add_field => { "[event][outcome]" => "success" } }
} else {
  mutate { add_field => { "[event][outcome]" => "unknown" } }
}
```

### Method 4: `translate` for Value Mapping

When source values need to be mapped to ECS values via a lookup:

```ruby
# Map Windows logon types to ECS strings
translate {
  field       => "logon_type"
  destination => "[event][type]"
  dictionary  => {
    "2" => "interactive"
    "3" => "network"
    "4" => "batch"
    "5" => "service"
    "7" => "unlock"
    "8" => "network_cleartext"
    "10" => "remote_interactive"
  }
  fallback => "unknown"
}
```

---

## CEF to ECS Mapping Reference

CEF has ~50 standard fields.
Here is the complete mapping for the most common ones:

| CEF Field | CEF Description | ECS Field |
|-----------|----------------|-----------|
| `src` | Source IP address | `source.ip` |
| `dst` | Destination IP | `destination.ip` |
| `spt` | Source port | `source.port` |
| `dpt` | Destination port | `destination.port` |
| `proto` | Transport protocol | `network.transport` |
| `suser` / `duser` | Source/dest username | `user.name` |
| `fname` | File name | `file.name` |
| `fsize` | File size | `file.size` |
| `act` | Action taken | `event.action` |
| `outcome` | Outcome | `event.outcome` |
| `msg` | Message description | `message` |
| `request` | Request URL | `url.full` |
| `requestMethod` | HTTP method | `http.request.method` |
| `cat` | Event category | `event.category` |
| `severity` | CEF severity 0–10 | `event.severity` (map to 0–100) |
| `deviceSeverity` | Device severity | `log.level` |
| `cn1` / `cn1Label` | Custom number + label | Custom field |
| `cs1` / `cs1Label` | Custom string + label | Custom field |

---

## LEEF to ECS Mapping Reference

| LEEF Field | LEEF Description | ECS Field |
|------------|-----------------|-----------|
| `src` | Source IP | `source.ip` |
| `dst` | Destination IP | `destination.ip` |
| `srcPort` | Source port | `source.port` |
| `dstPort` | Destination port | `destination.port` |
| `proto` | Protocol | `network.transport` |
| `usrName` | Username | `user.name` |
| `identSrc` | Source user identity | `user.name` |
| `identHostName` | Source hostname | `host.name` |
| `sev` | Severity | `event.severity` |
| `cat` | Category | `event.category` |
| `devTime` | Device timestamp | `@timestamp` |
| `srcMAC` | Source MAC | `source.mac` |
| `dstMAC` | Destination MAC | `destination.mac` |

---

## Validating Your Normalization

After applying normalization, verify that:

1. **All events have `@timestamp`** (no nulls or defaults)
1. **All events have `event.category`** and `event.outcome`
1. **IP fields are type `ip`** (verify with Elasticsearch mapping check)
1. **Integer fields are integers** (not strings)

```bash
# Check for events missing critical ECS fields
curl -s "http://localhost:9200/security-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "should": [
          { "bool": { "must_not": { "exists": { "field": "event.category" } } } },
          { "bool": { "must_not": { "exists": { "field": "event.outcome" } } } },
          { "bool": { "must_not": { "exists": { "field": "source.ip" } } } }
        ],
        "minimum_should_match": 1
      }
    },
    "size": 5,
    "_source": ["event.dataset", "message"]
  }'
```

---

## Checkpoint Questions

1. Why does ECS define `event.category` as an array rather than a scalar string?
1. What is the ECS field for the full command line of a process?
1. A CEF event has `act=Deny`. What is the correct ECS `event.outcome` mapping?
1. Why is it important to cast port fields to integers rather than keeping them as strings?
