# Drill 02 Solution: Normalization Mapping Exercise

---

## Event Set A Solution: AWS VPC Flow Log

| Source Field | Source Value | ECS Field | ECS Value | Type | Transformation |
|-------------|-------------|-----------|-----------|------|---------------|
| `srcaddr` | `203.0.113.42` | `source.ip` | `203.0.113.42` | ip | Direct rename |
| `dstaddr` | `10.0.1.100` | `destination.ip` | `10.0.1.100` | ip | Direct rename |
| `srcport` | `55234` | `source.port` | `55234` | integer | Rename + ensure int |
| `dstport` | `22` | `destination.port` | `22` | integer | Rename + ensure int |
| `protocol` | `6` | `network.transport` | `tcp` | keyword | Map via lookup table |
| `bytes` | `180` | `network.bytes` | `180` | long | Rename |
| `start` | `1734161000` | `@timestamp` | `2024-12-14T...Z` | date | epoch_s → ISO8601 |
| `action` | `REJECT` | `event.outcome` | `failure` | keyword | REJECT→failure, ACCEPT→success |
| — | — | `event.category` | `network` | keyword | Static |
| — | — | `cloud.provider` | `aws` | keyword | Static |
| `vpc_id` | `vpc-12345678` | `cloud.vpc.id` (custom) | `vpc-12345678` | keyword | Direct rename |
| `account_id` | `123456789012` | `cloud.account.id` | `123456789012` | keyword | Direct rename |

**Logstash implementation:**

```ruby
# IANA protocol number lookup
translate {
  field       => "protocol"
  destination => "[network][transport]"
  dictionary  => {
    "1"  => "icmp"
    "6"  => "tcp"
    "17" => "udp"
    "47" => "gre"
    "50" => "esp"
  }
  fallback    => "unknown"
}

# Convert Unix epoch to @timestamp
date {
  match  => ["start", "UNIX"]
  target => "@timestamp"
}

# Normalize action to ECS outcome
if [action] == "ACCEPT" {
  mutate { add_field => { "[event][outcome]" => "success" } }
} else if [action] == "REJECT" {
  mutate { add_field => { "[event][outcome]" => "failure" } }
}

# ECS field renames
mutate {
  rename => {
    "srcaddr"    => "[source][ip]"
    "dstaddr"    => "[destination][ip]"
    "srcport"    => "[source][port]"
    "dstport"    => "[destination][port]"
    "bytes"      => "[network][bytes]"
    "account_id" => "[cloud][account][id]"
    "vpc_id"     => "[labels][vpc_id]"
  }
  convert => {
    "[source][port]"      => "integer"
    "[destination][port]" => "integer"
    "[network][bytes]"    => "integer"
  }
  add_field => {
    "[event][category]"   => "network"
    "[event][kind]"       => "event"
    "[cloud][provider]"   => "aws"
    "[ecs][version]"      => "8.12.0"
  }
}
```

---

## Event Set B Solution: Cisco ASA LEEF Log

| Source Field | Source Value | ECS Field | Type |
|-------------|-------------|-----------|------|
| `src` | `10.0.5.22` | `source.ip` | ip |
| `dst` | `192.168.100.5` | `destination.ip` | ip |
| `srcPort` | `44321` | `source.port` | integer |
| `dstPort` | `443` | `destination.port` | integer |
| `proto` | `TCP` | `network.transport` | keyword (lowercase: `tcp`) |
| `usrName` | `vpnuser@corp.com` | `user.name` | keyword |
| `devTime` | `Dec 14 2024 09:15:00` | `@timestamp` | date |
| `cat` | `/Authentication/VPN` | `event.category` | keyword (map to `authentication`) |
| `sev` | `5` | `event.severity` | long |
| `msg` | `AAA authentication failed...` | `message` | text |
| — | — | `event.outcome` | keyword → `failure` (from msg content) |

**Severity conversion formula:**

```text
ECS severity = sev (0–10) × 10

Examples:
- LEEF sev 0 → ECS severity 0   (informational)
- LEEF sev 5 → ECS severity 50  (medium)
- LEEF sev 9 → ECS severity 90  (critical)
- LEEF sev 10 → ECS severity 100 (maximum)
```

**Logstash implementation:**

```ruby
# Normalize proto to lowercase
mutate { lowercase => ["proto"] }

# Convert LEEF severity (0-10) to ECS severity (0-100)
ruby {
  code => "
    sev = event.get('sev').to_i
    event.set('[event][severity]', sev * 10)
  "
}

# Determine event.outcome from message content
if "failed" in [msg] or "failure" in [msg] {
  mutate { add_field => { "[event][outcome]" => "failure" } }
} else if "success" in [msg] or "accepted" in [msg] {
  mutate { add_field => { "[event][outcome]" => "success" } }
}

date {
  match  => ["devTime", "MMM dd yyyy HH:mm:ss", "MMM  d yyyy HH:mm:ss"]
  target => "@timestamp"
}

mutate {
  rename => {
    "src"      => "[source][ip]"
    "dst"      => "[destination][ip]"
    "srcPort"  => "[source][port]"
    "dstPort"  => "[destination][port]"
    "proto"    => "[network][transport]"
    "usrName"  => "[user][name]"
    "msg"      => "message"
  }
  convert => {
    "[source][port]"      => "integer"
    "[destination][port]" => "integer"
  }
  add_field => {
    "[event][category]"  => "authentication"
    "[event][kind]"      => "event"
  }
}
```

---

## Event Set C Solution: CrowdStrike EDR Event

| Source Field | ECS Field | Type | Notes |
|-------------|-----------|------|-------|
| `timestamp` | `@timestamp` | date | epoch_millis format |
| `ComputerName` | `host.name` | keyword | Direct rename |
| `UserName` | `user.name` | keyword | Strip `CORP\\` prefix |
| `FileName` | `process.name` | keyword | Direct rename |
| `FilePath` + `FileName` | `process.executable` | keyword | Concatenate |
| `CommandLine` | `process.command_line` | wildcard | Direct rename |
| `ParentImageFileName` | `process.parent.name` | keyword | Direct rename |
| `ParentCommandLine` | `process.parent.command_line` | wildcard | Direct rename |
| `ProcessId_decimal` | `process.pid` | long | Rename |
| `ParentProcessId_decimal` | `process.parent.pid` | long | Rename |
| `MD5HashData` | `process.hash.md5` | keyword | Rename |
| `SHA256HashData` | `process.hash.sha256` | keyword | Rename |
| — | `event.category` | keyword | `process` |
| — | `event.type` | keyword | `start` |

**Logstash filter block:**

```ruby
filter {
  # Parse epoch milliseconds timestamp
  date {
    match  => ["timestamp", "UNIX_MS"]
    target => "@timestamp"
  }

  # Strip domain prefix from UserName (CORP\jsmith → jsmith)
  mutate {
    gsub => ["UserName", "^[^\\\\]+\\\\", ""]
  }

  # Build full executable path
  mutate {
    add_field => {
      "[process][executable]" => "%{FilePath}%{FileName}"
    }
  }

  # ECS field renames
  mutate {
    rename => {
      "ComputerName"            => "[host][name]"
      "UserName"                => "[user][name]"
      "FileName"                => "[process][name]"
      "CommandLine"             => "[process][command_line]"
      "ParentImageFileName"     => "[process][parent][name]"
      "ParentCommandLine"       => "[process][parent][command_line]"
      "ProcessId_decimal"       => "[process][pid]"
      "ParentProcessId_decimal" => "[process][parent][pid]"
      "MD5HashData"             => "[process][hash][md5]"
      "SHA256HashData"          => "[process][hash][sha256]"
      "aid"                     => "[labels][crowdstrike_aid]"
      "cid"                     => "[labels][crowdstrike_cid]"
    }
    convert => {
      "[process][pid]"        => "integer"
      "[process][parent][pid]" => "integer"
    }
    lowercase => ["[process][hash][md5]", "[process][hash][sha256]"]
    add_field => {
      "[event][category]"  => "process"
      "[event][type]"      => "start"
      "[event][kind]"      => "event"
      "[event][module]"    => "crowdstrike"
      "[event][dataset]"   => "crowdstrike.falcon"
      "[ecs][version]"     => "8.12.0"
    }
  }

  # Detect suspicious command characteristics
  if [process][command_line] =~ /(?i)-enc|-EncodedCommand/ {
    mutate {
      add_tag   => ["encoded_powershell"]
      add_field => { "[event][risk]" => "high" }
    }
  }
}
```

**Key points:**

* `UNIX_MS` in the `date` filter handles millisecond epoch timestamps
* The `gsub` pattern `^[^\\\\]+\\\\` removes everything up to and including the last backslash (domain prefix)
* Hash values should be lowercased for consistent lookups
* The `FilePath` in CrowdStrike ends with a backslash, so concatenation with `FileName` produces the correct full path
* Custom/vendor-specific fields that don't map to ECS should go into `labels` (for simple values) or custom namespaces

---

## Grading Rubric

* Event Set A mapping: 20 points (2 each)
* Event Set B mapping: 20 points (2 each) + 5 for formula
* Event Set C mapping: 25 points (2 each)
* Logstash filter block: 30 points
  * Correct timestamp handling: 8 points
  * Domain stripping: 7 points
  * Field renames: 10 points
  * Static ECS fields: 5 points
