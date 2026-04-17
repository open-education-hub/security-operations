# Guide 01: Log Parsing with Logstash Grok Patterns

**Level:** Basic

**Estimated time:** 30 minutes

**Goal:** Understand and write Grok patterns to parse common log formats

---

## What Is Grok?

Grok is a text-parsing mechanism in Logstash (and available as a library in other tools) that uses **named regular expressions** to extract structured fields from unstructured log strings.

Instead of writing raw regex like:

```text
(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```

You write:

```text
%{IP:source_ip}
```

Grok provides ~120 built-in patterns and allows you to define your own.

---

## Grok Pattern Syntax

```text
%{PATTERN_NAME:field_name:data_type}
```

* `PATTERN_NAME` — the name of a built-in or custom pattern
* `field_name` — the name to give the extracted value (optional)
* `data_type` — type coercion: `int`, `float` (optional; default is string)

**Examples:**

| Grok Expression | What It Extracts | Input Text |
|-----------------|-----------------|------------|
| `%{IP:src_ip}` | IP address as `src_ip` | `192.168.1.1` |
| `%{INT:port:int}` | Integer as `port` | `443` |
| `%{WORD:username}` | One word as `username` | `jdoe` |
| `%{GREEDYDATA:msg}` | Rest of the line as `msg` | `anything here` |
| `%{TIMESTAMP_ISO8601:ts}` | ISO8601 timestamp | `2024-12-14T07:42:01.000Z` |

---

## Frequently Used Built-in Patterns

```text
USERNAME       [a-zA-Z0-9._-]+
WORD           \b\w+\b
INT            (?:[+-]?(?:[0-9]+))
NUMBER         (?:%{BASE10NUM})
IP             (?:%{IPV6}|%{IPV4})
HOSTNAME       \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*.?\b
SYSLOGTIMESTAMP  %{MONTH} +%{MONTHDAY} %{TIME}
HTTPDATE       %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}
DATA           .*?           (non-greedy — stops at next match)
GREEDYDATA     .*            (greedy — takes everything remaining)
QS             %{QUOTEDSTRING}  (a quoted string, including quotes)
URIPATH        (?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)
URIPATHPARAM   %{URIPATH}(?:\?%{URIPARAM})?
```

---

## Exercise 1: Parse an Apache Access Log Line

**Input:**

```text
192.168.0.10 - alice [14/Dec/2024:09:00:01 +0000] "GET /api/users HTTP/1.1" 200 1024
```

**Step 1**: Identify the components:

1. Client IP: `192.168.0.10`
1. Ident: `-` (dash, often empty)
1. Auth user: `alice`
1. Timestamp: `14/Dec/2024:09:00:01 +0000`
1. HTTP method: `GET`
1. URI path: `/api/users`
1. HTTP version: `1.1`
1. Status code: `200`
1. Bytes: `1024`

**Step 2**: Write the pattern:

```text
%{IPORHOST:client_ip} %{DATA:ident} %{DATA:auth_user} \[%{HTTPDATE:access_time}\] "%{WORD:http_method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:http_version}" %{INT:status:int} %{INT:bytes:int}
```

**Step 3**: Test in Kibana Grok Debugger (Dev Tools → Grok Debugger) or online at https://grokdebug.herokuapp.com

**Expected extracted fields:**

```json
{
  "client_ip": "192.168.0.10",
  "ident": "-",
  "auth_user": "alice",
  "access_time": "14/Dec/2024:09:00:01 +0000",
  "http_method": "GET",
  "uri": "/api/users",
  "http_version": "1.1",
  "status": 200,
  "bytes": 1024
}
```

---

## Exercise 2: Parse an SSH Authentication Log

**Input:**

```text
Dec 14 07:42:01 webserver01 sshd[3822]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
```

**Pattern:**

```text
%{SYSLOGTIMESTAMP:syslog_ts} %{HOSTNAME:hostname} %{WORD:program}\[%{INT:pid:int}\]: %{WORD:action} password for (?:invalid user )?%{USERNAME:username} from %{IP:src_ip} port %{INT:src_port:int} %{WORD:ssh_proto}
```

**Expected fields:**

```json
{
  "syslog_ts": "Dec 14 07:42:01",
  "hostname": "webserver01",
  "program": "sshd",
  "pid": 3822,
  "action": "Failed",
  "username": "admin",
  "src_ip": "192.168.1.45",
  "src_port": 54321,
  "ssh_proto": "ssh2"
}
```

Note the `(?:invalid user )?` — a non-capturing group that makes the "invalid user" text optional.
This makes the same pattern work for both valid and invalid user failures.

---

## Exercise 3: Parse a Cisco ASA Syslog Message

**Input:**

```text
Dec 14 2024 07:42:00 %ASA-6-302013: Built inbound TCP connection 45123 for outside:203.0.113.42/31337 (203.0.113.42/31337) to inside:10.0.0.5/22 (10.0.0.5/22)
```

**Pattern:**

```text
%{MONTH:month} %{INT:day} %{YEAR:year} %{TIME:time} %%{DATA:asa_facility}-%{INT:asa_severity}-%{INT:asa_msgid}: Built %{WORD:direction} %{WORD:proto} connection %{INT:conn_id} for %{WORD:outside_iface}:%{IP:src_ip}\/%{INT:src_port:int} .+ to %{WORD:inside_iface}:%{IP:dst_ip}\/%{INT:dst_port:int}
```

---

## Multiple Pattern Alternatives

A single Grok filter can try multiple patterns using an array.
Logstash tries them in order and uses the first that matches:

```ruby
grok {
  match => {
    "message" => [
      # Pattern 1: Failed login for invalid user
      "Failed password for invalid user %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port:int}",
      # Pattern 2: Failed login for valid user
      "Failed password for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port:int}",
      # Pattern 3: Successful login
      "Accepted password for %{USERNAME:user} from %{IP:src_ip} port %{INT:src_port:int}",
      # Pattern 4: Disconnect
      "Disconnected from user %{USERNAME:user} %{IP:src_ip} port %{INT:src_port:int}"
    ]
  }
  tag_on_failure => ["_grokparsefailure"]
}
```

---

## Common Grok Mistakes

### Mistake 1: Missing whitespace/delimiter

```text
# Wrong: no space between fields
%{IP:ip}%{INT:port}

# Right: space between fields
%{IP:ip} %{INT:port}
```

### Mistake 2: Greedy vs non-greedy

```text
# Wrong: GREEDYDATA will consume the rest of the line,
# so the pattern after it never matches
"From: %{GREEDYDATA:from} To: %{DATA:to}"

# Right: Use DATA (non-greedy) when something follows
"From: %{DATA:from} To: %{GREEDYDATA:to}"
```

### Mistake 3: Not escaping special characters

```text
# Wrong: [ is a special regex character
"[%{HTTPDATE:ts}]"

# Right: escape brackets
"\[%{HTTPDATE:ts}\]"
```

### Mistake 4: Wrong pattern for the data type

```text
# Wrong: IP pattern won't match a hostname
%{IP:destination}

# Right: Use IPORHOST for things that can be either
%{IPORHOST:destination}
```

---

## Custom Pattern Files

For recurring patterns not in the default set, create a custom patterns file:

```console
# Create: /usr/share/logstash/patterns/my_patterns
CISCO_FACILITY %-[A-Z]+-\d+-\w+
SYSLOG_PRI <%{INT:syslog_facility_code}\>
AWS_REGION [a-z]{2}-[a-z]+-\d
```

Reference in Logstash:

```ruby
filter {
  grok {
    patterns_dir => ["/usr/share/logstash/patterns"]
    match => { "message" => "%{CISCO_FACILITY:facility}: %{GREEDYDATA:msg}" }
  }
}
```

---

## Checkpoint Questions

1. What is the difference between `%{DATA:x}` and `%{GREEDYDATA:x}`?
1. Why do we use `tag_on_failure => ["_grokparsefailure"]`?
1. How would you modify the SSH pattern to also capture the connection protocol (e.g., `ssh2`)?
1. What Logstash filter would you use to parse `key=value key=value` strings in a CEF extension?

**Answers:**

1. `DATA` is non-greedy (`.*?`) — stops at the next match. `GREEDYDATA` is greedy (`.*`) — takes everything until end of string.
1. Events that fail to parse get tagged, making it easy to identify and monitor parsing gaps without discarding events.
1. Add `%{WORD:ssh_proto}` at the end of the pattern.
1. The `kv` filter with `field_split => " "` and `value_split => "="`.
