# Demo 01: Log Parsing with Grok Patterns in Logstash

**Duration:** ~45 minutes

**Difficulty:** Beginner–Intermediate

**Prerequisites:** Docker and Docker Compose installed

---

## Overview

In this demo you will build a Logstash pipeline that ingests raw syslog messages from multiple sources (SSH, Apache, sudo, cron), parses them with Grok patterns, and ships the structured results to an Elasticsearch index.
You will use the Grok Debugger to test patterns before deploying them.

By the end of this demo you will be able to:

* Write and test Grok patterns for common log formats
* Build a multi-source Logstash pipeline
* Tag events with parse failure markers for quality monitoring

---

## Environment Setup

### docker-compose.yml

```yaml
version: '3.8'

services:
  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: demo01-logstash
    volumes:
      - ./pipeline:/usr/share/logstash/pipeline
      - ./sample-logs:/var/log/demo
      - ./patterns:/usr/share/logstash/patterns
    environment:
      - LS_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "5044:5044"
      - "9600:9600"
    networks:
      - demo-net

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: demo01-es
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    networks:
      - demo-net

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: demo01-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - demo-net

networks:
  demo-net:
    driver: bridge
```

---

## Step 1: Sample Log Files

Create the sample log files that the pipeline will parse.

### sample-logs/auth.log

```text
Dec 14 07:42:01 webserver01 sshd[3822]: Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2
Dec 14 07:42:03 webserver01 sshd[3822]: Failed password for invalid user root from 192.168.1.45 port 54322 ssh2
Dec 14 07:42:05 webserver01 sshd[3822]: Failed password for invalid user oracle from 192.168.1.45 port 54323 ssh2
Dec 14 07:42:08 webserver01 sshd[3840]: Accepted password for jdoe from 10.0.1.100 port 22100 ssh2
Dec 14 07:42:09 webserver01 sshd[3840]: pam_unix(sshd:session): session opened for user jdoe by (uid=0)
Dec 14 07:43:00 webserver01 sudo[3901]: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash
Dec 14 07:43:01 webserver01 sudo[3901]: pam_unix(sudo:auth): authentication failure; logname=jdoe uid=1001 euid=0 tty=/dev/pts/0
Dec 14 08:00:01 webserver01 CRON[4100]: (root) CMD (/usr/bin/php /var/www/cron.php)
Dec 14 09:15:22 webserver01 sshd[4200]: Invalid user testuser from 203.0.113.42 port 31337
Dec 14 09:15:23 webserver01 sshd[4201]: Failed password for invalid user testuser from 203.0.113.42 port 31338 ssh2
```

### sample-logs/apache_access.log

```text
192.168.0.10 - - [14/Dec/2024:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0)"
10.0.1.5 - alice [14/Dec/2024:09:00:05 +0000] "POST /api/login HTTP/1.1" 401 256 "https://example.com/login" "curl/7.68.0"
203.0.113.42 - - [14/Dec/2024:09:00:10 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 512 "-" "python-requests/2.28"
10.0.1.5 - alice [14/Dec/2024:09:00:15 +0000] "POST /api/login HTTP/1.1" 200 512 "https://example.com/login" "curl/7.68.0"
192.168.0.11 - bob [14/Dec/2024:09:01:00 +0000] "GET /admin/config HTTP/1.1" 403 128 "-" "Mozilla/5.0 (Linux)"
```

### sample-logs/firewall.log (CEF format)

```text
Dec 14 07:42:00 fw01 CEF:0|Cisco|ASA|9.8|106023|Deny IP due to Land Attack|8|src=192.168.1.45 spt=54321 dst=10.0.0.5 dpt=22 proto=TCP act=Deny msg=Access denied
Dec 14 07:42:05 fw01 CEF:0|Cisco|ASA|9.8|302013|Built inbound TCP connection|2|src=10.0.1.100 spt=22100 dst=10.0.0.5 dpt=22 proto=TCP act=Allow
Dec 14 08:00:00 fw01 CEF:0|Cisco|ASA|9.8|106023|Outbound Access Denied|6|src=10.0.2.50 spt=45000 dst=203.0.113.1 dpt=4444 proto=TCP act=Deny msg=Blocked outbound to suspicious IP
```

---

## Step 2: Custom Grok Patterns

Create custom patterns to extend built-in Grok patterns.

### patterns/custom_patterns

```text
# SSH-specific patterns
SSH_AUTH_TYPE (password|publickey|gssapi-with-mic|keyboard-interactive)
SSH_ACTION (Failed|Accepted|Disconnected|Invalid)

# Apache combined log format components
APACHE_USER [a-zA-Z0-9._-]+|-
APACHE_AUTH_USER [a-zA-Z0-9._-]+|-

# CEF header
CEF_HEADER CEF:%{INT:cef_version}\|%{DATA:device_vendor}\|%{DATA:device_product}\|%{DATA:device_version}\|%{DATA:signature_id}\|%{DATA:event_name}\|%{INT:severity}

# CEF key=value pairs
CEF_KEYVALUE (?:%{WORD:kv_key}=%{DATA:kv_val}(?:\s|$))+
```

---

## Step 3: Logstash Pipeline Configuration

### pipeline/01-inputs.conf

```ruby
input {
  # Tail the auth log file
  file {
    path => "/var/log/demo/auth.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"  # For demo: always re-read
    type => "syslog_auth"
    tags => ["auth", "syslog"]
  }

  # Tail Apache access log
  file {
    path => "/var/log/demo/apache_access.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    type => "apache_access"
    tags => ["web", "apache"]
  }

  # Tail firewall CEF log
  file {
    path => "/var/log/demo/firewall.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    type => "firewall_cef"
    tags => ["firewall", "cef"]
  }
}
```

### pipeline/02-filters.conf

```ruby
filter {

  # ================================================================
  # SYSLOG HEADER PARSER (common to all syslog-based logs)
  # ================================================================
  if [type] in ["syslog_auth"] {
    grok {
      patterns_dir => ["/usr/share/logstash/patterns"]
      match => {
        "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_host} %{PROG:process_name}(?:\[%{POSINT:process_pid}\])?: %{GREEDYDATA:syslog_message}"
      }
      tag_on_failure => ["_grokparsefailure_syslog_header"]
    }

    # Parse the syslog timestamp
    date {
      match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
      target => "@timestamp"
      timezone => "UTC"
    }

    # Normalize host to ECS
    mutate {
      rename => { "syslog_host" => "[host][name]" }
      rename => { "process_name" => "[process][name]" }
      rename => { "process_pid"  => "[process][pid]" }
      convert => { "[process][pid]" => "integer" }
    }
  }

  # ================================================================
  # SSH LOG PARSER
  # ================================================================
  if [type] == "syslog_auth" and [process][name] == "sshd" {
    grok {
      patterns_dir => ["/usr/share/logstash/patterns"]
      match => {
        "syslog_message" => [
          # Failed password for invalid user
          "%{SSH_ACTION:ssh_action} password for invalid user %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int} %{WORD:ssh_proto}",
          # Failed/Accepted password for valid user
          "%{SSH_ACTION:ssh_action} password for %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int} %{WORD:ssh_proto}",
          # Invalid user (no auth attempt yet)
          "Invalid user %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port:int}",
          # Session opened/closed
          "session %{WORD:session_action} for user %{USERNAME:user_name}"
        ]
      }
      tag_on_failure => ["_grokparsefailure_ssh"]
    }

    # Normalize to ECS
    if [src_ip] {
      mutate {
        rename => { "src_ip"   => "[source][ip]" }
        rename => { "src_port" => "[source][port]" }
      }
    }
    if [user_name] {
      mutate { rename => { "user_name" => "[user][name]" } }
    }

    # Set event fields
    mutate {
      add_field => {
        "[event][category]" => "authentication"
        "[event][type]"     => "start"
        "[network][protocol]" => "ssh"
      }
    }

    if [ssh_action] == "Failed" or [ssh_action] == "Invalid" {
      mutate { add_field => { "[event][outcome]" => "failure" } }
    } else if [ssh_action] == "Accepted" {
      mutate { add_field => { "[event][outcome]" => "success" } }
    }
  }

  # ================================================================
  # SUDO LOG PARSER
  # ================================================================
  if [type] == "syslog_auth" and [process][name] == "sudo" {
    grok {
      match => {
        "syslog_message" => [
          "%{USERNAME:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:runas_user} ; COMMAND=%{GREEDYDATA:command}",
          "pam_unix\(sudo:auth\): authentication failure; logname=%{USERNAME:sudo_user} uid=%{INT:user_uid:int}"
        ]
      }
      tag_on_failure => ["_grokparsefailure_sudo"]
    }

    mutate {
      add_field => {
        "[event][category]" => "process"
        "[event][type]"     => "start"
      }
    }

    if [sudo_user] {
      mutate { rename => { "sudo_user" => "[user][name]" } }
    }
    if [command] {
      mutate { rename => { "command" => "[process][command_line]" } }
    }
  }

  # ================================================================
  # APACHE ACCESS LOG PARSER
  # ================================================================
  if [type] == "apache_access" {
    grok {
      match => {
        "message" => "%{IPORHOST:client_ip} %{APACHE_USER:ident} %{APACHE_AUTH_USER:auth_user} \[%{HTTPDATE:access_time}\] \"%{WORD:http_method} %{URIPATHPARAM:request_uri} HTTP/%{NUMBER:http_version}\" %{INT:http_status:int} %{INT:bytes_sent:int}(?: %{QS:http_referer})?(?: %{QS:http_useragent})?"
      }
      tag_on_failure => ["_grokparsefailure_apache"]
    }

    date {
      match => ["access_time", "dd/MMM/yyyy:HH:mm:ss Z"]
      target => "@timestamp"
    }

    # Normalize to ECS
    mutate {
      rename => { "client_ip"     => "[source][ip]" }
      rename => { "http_method"   => "[http][request][method]" }
      rename => { "request_uri"   => "[url][path]" }
      rename => { "http_status"   => "[http][response][status_code]" }
      rename => { "bytes_sent"    => "[http][response][bytes]" }
      rename => { "http_useragent" => "[user_agent][original]" }
      add_field => {
        "[event][category]" => "web"
        "[event][type]"     => "access"
      }
    }

    if [auth_user] and [auth_user] != "-" {
      mutate { rename => { "auth_user" => "[user][name]" } }
    }

    # Set outcome based on status code
    if [http][response][status_code] >= 400 {
      mutate { add_field => { "[event][outcome]" => "failure" } }
    } else {
      mutate { add_field => { "[event][outcome]" => "success" } }
    }

    # Detect path traversal attempt
    if [url][path] =~ /\.\./ {
      mutate { add_tag => ["path_traversal_attempt"] }
    }
  }

  # ================================================================
  # CEF FIREWALL LOG PARSER
  # ================================================================
  if [type] == "firewall_cef" {
    # First parse the syslog wrapper
    grok {
      match => {
        "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{HOSTNAME:syslog_host} %{HOSTNAME:device_name} %{GREEDYDATA:cef_message}"
      }
      tag_on_failure => ["_grokparsefailure_cef_syslog"]
    }

    date {
      match => ["syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
      target => "@timestamp"
      timezone => "UTC"
    }

    # Parse CEF header
    grok {
      match => {
        "cef_message" => "CEF:%{INT:cef_version}\|%{DATA:device_vendor}\|%{DATA:device_product}\|%{DATA:device_version}\|%{DATA:signature_id}\|%{DATA:event_name}\|%{INT:cef_severity}\|%{GREEDYDATA:cef_extension}"
      }
      tag_on_failure => ["_grokparsefailure_cef_header"]
    }

    # Parse CEF extension key=value pairs using kv filter
    kv {
      source        => "cef_extension"
      field_split   => " "
      value_split   => "="
      target        => "cef_ext"
    }

    # Map CEF fields to ECS
    if [cef_ext][src] {
      mutate { rename => { "[cef_ext][src]" => "[source][ip]" } }
    }
    if [cef_ext][dst] {
      mutate { rename => { "[cef_ext][dst]" => "[destination][ip]" } }
    }
    if [cef_ext][spt] {
      mutate {
        rename  => { "[cef_ext][spt]" => "[source][port]" }
        convert => { "[source][port]" => "integer" }
      }
    }
    if [cef_ext][dpt] {
      mutate {
        rename  => { "[cef_ext][dpt]" => "[destination][port]" }
        convert => { "[destination][port]" => "integer" }
      }
    }
    if [cef_ext][proto] {
      mutate { rename => { "[cef_ext][proto]" => "[network][transport]" } }
    }

    mutate {
      add_field => {
        "[event][category]" => "network"
        "[event][type]"     => "connection"
      }
    }

    if [cef_ext][act] == "Deny" {
      mutate { add_field => { "[event][outcome]" => "failure" } }
    } else if [cef_ext][act] == "Allow" {
      mutate { add_field => { "[event][outcome]" => "success" } }
    }

    # Compute numeric severity to ECS severity string
    if [cef_severity] {
      if [cef_severity] >= 7 {
        mutate { add_field => { "[event][severity]" => "high" } }
      } else if [cef_severity] >= 4 {
        mutate { add_field => { "[event][severity]" => "medium" } }
      } else {
        mutate { add_field => { "[event][severity]" => "low" } }
      }
    }

    mutate {
      rename  => { "syslog_host"  => "[host][name]" }
      convert => { "cef_severity" => "integer" }
    }
  }

  # ================================================================
  # COMMON CLEANUP: Remove intermediate fields
  # ================================================================
  mutate {
    remove_field => ["syslog_timestamp", "syslog_message", "cef_message", "cef_extension"]
  }

  # Add pipeline metadata
  mutate {
    add_field => {
      "[event][ingested]" => "%{@timestamp}"
      "[ecs][version]"    => "8.12.0"
    }
  }
}
```

### pipeline/03-outputs.conf

```ruby
output {
  # Send all events to Elasticsearch
  elasticsearch {
    hosts  => ["http://elasticsearch:9200"]
    index  => "demo01-parsed-%{[type]}-%{+YYYY.MM.dd}"
    # Use ECS-compatible index template
    template_name    => "demo01"
    template_overwrite => true
  }

  # Print parse failures to stdout for debugging
  if "_grokparsefailure_syslog_header" in [tags] or
     "_grokparsefailure_ssh"           in [tags] or
     "_grokparsefailure_apache"        in [tags] or
     "_grokparsefailure_cef_header"    in [tags] {
    stdout {
      codec => rubydebug {
        metadata => false
      }
    }
  }
}
```

---

## Step 4: Running the Demo

```bash
# Start all services
docker-compose up -d

# Watch Logstash logs
docker logs -f demo01-logstash

# Wait for Elasticsearch to be ready (~30 seconds), then check indices
curl -s http://localhost:9200/_cat/indices?v

# Query parsed SSH events
curl -s -X GET "http://localhost:9200/demo01-parsed-syslog_auth-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "match": { "event.outcome": "failure" }
    },
    "_source": ["@timestamp", "host.name", "source.ip", "user.name", "event.outcome"],
    "size": 10
  }'

# Query parsed Apache events
curl -s -X GET "http://localhost:9200/demo01-parsed-apache_access-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "range": { "http.response.status_code": { "gte": 400 } }
    },
    "_source": ["@timestamp", "source.ip", "url.path", "http.response.status_code"],
    "size": 10
  }'

# Count parse failures (should be 0 with correct patterns)
curl -s "http://localhost:9200/demo01-parsed-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "terms": {
        "tags": ["_grokparsefailure_syslog_header", "_grokparsefailure_ssh", "_grokparsefailure_apache"]
      }
    },
    "size": 0
  }'
```

---

## Step 5: Testing with the Grok Debugger

Open Kibana at `http://localhost:5601` → Dev Tools → Grok Debugger.

Test patterns manually before adding them to the pipeline:

**Test 1: SSH failed login**

* Sample: `Failed password for invalid user admin from 192.168.1.45 port 54321 ssh2`
* Pattern: `%{WORD:ssh_action} password for invalid user %{USERNAME:user_name} from %{IP:src_ip} port %{INT:src_port} %{WORD:ssh_proto}`

**Test 2: Apache access log**

* Sample: `192.168.0.10 - - [14/Dec/2024:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024`
* Pattern: `%{IPORHOST:client_ip} %{DATA:ident} %{DATA:auth} \[%{HTTPDATE:time}\] "%{WORD:method} %{URIPATHPARAM:uri} HTTP/%{NUMBER:version}" %{INT:status} %{INT:bytes}`

---

## Step 6: Observability — Parse Quality Dashboard

Run this Elasticsearch query to get parse success/failure rates:

```json
GET demo01-parsed-*/_search
{
  "size": 0,
  "aggs": {
    "by_type": {
      "terms": { "field": "type.keyword" },
      "aggs": {
        "parse_failures": {
          "filter": {
            "terms": {
              "tags": [
                "_grokparsefailure_syslog_header",
                "_grokparsefailure_ssh",
                "_grokparsefailure_apache",
                "_grokparsefailure_cef_header"
              ]
            }
          }
        },
        "total": { "value_count": { "field": "@timestamp" } }
      }
    }
  }
}
```

---

## Cleanup

```console
docker-compose down -v
```

---

## Key Takeaways

1. Grok patterns use named captures (`%{PATTERN:fieldname}`) to extract fields from free-form text.
1. Chain multiple `grok` blocks: first parse the common envelope (syslog header), then parse the message body in a second pass.
1. Use `tag_on_failure` to label events that fail to parse — this is your quality signal.
1. Always use the `date` filter to set `@timestamp` from the event's own timestamp, not the ingestion time.
1. CEF and LEEF logs benefit from the `kv` filter for the extension section after grok parses the header.
1. Field normalization (renaming) should happen in `mutate` blocks after extraction.
