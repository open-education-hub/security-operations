# Demo 02: Normalizing to ECS with Elasticsearch

**Duration:** ~45 minutes

**Difficulty:** Intermediate

**Prerequisites:** Docker, Docker Compose, completion of Demo 01 recommended

---

## Overview

This demo demonstrates normalizing events from multiple sources to the Elastic Common Schema (ECS) and storing them in Elasticsearch with proper index templates.
You will:

1. Define an ECS-compliant index template with correct field mappings
1. Ingest events from Windows Event Log XML, Linux syslog, and AWS CloudTrail JSON
1. Use Logstash pipeline conditionals to normalize each source to ECS
1. Validate normalization correctness with Kibana Discovery and Dev Tools
1. Write cross-source queries that leverage the common schema

---

## Environment Setup

### docker-compose.yml

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: demo02-es
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    volumes:
      - esdata02:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - demo-net
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:9200/_cluster/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 10

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: demo02-logstash
    volumes:
      - ./pipeline:/usr/share/logstash/pipeline
      - ./sample-data:/var/log/demo
    environment:
      - LS_JAVA_OPTS=-Xms512m -Xmx512m
    depends_on:
      elasticsearch:
        condition: service_healthy
    networks:
      - demo-net

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: demo02-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - demo-net

volumes:
  esdata02:

networks:
  demo-net:
```

---

## Step 1: ECS Index Template

Create the ECS-compliant index template via the Elasticsearch API:

### setup/create-ecs-template.sh

```bash
#!/bin/bash
ES_HOST="${ES_HOST:-http://localhost:9200}"

echo "Creating ECS index template..."

curl -s -X PUT "${ES_HOST}/_index_template/ecs-security" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["security-*"],
    "priority": 500,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s"
      },
      "mappings": {
        "dynamic": "false",
        "_source": { "enabled": true },
        "properties": {
          "@timestamp":   { "type": "date" },
          "message":      { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
          "tags":         { "type": "keyword" },
          "labels":       { "type": "object" },
          "ecs": {
            "properties": {
              "version": { "type": "keyword" }
            }
          },
          "event": {
            "properties": {
              "kind":      { "type": "keyword" },
              "category":  { "type": "keyword" },
              "type":      { "type": "keyword" },
              "outcome":   { "type": "keyword" },
              "code":      { "type": "keyword" },
              "severity":  { "type": "long" },
              "ingested":  { "type": "date" },
              "created":   { "type": "date" },
              "dataset":   { "type": "keyword" },
              "module":    { "type": "keyword" }
            }
          },
          "source": {
            "properties": {
              "ip":   { "type": "ip" },
              "port": { "type": "integer" },
              "user": {
                "properties": {
                  "name": { "type": "keyword" }
                }
              },
              "geo": {
                "properties": {
                  "country_iso_code": { "type": "keyword" },
                  "city_name":        { "type": "keyword" }
                }
              }
            }
          },
          "destination": {
            "properties": {
              "ip":   { "type": "ip" },
              "port": { "type": "integer" }
            }
          },
          "host": {
            "properties": {
              "name":     { "type": "keyword" },
              "hostname": { "type": "keyword" },
              "ip":       { "type": "ip" },
              "os": {
                "properties": {
                  "type":     { "type": "keyword" },
                  "name":     { "type": "keyword" },
                  "version":  { "type": "keyword" }
                }
              }
            }
          },
          "user": {
            "properties": {
              "name":   { "type": "keyword" },
              "id":     { "type": "keyword" },
              "domain": { "type": "keyword" }
            }
          },
          "process": {
            "properties": {
              "name":         { "type": "keyword" },
              "pid":          { "type": "long" },
              "command_line": { "type": "wildcard" },
              "parent": {
                "properties": {
                  "name": { "type": "keyword" },
                  "pid":  { "type": "long" }
                }
              }
            }
          },
          "network": {
            "properties": {
              "protocol":    { "type": "keyword" },
              "transport":   { "type": "keyword" },
              "direction":   { "type": "keyword" },
              "bytes":       { "type": "long" }
            }
          },
          "url": {
            "properties": {
              "full":   { "type": "wildcard" },
              "domain": { "type": "keyword" },
              "path":   { "type": "wildcard" }
            }
          },
          "http": {
            "properties": {
              "request": {
                "properties": {
                  "method": { "type": "keyword" }
                }
              },
              "response": {
                "properties": {
                  "status_code": { "type": "integer" },
                  "bytes":       { "type": "long" }
                }
              }
            }
          },
          "cloud": {
            "properties": {
              "provider":   { "type": "keyword" },
              "region":     { "type": "keyword" },
              "account": {
                "properties": {
                  "id": { "type": "keyword" }
                }
              },
              "service": {
                "properties": {
                  "name": { "type": "keyword" }
                }
              }
            }
          },
          "log": {
            "properties": {
              "original": { "type": "keyword", "index": false }
            }
          }
        }
      }
    }
  }'

echo ""
echo "Template created. Verifying..."
curl -s "${ES_HOST}/_index_template/ecs-security" | python3 -m json.tool | head -20
```

---

## Step 2: Sample Data Files

### sample-data/windows_events.json (NDJSON)

```json
{"raw_xml": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><TimeCreated SystemTime='2024-12-14T08:00:00.000Z'/><Computer>WORKSTATION01</Computer><Channel>Security</Channel></System><EventData><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>administrator</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>203.0.113.42</Data><Data Name='IpPort'>31337</Data><Data Name='FailureReason'>%%2313</Data><Data Name='Status'>0xC000006D</Data></EventData></Event>"}
{"raw_xml": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID><TimeCreated SystemTime='2024-12-14T08:05:00.000Z'/><Computer>WORKSTATION01</Computer><Channel>Security</Channel></System><EventData><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>jdoe</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.1.55</Data><Data Name='IpPort'>49200</Data></EventData></Event>"}
{"raw_xml": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID><TimeCreated SystemTime='2024-12-14T08:06:00.000Z'/><Computer>WORKSTATION01</Computer></System><EventData><Data Name='SubjectUserName'>jdoe</Data><Data Name='SubjectDomainName'>CORP</Data><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd.exe /c whoami /all</Data><Data Name='ProcessId'>0x1234</Data><Data Name='ParentProcessName'>C:\\Windows\\explorer.exe</Data></EventData></Event>"}
```

### sample-data/cloudtrail_events.json (NDJSON)

```json
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDACKCEVSQ6C2EXAMPLE","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2024-12-14T09:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.42","userAgent":"Mozilla/5.0","responseElements":{"ConsoleLogin":"Failure"},"errorMessage":"Failed authentication"}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDACKCEVSQ6C2EXAMPLE","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2024-12-14T09:01:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.42","userAgent":"Mozilla/5.0","responseElements":{"ConsoleLogin":"Success"}}
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDACKCEVSQ6C2EXAMPLE","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","userName":"Alice"},"eventTime":"2024-12-14T09:02:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.42","requestParameters":{"bucketName":"sensitive-data","key":"payroll/2024.csv"}}
```

---

## Step 3: Normalization Pipeline

### pipeline/normalize-to-ecs.conf

```ruby
input {
  # Windows Events (pre-parsed JSON from Winlogbeat or custom parser)
  file {
    path => "/var/log/demo/windows_events.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "json"
    type => "windows_event"
  }

  # AWS CloudTrail JSON
  file {
    path => "/var/log/demo/cloudtrail_events.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "json"
    type => "aws_cloudtrail"
  }
}

filter {

  # ================================================================
  # WINDOWS EVENT LOG NORMALIZATION
  # ================================================================
  if [type] == "windows_event" and [raw_xml] {
    # Parse relevant fields from the raw XML using grok
    grok {
      match => {
        "raw_xml" => [
          "<EventID>%{INT:win_event_id:int}<\/EventID>",
          "<TimeCreated SystemTime='%{DATA:win_time_created}'\/>"
        ]
      }
    }

    grok {
      match => { "raw_xml" => "<Computer>%{DATA:win_computer}<\/Computer>" }
    }

    # Parse all Data Name fields
    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='TargetUserName'>%{DATA:win_target_user}<\/Data>"
      }
      tag_on_failure => ["_no_target_user"]
    }

    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='TargetDomainName'>%{DATA:win_target_domain}<\/Data>"
      }
      tag_on_failure => ["_no_target_domain"]
    }

    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='IpAddress'>%{IP:win_src_ip}<\/Data>"
      }
      tag_on_failure => ["_no_src_ip"]
    }

    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='IpPort'>%{INT:win_src_port:int}<\/Data>"
      }
      tag_on_failure => ["_no_src_port"]
    }

    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='NewProcessName'>%{DATA:win_process_path}<\/Data>"
      }
      tag_on_failure => ["_no_process_name"]
    }

    grok {
      match => {
        "raw_xml" => "(?s).*<Data Name='CommandLine'>%{DATA:win_command_line}<\/Data>"
      }
      tag_on_failure => ["_no_command_line"]
    }

    # Parse timestamp
    date {
      match => ["win_time_created", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", "yyyy-MM-dd'T'HH:mm:ss'Z'"]
      target => "@timestamp"
      timezone => "UTC"
    }

    # ECS Normalization — common fields
    mutate {
      add_field => {
        "[ecs][version]"    => "8.12.0"
        "[event][kind]"     => "event"
        "[event][module]"   => "windows"
        "[event][dataset]"  => "windows.security"
        "[log][original]"   => "%{raw_xml}"
      }
    }

    # ECS host
    if [win_computer] {
      mutate {
        rename => { "win_computer" => "[host][name]" }
        add_field => { "[host][os][type]" => "windows" }
      }
    }

    # ECS source
    if [win_src_ip] {
      mutate { rename => { "win_src_ip" => "[source][ip]" } }
    }
    if [win_src_port] {
      mutate { rename => { "win_src_port" => "[source][port]" } }
    }

    # ECS user
    if [win_target_user] and [win_target_user] != "-" {
      mutate { rename => { "win_target_user" => "[user][name]" } }
    }
    if [win_target_domain] {
      mutate { rename => { "win_target_domain" => "[user][domain]" } }
    }

    # ECS process (for Event ID 4688)
    if [win_process_path] {
      ruby {
        code => "
          path = event.get('win_process_path')
          if path
            parts = path.split('\\\\')
            event.set('[process][name]', parts.last)
            event.set('[process][executable]', path)
          end
        "
      }
    }
    if [win_command_line] {
      mutate { rename => { "win_command_line" => "[process][command_line]" } }
    }

    # Event ID specific mappings
    if [win_event_id] == 4625 {
      mutate {
        add_field => {
          "[event][code]"     => "4625"
          "[event][category]" => "authentication"
          "[event][type]"     => "start"
          "[event][outcome]"  => "failure"
        }
      }
    } else if [win_event_id] == 4624 {
      mutate {
        add_field => {
          "[event][code]"     => "4624"
          "[event][category]" => "authentication"
          "[event][type]"     => "start"
          "[event][outcome]"  => "success"
        }
      }
    } else if [win_event_id] == 4688 {
      mutate {
        add_field => {
          "[event][code]"     => "4688"
          "[event][category]" => "process"
          "[event][type]"     => "start"
          "[event][outcome]"  => "success"
        }
      }
    }

    mutate {
      remove_field => ["raw_xml", "win_event_id", "win_time_created"]
    }
  }

  # ================================================================
  # AWS CLOUDTRAIL NORMALIZATION
  # ================================================================
  if [type] == "aws_cloudtrail" {
    # Timestamp
    date {
      match => ["eventTime", "yyyy-MM-dd'T'HH:mm:ss'Z'"]
      target => "@timestamp"
      timezone => "UTC"
    }

    # ECS base
    mutate {
      add_field => {
        "[ecs][version]"    => "8.12.0"
        "[event][kind]"     => "event"
        "[event][module]"   => "aws"
        "[event][dataset]"  => "aws.cloudtrail"
      }
      rename => { "eventName"    => "[event][action]" }
      rename => { "sourceIPAddress" => "[source][ip]" }
    }

    # ECS cloud
    if [awsRegion] {
      mutate {
        rename => { "awsRegion" => "[cloud][region]" }
        add_field => { "[cloud][provider]" => "aws" }
      }
    }
    if [userIdentity][accountId] {
      mutate {
        add_field => { "[cloud][account][id]" => "%{[userIdentity][accountId]}" }
      }
    }

    # ECS user
    if [userIdentity][userName] {
      mutate {
        add_field => { "[user][name]" => "%{[userIdentity][userName]}" }
      }
    }

    # Determine event category and outcome
    if [eventSource] =~ /signin\.amazonaws\.com/ {
      mutate { add_field => { "[event][category]" => "authentication" } }

      if [responseElements][ConsoleLogin] == "Success" {
        mutate {
          add_field => {
            "[event][type]"    => "start"
            "[event][outcome]" => "success"
          }
        }
      } else {
        mutate {
          add_field => {
            "[event][type]"    => "start"
            "[event][outcome]" => "failure"
          }
        }
      }
    } else if [eventSource] =~ /s3\.amazonaws\.com/ {
      mutate {
        add_field => {
          "[event][category]"               => "file"
          "[event][type]"                   => "access"
          "[event][outcome]"                => "success"
          "[cloud][service][name]"          => "s3"
        }
      }
      if [requestParameters][bucketName] {
        mutate {
          add_field => { "[url][path]" => "s3://%{[requestParameters][bucketName]}/%{[requestParameters][key]}" }
        }
      }
    }

    # Clean up raw cloudtrail fields
    mutate {
      remove_field => ["eventVersion", "eventTime", "eventSource", "responseElements", "userIdentity"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "security-%{[event][dataset]}-%{+YYYY.MM.dd}"
  }

  stdout { codec => dots }
}
```

---

## Step 4: Validation Queries

Once the pipeline runs, validate normalization with these Elasticsearch queries:

### Query 1: Cross-source failed authentications

```bash
curl -s -X GET "http://localhost:9200/security-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          { "term": { "event.category": "authentication" } },
          { "term": { "event.outcome": "failure" } }
        ]
      }
    },
    "_source": ["@timestamp", "event.dataset", "source.ip", "user.name", "host.name"],
    "sort": [{ "@timestamp": "desc" }]
  }'
```

### Query 2: Same source IP across all sources (cross-source correlation)

```bash
# Find the suspicious IP across all data sources
curl -s -X GET "http://localhost:9200/security-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "term": { "source.ip": "203.0.113.42" }
    },
    "_source": ["@timestamp", "event.dataset", "event.category", "event.outcome", "user.name"],
    "aggs": {
      "sources": {
        "terms": { "field": "event.dataset" }
      }
    }
  }'
```

### Query 3: Normalization completeness check

```bash
# Events missing event.outcome (normalization gap)
curl -s -X GET "http://localhost:9200/security-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must_not": { "exists": { "field": "event.outcome" } }
      }
    },
    "size": 5,
    "_source": ["@timestamp", "event.dataset", "message"]
  }'
```

---

## Step 5: Kibana Data View Setup

1. Open `http://localhost:5601`
1. Navigate to **Stack Management → Data Views**
1. Create a data view: `security-*` with `@timestamp` as time field
1. Go to **Discover** and explore normalized events
1. Add columns: `event.dataset`, `event.category`, `event.outcome`, `source.ip`, `user.name`
1. Filter by `event.category: authentication` to see all auth events across all sources

---

## Key Takeaways

1. ECS provides a common vocabulary: `event.category`, `event.outcome`, `source.ip`, `user.name` mean the same thing regardless of source.
1. Index templates enforce correct field types — `source.ip` must be type `ip`, not `keyword`.
1. Cross-source correlation is now a simple field filter, not a format-specific query.
1. Always preserve the original message in `log.original` for forensic purposes.
1. Normalize event timestamps immediately; rely on `@timestamp` for all time-based queries.
