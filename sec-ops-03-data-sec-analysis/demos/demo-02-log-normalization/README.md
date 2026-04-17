# Demo 02: Log Normalization Using Logstash

**Difficulty:** Intermediate

**Time:** ~40 minutes

**Prerequisites:** Docker Desktop, completion of Demo 01 recommended

## Overview

Different log sources use completely different formats.
This demo shows how **Logstash** acts as a normalization layer that transforms disparate log formats into a common schema (Elastic Common Schema / ECS).

You will process three different input formats:

1. **Apache Combined Log Format** — unstructured text
1. **CEF (Common Event Format)** — structured but non-JSON
1. **Raw JSON** — structured but not ECS-compliant

All three will be transformed into normalized ECS-compatible JSON documents and indexed into **Elasticsearch**, then visualized in **Kibana**.

## Architecture

```text
  ┌─────────────────┐    ┌─────────────────────────────────────────────────┐
  │  log-producer   │    │                Logstash Pipeline                 │
  │  (generates     │───▶│  INPUT          FILTER           OUTPUT         │
  │   sample logs)  │    │  ──────         ──────           ──────         │
  └─────────────────┘    │  tcp:5000  ──▶  grok         ──▶ elasticsearch  │
                         │  tcp:5001  ──▶  date         ──▶ (normalized)   │
                         │  tcp:5002  ──▶  mutate                          │
                         │                 geoip                           │
                         │                 ruby (ECS)                      │
                         └──────────────────────────────────────────────────┘
                                                    │
                         ┌──────────────────────────▼──────────────────────┐
                         │            Elasticsearch + Kibana                │
                         │   Kibana: http://localhost:5601                  │
                         │   Index: security-normalized-*                   │
                         └─────────────────────────────────────────────────┘
```

## Understanding the Normalization Challenge

Before running the demo, review these raw log examples that represent the same type of event (a web request) in three different formats:

**Format 1 — Apache Combined Log:**

```text
203.0.113.10 - - [15/Mar/2024:14:23:01 +0000] "GET /login HTTP/1.1" 200 1234 "-" "curl/7.68.0"
```

**Format 2 — CEF:**

```text
CEF:0|Apache|HTTPD|2.4|ACCESS|HTTP Request|3|src=203.0.113.10 spt=54321 dpt=80 request=/login requestMethod=GET msg=200 OK
```

**Format 3 — Custom JSON:**

```json
{"ts":"2024-03-15T14:23:01Z","remote_ip":"203.0.113.10","method":"GET","path":"/login","code":200,"agent":"curl/7.68.0"}
```

After normalization, all three become:

```json
{
  "@timestamp": "2024-03-15T14:23:01.000Z",
  "source.ip": "203.0.113.10",
  "http.request.method": "GET",
  "url.path": "/login",
  "http.response.status_code": 200,
  "user_agent.original": "curl/7.68.0",
  "event.category": "web",
  "event.type": "access",
  "data_stream.dataset": "apache.access"
}
```

## Step-by-Step Instructions

### Step 1: Review the Logstash Pipeline

Open `config/logstash/pipeline/normalize.conf` and study:

* **Input** sections: one per format, on different ports
* **Filter** sections: conditional logic based on `[tags]`
* **Output** section: sends to Elasticsearch with a normalized index name

### Step 2: Start the Stack

```console
docker compose up -d

# Wait for Elasticsearch and Kibana to be ready (~2-3 min)
docker compose logs -f kibana | grep "Kibana is now available"
```

### Step 3: Send Test Events

The `log-producer` container automatically sends sample events.
You can also send manually:

```bash
# Send an Apache log line
echo '203.0.113.10 - - [15/Mar/2024:14:23:01 +0000] "GET /login HTTP/1.1" 200 1234 "-" "curl/7.68.0"' \
  | docker exec -i demo02-logstash nc -q1 localhost 5000

# Send a CEF event
echo 'CEF:0|Firewall|FW-1|6.0|DENY|Connection Denied|8|src=203.0.113.10 dst=10.0.0.5 spt=54321 dpt=22 proto=TCP act=deny' \
  | docker exec -i demo02-logstash nc -q1 localhost 5001

# Send a JSON event
echo '{"ts":"2024-03-15T14:23:05Z","remote_ip":"198.51.100.5","method":"POST","path":"/wp-admin/","code":403,"agent":"Nikto/2.1.6"}' \
  | docker exec -i demo02-logstash nc -q1 localhost 5002
```

### Step 4: Verify Normalization in Kibana

1. Open http://localhost:5601
1. Go to **Management** → **Stack Management** → **Index Patterns**
1. Create index pattern: `security-normalized-*`
1. Set time field: `@timestamp`
1. Go to **Discover** → select the index pattern

Verify that regardless of input format, all events have:

* `source.ip` (not `remote_ip`, `src`, or `IpAddress`)
* `@timestamp` (not `ts`, `date`, or `time`)
* `http.request.method` or `event.action`

### Step 5: Compare Raw vs. Normalized

In Kibana Discover, look at a document and click the JSON tab.
Notice:

* Field names follow ECS dotted notation
* Timestamps are UTC ISO8601
* GeoIP data has been added to `source.geo.*`

### Step 6: Clean Up

```console
docker compose down -v
```

## Key Concepts Demonstrated

1. **grok patterns** — Named regex patterns that extract fields from unstructured text
1. **date filter** — Parses various timestamp formats and sets `@timestamp`
1. **mutate filter** — Renames fields to ECS names, converts types
1. **geoip filter** — Enriches IP addresses with geolocation data
1. **Conditional logic** — `if [tags] contains "apache"` applies source-specific filters

## Exercise

Modify `normalize.conf` to add support for a fourth format — Syslog RFC5424:

```text
<165>1 2024-03-15T14:23:01Z webserver01 nginx 1234 - - GET /api/health HTTP/1.1 200
```

Map it to the same ECS fields as the other sources.
