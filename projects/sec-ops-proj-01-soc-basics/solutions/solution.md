# Solution: Project 01 — Build a Basic SOC Monitoring Setup

**Project:** SEC-OPS-PROJ-01

**Covers:** Sessions 01–05

---

## Overview

This solution provides complete reference implementations for all deliverables.
Student solutions may differ in tool choices and implementation details — evaluate based on whether the pipeline works, rules fire correctly, and the report is complete and honest.

---

## Part 1 Solution — docker-compose.yml

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Web application (generates access logs)
  webapp:
    image: nginx:1.25-alpine
    container_name: orion-webapp
    ports:
      - "8080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - nginx_logs:/var/log/nginx
    networks:
      - soc-net

  # Log collector
  fluent-bit:
    image: fluent/fluent-bit:2.2
    container_name: orion-fluent-bit
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro
      - nginx_logs:/var/log/nginx:ro
    depends_on:
      - webapp
      - opensearch
    networks:
      - soc-net

  # SIEM backend
  opensearch:
    image: opensearchproject/opensearch:2.11.0
    container_name: orion-opensearch
    environment:
      - discovery.type=single-node
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=Orion@SOC2024!
      - plugins.security.disabled=true   # dev mode only
    ports:
      - "9200:9200"
    volumes:
      - opensearch_data:/usr/share/opensearch/data
    networks:
      - soc-net

  # SIEM frontend
  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.11.0
    container_name: orion-dashboards
    ports:
      - "5601:5601"
    environment:
      - OPENSEARCH_HOSTS=http://opensearch:9200
      - DISABLE_SECURITY_DASHBOARDS_PLUGIN=true
    depends_on:
      - opensearch
    networks:
      - soc-net

volumes:
  nginx_logs:
  opensearch_data:

networks:
  soc-net:
    driver: bridge
```

---

## fluent-bit.conf

```ini
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info

[INPUT]
    Name          tail
    Path          /var/log/nginx/access.log
    Tag           nginx.access
    Parser        nginx_combined
    DB            /tmp/fluent-bit-nginx.db
    Mem_Buf_Limit 5MB
    Skip_Long_Lines On

[PARSER]
    Name          nginx_combined
    Format        regex
    Regex         ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>[^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
    Time_Key      time
    Time_Format   %d/%b/%Y:%H:%M:%S %z

[OUTPUT]
    Name          opensearch
    Match         nginx.*
    Host          opensearch
    Port          9200
    Index         nginx-access
    Type          _doc
    tls           Off
    tls.verify    Off
```

---

## Part 2 Solution — Detection Rules

### Rule 1: Directory Brute Force (Python polling script)

```python
#!/usr/bin/env python3
# detection_rules/rule_01_directory_bruteforce.py
"""
Detection Rule: Directory Brute Force
ATT&CK: T1595.003 - Active Scanning: Wordlist Scanning
Fires when: >20 HTTP 404s from same IP within 60 seconds
"""
import requests
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

OPENSEARCH_URL = "http://localhost:9200"
INDEX = "nginx-access"
THRESHOLD = 20
WINDOW_SECONDS = 60
POLL_INTERVAL = 30  # check every 30 seconds

def check_brute_force():
    window_start = (datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"code": "404"}},
                    {"range": {"@timestamp": {"gte": window_start}}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "remote.keyword", "size": 100, "min_doc_count": THRESHOLD}
            }
        },
        "size": 0
    }
    resp = requests.get(f"{OPENSEARCH_URL}/{INDEX}/_search", json=query)
    result = resp.json()
    buckets = result.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    for bucket in buckets:
        ip = bucket["key"]
        count = bucket["doc_count"]
        print(f"[ALERT] RULE-01 Directory Brute Force: {ip} generated {count} x 404 in last {WINDOW_SECONDS}s")
        print(f"        ATT&CK: T1595.003 | Severity: MEDIUM | Time: {datetime.now(timezone.utc).isoformat()}")

if __name__ == "__main__":
    print(f"Detection Rule 01 polling every {POLL_INTERVAL}s...")
    while True:
        check_brute_force()
        time.sleep(POLL_INTERVAL)
```

### Rule 2: Web Attack Patterns

```python
#!/usr/bin/env python3
# detection_rules/rule_02_web_attacks.py
"""
Detection Rule: Web Attack Pattern in URL
ATT&CK: T1190 - Exploit Public-Facing Application
Fires when: Request URL contains traversal/injection patterns
"""
import requests
import time
from datetime import datetime, timedelta, timezone

OPENSEARCH_URL = "http://localhost:9200"
INDEX = "nginx-access"
ATTACK_PATTERNS = ["../", "%2e%2e", "/etc/passwd", "/etc/shadow", "<script>", "UNION+SELECT", "' OR '1'='1"]
LAST_CHECKED = None

def check_web_attacks():
    global LAST_CHECKED
    now = datetime.now(timezone.utc)
    window_start = (LAST_CHECKED or (now - timedelta(seconds=60))).strftime("%Y-%m-%dT%H:%M:%SZ")
    LAST_CHECKED = now

    should_clauses = [{"wildcard": {"path.keyword": f"*{p}*"}} for p in ATTACK_PATTERNS]
    query = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": window_start}}}],
                "should": should_clauses,
                "minimum_should_match": 1
            }
        },
        "_source": ["@timestamp", "remote", "method", "path", "code"]
    }
    resp = requests.get(f"{OPENSEARCH_URL}/{INDEX}/_search", json=query)
    hits = resp.json().get("hits", {}).get("hits", [])
    for hit in hits:
        src = hit["_source"]
        print(f"[ALERT] RULE-02 Web Attack: {src['remote']} → {src['method']} {src['path'][:80]}")
        print(f"        Response: {src['code']} | ATT&CK: T1190 | Severity: HIGH")

if __name__ == "__main__":
    while True:
        check_web_attacks()
        time.sleep(30)
```

### Rule 3: Admin Page Access

```python
#!/usr/bin/env python3
# detection_rules/rule_03_admin_access.py
"""
Detection Rule: Successful Admin Page Access
ATT&CK: T1078 - Valid Accounts (web context)
Fires when: HTTP 200 on /admin or /wp-admin paths
"""
import requests
import time
from datetime import datetime, timedelta, timezone

OPENSEARCH_URL = "http://localhost:9200"
INDEX = "nginx-access"

def check_admin_access():
    window_start = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"code": "200"}},
                    {"range": {"@timestamp": {"gte": window_start}}},
                    {"bool": {"should": [
                        {"wildcard": {"path.keyword": "*/admin*"}},
                        {"wildcard": {"path.keyword": "*/wp-admin*"}}
                    ], "minimum_should_match": 1}}
                ]
            }
        },
        "_source": ["@timestamp", "remote", "path", "agent"]
    }
    resp = requests.get(f"{OPENSEARCH_URL}/{INDEX}/_search", json=query)
    hits = resp.json().get("hits", {}).get("hits", [])
    for hit in hits:
        src = hit["_source"]
        print(f"[ALERT] RULE-03 Admin Access: {src['remote']} → {src['path']}")
        print(f"        ATT&CK: T1078 | Severity: HIGH | Agent: {src.get('agent','?')[:60]}")

if __name__ == "__main__":
    while True:
        check_admin_access()
        time.sleep(30)
```

### ATT&CK Mapping Table

| Rule | Name | ATT&CK Technique | Tactic | Expected FP Rate |
|------|------|-----------------|--------|-----------------|
| RULE-01 | Directory Brute Force | T1595.003 — Wordlist Scanning | Reconnaissance | Low — legitimate scanners (SEO tools, uptime monitors) may trigger |
| RULE-02 | Web Attack Patterns | T1190 — Exploit Public-Facing Application | Initial Access | Very low — these patterns rarely appear in legitimate traffic |
| RULE-03 | Admin Page Access | T1078 — Valid Accounts | Persistence/Discovery | Medium — site administrators accessing the panel legitimately |

---

## Part 3 Solution — Attack Simulation

```bash
#!/usr/bin/env bash
# attack_simulation.sh

echo "=== Attack A: Directory Brute Force ==="
PATHS=(/admin /backup /config /.git /wp-login.php /phpmyadmin /robots.txt /test /debug /api /db /secret /.env /uploads /images /includes /js /css /files /temp /.htaccess /sitemap.xml)
for i in $(seq 1 3); do
  for path in "${PATHS[@]}"; do
    curl -s -o /dev/null "http://localhost:8080$path"
  done
done
echo "Attack A complete ($(( ${#PATHS[@]} * 3 )) requests sent)"
sleep 5

echo ""
echo "=== Attack B: Path Traversal ==="
curl -s -o /dev/null "http://localhost:8080/../../../etc/passwd"
curl -s -o /dev/null "http://localhost:8080/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl -s -o /dev/null "http://localhost:8080/?file=../../../etc/shadow"
echo "Attack B complete"
sleep 2

echo ""
echo "=== Attack C: Admin Page Probe ==="
curl -s -o /dev/null "http://localhost:8080/admin"
curl -s -o /dev/null "http://localhost:8080/admin/"
curl -s -o /dev/null "http://localhost:8080/wp-admin/"
echo "Attack C complete"

echo ""
echo "All attacks complete. Wait 60s then check for alerts."
```

---

## Part 4 Solution — SOC Operations Report Template

A strong student report will include:

* Architecture diagram (even a text-based one)
* Honest acknowledgment of gaps: no endpoint telemetry (only web logs), no authentication logs, no email security, rules are regex-based not ML-based, single log source
* Recommended next steps: add EDR, SSH login monitoring, email gateway logs, SOAR integration, regular rule tuning

---

## Scoring Notes for Instructors

**Part 1 (20 pts):** Full marks if `docker-compose up` produces a working stack with logs flowing to OpenSearch.
Partial credit if pipeline is configured but not fully functional.

**Part 2 (20 pts):** Full marks for 3 working, correctly scoped rules with ATT&CK mapping.
Deduct 5 pts each for: missing ATT&CK mapping, rule logic that would never fire, rule logic that always fires.

**Part 3 (25 pts):** Full marks for simulation scripts + proof of alerts.
Evidence can be screenshots, log output, or `curl` API response showing matching documents.
Deduct 10 pts if attack scripts are provided but no evidence of rule firing is shown.

**Part 4 (25 pts):** Evaluate on honesty and depth.
A report that claims no gaps loses 10 pts.
A report with 6 or more well-reasoned next steps earns full marks on that section.
