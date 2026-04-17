#!/usr/bin/env python3
"""
generate_events.py — SOC Project 01 Log Generator
===================================================
Simulates 5 security events against the SecureMed patient portal and ships
structured JSON logs directly to Elasticsearch.

Events (in order):
  1. Brute force  – 50 POST /login 401s from 185.220.101.42
  2. Successful login after brute force from same IP 185.220.101.42
  3. SQL injection – GET /search?q=1'+OR+'1'='1 from 10.10.50.100
  4. Large file download – GET /export/patients.csv (~10 MB) from 10.10.50.100
  5. C2 connection to known-bad IP 185.220.101.45:443 from internal 10.0.0.55

Environment variables:
  DEMO_MODE          = "fast"   → all 5 events in ~2 minutes (default)
                     = "normal" → events spread over ~30 minutes
  ELASTICSEARCH_URL  = http://elasticsearch:9200
  PATIENT_PORTAL_URL = http://patient-portal:80
"""

import json
import os
import random
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Configuration ────────────────────────────────────────────────────────────

ES_URL           = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
PORTAL_URL       = os.environ.get("PATIENT_PORTAL_URL", "http://patient-portal:80")
DEMO_MODE        = os.environ.get("DEMO_MODE", "fast").lower()
STARTUP_WAIT_SEC = 30          # wait for dependencies before doing anything

# Time between scripted events
if DEMO_MODE == "normal":
    EVENT_INTERVAL_SEC = 6 * 60   # ~6 min between events → ~30 min total
else:
    EVENT_INTERVAL_SEC = 20       # 20 s between events → ~2 min total

# Elasticsearch index names
INDEX_WEBLOG   = "patient-portal-access"
INDEX_SYSLOG   = "syslog"
INDEX_NETFLOW  = "network-monitor"

# Source IPs used in the simulation
IP_BRUTE_FORCE = "185.220.101.42"   # Event 1 & 2 (Tor exit node)
IP_INTERNAL    = "10.10.50.100"     # Event 3 & 4 (internal workstation)
IP_VICTIM_HOST = "10.0.0.55"        # Event 5 (internal host making C2 call)
IP_C2_SERVER   = "185.220.101.45"   # Event 5 (known-bad C2 IP)

# Legitimate user agents to blend in
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

NORMAL_PATHS = [
    "/", "/index.html", "/login", "/dashboard", "/profile",
    "/appointments", "/messages", "/about", "/contact", "/help",
]

NORMAL_IPS = [
    "10.0.0.10", "10.0.0.11", "10.0.0.15", "10.0.0.20", "10.0.0.25",
    "10.0.0.30", "10.0.0.40", "192.168.1.101", "192.168.1.102",
    "193.226.51.14",   # Romanian ISP IP (looks external/legitimate)
    "82.76.18.44",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def ts_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    print(f"[{ts_now()}] {msg}", flush=True)


def es_index(index: str, doc: dict) -> bool:
    """POST a document to Elasticsearch. Returns True on success."""
    url = f"{ES_URL}/{index}/_doc"
    data = json.dumps(doc).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status in (200, 201)
    except Exception as exc:
        log(f"  [WARN] ES index failed ({index}): {exc}")
        return False


def ensure_indices() -> None:
    """Create ES index mappings if they do not exist yet."""
    mappings = {
        INDEX_WEBLOG: {
            "mappings": {
                "properties": {
                    "@timestamp":   {"type": "date"},
                    "source.ip":    {"type": "ip"},
                    "http.request.method": {"type": "keyword"},
                    "url.path":     {"type": "keyword"},
                    "http.response.status_code": {"type": "integer"},
                    "http.response.bytes":       {"type": "long"},
                    "user_agent.original":       {"type": "text"},
                    "log.type":     {"type": "keyword"},
                    "event.category": {"type": "keyword"},
                    "event.type":   {"type": "keyword"},
                    "tags":         {"type": "keyword"},
                }
            }
        },
        INDEX_SYSLOG: {
            "mappings": {
                "properties": {
                    "@timestamp":   {"type": "date"},
                    "source.ip":    {"type": "ip"},
                    "host.name":    {"type": "keyword"},
                    "message":      {"type": "text"},
                    "log.level":    {"type": "keyword"},
                    "event.category": {"type": "keyword"},
                    "tags":         {"type": "keyword"},
                }
            }
        },
        INDEX_NETFLOW: {
            "mappings": {
                "properties": {
                    "@timestamp":       {"type": "date"},
                    "source.ip":        {"type": "ip"},
                    "destination.ip":   {"type": "ip"},
                    "destination.port": {"type": "integer"},
                    "network.bytes":    {"type": "long"},
                    "network.protocol": {"type": "keyword"},
                    "event.category":   {"type": "keyword"},
                    "tags":             {"type": "keyword"},
                }
            }
        },
    }
    for index, body in mappings.items():
        url = f"{ES_URL}/{index}"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201):
                    log(f"  Index '{index}' created / confirmed.")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                pass  # index already exists — that's fine
            else:
                log(f"  [WARN] Could not create index '{index}': {e}")
        except Exception as exc:
            log(f"  [WARN] Could not create index '{index}': {exc}")


def wait_for_elasticsearch(retries: int = 30, delay: int = 5) -> None:
    log("Waiting for Elasticsearch …")
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(f"{ES_URL}/_cluster/health", timeout=4) as r:
                health = json.loads(r.read())
                if health.get("status") in ("green", "yellow"):
                    log(f"  Elasticsearch ready (status={health['status']}).")
                    return
        except Exception:
            pass
        log(f"  Attempt {attempt}/{retries} — not ready yet. Retrying in {delay}s …")
        time.sleep(delay)
    log("  [ERROR] Elasticsearch did not become available. Continuing anyway.")


def wait_for_portal(retries: int = 15, delay: int = 3) -> None:
    log("Waiting for patient-portal …")
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(PORTAL_URL, timeout=4) as r:
                if r.status < 500:
                    log("  patient-portal ready.")
                    return
        except Exception:
            pass
        log(f"  Attempt {attempt}/{retries} — not ready yet. Retrying in {delay}s …")
        time.sleep(delay)
    log("  [WARN] patient-portal did not respond. Events will be logged to ES directly.")


# ── Apache Combined Log format helper ────────────────────────────────────────

def make_web_log(
    source_ip: str,
    method: str,
    path: str,
    status: int,
    bytes_sent: int,
    user_agent: str = None,
    referer: str = "-",
    tags: list = None,
    extra: dict = None,
) -> dict:
    ua = user_agent or random.choice(USER_AGENTS)
    doc = {
        "@timestamp": ts_now(),
        "log.type": "access",
        "source.ip": source_ip,
        "http.request.method": method,
        "url.path": path,
        "http.response.status_code": status,
        "http.response.bytes": bytes_sent,
        "user_agent.original": ua,
        "http.request.referer": referer,
        "event.category": "web",
        "event.type": "access",
        # Apache Combined Log format string (useful for regex parsing in Kibana)
        "message": (
            f'{source_ip} - - [{datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")}] '
            f'"{method} {path} HTTP/1.1" {status} {bytes_sent} '
            f'"{referer}" "{ua}"'
        ),
        "tags": tags or [],
    }
    if extra:
        doc.update(extra)
    return doc


# ── Actual HTTP requests to the portal (best-effort, logged either way) ──────

def portal_request(method: str, path: str, data: bytes = None) -> int:
    """Fire an HTTP request at the portal. Returns HTTP status code."""
    url = PORTAL_URL.rstrip("/") + path
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", random.choice(USER_AGENTS))
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0   # connection refused / timeout


# ── Event generators ──────────────────────────────────────────────────────────

def event_1_brute_force() -> None:
    """Event 1 — 50 failed POST /login attempts from Tor exit node."""
    log(">>> EVENT 1: Brute force attack (50 failed logins from 185.220.101.42)")
    passwords = [
        "password", "123456", "letmein", "admin", "qwerty",
        "welcome", "monkey", "dragon", "master", "sunshine",
    ]
    for i in range(50):
        pwd = random.choice(passwords)
        portal_request("POST", "/login",
                        data=f"username=admin&password={pwd}".encode())
        doc = make_web_log(
            source_ip=IP_BRUTE_FORCE,
            method="POST",
            path="/login",
            status=401,
            bytes_sent=random.randint(512, 1024),
            tags=["brute_force", "authentication_failure", "tor_exit_node"],
            extra={
                "event.category": "authentication",
                "event.type": "failed_login",
                "event.sequence": i + 1,
                "threat.indicator.ip": IP_BRUTE_FORCE,
                "http.request.body": f"username=admin&password={pwd}",
            },
        )
        es_index(INDEX_WEBLOG, doc)
        if i % 10 == 0:
            log(f"  Brute force attempt {i+1}/50 logged.")
        time.sleep(0.3)   # rapid-fire but not instant
    log("  Event 1 complete.")


def event_2_successful_login() -> None:
    """Event 2 — Successful login from the same brute-force IP."""
    log(">>> EVENT 2: Successful login after brute force (same IP 185.220.101.42)")
    portal_request("POST", "/login",
                   data="username=admin&password=SecureMed2024!".encode())
    doc = make_web_log(
        source_ip=IP_BRUTE_FORCE,
        method="POST",
        path="/login",
        status=302,
        bytes_sent=256,
        tags=["successful_login", "post_brute_force", "tor_exit_node", "suspicious"],
        extra={
            "event.category": "authentication",
            "event.type": "successful_login",
            "threat.indicator.ip": IP_BRUTE_FORCE,
            "http.request.body": "username=admin&password=***",
            "url.redirect": "/dashboard",
        },
    )
    es_index(INDEX_WEBLOG, doc)

    # Also emit a syslog-style event
    syslog_doc = {
        "@timestamp": ts_now(),
        "host.name": "patient-portal",
        "source.ip": IP_BRUTE_FORCE,
        "log.level": "WARNING",
        "event.category": "authentication",
        "message": (
            f"pam_unix(sshd:session): session opened for user admin "
            f"by {IP_BRUTE_FORCE}(uid=0)"
        ),
        "tags": ["syslog", "successful_login", "post_brute_force"],
    }
    es_index(INDEX_SYSLOG, syslog_doc)
    log("  Event 2 complete.")


def event_3_sql_injection() -> None:
    """Event 3 — SQL injection attempt in search parameter."""
    payloads = [
        "/search?q=1'+OR+'1'='1",
        "/search?q=1%27+OR+%271%27%3D%271",
        "/search?q=' UNION SELECT username,password FROM users--",
        "/search?q=1; DROP TABLE patients--",
        "/search?q=1' AND SLEEP(5)--",
    ]
    log(">>> EVENT 3: SQL injection attempts from 10.10.50.100")
    for i, path in enumerate(payloads):
        portal_request("GET", path)
        doc = make_web_log(
            source_ip=IP_INTERNAL,
            method="GET",
            path=path,
            status=400,
            bytes_sent=random.randint(256, 512),
            tags=["sql_injection", "web_attack", "internal_threat"],
            extra={
                "event.category": "intrusion_detection",
                "event.type": "sql_injection",
                "event.sequence": i + 1,
                "url.query": path.split("?", 1)[1] if "?" in path else "",
                "threat.technique.name": "SQL Injection",
                "threat.technique.id": "T1190",
            },
        )
        es_index(INDEX_WEBLOG, doc)
        log(f"  SQL injection payload {i+1}/{len(payloads)}: {path[:60]}")
        time.sleep(0.5)

    # Correlate with a netflow entry showing internal lateral scan
    netflow_doc = {
        "@timestamp": ts_now(),
        "source.ip": IP_INTERNAL,
        "destination.ip": "10.0.0.5",     # DB server
        "destination.port": 3306,
        "network.bytes": 4096,
        "network.protocol": "tcp",
        "event.category": "network",
        "tags": ["netflow", "internal_db_probe", "suspicious"],
        "message": f"{IP_INTERNAL} → 10.0.0.5:3306 (MySQL probe after SQLi attempt)",
    }
    es_index(INDEX_NETFLOW, netflow_doc)
    log("  Event 3 complete.")


def event_4_large_file_download() -> None:
    """Event 4 — Large file download of patient records (~10 MB)."""
    log(">>> EVENT 4: Large file download of patient records from 10.10.50.100")
    portal_request("GET", "/export/patients.csv")
    # Simulate 10 MB file (10 * 1024 * 1024 bytes)
    file_size = 10 * 1024 * 1024
    doc = make_web_log(
        source_ip=IP_INTERNAL,
        method="GET",
        path="/export/patients.csv",
        status=200,
        bytes_sent=file_size,
        tags=["data_exfiltration", "sensitive_file", "large_download", "patient_data"],
        extra={
            "event.category": "data_exfiltration",
            "event.type": "file_download",
            "file.name": "patients.csv",
            "file.size": file_size,
            "file.path": "/export/patients.csv",
            "threat.technique.name": "Data from Local System",
            "threat.technique.id": "T1005",
        },
    )
    es_index(INDEX_WEBLOG, doc)

    # Corresponding netflow entry showing the large transfer
    netflow_doc = {
        "@timestamp": ts_now(),
        "source.ip": "10.0.0.1",    # web server / patient-portal
        "destination.ip": IP_INTERNAL,
        "destination.port": random.randint(49152, 65535),
        "network.bytes": file_size,
        "network.protocol": "http",
        "event.category": "network",
        "tags": ["netflow", "large_transfer", "patient_data"],
        "message": (
            f"Large HTTP transfer: 10.0.0.1 → {IP_INTERNAL} "
            f"({file_size // 1024 // 1024} MB via /export/patients.csv)"
        ),
    }
    es_index(INDEX_NETFLOW, netflow_doc)
    log("  Event 4 complete.")


def event_5_c2_connection() -> None:
    """Event 5 — Internal host connecting to known-bad C2 IP on port 443."""
    log(f">>> EVENT 5: C2 connection from {IP_VICTIM_HOST} → {IP_C2_SERVER}:443")

    # Repeated heartbeat connections to the C2 server
    for i in range(5):
        netflow_doc = {
            "@timestamp": ts_now(),
            "source.ip": IP_VICTIM_HOST,
            "destination.ip": IP_C2_SERVER,
            "destination.port": 443,
            "network.bytes": random.randint(512, 4096),
            "network.protocol": "tcp",
            "event.category": "malware",
            "tags": [
                "c2_communication", "known_bad_ip", "tor_exit_node",
                "internal_host", "ioc_match",
            ],
            "message": (
                f"Outbound connection from internal host {IP_VICTIM_HOST} "
                f"to known-malicious IP {IP_C2_SERVER}:443 (Tor exit node / C2)"
            ),
            "threat.indicator.ip": IP_C2_SERVER,
            "threat.technique.name": "Application Layer Protocol: Web Protocols",
            "threat.technique.id": "T1071.001",
            "host.name": "workstation-055",
            "host.ip": IP_VICTIM_HOST,
        }
        es_index(INDEX_NETFLOW, netflow_doc)
        log(f"  C2 heartbeat {i+1}/5 logged.")
        time.sleep(1)

    # Syslog entry on the victim workstation
    syslog_doc = {
        "@timestamp": ts_now(),
        "host.name": "workstation-055",
        "source.ip": IP_VICTIM_HOST,
        "log.level": "ERROR",
        "event.category": "malware",
        "message": (
            f"Suspicious outbound TLS connection: {IP_VICTIM_HOST}:* → "
            f"{IP_C2_SERVER}:443 (IOC match: known Tor exit / C2 node)"
        ),
        "tags": ["syslog", "c2_connection", "ioc_match"],
    }
    es_index(INDEX_SYSLOG, syslog_doc)
    log("  Event 5 complete.")


# ── Background normal traffic generator ──────────────────────────────────────

def generate_normal_traffic(count: int = 20) -> None:
    """Emit a batch of realistic-looking benign web requests."""
    for _ in range(count):
        ip    = random.choice(NORMAL_IPS)
        path  = random.choice(NORMAL_PATHS)
        meth  = random.choice(["GET"] * 9 + ["POST"])
        status = random.choice([200] * 8 + [304, 404])
        size  = random.randint(1024, 50000)
        doc   = make_web_log(ip, meth, path, status, size)
        es_index(INDEX_WEBLOG, doc)
        time.sleep(random.uniform(0.05, 0.3))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    mode_label = "FAST (~2 min)" if DEMO_MODE != "normal" else "NORMAL (~30 min)"
    log("=" * 60)
    log(f"SOC Project 01 — Log Generator starting")
    log(f"  Mode         : {mode_label}")
    log(f"  Elasticsearch: {ES_URL}")
    log(f"  Patient portal: {PORTAL_URL}")
    log("=" * 60)

    log(f"Waiting {STARTUP_WAIT_SEC}s for dependencies to initialise …")
    time.sleep(STARTUP_WAIT_SEC)

    wait_for_elasticsearch()
    wait_for_portal()

    log("Creating Elasticsearch indices …")
    ensure_indices()

    log("Seeding background normal traffic (50 events) …")
    generate_normal_traffic(50)

    events = [
        event_1_brute_force,
        event_2_successful_login,
        event_3_sql_injection,
        event_4_large_file_download,
        event_5_c2_connection,
    ]

    log(f"Starting scripted event sequence (interval={EVENT_INTERVAL_SEC}s between events) …")
    for idx, event_fn in enumerate(events, start=1):
        event_fn()
        if idx < len(events):
            log(f"  Sleeping {EVENT_INTERVAL_SEC}s before next event …")
            # Generate a trickle of normal traffic during the wait
            steps = max(1, EVENT_INTERVAL_SEC // 5)
            for _ in range(steps):
                generate_normal_traffic(3)
                time.sleep(min(5, EVENT_INTERVAL_SEC / steps))

    log("All 5 scripted events complete. Switching to continuous background traffic.")
    log("Container will keep running to simulate ongoing normal activity.")
    log("Press Ctrl+C or stop the container to terminate.")

    round_num = 0
    while True:
        round_num += 1
        log(f"Background traffic round {round_num} …")
        generate_normal_traffic(10)
        time.sleep(30)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted — shutting down.")
        sys.exit(0)
