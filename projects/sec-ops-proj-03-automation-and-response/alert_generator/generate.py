"""
alert_generator/generate.py — Simulated SIEM Alert Generator

Sends test alerts to the SOAR API to exercise the full pipeline:
  - Alert ingestion (Task 1)
  - Triage playbook (Task 2)
  - Incident creation and deduplication

The alert set includes:
  - High-reputation-score IPs from ioc_db.json   → should trigger HIGH severity
  - Alerts targeting 10.0.0.15 (db-server-01)     → critical asset escalation
  - Alerts targeting 10.0.0.20 (pay-sys-01)        → critical asset escalation
  - Duplicate alert_ids                             → should return 409
  - Varied rule names and severities
"""

import requests
import time
import os
import random
import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOAR_API_URL = os.environ.get("SOAR_API_URL", "http://soar-api:7000")
ALERTS_ENDPOINT = f"{SOAR_API_URL}/api/alerts"

# Wait for the SOAR API to be ready
STARTUP_WAIT = 15  # seconds

# ---------------------------------------------------------------------------
# Predefined test alerts
# Each entry is a tuple: (alert_id, rule_name, severity, source_ip, dest_ip, dest_port)
# ---------------------------------------------------------------------------
TEST_ALERTS = [
    # --- High-score IPs from ioc_db.json (score > 70 → should become HIGH) ---
    ("SIEM-2024-000001", "HTTP Brute Force",         "medium", "185.220.101.42", "10.0.0.15",  443),
    ("SIEM-2024-000002", "SSH Brute Force",           "low",    "185.220.101.45", "10.0.0.30",   22),
    ("SIEM-2024-000003", "C2 Beacon Detected",        "medium", "45.142.212.100", "10.0.0.101", 8080),
    ("SIEM-2024-000004", "Port Scan Detected",        "low",    "91.108.56.120",  "10.0.0.5",   445),
    ("SIEM-2024-000005", "TOR Exit Node Traffic",     "medium", "198.98.56.149",  "10.0.0.20",  443),

    # --- Targeting critical assets (should trigger severity upgrade) ---
    ("SIEM-2024-000006", "SQL Injection Attempt",    "medium", "203.0.113.50",   "10.0.0.15",  5432),
    ("SIEM-2024-000007", "Unusual Auth to Pay Sys",  "medium", "203.0.113.51",   "10.0.0.20",  8443),
    ("SIEM-2024-000008", "LDAP Enumeration",         "low",    "203.0.113.52",   "10.0.0.5",   389),
    ("SIEM-2024-000009", "Credential Stuffing",      "medium", "203.0.113.53",   "10.0.0.31",  443),
    ("SIEM-2024-000010", "Directory Traversal",      "medium", "203.0.113.54",   "10.0.0.32",   80),

    # --- Moderate severity (mid-range IOC IPs, score 40-70) ---
    ("SIEM-2024-000011", "Suspicious POST Request",  "low",    "46.166.148.142", "10.0.0.30",  443),
    ("SIEM-2024-000012", "Known Bad User-Agent",     "low",    "185.232.22.111", "10.0.0.31",   80),
    ("SIEM-2024-000013", "Data Exfil Pattern",       "medium", "193.32.162.46",  "10.0.0.40", 8080),
    ("SIEM-2024-000014", "DNS Tunnelling Detected",  "medium", "37.187.129.166", "10.0.0.101",  53),
    ("SIEM-2024-000015", "Outbound C2 Traffic",      "medium", "163.172.67.180", "10.0.0.102",8888),

    # --- Low-severity / clean IPs (no IOC match) ---
    ("SIEM-2024-000016", "Failed Login Attempt",     "low",    "203.0.113.100",  "10.0.0.100",  22),
    ("SIEM-2024-000017", "Unusual Off-Hours Access", "low",    "198.51.100.50",  "10.0.0.104",  80),
    ("SIEM-2024-000018", "Large File Download",      "low",    "192.0.2.100",    "10.0.0.40",  445),
    ("SIEM-2024-000019", "Policy Violation: USB",    "low",    "192.0.2.101",    "10.0.0.108",   0),
    ("SIEM-2024-000020", "Cleartext Password in Log","low",    "192.0.2.102",    "10.0.0.109",   0),

    # --- Duplicates (same alert_id as earlier ones → must return 409) ---
    ("SIEM-2024-000001", "HTTP Brute Force",         "medium", "185.220.101.42", "10.0.0.15",  443),  # dup of 001
    ("SIEM-2024-000003", "C2 Beacon Detected",       "medium", "45.142.212.100", "10.0.0.101", 8080), # dup of 003

    # --- Additional mixed alerts ---
    ("SIEM-2024-000021", "Malware Hash Match",       "high",   "91.108.4.180",   "10.0.0.103", 4444),
    ("SIEM-2024-000022", "Ransomware IOC",           "high",   "5.188.86.220",   "10.0.0.50",  3389),
    ("SIEM-2024-000023", "Privilege Escalation",     "high",   "203.0.113.110",  "10.0.0.5",     0),
]


def _make_alert_payload(alert_id, rule_name, severity, source_ip, dest_ip, dest_port):
    """Build a complete alert JSON payload."""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = (
        f"{ts} {source_ip} -> {dest_ip}:{dest_port} "
        f"rule={rule_name!r} sev={severity}"
    )
    return {
        "alert_id": alert_id,
        "timestamp": ts,
        "rule_name": rule_name,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "destination_port": dest_port,
        "raw_log": raw,
    }


def send_alert(payload):
    """POST a single alert to the SOAR API and print the result."""
    try:
        resp = requests.post(ALERTS_ENDPOINT, json=payload, timeout=10)
        status = resp.status_code
        body = resp.json() if resp.content else {}
        if status == 201:
            print(f"  [OK 201] {payload['alert_id']} → incident {body.get('incident_id', '?')}")
        elif status == 409:
            print(f"  [DUP 409] {payload['alert_id']} — duplicate (expected)")
        elif status == 501:
            print(f"  [STUB 501] {payload['alert_id']} — endpoint not yet implemented")
        else:
            print(f"  [ERR {status}] {payload['alert_id']} — {body}")
    except requests.exceptions.ConnectionError:
        print(f"  [CONN ERR] Could not reach SOAR API at {SOAR_API_URL}")
    except Exception as exc:
        print(f"  [EXC] {payload['alert_id']}: {exc}")


def wait_for_api(max_wait=60):
    """Poll the metrics endpoint until the API is reachable."""
    print(f"Waiting up to {max_wait}s for SOAR API to become available …")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            resp = requests.get(f"{SOAR_API_URL}/api/metrics", timeout=3)
            if resp.status_code in (200, 501):
                print("SOAR API is reachable.")
                return True
        except Exception:
            pass
        time.sleep(3)
    print("WARNING: SOAR API did not respond in time — proceeding anyway.")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{'='*60}")
    print("  SOAR Alert Generator — Project 03")
    print(f"  Target: {ALERTS_ENDPOINT}")
    print(f"{'='*60}\n")

    # Give the Flask app time to start
    time.sleep(STARTUP_WAIT)
    wait_for_api()

    print(f"\nSending {len(TEST_ALERTS)} test alerts (1 every 10 seconds) …\n")
    for i, alert_args in enumerate(TEST_ALERTS, 1):
        payload = _make_alert_payload(*alert_args)
        print(f"[{i:02d}/{len(TEST_ALERTS)}] Sending {payload['alert_id']} ({payload['rule_name']}) …")
        send_alert(payload)
        if i < len(TEST_ALERTS):
            time.sleep(10)

    print("\nInitial alert batch complete.")
    print("Starting ongoing simulation (2 alerts every 60 seconds) …\n")

    # Ongoing simulation loop
    ongoing_templates = [
        ("HTTP Brute Force",     "medium", "185.220.101.47",  "10.0.0.15",  443),
        ("SSH Brute Force",      "low",    "185.220.102.8",   "10.0.0.30",   22),
        ("Port Scan",            "low",    "80.82.77.33",     "10.0.0.50",   80),
        ("Suspicious DNS Query", "low",    "194.165.16.201",  "10.0.0.101",  53),
        ("Web Shell Detected",   "high",   "45.142.212.101",  "10.0.0.31",  443),
    ]
    seq = 100  # offset for unique alert IDs in the loop
    while True:
        time.sleep(60)
        for _ in range(2):
            template = random.choice(ongoing_templates)
            rule, sev, src, dst, port = template
            alert_id = f"SIEM-LIVE-{seq:06d}"
            seq += 1
            payload = _make_alert_payload(alert_id, rule, sev, src, dst, port)
            print(f"[LIVE] Sending {alert_id} ({rule}) …")
            send_alert(payload)


if __name__ == "__main__":
    main()
