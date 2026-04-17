#!/usr/bin/env python3
"""
Log Producer for Demo 02
Sends sample events in three different formats to Logstash.
"""
import json
import random
import socket
import time
from datetime import datetime, timezone, timedelta
from faker import Faker

fake = Faker()

LOGSTASH_HOST = "logstash"
APACHE_PORT   = 5000
CEF_PORT      = 5001
JSON_PORT     = 5002

IPS_INTERNAL  = [f"192.168.{s}.{h}" for s in [1, 2] for h in range(2, 30)]
IPS_EXTERNAL  = ["203.0.113.10", "198.51.100.50", "185.220.101.5",
                 "1.2.3.4", "45.33.32.156", "66.240.205.34"]
METHODS       = ["GET", "POST", "PUT", "DELETE", "HEAD"]
PATHS         = ["/", "/login", "/api/users", "/api/data", "/admin",
                 "/wp-admin/", "/.env", "/health", "/api/v2/products"]
USER_AGENTS   = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Nikto/2.1.6",
    "Go-http-client/1.1",
]
STATUS_CODES  = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500]

CEF_VENDORS   = [("Palo Alto Networks", "PAN-OS"), ("Fortinet", "FortiGate"),
                 ("Check Point", "Firewall-1")]
CEF_ACTIONS   = ["allow", "deny", "drop", "reset"]
PROTOCOLS     = ["TCP", "UDP", "ICMP"]


def send_line(host, port, line):
    """Send a single line to a TCP socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall((line + "\n").encode())
    except Exception as e:
        print(f"[!] Failed to send to {host}:{port} — {e}")


def ts_apache(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def ts_iso(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_apache_log():
    ip     = random.choice(IPS_INTERNAL + IPS_EXTERNAL)
    method = random.choice(METHODS)
    path   = random.choice(PATHS)
    status = random.choice(STATUS_CODES)
    size   = random.randint(100, 50000)
    ua     = random.choice(USER_AGENTS)
    return f'{ip} - - [{ts_apache()}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def make_cef_event():
    vendor, product = random.choice(CEF_VENDORS)
    src_ip   = random.choice(IPS_EXTERNAL)
    dst_ip   = random.choice(IPS_INTERNAL[:5])
    src_port = random.randint(49152, 65535)
    dst_port = random.choice([22, 80, 443, 3389, 8080])
    proto    = random.choice(PROTOCOLS)
    action   = random.choice(CEF_ACTIONS)
    severity = random.randint(1, 10)
    sig      = f"FW-{random.randint(1000, 9999)}"
    name     = f"{'Allowed' if action == 'allow' else 'Blocked'} {proto} to port {dst_port}"
    ext      = f"src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto={proto} act={action}"
    return f"CEF:0|{vendor}|{product}|6.0|{sig}|{name}|{severity}|{ext}"


def make_json_event():
    ip     = random.choice(IPS_INTERNAL + IPS_EXTERNAL)
    method = random.choice(METHODS)
    path   = random.choice(PATHS)
    code   = random.choice(STATUS_CODES)
    ua     = random.choice(USER_AGENTS)
    return json.dumps({
        "ts":        ts_iso(),
        "remote_ip": ip,
        "method":    method,
        "path":      path,
        "code":      code,
        "agent":     ua,
        "bytes":     random.randint(100, 50000),
    })


if __name__ == "__main__":
    print(f"[*] Log producer starting — target: {LOGSTASH_HOST}")
    print(f"    Apache → :{APACHE_PORT}  CEF → :{CEF_PORT}  JSON → :{JSON_PORT}")
    time.sleep(10)  # Let Logstash fully start

    cycle = 0
    while True:
        cycle += 1
        print(f"\n--- Cycle {cycle} ---")

        # Send a batch of each format
        for _ in range(random.randint(3, 7)):
            log = make_apache_log()
            print(f"[Apache] {log[:80]}")
            send_line(LOGSTASH_HOST, APACHE_PORT, log)
            time.sleep(0.1)

        for _ in range(random.randint(2, 5)):
            log = make_cef_event()
            print(f"[CEF]    {log[:80]}")
            send_line(LOGSTASH_HOST, CEF_PORT, log)
            time.sleep(0.1)

        for _ in range(random.randint(3, 6)):
            log = make_json_event()
            print(f"[JSON]   {log[:80]}")
            send_line(LOGSTASH_HOST, JSON_PORT, log)
            time.sleep(0.1)

        time.sleep(random.uniform(5, 10))
