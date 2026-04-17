#!/usr/bin/env python3
"""
Traffic Generator for Demo 01
Simulates mixed web traffic including normal requests,
scanning attempts, and suspicious patterns.
"""
import random
import time
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)

TARGET = "http://web-server:80"

NORMAL_PATHS = ["/", "/index.html", "/api/users", "/api/data", "/health"]
SCAN_PATHS = ["/admin/", "/wp-admin/", "/.env", "/config.php", "/backup.zip",
              "/phpmyadmin/", "/.git/config", "/api/v1/admin"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.68.0",                       # Scripted tool
    "python-requests/2.28.0",            # Possible automation/attack
    "Go-http-client/1.1",               # Golang tool
    "Nikto/2.1.6",                       # Vulnerability scanner
    "sqlmap/1.7 (https://sqlmap.org)",  # SQL injection tool
]

ATTACKER_IPS = ["198.51.100.10", "203.0.113.50", "192.0.2.99"]
NORMAL_IPS = [f"10.0.{r}.{h}" for r in range(1, 5) for h in range(1, 20)]


def make_request(path, user_agent, source_ip=None):
    headers = {
        "User-Agent": user_agent,
        "X-Forwarded-For": source_ip or random.choice(NORMAL_IPS),
    }
    try:
        resp = requests.get(f"{TARGET}{path}", headers=headers, timeout=3)
        logger.info(f"GET {path} [{resp.status_code}] UA={user_agent[:30]}")
    except Exception as e:
        logger.debug(f"Request failed: {e}")


def simulate_normal_traffic():
    """Simulate legitimate user browsing."""
    for _ in range(random.randint(3, 8)):
        path = random.choice(NORMAL_PATHS)
        ua = random.choice(USER_AGENTS[:2])
        make_request(path, ua)
        time.sleep(random.uniform(0.5, 2.0))


def simulate_scan():
    """Simulate a vulnerability scan from an attacker IP."""
    logger.info("[!] Starting simulated vulnerability scan")
    attacker_ip = random.choice(ATTACKER_IPS)
    scanner_ua = random.choice(USER_AGENTS[3:])
    for path in SCAN_PATHS:
        make_request(path, scanner_ua, attacker_ip)
        time.sleep(random.uniform(0.1, 0.5))


def simulate_brute_force():
    """Simulate rapid requests to admin endpoint."""
    logger.info("[!] Starting simulated brute-force")
    attacker_ip = random.choice(ATTACKER_IPS)
    for _ in range(20):
        make_request("/admin/login", USER_AGENTS[2], attacker_ip)
        time.sleep(0.1)


if __name__ == "__main__":
    logger.info("Traffic generator started")
    cycle = 0
    while True:
        cycle += 1
        logger.info(f"--- Cycle {cycle} ---")

        # Normal traffic most of the time
        simulate_normal_traffic()

        # Occasional suspicious activity
        if cycle % 5 == 0:
            simulate_scan()
        if cycle % 10 == 0:
            simulate_brute_force()

        time.sleep(random.uniform(5, 15))
