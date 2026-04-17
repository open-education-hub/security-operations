#!/usr/bin/env python3
"""
generate_test_events.py — Test event generator for correlation rule validation.

Security Operations Course - Session 08: Event Normalization
Guide 03: Writing a Simple Multi-Event Correlation Rule

Purpose:
    Generates synthetic log events for testing threshold correlation rules.
    Three test cases:
      1. True positive: 12 SSH failures from same IP within 5 minutes → SHOULD FIRE
      2. True negative: 5 SSH failures from same IP → should NOT fire
      3. Multiple IPs: 10 failures each from 10 different IPs → should NOT fire for any

Output:
    Writes syslog-format SSH authentication messages to stdout (and optionally
    to a file). Feed these into your SIEM to validate rule detection.

Usage:
    python3 generate_test_events.py              # print all test cases to stdout
    python3 generate_test_events.py --case 1     # only test case 1
    python3 generate_test_events.py --output /tmp/ssh_test.log  # write to file
    python3 generate_test_events.py --inject     # inject into local Elasticsearch

Requirements (for --inject):
    pip install elasticsearch
"""

import argparse
import datetime
import sys
import random


# ── Syslog line templates ────────────────────────────────────────────────────

def make_ssh_failure(timestamp: datetime.datetime, hostname: str,
                     username: str, src_ip: str, src_port: int) -> str:
    """Generate a realistic SSH failed password syslog line."""
    pid = random.randint(1000, 65000)
    return (
        f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} "
        f"sshd[{pid}]: Failed password for invalid user {username} "
        f"from {src_ip} port {src_port} ssh2"
    )


def make_ssh_success(timestamp: datetime.datetime, hostname: str,
                     username: str, src_ip: str, src_port: int) -> str:
    """Generate a realistic SSH successful login syslog line."""
    pid = random.randint(1000, 65000)
    return (
        f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} "
        f"sshd[{pid}]: Accepted password for {username} "
        f"from {src_ip} port {src_port} ssh2"
    )


# ── Test case generators ─────────────────────────────────────────────────────

def case1_should_fire(base_time: datetime.datetime) -> list[str]:
    """
    Test Case 1: RULE SHOULD FIRE
    ==============================
    12 SSH failures from 203.0.113.42 to webserver01 within 4 minutes 10 seconds.
    Expected: Brute force alert fires (threshold=10, window=5min)
    """
    lines = []
    lines.append("# ── Test Case 1: TRUE POSITIVE (rule SHOULD fire) ──────────────────────────")
    lines.append(f"# 12 failures from 203.0.113.42 within 4m10s")
    lines.append(f"# Expected: brute force alert fires (threshold >10 in 5 min)")
    lines.append("")

    src_ip = "203.0.113.42"
    host = "webserver01"
    usernames = ["admin", "root", "user", "test", "oracle", "sa",
                 "postgres", "git", "ubuntu", "ec2-user", "admin", "root"]

    for i, username in enumerate(usernames):
        ts = base_time + datetime.timedelta(seconds=i * 21)  # one every 21s → 12 in ~4min
        src_port = 50000 + i
        lines.append(make_ssh_failure(ts, host, username, src_ip, src_port))

    lines.append("")
    return lines


def case2_should_not_fire(base_time: datetime.datetime) -> list[str]:
    """
    Test Case 2: RULE SHOULD NOT FIRE
    ===================================
    5 SSH failures from 198.51.100.10 — below the threshold of 10.
    Expected: No alert generated.
    """
    lines = []
    lines.append("# ── Test Case 2: TRUE NEGATIVE (rule should NOT fire) ──────────────────────")
    lines.append(f"# 5 failures from 198.51.100.10 within 2 minutes")
    lines.append(f"# Expected: NO alert (below threshold of 10)")
    lines.append("")

    src_ip = "198.51.100.10"
    host = "appserver02"
    usernames = ["admin", "root", "test", "deploy", "backup"]

    # Spread evenly over 2 minutes
    for i, username in enumerate(usernames):
        ts = base_time + datetime.timedelta(seconds=i * 25)
        src_port = 55000 + i
        lines.append(make_ssh_failure(ts, host, username, src_ip, src_port))

    lines.append("")
    return lines


def case3_multiple_ips(base_time: datetime.datetime) -> list[str]:
    """
    Test Case 3: MULTIPLE IPs — CORRELATION SHOULD NOT MERGE
    ==========================================================
    10 failures each from 10 different source IPs.
    Each IP individually is below the threshold.
    Expected: No alert (the rule groups BY source IP).
    """
    lines = []
    lines.append("# ── Test Case 3: MULTIPLE IPs — grouped correctly (no alert per IP) ────────")
    lines.append(f"# 10 failures each from 10 different IPs (100 total)")
    lines.append(f"# Expected: NO alert for any single IP (each has only 10, need >10)")
    lines.append("")

    host = "dbserver03"
    ips = [f"10.0.{i}.{random.randint(10, 200)}" for i in range(1, 11)]

    for ip_idx, src_ip in enumerate(ips):
        for attempt in range(10):
            ts = base_time + datetime.timedelta(seconds=ip_idx * 30 + attempt * 3)
            username = random.choice(["admin", "root", "oracle", "test"])
            src_port = 40000 + ip_idx * 100 + attempt
            lines.append(make_ssh_failure(ts, host, username, src_ip, src_port))
    lines.append("")
    return lines


def case4_brute_force_success(base_time: datetime.datetime) -> list[str]:
    """
    Test Case 4: BRUTE FORCE WITH SUCCESS
    ======================================
    15 failures from 192.0.2.99 followed by a successful login.
    Tests whether the rule fires AND the successful login is correlated.
    Expected: Alert fires on the 11th failure; success is additional context.
    """
    lines = []
    lines.append("# ── Test Case 4: BRUTE FORCE + SUCCESS (combined detection) ─────────────────")
    lines.append(f"# 15 failures then 1 success from 192.0.2.99")
    lines.append(f"# Expected: brute force alert fires; success is follow-up context")
    lines.append("")

    src_ip = "192.0.2.99"
    host = "jumpbox01"
    usernames = (["admin", "root", "ubuntu", "ec2-user", "centos",
                  "vagrant", "pi", "user", "operator", "service",
                  "backup", "sysadmin", "devops", "deploy", "ansible"])

    for i, username in enumerate(usernames):
        ts = base_time + datetime.timedelta(seconds=i * 12)
        src_port = 48000 + i
        lines.append(make_ssh_failure(ts, host, username, src_ip, src_port))

    # Successful login 30 seconds after last failure
    success_ts = base_time + datetime.timedelta(seconds=len(usernames) * 12 + 30)
    lines.append(make_ssh_success(success_ts, host, "backup", src_ip, 48099))
    lines.append(f"# ^ SUCCESS: 'backup' was the cracked account")
    lines.append("")
    return lines


# ── Elasticsearch injection ───────────────────────────────────────────────────

def inject_to_elasticsearch(lines: list[str],
                             host: str = "http://localhost:9200",
                             index: str = "security-ssh-test",
                             username: str = "elastic",
                             password: str = "changeme") -> None:
    """Inject generated events directly into Elasticsearch."""
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("ERROR: elasticsearch package not installed.", file=sys.stderr)
        print("Run: pip install elasticsearch", file=sys.stderr)
        sys.exit(1)

    es = Elasticsearch(host, basic_auth=(username, password))
    injected = 0
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        doc = {"message": line, "@timestamp": datetime.datetime.utcnow().isoformat()}
        es.index(index=index, document=doc)
        injected += 1
    print(f"Injected {injected} events into Elasticsearch index '{index}'")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate SSH test events for correlation rule testing"
    )
    parser.add_argument("--case", type=int, choices=[1, 2, 3, 4],
                        help="Generate only this test case (default: all)")
    parser.add_argument("--output", type=str, default=None,
                        help="Write output to file instead of stdout")
    parser.add_argument("--inject", action="store_true",
                        help="Inject events directly into Elasticsearch")
    parser.add_argument("--es-host", default="http://localhost:9200",
                        help="Elasticsearch host (for --inject)")
    parser.add_argument("--es-index", default="security-ssh-test",
                        help="Elasticsearch index (for --inject)")
    args = parser.parse_args()

    base_time = datetime.datetime(2024, 12, 14, 7, 40, 0)

    all_lines = []

    all_lines.append("# =============================================================================")
    all_lines.append("# SSH Brute Force Detection - Correlation Rule Test Events")
    all_lines.append("# Security Operations Course - Session 08: Event Normalization")
    all_lines.append("# Generated: " + datetime.datetime.utcnow().isoformat() + "Z")
    all_lines.append("# =============================================================================")
    all_lines.append("")
    all_lines.append("# Validation checklist:")
    all_lines.append("#   Case 1: Rule SHOULD fire  (12 failures from 1 IP in <5min)")
    all_lines.append("#   Case 2: Rule should NOT   (5 failures from 1 IP in <5min)")
    all_lines.append("#   Case 3: Rule should NOT   (10 IPs × 10 failures each)")
    all_lines.append("#   Case 4: Rule SHOULD fire  (15 failures + success from 1 IP)")
    all_lines.append("")

    generators = {
        1: case1_should_fire,
        2: case2_should_not_fire,
        3: case3_multiple_ips,
        4: case4_brute_force_success,
    }

    if args.case:
        # Offset the base time per case to keep events distinct
        case_time = base_time + datetime.timedelta(minutes=(args.case - 1) * 10)
        all_lines.extend(generators[args.case](case_time))
    else:
        for case_num, gen in generators.items():
            case_time = base_time + datetime.timedelta(minutes=(case_num - 1) * 10)
            all_lines.extend(gen(case_time))

    output_text = "\n".join(all_lines) + "\n"

    if args.inject:
        inject_to_elasticsearch(all_lines, host=args.es_host, index=args.es_index)
    elif args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"Wrote {sum(1 for l in all_lines if not l.startswith('#') and l.strip())} "
              f"log lines to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
