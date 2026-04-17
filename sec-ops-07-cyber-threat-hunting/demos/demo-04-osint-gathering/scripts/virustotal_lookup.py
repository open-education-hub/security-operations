#!/usr/bin/env python3
"""
VirusTotal IOC lookup using the free public API (v3).

Rate limit on free tier: 4 requests/minute.
This script sleeps 16 seconds between requests to stay within the limit.

Usage:
    export VT_API_KEY="your-free-api-key"
    python3 scripts/virustotal_lookup.py

Get a free API key at: https://www.virustotal.com/gui/join-us

IMPORTANT: All IP addresses and domains used in this demo are either
           RFC-5737 documentation examples (192.0.2.x, 198.51.100.x)
           or fictional educational indicators. Do NOT run active
           lookups on real production infrastructure without permission.
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

# Seconds to wait between requests (free tier: 4 req/min = 15s minimum)
REQUEST_DELAY = 16


# ---------------------------------------------------------------------------
# Low-level request helper
# ---------------------------------------------------------------------------

def _vt_get(endpoint: str) -> dict:
    """Perform a GET request against the VT API v3 and return parsed JSON."""
    if not VT_API_KEY:
        raise RuntimeError(
            "VT_API_KEY environment variable is not set.\n"
            "  export VT_API_KEY='your-free-api-key'"
        )

    url = f"{VT_BASE}/{endpoint}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", VT_API_KEY)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"error": "not_found"}
        if exc.code == 401:
            return {"error": "invalid_api_key"}
        if exc.code == 429:
            return {"error": "rate_limited"}
        return {"error": f"http_{exc.code}"}
    except Exception as exc:
        return {"error": str(exc)}


def _rate_limit_sleep() -> None:
    """Pause to respect the free-tier rate limit."""
    print(f"    (waiting {REQUEST_DELAY}s for rate limit...)")
    time.sleep(REQUEST_DELAY)


# ---------------------------------------------------------------------------
# Individual lookup functions
# ---------------------------------------------------------------------------

def lookup_domain(domain: str) -> dict:
    """Print reputation and metadata for a domain."""

    print(f"\n{'=' * 60}")
    print(f"Domain Analysis: {domain}")
    print(f"{'=' * 60}")

    _rate_limit_sleep()
    result = _vt_get(f"domains/{domain}")

    if "error" in result:
        print(f"[!] Error: {result['error']}")
        return {}

    attrs = result.get("data", {}).get("attributes", {})

    # Reputation / detection stats
    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    verdict = "MALICIOUS" if mal > 3 else ("SUSPICIOUS" if mal > 0 else "CLEAN")

    print(f"\n[Reputation]")
    print(f"  Malicious:  {mal}/{total} engines")
    print(f"  Suspicious: {sus}/{total} engines")
    print(f"  Verdict:    {verdict}")

    # WHOIS-equivalent info
    print(f"\n[Registration]")
    print(f"  Created:   {attrs.get('creation_date', 'Unknown')}")
    print(f"  Updated:   {attrs.get('last_update_date', 'Unknown')}")
    print(f"  Registrar: {attrs.get('registrar', 'Unknown')}")

    # DNS records
    print(f"\n[DNS Records]")
    for record_type, records in attrs.get("last_dns_records", {}).items():
        if isinstance(records, list):
            for record in records[:3]:
                val = record.get("value", record) if isinstance(record, dict) else record
                print(f"  {record_type}: {val}")

    # Vendor categories
    categories = attrs.get("categories", {})
    if categories:
        print(f"\n[Vendor Categories]")
        for vendor, category in list(categories.items())[:5]:
            print(f"  {vendor}: {category}")

    return attrs


def lookup_ip(ip_address: str) -> dict:
    """Print reputation and network info for an IP address."""

    print(f"\n{'=' * 60}")
    print(f"IP Analysis: {ip_address}")
    print(f"{'=' * 60}")

    _rate_limit_sleep()
    result = _vt_get(f"ip_addresses/{ip_address}")

    if "error" in result:
        print(f"[!] Error: {result['error']}")
        return {}

    attrs = result.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    total = sum(stats.values()) or 1

    print(f"\n[Reputation]")
    print(f"  Malicious:  {mal}/{total} engines")
    print(f"  Verdict:    {'MALICIOUS' if mal > 3 else 'SUSPICIOUS' if mal > 0 else 'CLEAN'}")

    print(f"\n[Network Information]")
    print(f"  Country:   {attrs.get('country', 'Unknown')}")
    print(f"  ASN:       {attrs.get('asn', 'Unknown')}")
    print(f"  AS Owner:  {attrs.get('as_owner', 'Unknown')}")
    print(f"  Network:   {attrs.get('network', 'Unknown')}")

    tags = attrs.get("tags", [])
    if tags:
        print(f"  Tags:      {', '.join(tags)}")

    return attrs


def lookup_hash(sha256_hash: str) -> dict:
    """Print detection and metadata for a file hash."""

    print(f"\n{'=' * 60}")
    print(f"File Hash Analysis: {sha256_hash[:20]}...")
    print(f"{'=' * 60}")

    _rate_limit_sleep()
    result = _vt_get(f"files/{sha256_hash}")

    if "error" in result:
        if result["error"] == "not_found":
            print("[✓] Hash not found in VirusTotal (not previously submitted)")
        else:
            print(f"[!] Error: {result['error']}")
        return {}

    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    total = sum(stats.values()) or 1

    print(f"\n[Detection]")
    print(f"  Detections: {mal}/{total} engines")
    print(f"  Verdict:    {'MALICIOUS' if mal > 3 else 'SUSPICIOUS' if mal > 0 else 'CLEAN'}")

    print(f"\n[File Information]")
    print(f"  Type:       {attrs.get('type_description', 'Unknown')}")
    print(f"  Size:       {attrs.get('size', 0)} bytes")
    print(f"  First Seen: {attrs.get('first_submission_date', 'Unknown')}")

    # Most common malware family names from detections
    names: set = set()
    for _vendor, det in attrs.get("last_analysis_results", {}).items():
        if det.get("category") == "malicious" and det.get("result"):
            names.add(det["result"])

    if names:
        print(f"\n[Malware Names from Vendors]")
        for name in list(names)[:10]:
            print(f"  - {name}")

    tags = attrs.get("tags", [])
    if tags:
        print(f"\n[Tags]: {', '.join(tags)}")

    return attrs


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not VT_API_KEY:
        print(
            "[!] VT_API_KEY is not set.\n"
            "    Register for a free key at: https://www.virustotal.com/gui/join-us\n"
            "    Then: export VT_API_KEY='your-key'"
        )
        sys.exit(1)

    print("=== VirusTotal OSINT Lookup Demo ===")
    print("Using free API tier — 4 requests/minute limit")
    print()

    # These are RFC-5737 documentation addresses (safe for demo lookups)
    # Replace with real indicators from your threat intelligence in practice
    lookup_domain("update-secure-cdn.com")
    lookup_ip("192.0.2.15")

    print("\n=== Analysis Complete ===")
    print("Next steps:")
    print("  1. Add findings to the threat actor profile")
    print("  2. Import confirmed indicators into MISP (run create_event.py)")
    print("  3. Block confirmed malicious IPs/domains")
    print("  4. Hunt for related infrastructure using passive DNS (passive_dns.py)")
