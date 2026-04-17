#!/usr/bin/env python3
"""
Passive DNS and Certificate Transparency OSINT.

Uses free, public APIs (no API key required):
  - crt.sh : Certificate Transparency log search
  - IP range pattern analysis (offline)

Usage:
    python3 scripts/passive_dns.py

No external dependencies beyond the Python standard library.
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def query_crtsh(domain: str) -> tuple:
    """
    Query crt.sh for all TLS certificates issued to subdomains of `domain`.

    Returns (subdomains: set, cert_info: list).
    """
    print(f"\n[*] Querying Certificate Transparency logs for: *.{domain}")

    encoded = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={encoded}&output=json"

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CyberThreathuntingDemo/1.0 (educational)")

        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())

    except urllib.error.URLError as exc:
        print(f"  [!] Network error: {exc}")
        return set(), []
    except Exception as exc:
        print(f"  [!] Unexpected error: {exc}")
        return set(), []

    subdomains: set = set()
    cert_info = []

    for cert in data:
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip()
            if name and domain in name:
                subdomains.add(name)

        cert_info.append(
            {
                "issuer": cert.get("issuer_name", ""),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "serial": str(cert.get("serial_number", ""))[:16],
                "common_name": cert.get("common_name", ""),
            }
        )

    print(f"\n[Certificate Transparency Results]")
    print(f"  Total certificates found:   {len(data)}")
    print(f"  Unique subdomains/hostnames: {len(subdomains)}")

    if subdomains:
        print(f"\n  Subdomains:")
        for sub in sorted(subdomains)[:20]:
            print(f"    {sub}")

    if cert_info:
        print(f"\n  Certificate Timeline (5 most recent):")
        sorted_certs = sorted(
            cert_info, key=lambda x: x.get("not_before", ""), reverse=True
        )
        for cert in sorted_certs[:5]:
            print(
                f"    {cert['not_before'][:10]} | "
                f"{cert['common_name'][:40]:<40} | "
                f"{cert['issuer'][:30]}"
            )

    return subdomains, cert_info


# ---------------------------------------------------------------------------
# Passive DNS helpers
# ---------------------------------------------------------------------------

def list_passive_dns_resources() -> None:
    """Print free/low-cost passive DNS resources."""
    print(f"\n[*] Free Passive DNS Resources")
    resources = [
        ("SecurityTrails", "https://securitytrails.com", "50 free queries/month"),
        ("CIRCL Passive DNS", "https://www.circl.lu/services/passive-dns/", "Free for researchers"),
        ("PassiveDNS (Mnemonic)", "https://passivedns.mnemonic.no", "Norwegian CERT, free"),
        ("DNS Dumpster", "https://dnsdumpster.com", "Free web UI"),
        ("VirusTotal", "https://www.virustotal.com", "DNS history in Relations tab"),
    ]
    for name, url, notes in resources:
        print(f"  {name:<25} {url:<50} ({notes})")


# ---------------------------------------------------------------------------
# IP range analysis
# ---------------------------------------------------------------------------

def analyze_ip_ranges(ips: list) -> None:
    """Group IP addresses by /24 subnet and report patterns."""
    if not ips:
        return

    print(f"\n[*] IP Range Analysis")
    subnets: dict = {}

    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = ".".join(parts[:3]) + ".0/24"
            subnets.setdefault(subnet, []).append(ip)

    print(f"  {len(subnets)} unique /24 subnet(s) found:")
    for subnet, subnet_ips in sorted(subnets.items()):
        print(f"    {subnet}: {len(subnet_ips)} IP(s) — {', '.join(subnet_ips[:5])}")

    if len(subnets) == 1:
        print("\n  [!] All IPs in the same /24 — possible dedicated hosting")
    elif len(subnets) > len(ips) * 0.8:
        print("\n  [!] IPs spread across many subnets — may use bulletproof/shared hosting")


# ---------------------------------------------------------------------------
# Infrastructure mapping
# ---------------------------------------------------------------------------

def build_infrastructure_map(
    domain: str,
    related_ips: list = None,
    related_domains: list = None,
) -> dict:
    """
    Build a combined infrastructure map from CT logs and IP analysis.
    Saves the result as infrastructure_<domain>.json.
    """
    print(f"\n{'=' * 60}")
    print(f"INFRASTRUCTURE MAP: {domain}")
    print(f"{'=' * 60}")

    infrastructure = {
        "primary_domain": domain,
        "subdomains": [],
        "related_domains": related_domains or [],
        "ip_addresses": related_ips or [],
        "certificates": [],
    }

    subdomains, certs = query_crtsh(domain)
    infrastructure["subdomains"] = list(subdomains)
    infrastructure["certificates"] = certs

    list_passive_dns_resources()

    if related_ips:
        analyze_ip_ranges(related_ips)

    # Save to disk
    safe_name = domain.replace(".", "_")
    out_file = f"infrastructure_{safe_name}.json"
    with open(out_file, "w") as fh:
        json.dump(infrastructure, fh, indent=2, default=str)
    print(f"\n[✓] Infrastructure map saved: {out_file}")

    return infrastructure


# ---------------------------------------------------------------------------
# Pattern analysis
# ---------------------------------------------------------------------------

def print_pattern_analysis(domain: str, infrastructure: dict) -> None:
    """Print human-readable pattern observations about the infrastructure."""
    print(f"\n{'=' * 60}")
    print("PATTERN ANALYSIS")
    print(f"{'=' * 60}")
    print(f"Primary domain: {domain}")

    keywords = ["update", "cdn", "secure", "auth", "verify", "portal", "login", "api"]
    found_keywords = [kw for kw in keywords if kw in domain.lower()]
    if found_keywords:
        print(
            f"\n[!] Domain contains impersonation keywords: "
            f"{', '.join(found_keywords)}"
        )
        print("    Pattern: Impersonates CDN / auth / security service")

    n_certs = len(infrastructure.get("certificates", []))
    n_subdomains = len(infrastructure.get("subdomains", []))
    print(f"\n[Summary]")
    print(f"  TLS certificates found:    {n_certs}")
    print(f"  Unique subdomains/hostnames: {n_subdomains}")

    print(f"\n[Hunting Pivots]")
    print("  1. Search for other domains resolving to the same IP addresses")
    print("  2. Look for certificates issued by the same provider on the same day")
    print("  3. Search for domains with similar naming patterns (same keywords)")
    print("  4. Check WHOIS history for common registrant data points")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # These are fictional educational indicators mirroring the demo scenario.
    # Replace with real IOCs from threat intelligence in practice.
    TARGET_DOMAIN = "update-secure-cdn.com"
    RELATED_IPS = ["192.0.2.15", "192.0.2.22", "198.51.100.15"]
    RELATED_DOMAINS = ["auth-verify-portal.net", "cdn-update-service.com"]

    print("=== Passive DNS & Certificate Transparency OSINT Demo ===\n")

    infra = build_infrastructure_map(TARGET_DOMAIN, RELATED_IPS, RELATED_DOMAINS)
    print_pattern_analysis(TARGET_DOMAIN, infra)

    # Small courtesy delay before any additional calls
    time.sleep(2)
    print("\n[✓] OSINT collection complete.")
    print("    Import findings into MISP using scripts/create_event.py")
