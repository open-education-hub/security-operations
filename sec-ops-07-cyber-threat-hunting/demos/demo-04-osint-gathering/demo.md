# Demo 04: OSINT Gathering for Threat Actor Profiling

**Duration:** ~35 minutes

**Difficulty:** Intermediate

**Prerequisites:** Reading material sections 8, 12; Python 3; basic web browsing

---

## Overview

In this demo, we will conduct OSINT (Open Source Intelligence) gathering to build a threat actor profile using only public tools and sources.
We will:

1. Investigate a threat actor using public ATT&CK data
1. Gather infrastructure intelligence from free sources
1. Analyze malware samples via VirusTotal
1. Perform passive DNS analysis
1. Build a structured threat actor profile
1. Create a Python-based OSINT collection script

> **Important:** All techniques in this demo use only publicly available, legal tools. We are NOT conducting active reconnaissance against any real target. All IP addresses and domains used are either examples or public threat intelligence.

---

## Scenario: Profiling FIN-STORM Activity

Your organization has detected suspicious activity.
An initial investigation reveals a domain: `update-secure-cdn[.]com` (defanged).
Your task is to build an intelligence profile on the actor behind this infrastructure.

---

## Step 1: ATT&CK Group Research

### Using the ATT&CK Web Interface

1. Navigate to https://attack.mitre.org/groups/
1. Search for financially motivated groups targeting your sector
1. For this demo, we'll use **FIN7** as a reference group

**Key information to extract:**

* Group aliases (FIN7, Carbanak, GOLD NIAGARA)
* Target sectors (Financial, Hospitality, Retail)
* TTPs used (which ATT&CK techniques)
* Tools and malware
* Associated software

### ATT&CK via Python API

```console
pip install mitreattack-python
```

Create `scripts/attck_research.py`:

```python
#!/usr/bin/env python3
"""
Query MITRE ATT&CK for group and technique information
"""

from mitreattack.stix20 import MitreAttackData

def research_group(group_name):
    """Research an ATT&CK group"""

    # Load ATT&CK data (downloads from GitHub if not cached)
    print(f"[*] Loading ATT&CK data...")
    mitre = MitreAttackData("enterprise-attack.json")

    # Find groups by name
    groups = mitre.get_groups()

    target_group = None
    for group in groups:
        if hasattr(group, 'name') and group_name.lower() in group.name.lower():
            target_group = group
            break
        # Also check aliases
        if hasattr(group, 'aliases'):
            for alias in group.aliases:
                if group_name.lower() in alias.lower():
                    target_group = group
                    break

    if not target_group:
        print(f"[-] Group '{group_name}' not found")
        return

    print(f"\n{'='*60}")
    print(f"Group: {target_group.name}")
    print(f"{'='*60}")

    # Print aliases
    if hasattr(target_group, 'aliases') and target_group.aliases:
        print(f"Aliases: {', '.join(target_group.aliases)}")

    # Print description
    if hasattr(target_group, 'description'):
        desc = target_group.description[:300]
        print(f"\nDescription:\n{desc}...")

    # Get techniques used by this group
    print(f"\n[*] Techniques used by {target_group.name}:")
    techniques = mitre.get_techniques_used_by_group(target_group.id)

    # Organize by tactic
    by_tactic = {}
    for tech in techniques:
        if hasattr(tech, 'kill_chain_phases'):
            for phase in tech.kill_chain_phases:
                tactic = phase.phase_name
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append({
                    'id': tech.external_id if hasattr(tech, 'external_id') else 'N/A',
                    'name': tech.name,
                    'description': tech.description[:100] if hasattr(tech, 'description') else ''
                })

    for tactic, techs in sorted(by_tactic.items()):
        print(f"\n  [{tactic.upper().replace('-', ' ')}]")
        for t in techs[:5]:  # Show first 5 per tactic
            print(f"    - {t['name']}")

    # Get associated software/malware
    print(f"\n[*] Software used by {target_group.name}:")
    software = mitre.get_software_used_by_group(target_group.id)
    for s in software[:10]:
        print(f"  - {s.name} ({s.type if hasattr(s, 'type') else 'tool'})")

    return target_group

def get_technique_hunting_queries(technique_id):
    """Get data sources and hunting suggestions for a technique"""

    mitre = MitreAttackData("enterprise-attack.json")

    techniques = mitre.get_techniques()

    for tech in techniques:
        ext_refs = getattr(tech, 'external_references', [])
        for ref in ext_refs:
            if hasattr(ref, 'external_id') and ref.external_id == technique_id:
                print(f"\n{'='*60}")
                print(f"Technique: {tech.name} ({technique_id})")
                print(f"{'='*60}")

                # Data sources
                if hasattr(tech, 'x_mitre_data_sources'):
                    print("\nData Sources (for hunting):")
                    for ds in tech.x_mitre_data_sources:
                        print(f"  - {ds}")

                # Detection notes
                if hasattr(tech, 'x_mitre_detection'):
                    print(f"\nDetection Guidance:\n{tech.x_mitre_detection[:300]}...")

                return tech

    print(f"[-] Technique {technique_id} not found")

if __name__ == "__main__":
    # Research FIN7 group
    research_group("FIN7")

    # Get hunting guidance for key techniques
    print("\n\n=== HUNTING GUIDANCE ===")
    for technique_id in ["T1059.001", "T1003.001", "T1047"]:
        get_technique_hunting_queries(technique_id)
```

---

## Step 2: Investigate Infrastructure with Free OSINT Tools

### Using URLScan.io (Web-based, free)

Navigate to https://urlscan.io and search for the domain.

**For this demo, search for a known example domain:**

```text
Search: update-secure-cdn.com
```

What URLScan shows:

* Screenshot of the website
* IP address and ASN
* Outgoing links and loaded resources
* Redirects
* HTTP headers and certificates
* DOM links

### Using VirusTotal (Free tier)

VirusTotal aggregates data from 70+ security vendors.

Create `scripts/virustotal_lookup.py`:

```python
#!/usr/bin/env python3
"""
VirusTotal IOC lookup using free API
Rate limit: 4 requests/minute on free tier

Get your free API key at: https://www.virustotal.com/gui/join-us
"""

import os
import time
import json
import urllib.request
import urllib.error

# Get free API key from environment
VT_API_KEY = os.environ.get('VT_API_KEY', 'YOUR_FREE_API_KEY_HERE')

def vt_request(endpoint, params=None):
    """Make a VirusTotal API request"""
    base_url = "https://www.virustotal.com/api/v3"
    url = f"{base_url}/{endpoint}"

    if params:
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query_string}"

    req = urllib.request.Request(url)
    req.add_header("x-apikey", VT_API_KEY)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": str(e)}

def lookup_domain(domain):
    """Get comprehensive domain intelligence"""

    print(f"\n{'='*60}")
    print(f"Domain Analysis: {domain}")
    print(f"{'='*60}")

    # Rate limit: 4 requests/minute on free tier
    time.sleep(15)  # Be respectful of rate limits

    result = vt_request(f"domains/{domain}")

    if "error" in result:
        print(f"[!] Error: {result['error']}")
        return

    if "data" not in result:
        print(f"[!] No data returned")
        return

    data = result["data"]
    attrs = data.get("attributes", {})

    # Basic info
    print(f"\n[Reputation]")
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = sum(stats.values())

    print(f"  Malicious:  {malicious}/{total} engines")
    print(f"  Suspicious: {suspicious}/{total} engines")
    print(f"  Verdict:    {'MALICIOUS' if malicious > 3 else 'SUSPICIOUS' if malicious > 0 else 'CLEAN'}")

    # Registration info
    print(f"\n[Registration]")
    print(f"  Created:    {attrs.get('creation_date', 'Unknown')}")
    print(f"  Updated:    {attrs.get('last_update_date', 'Unknown')}")
    print(f"  Registrar:  {attrs.get('registrar', 'Unknown')}")

    # DNS
    print(f"\n[DNS Records]")
    for record_type, records in attrs.get("last_dns_records", {}).items():
        if isinstance(records, list):
            for record in records[:3]:
                print(f"  {record_type}: {record.get('value', record)}")

    # Categories (from different vendors)
    categories = attrs.get("categories", {})
    if categories:
        print(f"\n[Categories]")
        for vendor, category in list(categories.items())[:5]:
            print(f"  {vendor}: {category}")

    # Related URLs (recently seen malicious URLs on this domain)
    print(f"\n[Recently Malicious URLs]")
    urls_result = vt_request(f"domains/{domain}/urls")
    if "data" in urls_result:
        for url_data in urls_result["data"][:5]:
            url_attrs = url_data.get("attributes", {})
            url = url_attrs.get("url", "")
            stats = url_attrs.get("last_analysis_stats", {})
            print(f"  [{stats.get('malicious', 0)} detections] {url[:80]}")

    return attrs

def lookup_ip(ip_address):
    """Get IP address intelligence"""

    print(f"\n{'='*60}")
    print(f"IP Analysis: {ip_address}")
    print(f"{'='*60}")

    time.sleep(15)

    result = vt_request(f"ip_addresses/{ip_address}")

    if "data" not in result:
        print(f"[!] No data for IP: {ip_address}")
        return

    attrs = result["data"].get("attributes", {})

    # Reputation
    stats = attrs.get("last_analysis_stats", {})
    print(f"\n[Reputation]")
    print(f"  Malicious:  {stats.get('malicious', 0)}/{sum(stats.values())} engines")

    # Network info
    print(f"\n[Network Information]")
    print(f"  Country:    {attrs.get('country', 'Unknown')}")
    print(f"  ASN:        {attrs.get('asn', 'Unknown')}")
    print(f"  AS Owner:   {attrs.get('as_owner', 'Unknown')}")
    print(f"  Network:    {attrs.get('network', 'Unknown')}")

    # Tags
    tags = attrs.get("tags", [])
    if tags:
        print(f"  Tags:       {', '.join(tags)}")

    return attrs

def lookup_hash(sha256_hash):
    """Analyze a file hash"""

    print(f"\n{'='*60}")
    print(f"File Hash Analysis: {sha256_hash[:16]}...")
    print(f"{'='*60}")

    time.sleep(15)

    result = vt_request(f"files/{sha256_hash}")

    if "data" not in result:
        print(f"[!] Hash not found in VirusTotal")
        return

    attrs = result["data"].get("attributes", {})

    # Detection stats
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    print(f"\n[Detection]")
    print(f"  Detections: {malicious}/{total} engines")
    print(f"  Verdict:    {'MALICIOUS' if malicious > 3 else 'SUSPICIOUS' if malicious > 0 else 'CLEAN'}")

    # File info
    print(f"\n[File Information]")
    print(f"  Type:       {attrs.get('type_description', 'Unknown')}")
    print(f"  Size:       {attrs.get('size', 0)} bytes")
    print(f"  First Seen: {attrs.get('first_submission_date', 'Unknown')}")

    # Common name detections
    print(f"\n[Common Malware Names]")
    results = attrs.get("last_analysis_results", {})
    names = set()
    for vendor, result in results.items():
        if result.get("category") == "malicious":
            name = result.get("result", "")
            if name:
                names.add(name)
    for name in list(names)[:10]:
        print(f"  - {name}")

    # Behavioral tags
    tags = attrs.get("tags", [])
    if tags:
        print(f"\n[Tags]: {', '.join(tags)}")

    return attrs

if __name__ == "__main__":
    print("=== VirusTotal OSINT Lookup Demo ===")
    print("Note: Using free API tier (4 req/min limit)")
    print()

    # Look up example indicators (these are public threat intel examples)
    # In a real scenario, these would come from your threat intel

    # Example domain lookup
    lookup_domain("update-secure-cdn.com")

    # Example IP lookup
    lookup_ip("192.0.2.15")

    print("\n=== Analysis Complete ===")
    print("Next steps:")
    print("  1. Add findings to your threat actor profile")
    print("  2. Import indicators into MISP")
    print("  3. Block confirmed malicious IPs/domains")
    print("  4. Hunt for related infrastructure")
```

---

## Step 3: Passive DNS Investigation

Passive DNS records show historical DNS resolutions, revealing when domains pointed to which IPs.

### Using SecurityTrails (Free tier available)

Navigate to https://securitytrails.com

1. Search for the domain
1. Review: Historical DNS records, Subdomains, Related domains
1. Look for infrastructure patterns: shared hosting, common registrar patterns

### Using Certificate Transparency Logs (crt.sh)

Certificate Transparency (CT) logs record all TLS certificates.
This reveals subdomains and infrastructure:

```bash
# Query crt.sh for certificate history
curl -s "https://crt.sh/?q=%25.update-secure-cdn.com&output=json" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
domains = set()
for cert in data:
    name = cert.get('name_value', '')
    for d in name.split('\n'):
        domains.add(d.strip())
for d in sorted(domains):
    print(d)
"
```

### Create a Passive DNS Tool

Create `scripts/passive_dns.py`:

```python
#!/usr/bin/env python3
"""
Passive DNS and Certificate Transparency OSINT
Uses free, public APIs
"""

import json
import urllib.request
import urllib.parse
import time

def query_crtsh(domain):
    """Query Certificate Transparency logs via crt.sh"""

    print(f"\n[*] Querying Certificate Transparency for: {domain}")

    # Query for wildcard to find subdomains
    encoded_domain = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={encoded_domain}&output=json"

    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'OSINT-Research-Tool/1.0')

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        # Extract unique subdomains
        subdomains = set()
        cert_info = []

        for cert in data:
            name_value = cert.get('name_value', '')
            for name in name_value.split('\n'):
                name = name.strip()
                if name and domain in name:
                    subdomains.add(name)

            cert_info.append({
                'issuer': cert.get('issuer_name', ''),
                'not_before': cert.get('not_before', ''),
                'not_after': cert.get('not_after', ''),
                'serial': cert.get('serial_number', '')[:16],
                'common_name': cert.get('common_name', '')
            })

        print(f"\n[Certificate Transparency Results]")
        print(f"  Total certificates found: {len(data)}")
        print(f"  Unique subdomains/names: {len(subdomains)}")

        print(f"\n  Subdomains:")
        for sub in sorted(subdomains)[:20]:
            print(f"    {sub}")

        # Show certificate timeline
        print(f"\n  Certificate Timeline (most recent):")
        sorted_certs = sorted(cert_info,
                              key=lambda x: x.get('not_before', ''),
                              reverse=True)
        for cert in sorted_certs[:5]:
            print(f"    {cert['not_before'][:10]} | "
                  f"{cert['common_name'][:40]} | "
                  f"{cert['issuer'][:30]}")

        return subdomains, cert_info

    except Exception as e:
        print(f"  [!] Error: {e}")
        return set(), []

def query_dns_dumpster(domain):
    """
    DNS reconnaissance using dnsdumpster.com data
    Note: This is a simplified example. Real implementation
    requires the dnsdumpster API or scraping.
    """

    print(f"\n[*] DNS Intelligence for: {domain}")
    print("  [Note] For full passive DNS, consider:")
    print("  - https://dnsdumpster.com (free web)")
    print("  - https://securitytrails.com (free tier: 50 req/month)")
    print("  - https://passivedns.mnemonic.no (Norwegian CERT, free)")
    print("  - https://www.circl.lu/services/passive-dns/ (CIRCL, researchers)")

def analyze_ip_ranges(ips):
    """Analyze IP addresses for patterns suggesting shared infrastructure"""

    if not ips:
        return

    print(f"\n[*] IP Range Analysis")

    # Group by /24 subnet
    subnets = {}
    for ip in ips:
        parts = ip.split('.')
        if len(parts) == 4:
            subnet = '.'.join(parts[:3]) + '.0/24'
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(ip)

    print(f"  Found {len(subnets)} unique /24 subnets:")
    for subnet, subnet_ips in sorted(subnets.items()):
        print(f"    {subnet}: {len(subnet_ips)} IPs - {', '.join(subnet_ips[:5])}")

    # Pattern analysis
    if len(subnets) == 1:
        print(f"\n  [!] All IPs in same /24 - possible dedicated hosting")
    elif len(subnets) > len(ips) * 0.8:
        print(f"\n  [!] IPs spread across many subnets - may use bulletproof hosting")

def build_infrastructure_map(domain, related_ips=None, related_domains=None):
    """Build an infrastructure map of the threat actor"""

    print(f"\n{'='*60}")
    print(f"INFRASTRUCTURE MAP: {domain}")
    print(f"{'='*60}")

    infrastructure = {
        'primary_domain': domain,
        'subdomains': [],
        'related_domains': related_domains or [],
        'ip_addresses': related_ips or [],
        'certificates': []
    }

    # Get certificate transparency data
    subdomains, certs = query_crtsh(domain)
    infrastructure['subdomains'] = list(subdomains)
    infrastructure['certificates'] = certs

    # DNS analysis
    query_dns_dumpster(domain)

    # IP analysis
    if related_ips:
        analyze_ip_ranges(related_ips)

    # Save infrastructure map
    output_file = f"infrastructure_{domain.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(infrastructure, f, indent=2, default=str)

    print(f"\n[✓] Infrastructure map saved to: {output_file}")

    return infrastructure

if __name__ == "__main__":
    # Demo with example infrastructure
    # In practice, use actual IOCs from threat intelligence

    print("=== Passive DNS & Infrastructure OSINT Demo ===\n")

    # Example: Investigate the "update-secure-cdn.com" domain from our scenario
    # (Note: This is a fictional domain used for educational purposes)
    domain = "update-secure-cdn.com"
    related_ips = ["192.0.2.15", "192.0.2.22", "198.51.100.15"]
    related_domains = ["auth-verify-portal.net", "cdn-update-service.com"]

    infra = build_infrastructure_map(domain, related_ips, related_domains)

    # Infrastructure pattern analysis
    print("\n[*] PATTERN ANALYSIS")
    print("="*60)
    print(f"Primary domain: {domain}")
    print(f"Naming pattern: 'update/cdn/secure/auth' keywords suggest impersonation")
    print(f"Registration: Check for privacy protection services")
    print(f"Hosting: Check if IPs belong to bulletproof hosting providers")
    print(f"\nHunting pivot:")
    print(f"  1. Search for other domains resolving to same IPs")
    print(f"  2. Look for certificate subjects with similar patterns")
    print(f"  3. Search for domains registered by same registrant")
    print(f"  4. Check WHOIS history for infrastructure patterns")
```

---

## Step 4: Build the Threat Actor Profile

Create `profiles/fin-storm-profile.md`:

```markdown
# Threat Actor Profile: FIN-STORM
**Classification:** TLP:AMBER
**Confidence:** Medium
**Date Created:** 2024-03-15
**Last Updated:** 2024-03-15
**Profile Author:** SecureBank Threat Intelligence Team

---

## 1. Identity and Attribution

| Field | Value |
|-------|-------|
| Actor Name | FIN-STORM |
| Aliases | STORM-0231 (Microsoft), GOLD-TEMPEST (Secureworks) |
| Attribution Confidence | Medium |
| Suspected Sponsorship | Financially Motivated Criminal Organization |
| Geographic Origin | Eastern Europe (suspected, low confidence) |

**Attribution Basis:**
- TTPs overlap significantly with FIN7/Carbanak (carbanak group tools observed)
- Infrastructure patterns consistent with Eastern European cybercriminal groups
- Operational times suggest UTC+2 to UTC+3 timezone
- Use of modified Cobalt Strike and custom PowerShell tools

**Caveats:**
- Attribution to specific nation or group cannot be confirmed
- Possible false flag operations
- Tool sharing with other groups cannot be ruled out

---

## 2. Motivation and Objectives

**Primary Motivation:** Financial gain
**Objectives:**
- Business Email Compromise (BEC)
- Financial fraud via system access to banking platforms
- Ransomware deployment as secondary objective
- Data theft for sale

---

## 3. Targeting

**Sectors:**
- Financial Services (primary)
- Retail and Hospitality (secondary)
- Healthcare (occasional)

**Geography:**
- Western Europe (UK, Germany, France, Netherlands)
- North America (secondary targeting)

**Organization Size:** Mid to large enterprises (>500 employees)

**Victim Selection Criteria:**
- Organizations with significant financial assets or transactions
- Companies with known cybersecurity weaknesses
- Organizations undergoing mergers/acquisitions (increased complexity)

---

## 4. Tactics, Techniques, and Procedures (TTPs)

### Kill Chain Mapping

| Phase | Technique | ATT&CK ID | Confidence |
|-------|-----------|-----------|------------|
| Initial Access | Spear-phishing with macro documents | T1566.001 | High |
| Execution | PowerShell with encoded commands | T1059.001 | High |
| Defense Evasion | AMSI bypass | T1562.001 | Medium |
| Defense Evasion | PowerShell execution policy bypass | T1059.001 | High |
| Credential Access | LSASS memory dumping (Mimikatz) | T1003.001 | High |
| Lateral Movement | WMI remote execution | T1047 | High |
| Lateral Movement | PsExec alternative (Impacket) | T1021.002 | Medium |
| Collection | Data staging in system directories | T1074.001 | Medium |
| Exfiltration | HTTPS exfiltration | T1048.002 | High |
| C2 | HTTPS-based C2 (Cobalt Strike) | T1071.001 | High |

### Preferred Tools

| Tool | Type | Purpose |
|------|------|---------|
| Cobalt Strike (modified) | Commercial RAT | C2, lateral movement |
| Mimikatz variants | Credential dumping tool | Credential harvesting |
| Impacket | Open-source suite | SMB lateral movement |
| Custom PowerShell loaders | Custom malware | Staging, persistence |
| Macro-enabled Office documents | Delivery vehicle | Initial access |

---

## 5. Infrastructure

### Observed Patterns

**Domain Registration:**
- Common registrars: NameCheap, GoDaddy (privacy protection often used)
- Domain age: Usually <30 days when used
- Naming conventions: impersonates CDN providers, authentication services, security updates
- Common keywords: update, secure, cdn, auth, verify, portal, login

**Hosting:**
- Primarily uses bulletproof hosting providers
- Frequently observed ASNs: [See IOC feed for current details]
- Geographic location of infrastructure: Netherlands, Romania (primarily)
- Use of cloud services (AWS, Azure) for some C2 to blend in

**Certificate Patterns:**
- Self-signed certificates common for internal tooling
- Let's Encrypt certificates for phishing pages
- Certificates issued within 24h of domain registration

### Current IOCs

> **Note:** IOCs should be consumed from live threat feeds; hardcoded IOCs age quickly.
> Current IOCs maintained in MISP Event ID: [Link to MISP]

---

## 6. Countermeasures

### Detection

**High-fidelity detections (low FP):**
- Office applications spawning PowerShell (Sigma rule: office_spawns_powershell)
- LSASS access by non-security processes (Sigma rule: lsass_memory_access)
- WMI spawning command shells (Sigma rule: wmi_remote_execution)
- Encoded PowerShell from unusual parents (Sigma rule: ps_encoded_command)

**Network detections:**
- Newly registered domains (<30 days) in web traffic
- C2 beaconing patterns (regular intervals, HTTPS to residential/cheap hosting)
- Large HTTPS transfers to non-business destinations

### Prevention

**Priority 1 (Immediate):**
- Block macro execution in Office applications (Group Policy)
- Enable Protected View and Attack Surface Reduction rules
- Implement application whitelisting on sensitive systems

**Priority 2 (Short-term):**
- Disable WMI remote execution where not required
- Implement LSASS protection (RunAsPPL registry key)
- Deploy Credential Guard on Windows 10/11 systems

**Priority 3 (Medium-term):**
- Enhanced email security (sandbox detonation of attachments)
- Network traffic inspection with SSL inspection where legally permitted
- User security awareness training focused on phishing

---

## 7. Intelligence Sources

| Source | Reliability | Notes |
|--------|-------------|-------|
| Internal IR findings | High | Confirmed direct observation |
| FS-ISAC Community Reports | High | Peer-validated intel |
| Vendor Reports (CrowdStrike, Mandiant) | Medium-High | Well-researched |
| Open-source threat feeds | Medium | Variable quality |
| Social media / researcher tweets | Low-Medium | Good for timeliness |

---

## 8. Profile Confidence Assessment

| Area | Confidence | Basis |
|------|------------|-------|
| Motivation | High | Consistent financial fraud pattern |
| Target sectors | High | Multiple confirmed victims |
| TTPs | High | Multiple incident observations |
| Tools | Medium | Limited sample analysis |
| Attribution | Low-Medium | No definitive technical evidence |
| Infrastructure patterns | Medium | Pattern analysis, limited dataset |

---

## 9. Related Actors

- **FIN7/Carbanak**: Significant TTP overlap; may be same group, spinoff, or borrowing techniques
- **Lazarus Group**: Occasional tool overlap but different operational pattern
- **Unnamed criminal group**: Observed purchasing FIN-STORM tools on underground forums

---

*Profile maintained by: SecureBank Threat Intelligence Team*
*Review cycle: Monthly or upon new significant intelligence*
```

---

## Summary

In this demo you:

1. Used the MITRE ATT&CK API to research threat actor TTPs
1. Queried VirusTotal for domain, IP, and hash intelligence
1. Used Certificate Transparency logs to map threat actor infrastructure
1. Built a structured threat actor profile using the Diamond Model framework

**OSINT tooling summary:**

* **MITRE ATT&CK**: Structured TTP database
* **VirusTotal**: Multi-engine reputation + file analysis
* **crt.sh**: Certificate transparency for subdomain discovery
* **URLScan**: Website analysis and screenshot
* **SecurityTrails**: Passive DNS and subdomain history
* **Shodan/Censys**: Internet asset discovery (use responsibly)

**Key principles:**

* Always work with defanged indicators (replace `.` with `[.]`)
* Document your sources and confidence levels
* OSINT is intelligence gathering, not hacking—stay within legal bounds
* Fresh IOCs are valuable; stale IOCs generate false positives
