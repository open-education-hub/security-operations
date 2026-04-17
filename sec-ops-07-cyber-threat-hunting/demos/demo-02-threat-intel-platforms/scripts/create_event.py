#!/usr/bin/env python3
"""
MISP Event Creation Demo
Creates a FIN-STORM campaign event with multiple attributes and objects.

Usage:
    export MISP_URL="https://localhost"
    export MISP_KEY="your-api-key-here"
    python3 create_event.py

Prerequisites:
    pip install pymisp
"""

import os
import sys
from pymisp import PyMISP, MISPEvent, MISPObject

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------
MISP_URL = os.environ.get("MISP_URL", "https://localhost")
MISP_KEY = os.environ.get("MISP_KEY", "your-api-key")
VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Event creation
# ---------------------------------------------------------------------------

def create_finstorm_event(misp: PyMISP) -> str:
    """Create a FIN-STORM phishing campaign event with IOCs and objects."""

    # --- Base event -------------------------------------------------------
    event = MISPEvent()
    event.distribution = 0       # Your organisation only
    event.threat_level_id = 1    # High
    event.analysis = 1           # Ongoing
    event.info = "FIN-STORM Phishing Campaign - Financial Sector - March 2024"

    # --- Tags -------------------------------------------------------------
    event.add_tag("tlp:amber")
    event.add_tag("mitre-attack:execution:T1059.001")
    event.add_tag("mitre-attack:credential-access:T1003.001")
    event.add_tag("mitre-attack:lateral-movement:T1047")

    # Submit the base event first so we get an ID
    result = misp.add_event(event)
    event_id = result["Event"]["id"]
    print(f"[+] Created event ID: {event_id}")

    # --- Network and file indicators -------------------------------------
    indicators = [
        {
            "type": "ip-dst",
            "value": "192.0.2.15",
            "comment": "FIN-STORM C2 server #1",
            "to_ids": True,
        },
        {
            "type": "ip-dst",
            "value": "198.51.100.22",
            "comment": "FIN-STORM C2 server #2",
            "to_ids": True,
        },
        {
            "type": "domain",
            "value": "update-secure-cdn.com",
            "comment": "FIN-STORM C2 domain",
            "to_ids": True,
        },
        {
            "type": "domain",
            "value": "auth-verify-portal.net",
            "comment": "FIN-STORM phishing domain",
            "to_ids": True,
        },
        {
            "type": "url",
            "value": "https://auth-verify-portal.net/payload.ps1",
            "comment": "PowerShell loader delivery URL",
            "to_ids": True,
        },
        {
            "type": "sha256",
            "value": "a3f5c2e1d9b47f83a291e4c5d678901234567890123456789012345678901234",
            "comment": "PowerShell loader dropper hash",
            "to_ids": True,
        },
        {
            "type": "sha256",
            "value": "7c89d3a2f1e47b23c85" + "2" * 45,
            "comment": "Macro dropper hash",
            "to_ids": True,
        },
        {
            "type": "yara",
            "value": (
                'rule FIN_STORM_PS_Loader {\n'
                '    meta:\n'
                '        author = "SecureBank Threat Intel"\n'
                '        description = "FIN-STORM PowerShell loader"\n'
                '        tlp = "AMBER"\n'
                '    strings:\n'
                '        $s1 = "update-secure-cdn.com" ascii wide\n'
                '        $s2 = "auth-verify-portal.net" ascii wide\n'
                '        $s3 = "-EncodedCommand" ascii\n'
                '        $b1 = { 4D 5A 90 00 }\n'
                '    condition:\n'
                '        uint16(0) == 0x5A4D and\n'
                '        ($s1 or $s2) and $s3\n'
                '}'
            ),
            "comment": "YARA rule for PS loader detection",
            "to_ids": True,
        },
    ]

    for ioc in indicators:
        misp.add_attribute(event_id, ioc)
        print(f"[+] Added {ioc['type']}: {str(ioc['value'])[:50]}...")

    # --- File object: weaponised Word document ---------------------------
    file_obj = MISPObject("file")
    file_obj.add_attribute("filename", value="invoice_march_2024.docm")
    file_obj.add_attribute(
        "sha256",
        value="7c89d3a2f1e47b23c85" + "2" * 45,
        to_ids=True,
    )
    file_obj.add_attribute("size-in-bytes", value="145920")
    file_obj.add_attribute(
        "mimetype",
        value="application/vnd.ms-word.document.macroenabled.12",
    )
    misp.add_object(event_id, file_obj)
    print("[+] Added file object: invoice_march_2024.docm")

    # --- Network-connection object: C2 beacon ---------------------------
    net_obj = MISPObject("network-connection")
    net_obj.add_attribute("ip-dst", value="192.0.2.15", to_ids=True)
    net_obj.add_attribute("dst-port", value="443")
    net_obj.add_attribute("hostname-dst", value="update-secure-cdn.com")
    net_obj.add_attribute("layer7-protocol", value="HTTPS")
    misp.add_object(event_id, net_obj)
    print("[+] Added network-connection object")

    print(f"\n[✓] Event {event_id} created successfully!")
    print(f"    View at: {MISP_URL}/events/view/{event_id}")
    return event_id


# ---------------------------------------------------------------------------
# IOC search
# ---------------------------------------------------------------------------

def search_for_indicators(misp: PyMISP) -> None:
    """Display a sample of recent IDS-enabled indicators from MISP."""

    print("\n--- Recent indicators (last 7 days) ---")
    results = misp.search(
        publish_timestamp="7d",
        type_attribute=["ip-dst", "domain", "url"],
        to_ids=True,
        pythonify=True,
    )
    print(f"Found {len(results)} events with recent IOCs")

    for event in results[:3]:
        print(f"\n  Event: {event.info}")
        print(f"  ID: {event.id}", end="  TLP: ")
        for tag in event.tags:
            if "tlp" in tag.name.lower():
                print(tag.name, end=" ")
        print()
        for attr in event.attributes[:5]:
            print(f"    [{attr.type}] {str(attr.value)[:60]}")


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def export_to_csv(misp: PyMISP, event_id: str) -> None:
    """Export IDS-enabled IOCs from a MISP event to CSV and STIX 2.1."""

    print(f"\n--- Exporting IOCs for event {event_id} ---")
    event = misp.get_event(event_id, pythonify=True)

    csv_path = "iocs_export.csv"
    with open(csv_path, "w") as f:
        f.write("type,value,comment,to_ids\n")
        for attr in event.attributes:
            if attr.to_ids:
                value = str(attr.value).replace(",", ";")
                comment = str(attr.comment).replace(",", ";")
                f.write(f"{attr.type},{value},{comment},{attr.to_ids}\n")
    print(f"[✓] Exported {csv_path}")

    # STIX 2.1 export
    try:
        stix_export = misp.get_stix(event_id, version="2.1")
        with open("iocs_export_stix.json", "w") as f:
            f.write(str(stix_export))
        print("[✓] Exported iocs_export_stix.json (STIX 2.1)")
    except Exception as exc:
        print(f"[!] STIX export failed: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if MISP_KEY == "your-api-key":
        print("[!] Set MISP_KEY environment variable before running.")
        print("    export MISP_KEY='your-actual-api-key'")
        sys.exit(1)

    print(f"[*] Connecting to MISP at {MISP_URL} ...")
    misp_conn = PyMISP(MISP_URL, MISP_KEY, ssl=VERIFY_SSL)
    print("[✓] Connected!")

    # 1. Create the demo event
    eid = create_finstorm_event(misp_conn)

    # 2. Show recent indicators
    search_for_indicators(misp_conn)

    # 3. Export the event
    export_to_csv(misp_conn, eid)
