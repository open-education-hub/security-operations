#!/usr/bin/env python3
"""
MISP Populator — Demo 04
Loads sample threat intelligence events into a local MISP instance.
"""
import os
import sys
import time

MISP_URL = os.getenv("MISP_URL", "http://localhost")
MISP_KEY = os.getenv("MISP_KEY", "YOUR_MISP_API_KEY")

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
except ImportError:
    print("[!] pymisp not installed. Run: pip install pymisp")
    sys.exit(1)

SAMPLE_EVENTS = [
    {
        "info":         "Emotet Campaign — March 2024 — Distribution Network",
        "threat_level": 1,  # High
        "analysis":     2,  # Completed
        "distribution": 3,  # All communities
        "tags":         ["tlp:green", "misp-galaxy:threat-actor=\"Emotet\""],
        "attributes": [
            {"type": "ip-dst",  "value": "185.220.101.5",   "comment": "Emotet C2 Server"},
            {"type": "ip-dst",  "value": "203.0.113.50",     "comment": "Emotet distribution host"},
            {"type": "domain",  "value": "update-services.ru", "comment": "Emotet C2 domain"},
            {"type": "sha256",  "value": "b2d58de3f5a3e9f7c1a8d4b9e6c2f0a1234567890abcdef",
             "comment": "Emotet dropper — Invoice_March2024.docm payload"},
            {"type": "filename","value": "Invoice_March2024.docm", "comment": "Phishing attachment name"},
            {"type": "filename","value": "svchost32.exe", "comment": "Emotet persistence binary"},
        ]
    },
    {
        "info":         "Cobalt Strike Beacon — Lateral Movement Campaign",
        "threat_level": 1,
        "analysis":     2,
        "distribution": 3,
        "tags":         ["tlp:amber", "misp-galaxy:tool=\"Cobalt Strike\"",
                         "mitre-attack:lateral-movement:T1021.002"],
        "attributes": [
            {"type": "ip-dst",  "value": "198.51.100.10", "comment": "Cobalt Strike team server"},
            {"type": "domain",  "value": "secure-login-portal.net", "comment": "CS C2 redirector"},
            {"type": "sha256",  "value": "aabbccddeeff0011223344556677889900aabbccddeeff0011223344556677889900",
             "comment": "Cobalt Strike stager beacon"},
            {"type": "user-agent", "value": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/7.0)",
             "comment": "Default Cobalt Strike malleable C2 UA"},
        ]
    },
    {
        "info":         "Ransomware IOCs — LockBit 3.0 Infrastructure",
        "threat_level": 1,
        "analysis":     2,
        "distribution": 3,
        "tags":         ["tlp:green", "misp-galaxy:ransomware=\"LockBit\"",
                         "mitre-attack:impact:T1486"],
        "attributes": [
            {"type": "ip-dst",  "value": "192.0.2.99", "comment": "LockBit leak site (TOR exit)"},
            {"type": "domain",  "value": "lockbit3753qzxnj.onion.ly", "comment": "LockBit 3.0 public leak site"},
            {"type": "filename","value": "README-LockBit.txt", "comment": "Ransom note filename"},
            {"type": "sha256",  "value": "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
             "comment": "LockBit 3.0 encryptor sample"},
            {"type": "mutex",   "value": "Global\\{BEF590BE-11A5-4C0F-B58B-9A6A6F42EF12}",
             "comment": "LockBit mutex for anti-double execution"},
        ]
    },
]


def wait_for_misp(max_retries=30):
    """Wait for MISP to be fully operational."""
    import requests
    for i in range(max_retries):
        try:
            r = requests.get(f"{MISP_URL}/users/login", timeout=10, verify=False)
            if r.status_code == 200:
                print(f"[+] MISP is up (attempt {i+1})")
                return True
        except Exception:
            pass
        print(f"[.] Waiting for MISP... ({i+1}/{max_retries})")
        time.sleep(10)
    return False


def get_api_key():
    """Retrieve the admin API key from MISP."""
    import requests
    import warnings
    warnings.filterwarnings("ignore")

    # Try to authenticate and get auth key
    session = requests.Session()
    session.verify = False

    # Login
    r = session.post(f"{MISP_URL}/users/login", data={
        "data[User][email]":    "admin@admin.test",
        "data[User][password]": "admin",
    }, timeout=30)

    if r.status_code != 200 or "invalid" in r.text.lower():
        print("[!] Could not log into MISP with default credentials")
        return None

    # Get auth key via API
    r2 = session.get(f"{MISP_URL}/users/view/me.json", timeout=10)
    if r2.status_code == 200:
        data = r2.json()
        return data.get("User", {}).get("authkey")
    return None


def populate(misp_key=None):
    if not wait_for_misp():
        print("[!] MISP not available. Exiting.")
        sys.exit(1)

    key = misp_key or MISP_KEY
    if key == "YOUR_MISP_API_KEY":
        print("[~] API key not set, attempting to retrieve from MISP...")
        key = get_api_key()
        if not key:
            print("[!] Could not get API key. Populate manually via MISP web UI.")
            return

    try:
        misp = PyMISP(MISP_URL, key, False)
        print(f"[+] Connected to MISP at {MISP_URL}")
    except Exception as e:
        print(f"[!] Failed to connect to MISP: {e}")
        return

    for evt_data in SAMPLE_EVENTS:
        print(f"\n[*] Creating event: {evt_data['info']}")

        event = MISPEvent()
        event.info            = evt_data["info"]
        event.threat_level_id = evt_data["threat_level"]
        event.analysis        = evt_data["analysis"]
        event.distribution    = evt_data["distribution"]

        for attr in evt_data["attributes"]:
            a = event.add_attribute(attr["type"], attr["value"])
            a.comment = attr.get("comment", "")

        result = misp.add_event(event, pythonify=True)

        if hasattr(result, 'uuid'):
            print(f"[+] Created event UUID: {result.uuid}")
            # Add tags
            for tag in evt_data.get("tags", []):
                misp.tag(result, tag)
                print(f"    Tagged: {tag}")
        else:
            print(f"[!] Event creation result: {result}")

    print(f"\n[+] MISP populated with {len(SAMPLE_EVENTS)} threat intelligence events!")


if __name__ == "__main__":
    populate()
