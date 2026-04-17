#!/usr/bin/env python3
"""
Load a complete P1 ransomware IR case into TheHive for demo purposes.
"""
import time, json, sys
import urllib.request
import urllib.error
import base64

THEHIVE_URL = "http://thehive:9000"
CREDS = base64.b64encode(b"admin:secret").decode()
HEADERS = {
    "Authorization": f"Basic {CREDS}",
    "Content-Type": "application/json"
}

def api(method, path, data=None):
    url = f"{THEHIVE_URL}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"API error {path}: {e}")
        return None

def wait_for_thehive():
    for i in range(30):
        try:
            urllib.request.urlopen(f"{THEHIVE_URL}/api/status")
            print("TheHive ready")
            return True
        except:
            print(f"Waiting for TheHive... ({i+1}/30)")
            time.sleep(10)
    return False

def main():
    if not wait_for_thehive():
        sys.exit(1)
    time.sleep(5)

    # Create P1 ransomware case
    case = api("POST", "/api/v1/case", {
        "title": "RANSOMWARE — CRITICAL — finance-dept — INC-2024-1147",
        "description": """## Incident Summary

**Initial Detection:** 2024-11-14 09:18 UTC
**Detected By:** CrowdStrike Falcon EDR behavioral alert
**Detection Rule:** RansomwareActivity_FileEncryptionMassive

3 Finance department workstations (finance-ws-040, 041, 042) show mass file
encryption activity. Ransom note 'HOW_TO_DECRYPT.txt' found in multiple directories.
Encryption extension: .LOCKBIT3

**Business Impact:** Finance department unable to access files. Month-end reporting
at risk. No known customer data affected at this time.
""",
        "severity": 3,
        "status": "InProgress",
        "startDate": 1731575880000,
        "tags": ["ransomware", "lockbit", "P1", "finance", "demo"],
        "tlp": 2,
        "pap": 2,
        "flag": True
    })

    if not case:
        print("Failed to create case")
        sys.exit(1)

    case_id = case.get("_id") or case.get("id", "")
    print(f"Case created: {case_id}")

    # Add observables
    observables = [
        {"dataType": "ip", "data": "185.220.101.5", "ioc": True,
         "tags": ["c2", "tor-exit"], "message": "C2 communication observed during initial beacon"},
        {"dataType": "hash", "data": "9f8e7d6c5b4a3928374655647382910a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e",
         "ioc": True, "tags": ["ransomware", "lockbit3"], "message": "LockBit 3.0 encryptor binary SHA256"},
        {"dataType": "hostname", "data": "finance-ws-040", "ioc": False,
         "tags": ["affected-host"], "message": "First affected host — isolated at 09:35 UTC"},
        {"dataType": "hostname", "data": "finance-ws-041", "ioc": False,
         "tags": ["affected-host"], "message": "Second affected host — isolated at 09:42 UTC"},
        {"dataType": "hostname", "data": "finance-ws-042", "ioc": False,
         "tags": ["affected-host"], "message": "Third affected host — isolated at 09:44 UTC"},
        {"dataType": "filename", "data": "HOW_TO_DECRYPT.txt", "ioc": True,
         "tags": ["ransom-note"], "message": "Ransom note dropped in all encrypted directories"},
    ]

    for obs in observables:
        result = api("POST", f"/api/v1/case/{case_id}/observable", obs)
        if result:
            print(f"  Observable added: {obs['dataType']}: {obs['data'][:40]}")

    print("\n✓ Demo scenario loaded successfully")
    print(f"  Access TheHive at http://localhost:9000")
    print(f"  Login: admin / secret")
    print(f"  Case: INC-2024-1147 (RANSOMWARE — CRITICAL)")

if __name__ == "__main__":
    main()
