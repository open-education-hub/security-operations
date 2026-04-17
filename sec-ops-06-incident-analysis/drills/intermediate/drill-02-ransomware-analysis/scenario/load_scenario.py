#!/usr/bin/env python3
"""
Drill 02 Intermediate — Ransomware Scenario Data Loader
Loads a complete ransomware incident into Elasticsearch for student investigation.

Scenario: RetailCo Ltd - 2024-11-23 (Saturday, 03:15 UTC)
VPN access:  01:02 UTC from external IP 185.234.219.44
C2 beacon:   02:18 UTC to 94.130.88.15
Ransomware:  03:15 UTC - mass file encryption begins
"""

import json
import time
import os
import requests

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")

# Base: 2024-11-23 00:00:00 UTC = 1732320000
DAY_START = 1732320000

def ts(h, m=0, s=0):
    return DAY_START + h * 3600 + m * 60 + s

def post(index, host, timestamp, event):
    try:
        r = requests.post(
            f"{ES_HOST}/{index}/_doc",
            json={"@timestamp": timestamp, "host": host, **event},
            auth=(ES_USER, ES_PASS),
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return r.status_code in (200, 201)
    except Exception as e:
        print(f"  Error indexing to {index}: {e}")
        return False

def wait_for_es():
    print("Waiting for Elasticsearch...", flush=True)
    for i in range(40):
        try:
            r = requests.get(f"{ES_HOST}/_cluster/health",
                             auth=(ES_USER, ES_PASS), timeout=5)
            if r.status_code == 200:
                print("Elasticsearch ready.", flush=True)
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


# =====================================================================
# SCENARIO DATA
# Timeline:
#   2024-11-22 (days prior): phishing email to WS-03 user
#   2024-11-23 01:02 UTC: VPN login from external IP
#   2024-11-23 01:05-02:18 UTC: lateral movement, priv escalation
#   2024-11-23 02:18 UTC: C2 beacon begins from FILE-SRV01
#   2024-11-23 02:20-03:10 UTC: data staging/exfiltration
#   2024-11-23 03:15 UTC: ransomware deployment begins
# =====================================================================

EVENTS = [
    # ── Pre-incident: phishing email (7 days before) ────────────────
    {
        "index": "email", "host": "MAIL01",
        "ts": DAY_START - 7 * 86400 + 9 * 3600 + 33 * 60,
        "event": {
            "sourcetype": "mail:smtp",
            "to_address": "mwilson@retailco.com",
            "from_address": "invoices@retail-suppliers-portal.net",
            "subject": "November Invoice - ACTION REQUIRED",
            "sender_ip": "185.234.219.44",
            "attachment_name": "Invoice_Nov2024.xlsm",
            "attachment_hash_sha256": "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4",
            "spf_result": "FAIL",
            "dkim_result": "FAIL",
            "action": "DELIVERED"
        }
    },
    # ── VPN authentication ───────────────────────────────────────────
    {
        "index": "vpn_logs", "host": "VPN01",
        "ts": ts(1, 2),
        "event": {
            "sourcetype": "vpn:cisco_anyconnect",
            "src_ip": "185.234.219.44",
            "username": "mwilson",
            "auth_result": "SUCCESS",
            "mfa_used": False,
            "vpn_client_version": "4.10.02086",
            "assigned_ip": "172.16.100.55"
        }
    },
    # ── Internal reconnaissance (via VPN) ────────────────────────────
    {
        "index": "sysmon", "host": "DC01",
        "ts": ts(1, 8, 30),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 1, "Computer": "DC01",
            "User": "RETAILCO\\mwilson",
            "Image": "C:\\Windows\\System32\\nltest.exe",
            "CommandLine": "nltest /domain_trusts /all_trusts",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
    },
    {
        "index": "sysmon", "host": "DC01",
        "ts": ts(1, 12),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 1, "Computer": "DC01",
            "User": "RETAILCO\\mwilson",
            "Image": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net group \"Domain Admins\" /domain",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
    },
    # ── Credential theft (Kerberoasting) ─────────────────────────────
    {
        "index": "winlogs", "host": "DC01",
        "ts": ts(1, 25),
        "event": {
            "sourcetype": "xmlwineventlog:security",
            "EventCode": 4769, "ComputerName": "DC01",
            "Account_Name": "mwilson@RETAILCO.LOCAL",
            "Service_Name": "svc_backup",
            "Ticket_Encryption_Type": "0x17",
            "Client_Address": "172.16.100.55"
        }
    },
    # ── Admin credential used for DC access ──────────────────────────
    {
        "index": "winlogs", "host": "DC01",
        "ts": ts(1, 45),
        "event": {
            "sourcetype": "xmlwineventlog:security",
            "EventCode": 4624, "ComputerName": "DC01",
            "Account_Name": "svc_backup", "Account_Domain": "RETAILCO",
            "Logon_Type": 3,
            "Source_Network_Address": "172.16.100.55",
        }
    },
    # ── Shadow copy deletion on DC ────────────────────────────────────
    {
        "index": "sysmon", "host": "DC01",
        "ts": ts(2, 10),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 1, "Computer": "DC01",
            "User": "RETAILCO\\svc_backup",
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
    },
    # ── Scheduled task on DC for ransomware deployment ───────────────
    {
        "index": "sysmon", "host": "DC01",
        "ts": ts(2, 12),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 1, "Computer": "DC01",
            "User": "RETAILCO\\svc_backup",
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks /create /tn \"WindowsUpdate\" /sc once /st 03:15 /tr \"C:\\ProgramData\\winsvc.exe\" /ru SYSTEM",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
    },
    # ── C2 beacon begins from FILE-SRV01 ─────────────────────────────
    *[{
        "index": "firewall", "host": "FW01",
        "ts": ts(2, 18) + i * 60,
        "event": {
            "sourcetype": "firewall:paloalto",
            "src_ip": "192.168.50.10", "src_port": 50000 + i,
            "dest_ip": "94.130.88.15", "dest_port": 443,
            "protocol": "tcp", "action": "allow",
            "bytes_out": 512, "bytes_in": 128,
            "application": "ssl", "session_duration": 30
        }
    } for i in range(57)],  # 57 beacons (1/min from 02:18 to 03:15)
    # ── Data staging: customer records ───────────────────────────────
    {
        "index": "sysmon", "host": "FILE-SRV01",
        "ts": ts(2, 22),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 1, "Computer": "FILE-SRV01",
            "User": "RETAILCO\\svc_backup",
            "Image": "C:\\Windows\\System32\\robocopy.exe",
            "CommandLine": "robocopy \\\\FILE-SRV01\\Customers C:\\ProgramData\\staging /E /R:0",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
    },
    # ── Exfiltration of staged data ───────────────────────────────────
    {
        "index": "firewall", "host": "FW01",
        "ts": ts(2, 45),
        "event": {
            "sourcetype": "firewall:paloalto",
            "src_ip": "192.168.50.10", "src_port": 54321,
            "dest_ip": "94.130.88.15", "dest_port": 443,
            "protocol": "tcp", "action": "allow",
            "bytes_out": 2684354560,  # ~2.5 GB
            "bytes_in": 65536,
            "application": "ssl", "session_duration": 1800
        }
    },
    # ── Ransomware execution: mass file encryption ────────────────────
    *[{
        "index": "sysmon", "host": f"WS-{i:02d}",
        "ts": ts(3, 15) + i * 10,
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 11, "Computer": f"WS-{i:02d}",
            "User": "SYSTEM",
            "Image": "C:\\ProgramData\\winsvc.exe",
            "TargetFilename": f"C:\\Users\\user{i:02d}\\Documents\\report_{i:04d}.docx.retailco_enc"
        }
    } for i in range(1, 21)],
    # ── Ransom note creation ──────────────────────────────────────────
    {
        "index": "sysmon", "host": "FILE-SRV01",
        "ts": ts(3, 16),
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 11, "Computer": "FILE-SRV01",
            "User": "SYSTEM",
            "Image": "C:\\ProgramData\\winsvc.exe",
            "TargetFilename": "C:\\Shares\\HOW_TO_RECOVER.html"
        }
    },
    # ── Mass file modification on FILE-SRV01 (50,000 files) ───────────
    *[{
        "index": "sysmon", "host": "FILE-SRV01",
        "ts": ts(3, 15) + i * 3,
        "event": {
            "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "EventID": 11, "Computer": "FILE-SRV01",
            "User": "SYSTEM",
            "Image": "C:\\ProgramData\\winsvc.exe",
            "TargetFilename": f"C:\\Shares\\Customers\\customer_{i:06d}.csv.retailco_enc"
        }
    } for i in range(0, 200, 1)],  # Sampled: 200 events represent 50k files
]


def main():
    if not wait_for_es():
        print("ERROR: Elasticsearch not available after 3 minutes.")
        return

    print(f"Loading {len(EVENTS)} scenario events...", flush=True)
    success = 0
    for i, evt in enumerate(EVENTS):
        if post(evt["index"], evt["host"], evt["ts"], evt["event"]):
            success += 1
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i+1}/{len(EVENTS)}", flush=True)

    print(f"\nLoaded {success}/{len(EVENTS)} events successfully.")
    print("\nScenario: RetailCo Ransomware Incident (2024-11-23)")
    print("Access Kibana at http://localhost:5602 (elastic/changeme)")
    print("\nKey facts (INSTRUCTOR ONLY):")
    print("  Initial access:  Phishing to mwilson 7 days prior")
    print("  VPN account:     mwilson (no MFA)")
    print("  Kerberoasted:    svc_backup account (weak password)")
    print("  C2 IP:           94.130.88.15")
    print("  Data exfil:      ~2.5 GB customer records before encryption")
    print("  Affected systems: WS-01 through WS-20, FILE-SRV01, BACKUP-SRV01, DC01")
    print("  POS terminals:   NOT encrypted (separate network segment)")

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
