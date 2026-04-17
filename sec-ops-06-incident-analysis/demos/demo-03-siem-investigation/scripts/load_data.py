#!/usr/bin/env python3
"""
Demo 03 — Data Loader
Generates realistic log data and loads it into Splunk via HEC.
"""

import json
import time
import os
import requests
from datetime import datetime, timezone, timedelta

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "splunk")
SPLUNK_PORT = os.environ.get("SPLUNK_PORT", "8088")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "demo03-hec-token")
HEC_URL = f"http://{SPLUNK_HOST}:{SPLUNK_PORT}/services/collector/event"

# Base timestamp: 2024-11-15 09:40:00 UTC
BASE_TS = 1731660000

def ts(offset_seconds):
    """Return epoch timestamp with offset from base."""
    return BASE_TS + offset_seconds

def send_event(index, sourcetype, host, timestamp, event_data):
    payload = {
        "time": timestamp,
        "host": host,
        "index": index,
        "sourcetype": sourcetype,
        "event": event_data
    }
    try:
        r = requests.post(
            HEC_URL,
            json=payload,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            timeout=10
        )
        return r.status_code == 200
    except Exception as e:
        print(f"Failed to send event: {e}")
        return False


def generate_email_logs():
    """Generate email server logs for the phishing campaign."""
    events = [
        {
            "index": "email", "sourcetype": "mail:smtp", "host": "MAIL01",
            "ts": ts(130),
            "event": {
                "to_address": "jsmith@acme.local",
                "from_address": "accounting@acme-invoices.net",
                "subject": "URGENT: Invoice #INV-2024-8847 requires your approval",
                "sender_ip": "185.220.101.47",
                "attachment_name": "Invoice_INV-2024-8847.docm",
                "attachment_size": 67234,
                "spf_result": "FAIL",
                "dkim_result": "FAIL",
                "dmarc_result": "FAIL",
                "dmarc_policy": "none",
                "action": "DELIVERED",
                "message_id": "<a7b2c3d4e5f6@acme-invoices.net>"
            }
        },
        {
            "index": "email", "sourcetype": "mail:smtp", "host": "MAIL01",
            "ts": ts(1280),
            "event": {
                "to_address": "mwilson@acme.local",
                "from_address": "accounting@acme-invoices.net",
                "subject": "URGENT: Invoice #INV-2024-8847 requires your approval",
                "sender_ip": "185.220.101.47",
                "attachment_name": "Invoice_INV-2024-8847.docm",
                "attachment_size": 67234,
                "spf_result": "FAIL",
                "dkim_result": "FAIL",
                "dmarc_result": "FAIL",
                "dmarc_policy": "none",
                "action": "DELIVERED",
                "message_id": "<a7b2c3d4e5f7@acme-invoices.net>"
            }
        }
    ]
    return events


def generate_proxy_logs():
    """Generate web proxy logs for the phishing click and C2."""
    return [
        {
            "index": "proxy", "sourcetype": "proxy:squid", "host": "PROXY01",
            "ts": ts(262),
            "event": {
                "user": "jsmith",
                "src_ip": "192.168.10.42",
                "dest_ip": "185.220.101.47",
                "dest_port": 80,
                "uri": "http://185.220.101.47/track?id=a7b2c3",
                "http_method": "GET",
                "status_code": 200,
                "bytes_out": 342,
                "bytes_in": 4521,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        }
    ]


def generate_sysmon_logs():
    """Generate Sysmon event logs for the compromised host."""
    return [
        # File creation — malicious docm
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(268),
            "event": {
                "EventID": 11,
                "Computer": "WS-JSMITH",
                "User": "ACME\\jsmith",
                "TargetFilename": "C:\\Users\\jsmith\\Downloads\\Invoice_INV-2024-8847.docm",
                "MD5": "3b4c9e2f1a8d7e6f5b4c3d2e1f0a9b8c",
                "SHA256": "a3f9b2c1e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2",
                "FileSize": 67234
            }
        },
        # Process creation — macro execution chain
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(275),
            "event": {
                "EventID": 1,
                "Computer": "WS-JSMITH",
                "User": "ACME\\jsmith",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0=",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ParentCommandLine": "WINWORD.EXE /n Invoice_INV-2024-8847.docm",
                "MD5": "ad7b9c14083b52bc532fba5948342b98",
                "ProcessId": 4521,
                "ParentProcessId": 3812
            }
        },
        # PowerShell execution
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(275),
            "event": {
                "EventID": 1,
                "Computer": "WS-JSMITH",
                "User": "ACME\\jsmith",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0A",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABj...",
                "MD5": "eb84f6a3fa7a2c3d4b5e6f7a8b9c0d1e",
                "ProcessId": 4888,
                "ParentProcessId": 4521
            }
        },
        # Network connection — C2
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(302),
            "event": {
                "EventID": 3,
                "Computer": "WS-JSMITH",
                "User": "ACME\\jsmith",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "DestinationIp": "185.220.101.47",
                "DestinationPort": 4444,
                "Protocol": "tcp",
                "Initiated": True,
                "SourceIp": "192.168.10.42",
                "SourcePort": 49821
            }
        },
        # Discovery commands
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(421),
            "event": {
                "EventID": 1, "Computer": "WS-JSMITH", "User": "ACME\\jsmith",
                "Image": "C:\\Windows\\System32\\net.exe",
                "CommandLine": "net user /domain",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 5102
            }
        },
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(434),
            "event": {
                "EventID": 1, "Computer": "WS-JSMITH", "User": "ACME\\jsmith",
                "Image": "C:\\Windows\\System32\\net.exe",
                "CommandLine": "net group \"Domain Admins\" /domain",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessId": 5234
            }
        },
        # LSASS memory access (Mimikatz)
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "WS-JSMITH", "ts": ts(1952),
            "event": {
                "EventID": 10,
                "Computer": "WS-JSMITH",
                "SourceImage": "C:\\Windows\\Temp\\svchost32.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll|C:\\Windows\\System32\\KERNELBASE.dll|UNKNOWN"
            }
        },
        # Large archive on file server
        {
            "index": "sysmon", "sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
            "host": "FILE-SRV01", "ts": ts(3840),
            "event": {
                "EventID": 11,
                "Computer": "FILE-SRV01",
                "User": "ACME\\administrator",
                "TargetFilename": "C:\\Users\\administrator\\Desktop\\data.zip",
                "MD5": "f1e2d3c4b5a69788c7d6e5f4a3b2c1d0",
                "FileSize": 4520304640
            }
        }
    ]


def generate_firewall_logs():
    """Generate firewall logs."""
    return [
        {
            "index": "firewall", "sourcetype": "firewall:paloalto", "host": "FW01",
            "ts": ts(302),
            "event": {
                "src_ip": "192.168.10.42", "src_port": 49821,
                "dest_ip": "185.220.101.47", "dest_port": 4444,
                "protocol": "tcp", "action": "allow",
                "bytes_out": 1024, "bytes_in": 2048,
                "application": "unknown"
            }
        },
        # Exfiltration
        {
            "index": "firewall", "sourcetype": "firewall:paloalto", "host": "FW01",
            "ts": ts(4020),
            "event": {
                "src_ip": "10.0.1.10", "src_port": 54123,
                "dest_ip": "142.250.80.100", "dest_port": 443,
                "protocol": "tcp", "action": "allow",
                "bytes_out": 4520304640, "bytes_in": 1024,
                "application": "ssl",
                "dest_hostname": "storage.googleapis.com"
            }
        }
    ]


def generate_winlogs():
    """Generate Windows Security Event logs for lateral movement."""
    return [
        # Lateral movement: WS-JSMITH -> DC01
        {
            "index": "winlogs", "sourcetype": "xmlwineventlog:security",
            "host": "DC01", "ts": ts(2310),
            "event": {
                "EventCode": 4624,
                "ComputerName": "DC01",
                "Account_Name": "administrator",
                "Account_Domain": "ACME",
                "Logon_Type": 3,
                "Source_Network_Address": "192.168.10.42",
                "Workstation_Name": "WS-JSMITH",
                "Logon_Process": "NtLmSsp"
            }
        },
        # Lateral movement: WS-JSMITH -> FILE-SRV01
        {
            "index": "winlogs", "sourcetype": "xmlwineventlog:security",
            "host": "FILE-SRV01", "ts": ts(2480),
            "event": {
                "EventCode": 4624,
                "ComputerName": "FILE-SRV01",
                "Account_Name": "administrator",
                "Account_Domain": "ACME",
                "Logon_Type": 3,
                "Source_Network_Address": "192.168.10.42",
                "Workstation_Name": "WS-JSMITH",
                "Logon_Process": "NtLmSsp"
            }
        }
    ]


def wait_for_splunk():
    print("Waiting for Splunk HEC to be ready...")
    for _ in range(30):
        try:
            r = requests.get(f"http://{SPLUNK_HOST}:{SPLUNK_PORT}/services/collector/health",
                             timeout=5)
            if r.status_code == 200:
                print("Splunk HEC is ready.")
                return True
        except Exception:
            pass
        time.sleep(10)
    print("WARNING: Splunk HEC did not respond — check container status.")
    return False


def main():
    if not wait_for_splunk():
        print("Proceeding anyway — data will be written to files for manual import.")

    all_events = (
        generate_email_logs() +
        generate_proxy_logs() +
        generate_sysmon_logs() +
        generate_firewall_logs() +
        generate_winlogs()
    )

    print(f"Loading {len(all_events)} events into Splunk...")
    success = 0
    for evt in all_events:
        if send_event(evt["index"], evt["sourcetype"], evt["host"], evt["ts"], evt["event"]):
            success += 1

    print(f"Loaded {success}/{len(all_events)} events successfully.")

    # Also write to files for reference
    os.makedirs("/data/reference", exist_ok=True)
    with open("/data/reference/all_events.json", "w") as f:
        json.dump(all_events, f, indent=2, default=str)
    print("Reference data written to /data/reference/all_events.json")


if __name__ == "__main__":
    main()
