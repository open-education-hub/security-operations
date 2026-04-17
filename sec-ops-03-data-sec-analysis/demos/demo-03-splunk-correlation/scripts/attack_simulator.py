#!/usr/bin/env python3
"""
Attack Simulator for Demo 03
Sends a realistic multi-step attack scenario to Splunk via HEC.
Simulates: Phishing → Macro Execution → PowerShell C2 → Persistence
"""
import json
import os
import requests
import time
from datetime import datetime, timezone, timedelta

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL",   "http://splunk:8088")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN",  "demo03-token")

HEC_ENDPOINT = f"{SPLUNK_HEC_URL}/services/collector/event"
HEADERS      = {
    "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
    "Content-Type":  "application/json",
}

# Attack scenario timeline — base time is now, steps offset forward
BASE_TIME = datetime.now(timezone.utc)

def ts(offset_seconds=0):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

def send_event(event_data, sourcetype="attack_sim", index="main"):
    payload = {
        "time":       (BASE_TIME + timedelta(seconds=event_data.get("_offset", 0))).timestamp(),
        "host":       event_data.get("host", "WORKSTATION-042"),
        "sourcetype": sourcetype,
        "index":      index,
        "event":      event_data,
    }
    try:
        resp = requests.post(HEC_ENDPOINT, headers=HEADERS, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"[+] Sent: {event_data.get('attack_step', 'event')} - {event_data.get('description', '')[:60]}")
        else:
            print(f"[!] HEC error {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        print(f"[!] Send failed: {e}")


# ─── Attack Scenario: Phishing → Macro → PowerShell → C2 → Persistence ───────

ATTACK_EVENTS = [
    # T+0: Phishing email received and attachment opened (simulated via proxy log)
    {
        "_offset": 0,
        "attack_step": "1_phishing_delivery",
        "description": "User opened phishing attachment via Outlook",
        "host": "WORKSTATION-042",
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "process_create",
        "User": "CORP\\jsmith",
        "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\jsmith\\Downloads\\Invoice_March2024.docm\"",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ProcessId": 4521,
        "ParentProcessId": 1024,
        "Hashes": "SHA256=44d88612fea8a8f36de82e1278abb02f3524ec74",
    },

    # T+12: Macro execution — Word spawns PowerShell
    {
        "_offset": 12,
        "attack_step": "2_macro_execution",
        "description": "WINWORD spawned PowerShell with encoded command (MITRE T1566.001 + T1059.001)",
        "host": "WORKSTATION-042",
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "process_create",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "ProcessId": 6782,
        "ParentProcessId": 4521,
        "Hashes": "SHA256=a84f0ea0b3f5e85a7da21e5d00c25a4f73a8b3e9",
    },

    # T+15: PowerShell makes network connection to C2
    {
        "_offset": 15,
        "attack_step": "3_c2_connection",
        "description": "PowerShell connected to C2 infrastructure over HTTPS (MITRE T1071.001)",
        "host": "WORKSTATION-042",
        "EventID": 3,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "network_connection",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessId": 6782,
        "SourceIp": "192.168.1.42",
        "SourcePort": 54321,
        "DestinationIp": "185.220.101.5",
        "DestinationPort": 443,
        "Protocol": "tcp",
        "DestinationHostname": "update-services.ru",
    },

    # T+18: DNS resolution of C2 domain
    {
        "_offset": 18,
        "attack_step": "3b_dns_c2",
        "description": "DNS query for known C2 domain (newly registered, high entropy)",
        "host": "WORKSTATION-042",
        "EventID": 22,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "dns_query",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "QueryName": "update-services.ru",
        "QueryResults": "185.220.101.5",
        "domain_age_days": 3,
        "domain_registrar": "reg.ru",
    },

    # T+45: Malware drops additional payload
    {
        "_offset": 45,
        "attack_step": "4_payload_drop",
        "description": "Malware created executable in APPDATA (MITRE T1547)",
        "host": "WORKSTATION-042",
        "EventID": 11,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "file_create",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "TargetFilename": "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\svchost32.exe",
        "CreationUtcTime": ts(45),
        "Hashes": "SHA256=b2d58de3f5a3e9f7c1a8d4b9e6c2f0a1234567890abcdef",
    },

    # T+60: Persistence via scheduled task
    {
        "_offset": 60,
        "attack_step": "5_persistence",
        "description": "Scheduled task created for malware persistence (MITRE T1053.005)",
        "host": "WORKSTATION-042",
        "EventID": 4698,
        "event_type": "scheduled_task_created",
        "User": "CORP\\jsmith",
        "SubjectUserName": "jsmith",
        "TaskName": "\\Microsoft\\Windows\\UpdateCheck",
        "TaskContent": "<Task><Actions><Exec><Command>C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\svchost32.exe</Command></Exec></Actions></Task>",
    },

    # T+70: Lateral movement attempt — net use to domain controller
    {
        "_offset": 70,
        "attack_step": "6_lateral_movement",
        "description": "Malware attempted SMB connection to Domain Controller (MITRE T1021.002)",
        "host": "WORKSTATION-042",
        "EventID": 3,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "network_connection",
        "User": "CORP\\jsmith",
        "Image": "C:\\Windows\\System32\\net.exe",
        "SourceIp": "192.168.1.42",
        "SourcePort": 55001,
        "DestinationIp": "192.168.1.10",
        "DestinationPort": 445,
        "Protocol": "tcp",
        "DestinationHostname": "SERVER-DC01",
    },

    # T+75: Multiple failed logons on DC
    {
        "_offset": 75,
        "attack_step": "6b_pass_the_hash_attempt",
        "description": "Failed Kerberos authentication from workstation to DC",
        "host": "SERVER-DC01",
        "EventID": 4768,
        "event_type": "kerberos_tgt_request",
        "TargetUserName": "Administrator",
        "IpAddress": "192.168.1.42",
        "Status": "0x18",  # Wrong password
        "TicketOptions": "0x40810010",
        "TicketEncryptionType": "0x17",  # RC4 — potential overpass-the-hash
    },
]


if __name__ == "__main__":
    print("[*] Attack simulator starting")
    print(f"[*] Sending to {HEC_ENDPOINT}")
    time.sleep(5)

    # Send all attack events
    for event in ATTACK_EVENTS:
        send_event(event)
        time.sleep(0.5)

    print("\n[+] All attack events sent!")
    print("[*] Running continuous background noise...")

    # Continue sending normal + noisy events in background
    import random
    USERS = ["jsmith", "mjones", "alee", "bwilson"]
    HOSTS = ["WORKSTATION-042", "WORKSTATION-017", "LAPTOP-HR-01"]

    cycle = 0
    while True:
        cycle += 1
        # Legit process events
        noise_event = {
            "_offset": 0,
            "attack_step": "background_noise",
            "description": "Normal workstation activity",
            "host": random.choice(HOSTS),
            "EventID": 1,
            "event_type": "process_create",
            "User": f"CORP\\{random.choice(USERS)}",
            "Image": random.choice([
                "C:\\Windows\\System32\\notepad.exe",
                "C:\\Program Files\\Chrome\\chrome.exe",
                "C:\\Windows\\explorer.exe",
            ]),
            "CommandLine": "normal_activity",
        }
        send_event(noise_event)
        time.sleep(random.uniform(3, 8))
