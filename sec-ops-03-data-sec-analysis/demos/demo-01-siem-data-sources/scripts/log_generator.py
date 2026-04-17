#!/usr/bin/env python3
"""
Log Generator for Demo 01
Simulates Windows authentication events and Sysmon-style endpoint events.
Writes JSON log lines to files that the Splunk forwarder monitors.
"""
import json
import random
import time
import os
from datetime import datetime, timezone
from faker import Faker

fake = Faker()

AUTH_LOG = "/var/log/demo/auth_events.log"
SYSMON_LOG = "/var/log/demo/sysmon.log"

# Ensure log directory exists
os.makedirs("/var/log/demo", exist_ok=True)

USERS = ["jsmith", "mjones", "alee", "bwilson", "cgarcia", "admin", "svc_backup"]
HOSTS = ["WORKSTATION-042", "WORKSTATION-017", "SERVER-DC01", "LAPTOP-HR-01", "SERVER-WEB01"]
INTERNAL_IPS = [f"192.168.{s}.{h}" for s in [1, 2, 10] for h in range(2, 50)]
ATTACKER_IPS = ["198.51.100.10", "203.0.113.50", "185.220.101.5"]

LEGIT_PROCESSES = [
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    ("C:\\Program Files\\Chrome\\chrome.exe", "chrome.exe", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe", "C:\\Windows\\System32\\services.exe"),
]

MALICIOUS_PROCESSES = [
    ("C:\\Windows\\Temp\\update.exe", "update.exe", "C:\\Program Files\\Office\\WINWORD.EXE",
     "C:\\Windows\\Temp\\update.exe -encode aHR0cHM6Ly9tYWxpY2lvdXMuY29t"),
    ("C:\\Windows\\System32\\powershell.exe", "powershell.exe", "C:\\Program Files\\Office\\EXCEL.EXE",
     "powershell.exe -nop -w hidden -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdA=="),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe", "C:\\Windows\\System32\\wscript.exe",
     "cmd.exe /c whoami && net user"),
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_event(filepath, event):
    with open(filepath, "a") as f:
        f.write(json.dumps(event) + "\n")


def gen_successful_logon():
    user = random.choice(USERS[:-2])  # skip service accounts
    src_ip = random.choice(INTERNAL_IPS)
    event = {
        "timestamp": now_iso(),
        "EventID": 4624,
        "event_type": "successful_login",
        "Computer": random.choice(HOSTS),
        "username": user,
        "src_ip": src_ip,
        "logon_type": random.choice([2, 3, 10]),  # interactive, network, remote
        "logon_type_name": random.choice(["Interactive", "Network", "RemoteInteractive"]),
        "domain": "CORP",
    }
    write_event(AUTH_LOG, event)


def gen_failed_logon(is_brute=False):
    user = random.choice(USERS)
    src_ip = random.choice(ATTACKER_IPS if is_brute else INTERNAL_IPS)
    reasons = ["Bad password", "Account disabled", "Account locked", "Clock skew too great"]
    event = {
        "timestamp": now_iso(),
        "EventID": 4625,
        "event_type": "failed_login",
        "Computer": random.choice(HOSTS),
        "username": user,
        "src_ip": src_ip,
        "failure_reason": random.choice(reasons),
        "logon_type": 3,
        "domain": "CORP",
    }
    write_event(AUTH_LOG, event)


def gen_process_creation(is_malicious=False):
    host = random.choice(HOSTS)
    user = random.choice(USERS[:5])
    if is_malicious:
        img, name, parent, cmdline = random.choice(MALICIOUS_PROCESSES)
    else:
        img, name, parent = random.choice(LEGIT_PROCESSES)
        cmdline = img

    event = {
        "timestamp": now_iso(),
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "process_create",
        "Computer": host,
        "User": f"CORP\\{user}",
        "Image": img,
        "OriginalFileName": name,
        "CommandLine": cmdline,
        "ParentImage": parent,
        "ProcessId": random.randint(1000, 9999),
        "ParentProcessId": random.randint(1000, 9999),
        "Hashes": f"SHA256={fake.sha256()}",
        "is_malicious_sim": is_malicious,
    }
    write_event(SYSMON_LOG, event)


def gen_network_connection(is_suspicious=False):
    host = random.choice(HOSTS)
    user = random.choice(USERS[:5])
    if is_suspicious:
        dst_ip = random.choice(ATTACKER_IPS)
        dst_port = 443
        process = "C:\\Windows\\Temp\\update.exe"
    else:
        dst_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_port = random.choice([80, 443, 8080, 53])
        process = "C:\\Program Files\\Chrome\\chrome.exe"

    event = {
        "timestamp": now_iso(),
        "EventID": 3,
        "SourceName": "Microsoft-Windows-Sysmon",
        "event_type": "network_connection",
        "Computer": host,
        "User": f"CORP\\{user}",
        "Image": process,
        "SourceIp": random.choice(INTERNAL_IPS[:10]),
        "SourcePort": random.randint(49152, 65535),
        "DestinationIp": dst_ip,
        "DestinationPort": dst_port,
        "Protocol": "tcp",
    }
    write_event(SYSMON_LOG, event)


if __name__ == "__main__":
    print("Log generator started — writing to", AUTH_LOG, "and", SYSMON_LOG)
    cycle = 0

    while True:
        cycle += 1

        # Normal activity: lots of legit logons and processes
        for _ in range(random.randint(3, 6)):
            gen_successful_logon()
        for _ in range(random.randint(2, 4)):
            gen_process_creation(is_malicious=False)
        for _ in range(random.randint(3, 5)):
            gen_network_connection(is_suspicious=False)

        # Occasional failures
        if random.random() < 0.3:
            gen_failed_logon()

        # Simulated attack every ~10 cycles
        if cycle % 10 == 0:
            print(f"[!] Simulating attack activity at cycle {cycle}")
            # Brute force
            for _ in range(15):
                gen_failed_logon(is_brute=True)
                time.sleep(0.05)
            # Malware execution (Office spawns PowerShell)
            gen_process_creation(is_malicious=True)
            # C2 connection
            gen_network_connection(is_suspicious=True)

        time.sleep(random.uniform(3, 8))
