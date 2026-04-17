#!/usr/bin/env python3
"""
Demo 01 — Incident Lifecycle Simulator
Generates realistic log data for the phishing incident scenario
and indexes it into Elasticsearch.
"""

import json
import time
import os
import requests
from datetime import datetime, timezone

ES_HOST = os.environ.get("ES_HOST", "http://logserver:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")

# === Simulated log data ===

SYSMON_LOGS = [
    {
        "EventID": 1,
        "TimeCreated": "2024-11-15T09:44:35Z",
        "Computer": "WS-JSMITH",
        "User": "ACME\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ParentCommandLine": "cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdA==",
        "GrandParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdA=="
    },
    {
        "EventID": 3,
        "TimeCreated": "2024-11-15T09:45:02Z",
        "Computer": "WS-JSMITH",
        "User": "ACME\\jsmith",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "DestinationIp": "185.220.101.47",
        "DestinationPort": 4444,
        "Protocol": "tcp",
        "Initiated": True
    },
]

MAIL_LOGS = [
    {
        "timestamp": "2024-11-15T09:42:11Z",
        "server": "MAIL01",
        "action": "DELIVERED",
        "to": "jsmith@acmecorp.local",
        "from": "accounting@acme-invoices.net",
        "subject": "URGENT: Invoice #INV-2024-8847 requires your approval",
        "attachment": "Invoice_INV-2024-8847.docm",
        "attachment_size": 67234,
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "sender_ip": "185.220.101.47"
    }
]


def wait_for_es():
    print("Waiting for Elasticsearch...")
    for _ in range(30):
        try:
            r = requests.get(f"{ES_HOST}/_cluster/health",
                             auth=(ES_USER, ES_PASS), timeout=5)
            if r.status_code == 200:
                print("Elasticsearch is ready.")
                return True
        except Exception:
            pass
        time.sleep(5)
    print("ERROR: Elasticsearch did not become ready.")
    return False


def index_document(index, doc):
    r = requests.post(
        f"{ES_HOST}/{index}/_doc",
        json=doc,
        auth=(ES_USER, ES_PASS),
        headers={"Content-Type": "application/json"}
    )
    return r.status_code in (200, 201)


def write_log_files():
    os.makedirs("/var/log/simulated", exist_ok=True)
    with open("/var/log/simulated/sysmon.log", "w") as f:
        for entry in SYSMON_LOGS:
            f.write(json.dumps(entry) + "\n")
    with open("/var/log/simulated/mail.log", "w") as f:
        for entry in MAIL_LOGS:
            f.write(json.dumps(entry) + "\n")
    print("Log files written to /var/log/simulated/")


def index_logs():
    print("Indexing logs into Elasticsearch...")
    for doc in SYSMON_LOGS:
        index_document("demo01-sysmon", doc)
    for doc in MAIL_LOGS:
        index_document("demo01-mail", doc)
    print("Logs indexed.")


def main():
    write_log_files()
    if wait_for_es():
        index_logs()
    print("Simulator ready. Container will stay alive for tool execution.")
    # Keep alive
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
