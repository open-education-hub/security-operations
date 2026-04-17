#!/usr/bin/env python3
"""
Drill 02 Advanced — Insider Threat Scenario Data Loader
Loads 90 days of log data for a departing researcher investigation.

Organization: PharmaResearch Inc (pharma.local)
Subject:      dr.chen (Dr. Linda Chen) - Senior Researcher, resigned 30 days ago
Goal:         Determine if DLP alerts represent malicious data exfiltration

Timeline:
  Day -90 to -31: Normal work period (baseline for comparison)
  Day -30: Resignation submitted
  Day -20 to -16: Increased file access in Compounds database
  Day -15: DLP Alert 1 - 847 Compounds files accessed
  Day -13 to -11: Email with large attachment to personal email
  Day -10: DLP Alert 2 - Large attachment to gmail
  Day -5:  DLP Alert 3 - 4.2 GB USB copy
  Day 0:   Investigation initiated
"""

import time
import os
import requests
import random

ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "changeme")

# Investigation date: 2024-11-20
DAY0 = 1732060800
DAY = 86400


def d(days_before, hour=10, minute=0, second=0):
    return DAY0 - days_before * DAY + hour * 3600 + minute * 60 + second


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


def build_events():
    events = []

    # ── Baseline period: normal file access (days 90 to 31 before today) ────
    # Dr. Chen's normal daily file access: 40-80 files/day during business hours
    for day in range(90, 31, -1):
        day_of_week = (DAY0 - day * DAY) % (7 * DAY) // DAY % 7  # 0=Mon
        if day_of_week >= 5:  # skip weekends
            continue
        num_accesses = random.randint(40, 80)
        for i in range(num_accesses):
            hour = random.randint(8, 17)
            events.append(("winlogs", "RESEARCH-WS-LC01", d(day, hour, random.randint(0, 59)),
                {"sourcetype": "xmlwineventlog:security",
                 "EventCode": 4663, "ComputerName": "FILE-SRV01",
                 "Account_Name": "dr.chen",
                 "Object_Name": f"\\\\FILE-SRV01\\Research\\Compounds\\compound_{random.randint(1000, 5000):05d}.dat",
                 "Access_Mask": "0x1",  # Read
                 "Object_Type": "File"}))

    # ── Baseline USB usage: rarely used, just a few times ────────────────────
    for day in [75, 62, 44]:
        events.append(("sysmon", "RESEARCH-WS-LC01", d(day, 16, 30),
            {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
             "EventID": 6, "Computer": "RESEARCH-WS-LC01",
             "User": "PHARMA\\dr.chen",
             "ImageLoaded": "C:\\Windows\\System32\\drivers\\usbstor.sys"}))

    # ── Resignation submitted: Day -30 ────────────────────────────────────────
    # (No log event - this is an HR record, referenced in scenario background)

    # ── Post-resignation: file access increases ───────────────────────────────
    for day in range(30, 15, -1):
        day_of_week = (DAY0 - day * DAY) % (7 * DAY) // DAY % 7
        if day_of_week >= 5:
            continue
        # 120-180 files/day (3x normal) - accessing broader compound set
        num_accesses = random.randint(120, 180)
        for i in range(num_accesses):
            hour = random.randint(7, 19)  # also earlier/later than normal
            events.append(("winlogs", "RESEARCH-WS-LC01", d(day, hour, random.randint(0, 59)),
                {"sourcetype": "xmlwineventlog:security",
                 "EventCode": 4663, "ComputerName": "FILE-SRV01",
                 "Account_Name": "dr.chen",
                 "Object_Name": f"\\\\FILE-SRV01\\Research\\Compounds\\compound_{random.randint(1000, 9999):05d}.dat",
                 "Access_Mask": "0x1",
                 "Object_Type": "File"}))

    # ── DLP Alert 1: Bulk file access - 847 files in one day ─────────────────
    for i in range(847):
        events.append(("winlogs", "RESEARCH-WS-LC01", d(15, 9) + i * 37,
            {"sourcetype": "xmlwineventlog:security",
             "EventCode": 4663, "ComputerName": "FILE-SRV01",
             "Account_Name": "dr.chen",
             "Object_Name": f"\\\\FILE-SRV01\\Research\\Compounds\\compound_{1000 + i:05d}.dat",
             "Access_Mask": "0x1",  # Read only
             "Object_Type": "File"}))

    # ── Baseline email: normal work emails ───────────────────────────────────
    for day in range(90, 11, -1):
        day_of_week = (DAY0 - day * DAY) % (7 * DAY) // DAY % 7
        if day_of_week >= 5:
            continue
        for _ in range(random.randint(5, 15)):
            events.append(("email", "MAIL01", d(day, random.randint(9, 17), random.randint(0, 59)),
                {"sourcetype": "mail:smtp",
                 "from_address": "dr.chen@pharma.local",
                 "to_address": f"colleague{random.randint(1,20)}@pharma.local",
                 "subject": "Re: Research update",
                 "attachment_name": None,
                 "attachment_size_bytes": 0}))

    # ── Personal email: check baseline ───────────────────────────────────────
    # dr.chen has 2 personal emails in 90 days baseline (before resignation)
    events.append(("email", "MAIL01", d(75, 17, 22),
        {"sourcetype": "mail:smtp",
         "from_address": "dr.chen@pharma.local",
         "to_address": "linchen.personal@gmail.com",
         "subject": "Vacation planning",
         "attachment_name": "hotel_booking.pdf",
         "attachment_size_bytes": 245760}))

    events.append(("email", "MAIL01", d(52, 12, 5),
        {"sourcetype": "mail:smtp",
         "from_address": "dr.chen@pharma.local",
         "to_address": "linchen.personal@gmail.com",
         "subject": "Fwd: Conference agenda",
         "attachment_name": "pharma_conf_agenda.pdf",
         "attachment_size_bytes": 512000}))

    # ── DLP Alert 2: Large email to personal gmail ────────────────────────────
    events.append(("email", "MAIL01", d(10, 20, 44),
        {"sourcetype": "mail:smtp",
         "from_address": "dr.chen@pharma.local",
         "to_address": "linchen.personal@gmail.com",
         "subject": "My research archive",
         "attachment_name": "compound_synthesis_notes_2019_2024.zip",
         "attachment_size_bytes": 11534336,  # 11 MB
         "spf_result": "PASS", "dkim_result": "PASS"}))

    # Email was sent after hours (8:44 PM)

    # ── DLP Alert 3: USB copy of 4.2 GB ──────────────────────────────────────
    events.append(("sysmon", "RESEARCH-WS-LC01", d(5, 8, 12),
        {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
         "EventID": 6, "Computer": "RESEARCH-WS-LC01",
         "User": "PHARMA\\dr.chen",
         "ImageLoaded": "C:\\Windows\\System32\\drivers\\usbstor.sys"}))

    # Files copied to USB (E:\)
    compound_files = [
        ("compound_synthesis_all.zip", 2147483648),   # 2 GB
        ("experimental_results_2024.xlsx", 15728640), # 15 MB
        ("competitor_analysis.docx", 5242880),        # 5 MB
        ("personal_cv.docx", 262144),                  # 256 KB - personal
        ("personal_photos.zip", 1887436800),           # 1.75 GB - personal
        ("research_notes_2022_2024.pdf", 20971520),   # 20 MB
    ]

    for i, (filename, size) in enumerate(compound_files):
        events.append(("sysmon", "RESEARCH-WS-LC01", d(5, 8, 15) + i * 300,
            {"sourcetype": "xmlwineventlog:microsoft-windows-sysmon/operational",
             "EventID": 11, "Computer": "RESEARCH-WS-LC01",
             "User": "PHARMA\\dr.chen",
             "Image": "C:\\Windows\\explorer.exe",
             "TargetFilename": f"E:\\{filename}",
             "FileSize": size}))

    # ── Cloud storage access: after resignation ───────────────────────────────
    for day in [25, 18, 12, 7, 5]:
        events.append(("proxy", "RESEARCH-WS-LC01", d(day, random.randint(16, 19), random.randint(0, 59)),
            {"sourcetype": "proxy:squid",
             "user": "dr.chen", "src_ip": "10.10.3.55",
             "dest_domain": "drive.google.com",
             "dest_port": 443, "http_method": "PUT",
             "bytes_out": random.randint(10485760, 524288000),
             "bytes_in": 2048}))

    # ── Printing: no unusual printing ────────────────────────────────────────
    # (baseline: normal scientific papers only)
    for day in [30, 22, 18, 12]:
        events.append(("winlogs", "RESEARCH-WS-LC01", d(day, 14, random.randint(0, 59)),
            {"sourcetype": "xmlwineventlog:security",
             "EventCode": 307, "ComputerName": "PRINT-SRV01",
             "UserName": "dr.chen",
             "PrinterName": "Research-HP-LaserJet",
             "DocumentName": f"compound_summary_{day}.pdf",
             "JobSize": random.randint(3, 15)}))

    return events


def main():
    if not wait_for_es():
        print("ERROR: Elasticsearch not available.")
        return

    events = build_events()
    print(f"Loading {len(events)} events (90-day insider threat timeline)...", flush=True)

    success = 0
    for i, (index, host, timestamp, event) in enumerate(events):
        if post(index, host, timestamp, event):
            success += 1
        if (i + 1) % 200 == 0:
            print(f"  Progress: {i+1}/{len(events)}", flush=True)

    print(f"\nLoaded {success}/{len(events)} events.")
    print("\nScenario: PharmaResearch Insider Threat Investigation")
    print("Access Kibana at http://localhost:5604 (elastic/changeme)")
    print("\nKEY FINDINGS (INSTRUCTOR ONLY):")
    print("  Baseline file access:   40-80 files/day (normal research)")
    print("  Post-resignation:       120-180 files/day (+3x) - ANOMALOUS")
    print("  DLP Alert 1:            847 files in 1 day - compounds database sweep")
    print("  DLP Alert 2:            11 MB email (compound synthesis notes) - SUSPICIOUS")
    print("  DLP Alert 3:            USB: 4.2 GB total - mixed research + personal")
    print("  Cloud storage:          5x Google Drive uploads post-resignation")
    print("  Assessment:             HIGH risk - pattern suggests data theft")
    print("  Note: Some behavior could be legitimate project completion - ambiguous")

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
