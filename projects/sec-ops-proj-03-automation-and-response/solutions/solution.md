# Solution: Project 03 — SOC Automation and Response

**Project:** SEC-OPS-PROJ-03

**Covers:** Sessions 09–11

---

## Part 1 Solution — Phishing Response Playbook

```python
#!/usr/bin/env python3
"""
Helios Maritime Logistics — Automated Phishing Response Playbook
Project 03 Reference Solution
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

# ─── Load data ────────────────────────────────────────────────────────────────
with open("/data/alert_queue.json") as f:
    alerts = json.load(f)

with open("/data/asset_inventory.json") as f:
    asset_inventory = {e["email"]: e for e in json.load(f)}

with open("/data/threat_intel.json") as f:
    threat_intel_raw = json.load(f)
    ti_ips     = {e["ioc"]: e for e in threat_intel_raw if e.get("type") == "ip"}
    ti_hashes  = {e["ioc"]: e for e in threat_intel_raw if e.get("type") == "md5"}
    ti_domains = {e["ioc"]: e for e in threat_intel_raw if e.get("type") == "domain"}

# ─── Output files ─────────────────────────────────────────────────────────────
BLOCKLIST       = Path("/tmp/blocklist.txt")
QUARANTINE_LOG  = Path("/tmp/quarantine_log.json")
NOTIFICATIONS   = Path("/tmp/notifications.json")
ANALYST_QUEUE   = Path("/tmp/analyst_queue.json")

for f in [QUARANTINE_LOG, NOTIFICATIONS, ANALYST_QUEUE]:
    f.write_text("[]")
BLOCKLIST.write_text("")

def append_json(filepath, record):
    existing = json.loads(filepath.read_text())
    existing.append(record)
    filepath.write_text(json.dumps(existing, indent=2))

def append_blocklist(value):
    with open(BLOCKLIST, "a") as f:
        f.write(value + "\n")

# ─── Step 1: Triage Scoring ───────────────────────────────────────────────────
TYPOSQUAT_BRANDS = ["microsoft", "amazon", "google", "paypal", "helios"]
RISKY_EXTENSIONS = {".exe", ".dll", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta"}

def compute_risk_score(alert):
    email   = alert["email"]
    score   = 0
    reasons = []

    # Attachment extension
    attachment = email.get("attachment", "")
    ext = "." + attachment.rsplit(".", 1)[-1].lower() if "." in attachment else ""
    if ext in RISKY_EXTENSIONS:
        score += 20
        reasons.append(f"Risky extension: {ext} (+20)")

    # Typosquatting
    sender_domain = email.get("sender", "").split("@")[-1].lower()
    if any(brand in sender_domain for brand in TYPOSQUAT_BRANDS):
        score += 15
        reasons.append(f"Typosquatting brand in domain (+15)")

    # Threat intel — sender IP
    sender_ip = email.get("sender_ip","")
    ti_ip = ti_ips.get(sender_ip)
    if ti_ip and ti_ip.get("score", 0) > 50:
        score += 25
        reasons.append(f"Sender IP in TI (score {ti_ip['score']}) (+25)")

    # Threat intel — sender domain
    ti_domain = ti_domains.get(sender_domain)
    if ti_domain:
        domain_age = ti_domain.get("domain_age_days", 999)
        if domain_age < 30:
            score += 30
            reasons.append(f"Domain age {domain_age} days < 30 (+30)")

    # Threat intel — attachment hash
    attachment_md5 = email.get("attachment_md5","")
    ti_hash = ti_hashes.get(attachment_md5)
    if ti_hash:
        score += 20
        reasons.append(f"Attachment hash in TI (+20)")

    # High-severity overrides
    if email.get("attachment_opened"):
        score += 40
        reasons.append("Attachment OPENED by recipient (+40)")

    if email.get("link_clicked"):
        score += 30
        reasons.append("Link CLICKED by recipient (+30)")

    return min(score, 100), reasons

# ─── Step 2: Asset Enrichment ─────────────────────────────────────────────────
def enrich_asset(recipient_email):
    asset = asset_inventory.get(recipient_email, {})
    return {
        "name":            asset.get("name", "Unknown"),
        "department":      asset.get("department", "Unknown"),
        "manager_email":   asset.get("manager_email"),
        "security_trained": asset.get("security_training_completed_within_12m", False)
    }

# ─── Step 3: Threat Intel Enrichment ─────────────────────────────────────────
def enrich_threat_intel(sender_ip, attachment_md5):
    ip_data   = ti_ips.get(sender_ip, {})
    hash_data = ti_hashes.get(attachment_md5, {})
    return {
        "ip_score":      ip_data.get("score", 0),
        "ip_category":   ip_data.get("category", "unknown"),
        "ip_last_seen":  ip_data.get("last_seen"),
        "hash_score":    hash_data.get("score", 0),
        "hash_category": hash_data.get("category", "unknown"),
        "hash_family":   hash_data.get("malware_family")
    }

# ─── Step 4: Decision Engine ─────────────────────────────────────────────────
def decide(risk_score):
    if risk_score >= 70:
        return "BLOCK"
    elif risk_score >= 40:
        return "CONTAIN"
    else:
        return "MONITOR"

# ─── Step 5: Action Execution ─────────────────────────────────────────────────
def execute_actions(alert, decision, asset_info, ti_info, risk_score, reasons):
    email = alert["email"]
    now   = datetime.now(timezone.utc).isoformat()

    if decision in ("BLOCK", "CONTAIN"):
        # Quarantine
        append_json(QUARANTINE_LOG, {
            "alert_id":   alert["alert_id"],
            "timestamp":  now,
            "decision":   decision,
            "risk_score": risk_score,
            "sender":     email["sender"],
            "recipient":  email["recipient"],
            "reasons":    reasons
        })

        # Notification to recipient
        append_json(NOTIFICATIONS, {
            "to":      email["recipient"],
            "subject": f"Security Alert: Suspicious email quarantined",
            "body":    f"Dear {asset_info['name']}, a suspicious email from {email['sender']} has been quarantined. Do not attempt to retrieve it. Reference: {alert['alert_id']}.",
            "sent_at": now
        })

    if decision == "BLOCK":
        # Block sender IP and domain
        append_blocklist(email.get("sender_ip",""))
        sender_domain = email["sender"].split("@")[-1]
        append_blocklist(sender_domain)

        # Notify manager
        if asset_info.get("manager_email"):
            append_json(NOTIFICATIONS, {
                "to":      asset_info["manager_email"],
                "subject": f"Security Alert: {asset_info['name']} received high-risk phishing",
                "body":    f"Alert {alert['alert_id']}: {asset_info['name']} in {asset_info['department']} received a high-risk phishing email (score {risk_score}/100). Email quarantined and sender blocked.",
                "sent_at": now
            })

    elif decision == "MONITOR":
        # Add to watchlist / analyst queue with low priority
        append_json(ANALYST_QUEUE, {
            "alert_id":   alert["alert_id"],
            "priority":   "low",
            "risk_score": risk_score,
            "reasons":    reasons
        })

    elif decision == "CONTAIN":
        # Add to analyst queue with medium priority
        append_json(ANALYST_QUEUE, {
            "alert_id":   alert["alert_id"],
            "priority":   "medium",
            "risk_score": risk_score,
            "reasons":    reasons
        })

# ─── Process all alerts ───────────────────────────────────────────────────────
from collections import Counter
decisions  = Counter()
start_time = time.time()

for alert in alerts:
    risk_score, reasons    = compute_risk_score(alert)
    asset_info             = enrich_asset(alert["email"]["recipient"])
    ti_info                = enrich_threat_intel(
        alert["email"].get("sender_ip",""),
        alert["email"].get("attachment_md5","")
    )
    decision = decide(risk_score)
    execute_actions(alert, decision, asset_info, ti_info, risk_score, reasons)
    decisions[decision] += 1

elapsed_ms = (time.time() - start_time) * 1000

# ─── Summary ─────────────────────────────────────────────────────────────────
print("=" * 50)
print("PHISHING PLAYBOOK RUN SUMMARY")
print("=" * 50)
print(f"Total alerts processed : {len(alerts)}")
print(f"BLOCK actions          : {decisions['BLOCK']}")
print(f"CONTAIN actions        : {decisions['CONTAIN']}")
print(f"MONITOR actions        : {decisions['MONITOR']}")
print(f"Mean processing time   : {elapsed_ms/len(alerts):.1f} ms per alert")
auto_resolved  = decisions["BLOCK"] + decisions["CONTAIN"]
time_saved_hrs = auto_resolved * 45 / 60
print(f"Estimated analyst time saved : {time_saved_hrs:.1f} hours")
```

---

## Part 2 Solution — VERIS Incident Record

```json
{
  "incident_id": "INC-HML-2024-1147",
  "summary": "Phishing email with malicious attachment led to credential theft and exfiltration of supplier payment records. Threat actor used stolen credentials to access the invoice portal and downloaded approximately 50,000 records containing personal financial data.",
  "source_id": "Helios Maritime Logistics SOC",
  "security_incident": "Confirmed",

  "victim": {
    "industry": ["Transportation"],
    "employee_count": "1001 to 10000",
    "country": ["NLD"],
    "locations_affected": 1,
    "notes": "Headquartered in Rotterdam, Netherlands. Subject to GDPR and NIS2 Directive."
  },

  "actor": {
    "external": {
      "variety": ["Organized crime"],
      "motive": ["Financial"],
      "country": ["Unknown"],
      "notes": "Eastern European nexus based on C2 infrastructure geolocation. Financially motivated based on target selection (payment records)."
    }
  },

  "action": {
    "social": {
      "variety": ["Phishing"],
      "target": ["End-user"],
      "result": ["Clicked malicious link", "Install malware"],
      "notes": "Spearphishing email with malicious Word attachment containing macro dropper."
    },
    "hacking": {
      "variety": ["Use of stolen creds"],
      "vector": ["Web application"],
      "result": ["Exfiltrate"],
      "notes": "Stolen credentials used to authenticate to the company invoice portal. No software vulnerability exploited."
    }
  },

  "asset": {
    "assets": [
      {"variety": "U - Desktop", "amount": 1},
      {"variety": "S - Web application", "amount": 1},
      {"variety": "D - Sensitive", "amount": 1}
    ],
    "cloud": ["On-prem"]
  },

  "attribute": {
    "confidentiality": {
      "data_disclosure": "Yes",
      "data": [
        {"variety": "Payment", "amount": 50000},
        {"variety": "Personal", "amount": 50000}
      ],
      "notes": "50,000 supplier payment records. Records include IBAN, payment amounts, and supplier PII — constitutes personal data under GDPR Article 4."
    },
    "integrity": {
      "variety": ["Software installation"],
      "notes": "Cobalt Strike Beacon installed on WS-CALDERA-014."
    },
    "availability": {
      "variety": [],
      "notes": "No availability impact confirmed."
    }
  },

  "discovery_method": "Security software (AV, IDS, FW, UTM, etc.)",
  "discovery_notes": "DNS monitoring alert detected beaconing to known C2 domain in threat intelligence feed.",

  "timeline": {
    "compromise": {"unit": "hours", "value": 0},
    "exfiltration": {"unit": "hours", "value": 5.4},
    "discovery": {"unit": "hours", "value": 6.0},
    "containment": {"unit": "hours", "value": 7.5},
    "notes": "All times relative to initial phishing email receipt."
  },

  "ioc": [
    {"type": "ip", "value": "198.51.100.47", "notes": "C2 server"},
    {"type": "domain", "value": "analytics-cdn.caldera-updates.net", "notes": "C2 domain"},
    {"type": "md5", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "notes": "Cobalt Strike Beacon"}
  ],

  "schema_version": "1.3.7"
}
```

**VERIS Justification Key Points:**

* `action.hacking.variety: "Use of stolen creds"` — The attacker did not exploit a software vulnerability to access the invoice portal. They used credentials obtained via the phishing/malware stage. This is distinct from `Exploit vuln`.
* `attribute.confidentiality.data.variety: ["Payment", "Personal"]` — The supplier records contain both payment data (bank accounts, invoice amounts) and personal data (supplier names, addresses). Under GDPR Article 4, personal data means any data relating to an identified or identifiable natural person. Many suppliers are sole traders or small businesses where the financial contact is the individual themselves.
* `actor.external.motive: ["Financial"]` — Target selection (payment records rather than IP) and the monetisable nature of the data (financial fraud, BEC follow-on attacks) indicate financial motivation.

---

## Part 3 Solution — Metrics Report Generator

```python
#!/usr/bin/env python3
# /tmp/metrics_report_generator.py
import json
from datetime import datetime, timezone
from statistics import mean

with open("/data/soc_metrics_4weeks.json") as f:
    weeks = json.load(f)  # List of 4 weekly metric dicts, latest last

this_week = weeks[-1]
last_week = weeks[-2]

BENCHMARKS = {
    "mean_time_to_detect_hours":  {"target": 4,   "lower_is_better": True,  "unit": "h"},
    "mean_time_to_respond_hours": {"target": 1,   "lower_is_better": True,  "unit": "h"},
    "false_positive_rate_pct":    {"target": 40,  "lower_is_better": True,  "unit": "%"},
    "automation_rate_pct":        {"target": 40,  "lower_is_better": False, "unit": "%"},
    "alert_triage_coverage":      {"target": 90,  "lower_is_better": False, "unit": "%"},
    "critical_sla_breach_count":  {"target": 5,   "lower_is_better": True,  "unit": ""},
}

# Calculate derived metric
def triage_coverage(week):
    return round(week.get("alerts_triaged",0) / week.get("alerts_generated",1) * 100, 1)

this_week["alert_triage_coverage"] = triage_coverage(this_week)
last_week["alert_triage_coverage"] = triage_coverage(last_week)

def trend_str(metric, current, previous):
    bench = BENCHMARKS.get(metric, {})
    lower_better = bench.get("lower_is_better", True)
    delta = current - previous
    if abs(delta) < 0.1:
        return "→ stable"
    if lower_better:
        return "↓ BETTER" if delta < 0 else "↑ WORSE"
    else:
        return "↑ BETTER" if delta > 0 else "↓ WORSE"

def vs_target(metric, current):
    bench = BENCHMARKS.get(metric)
    if not bench:
        return ""
    target = bench["target"]
    lower  = bench["lower_is_better"]
    met    = (current <= target) if lower else (current >= target)
    return f"✓ (target: {target}{bench['unit']})" if met else f"✗ (target: {target}{bench['unit']})"

metrics_to_show = [
    ("MTTD (hours)",            "mean_time_to_detect_hours"),
    ("MTTR (hours)",            "mean_time_to_respond_hours"),
    ("False Positive Rate (%)", "false_positive_rate_pct"),
    ("Automation Rate (%)",     "automation_rate_pct"),
    ("Triage Coverage (%)",     "alert_triage_coverage"),
    ("SLA Breaches",            "critical_sla_breach_count"),
]

rows = []
for label, key in metrics_to_show:
    cur  = this_week.get(key, 0)
    prev = last_week.get(key, 0)
    rows.append((label, cur, prev, trend_str(key, cur, prev), vs_target(key, cur)))

# Executive summary
worst = max(rows, key=lambda r: 1 if "WORSE" in r[3] else 0)
best  = max(rows, key=lambda r: 1 if "BETTER" in r[3] else 0)

# Recommendations
recommendations = []
for label, cur, prev, trend, vs_tgt in rows:
    if "✗" in vs_tgt:
        if "MTTD" in label:
            recommendations.append("• MTTD is above target. Review alert enrichment pipeline and enable automated triage for top 3 alert categories.")
        if "False Positive" in label:
            recommendations.append("• False positive rate exceeds target. Schedule a detection rule review sprint. Target the top 5 rules by false positive count.")
        if "Automation" in label:
            recommendations.append("• Automation rate is below target. Identify the 3 highest-volume alert types and implement automated disposition for at least 2 of them.")
        if "Triage" in label:
            recommendations.append("• Alert triage coverage is below 90%. Either reduce alert volume (tune rules) or increase analyst capacity for peak hours.")
        if "SLA" in label:
            recommendations.append("• SLA breaches exceed target. Review P1/P2 escalation paths and ensure 24×7 on-call coverage is effective.")

# ASCII bar chart
daily_volumes = this_week.get("daily_alert_volumes", [320, 480, 510, 290, 440, 390, 420])
max_vol = max(daily_volumes)
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
bar_width = 40
chart = "\nDaily Alert Volume — This Week\n"
for i, vol in enumerate(daily_volumes):
    bar = "█" * int(vol / max_vol * bar_width)
    chart += f"  {DAYS[i]}: {bar:<40s} {vol}\n"

# Render report
report = f"""# SOC Weekly Metrics Report — Helios Maritime Logistics
**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
**Week:** {this_week.get("week_label", "W46 2024")}

---

## Executive Summary

- **Best performance:** {best[0]} improved week-over-week ({best[3]})
- **Biggest concern:** {worst[0]} is worsening ({worst[3]}) and remains below benchmark
- **Key trend:** Total alerts this week: {this_week.get('alerts_generated', '?')} ({"↑ higher" if this_week.get('alerts_generated',0) > last_week.get('alerts_generated',0) else "↓ lower"} than last week)

---

## Weekly Metrics

| Metric | This Week | Last Week | Trend | vs Target |
|--------|-----------|-----------|-------|-----------|
"""
for label, cur, prev, trend, vs_tgt in rows:
    report += f"| {label} | {cur} | {prev} | {trend} | {vs_tgt} |\n"

report += "\n---\n\n## Automated Recommendations\n\n"
report += "\n".join(recommendations) if recommendations else "_All metrics within target. No recommendations this week._"

report += "\n\n---\n"
report += chart

with open("/tmp/soc_weekly_report.md", "w") as f:
    f.write(report)

print("Report written to /tmp/soc_weekly_report.md")
print(report)
```

---

## Scoring Notes for Instructors

**Part 1 (45 pts):**

* Triage scoring (15): All conditions implemented; `attachment_opened` correctly overrides to high risk
* Enrichment (15): Both asset and threat intel lookups functional; missing keys handled gracefully
* Decision engine + actions (15): Correct thresholds; all 4 output files populated; BLOCK correctly adds to blocklist

**Part 2 (30 pts):**

* VERIS record (20): All required sections present; correct VERIS enumeration values used (not free text); timeline populated
* Justification (10): Explains credential theft vs. vuln exploitation distinction; explains GDPR personal data relevance; correct motive enumeration

**Part 3 (25 pts):**

* Calculations (10): All 6 metrics calculated including derived triage coverage
* Trend and benchmark comparison (10): Correct direction indicators; benchmark comparison accurate
* Report quality (5): Executive summary is informative; recommendations are specific
