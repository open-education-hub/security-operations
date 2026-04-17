#!/usr/bin/env python3
"""
SOC metrics data generator — simulates 30 days of SOC activity.
"""
import random
import math

def generate_metrics():
    random.seed(42)
    days = 30

    # Simulate improving MTTD over 30 days (from 12h down to 4.2h)
    mttd_trend = [round(12.0 - (7.8 * (i / (days - 1))) + random.uniform(-1, 1), 1) for i in range(days)]
    mttd_trend = [max(1.0, v) for v in mttd_trend]

    # MTTR trend (improving from 18h to 6.8h)
    mttr_trend = [round(18.0 - (11.2 * (i / (days - 1))) + random.uniform(-1.5, 1.5), 1) for i in range(days)]
    mttr_trend = [max(2.0, v) for v in mttr_trend]

    # Alert volume per day per source
    sources = ["SIEM", "EDR", "Network IDS", "Cloud"]
    alert_volume = {}
    for src in sources:
        base = {"SIEM": 120, "EDR": 80, "Network IDS": 60, "Cloud": 40}[src]
        alert_volume[src] = [max(0, int(base + random.gauss(0, base * 0.2))) for _ in range(days)]

    # Add a spike on day 20 (simulated attack)
    for src in sources:
        alert_volume[src][19] = int(alert_volume[src][19] * 2.5)

    # Daily totals
    total_alerts = [sum(alert_volume[src][i] for src in sources) for i in range(days)]

    # False positive rate (improving from 55% to 34%)
    fpr_trend = [round(55.0 - (21.0 * (i / (days - 1))) + random.uniform(-3, 3), 1) for i in range(days)]
    fpr_trend = [max(10.0, min(70.0, v)) for v in fpr_trend]

    # Confirmed incidents per day
    incidents = [max(0, int(total_alerts[i] * (1 - fpr_trend[i] / 100))) for i in range(days)]
    incidents = [min(v, 50) for v in incidents]  # cap at 50 per day

    # Severity breakdown for last 7 days
    severity = {
        "Critical": random.randint(2, 8),
        "High": random.randint(10, 25),
        "Medium": random.randint(30, 60),
        "Low": random.randint(60, 120),
        "Informational": random.randint(100, 200),
    }

    # ATT&CK coverage
    total_techniques = 103
    covered_techniques = 47
    coverage_pct = round(covered_techniques / total_techniques * 100, 1)

    # Day labels
    day_labels = [f"Day {i+1}" for i in range(days)]

    return {
        "current_mttd": mttd_trend[-1],
        "current_mttr": mttr_trend[-1],
        "current_fpr": fpr_trend[-1],
        "today_alerts": total_alerts[-1],
        "today_incidents": incidents[-1],
        "mttd_trend": mttd_trend,
        "mttr_trend": mttr_trend,
        "fpr_trend": fpr_trend,
        "total_alerts": total_alerts,
        "alert_volume": alert_volume,
        "incidents": incidents,
        "severity": severity,
        "attack_coverage": coverage_pct,
        "covered_techniques": covered_techniques,
        "total_techniques": total_techniques,
        "day_labels": day_labels,
        "sources": sources,
    }
