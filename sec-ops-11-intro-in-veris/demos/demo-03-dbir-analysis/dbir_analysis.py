#!/usr/bin/env python3
"""
VERIS Demo 03 - DBIR-Style Analysis Script
Session 11 | Security Operations Master Class | Digital4Security

Run: python3 dbir_analysis.py
"""
import random
from collections import Counter
from statistics import mean, median

random.seed(42)

ACTOR_DIST = [
    ("external", "Organized crime", "Financial", 0.40),
    ("external", "Unknown", "Unknown", 0.15),
    ("internal", "End-user", "Negligence", 0.25),
    ("internal", "System administrator", "Convenience", 0.10),
    ("partner", "Third-party vendor", "Unknown", 0.05),
    ("external", "Nation-state", "Espionage", 0.05),
]
ACTION_DIST = [
    ("social", "Phishing", "Email", 0.28),
    ("hacking", "Use of stolen credentials", "Web application", 0.20),
    ("error", "Misconfiguration", "Unknown", 0.18),
    ("malware", "Ransomware", "Email attachment", 0.14),
    ("misuse", "Privilege abuse", "Unknown", 0.10),
    ("error", "Misdelivery", "Unknown", 0.06),
    ("physical", "Theft", "Unknown", 0.04),
]
ATTR_DIST = [
    ("confidentiality", "Medical (PHI)", 0.45),
    ("confidentiality", "Personal", 0.15),
    ("availability", "Encryption", 0.14),
    ("integrity", "Software installation", 0.12),
    ("confidentiality", "Credentials", 0.10),
    ("availability", "Interruption", 0.04),
]
DISCOVERY_DIST = [
    ("external", "Customer complaint", 0.30),
    ("external", "Fraud detection", 0.15),
    ("internal", "NIDS/SIEM", 0.20),
    ("internal", "Audit", 0.18),
    ("external", "Law enforcement", 0.08),
    ("internal", "User complaint", 0.09),
]
DISCOVERY_DAYS = {
    "external": lambda: random.randint(30, 200),
    "internal": lambda: random.randint(1, 45),
}


def weighted_choice(dist):
    r, cumulative = random.random(), 0
    for item in dist:
        cumulative += item[-1]
        if r <= cumulative:
            return item
    return dist[-1]


def generate_incident(i):
    ae = weighted_choice(ACTOR_DIST)
    ace = weighted_choice(ACTION_DIST)
    atr = weighted_choice(ATTR_DIST)
    de = weighted_choice(DISCOVERY_DIST)
    year = random.choice([2022, 2023, 2024])
    disc_days = DISCOVERY_DAYS[de[0]]()
    inc = {
        "incident_id": f"hc-{i:03d}",
        "timeline": {"incident": {"year": year}, "discovery": {"unit": "Days", "value": disc_days}},
        "actor": {ae[0]: {"variety": [ae[1]], "motive": [ae[2]]}},
        "action": {ace[0]: {"variety": [ace[1]], "vector": [ace[2]]}},
        "attribute": {},
        "_discovery_type": de[0],
        "_discovery_variety": de[1]
    }
    if atr[0] == "confidentiality":
        inc["attribute"]["confidentiality"] = {
            "data_disclosure": "Yes",
            "data_total": random.randint(100, 50000),
            "data": [{"variety": atr[1], "amount": random.randint(100, 50000)}]
        }
    elif atr[0] == "availability":
        inc["attribute"]["availability"] = {"variety": [atr[1]], "duration": {"unit": "Days", "value": random.randint(1, 14)}}
    else:
        inc["attribute"]["integrity"] = {"variety": [atr[1]]}
    return inc


INCIDENTS = [generate_incident(i) for i in range(1, 51)]


def bar(pct, width=30):
    return "█" * int(pct * width / 100)


def actor_analysis():
    print("\n" + "─" * 60)
    print("  ACTOR ANALYSIS")
    print("─" * 60)
    types, varieties, motives = Counter(), Counter(), Counter()
    for inc in INCIDENTS:
        for at, d in inc["actor"].items():
            types[at] += 1
            for v in d.get("variety", []): varieties[v] += 1
            for m in d.get("motive", []): motives[m] += 1
    n = len(INCIDENTS)
    print(f"\n  Actor Types:")
    for k, v in types.most_common():
        p = v / n * 100
        print(f"    {k:<14} {bar(p):<30} {p:5.1f}% ({v})")
    print(f"\n  Top Varieties:")
    for k, v in varieties.most_common(5):
        print(f"    {k:<32} {v:3d}")
    print(f"\n  Top Motives:")
    for k, v in motives.most_common(4):
        print(f"    {k:<20} {v:3d}")


def action_analysis():
    print("\n" + "─" * 60)
    print("  ACTION ANALYSIS")
    print("─" * 60)
    cats, varieties = Counter(), Counter()
    for inc in INCIDENTS:
        for at, d in inc["action"].items():
            cats[at] += 1
            for v in d.get("variety", []): varieties[v] += 1
    n = len(INCIDENTS)
    print(f"\n  Action Categories:")
    for k, v in cats.most_common():
        p = v / n * 100
        print(f"    {k:<14} {bar(p):<28} {p:5.1f}% ({v})")
    print(f"\n  Top Varieties:")
    for k, v in varieties.most_common(7):
        print(f"    {k:<36} {v:3d}")
    ph = varieties.get("Phishing", 0) / n * 100
    cr = varieties.get("Use of stolen credentials", 0) / n * 100
    print(f"\n  SOC INSIGHT: Phishing+Credential theft = {ph+cr:.1f}% of incidents → prioritize MFA + email security")


def attribute_analysis():
    print("\n" + "─" * 60)
    print("  ATTRIBUTE ANALYSIS (CIA Triad)")
    print("─" * 60)
    types, dtypes = Counter(), Counter()
    breaches = 0
    for inc in INCIDENTS:
        for at, d in inc["attribute"].items():
            types[at] += 1
            if at == "confidentiality":
                if d.get("data_disclosure") in ["Yes", "Potentially"]: breaches += 1
                for x in d.get("data", []): dtypes[x["variety"]] += 1
    n = len(INCIDENTS)
    for k, v in types.most_common():
        print(f"    {k:<18} {v:3d} ({v/n*100:.1f}%)")
    print(f"\n  Confirmed breaches: {breaches}/{n} ({breaches/n*100:.1f}%)")
    print(f"\n  Data Types:")
    for k, v in dtypes.most_common():
        print(f"    {k:<25} {v:3d}")


def discovery_analysis():
    print("\n" + "─" * 60)
    print("  DISCOVERY ANALYSIS")
    print("─" * 60)
    types, varieties = Counter(), Counter()
    int_days, ext_days = [], []
    for inc in INCIDENTS:
        dt = inc["_discovery_type"]; dv = inc["_discovery_variety"]
        dd = inc["timeline"]["discovery"]["value"]
        types[dt] += 1; varieties[dv] += 1
        (int_days if dt == "internal" else ext_days).append(dd)
    n = len(INCIDENTS)
    for k, v in types.most_common():
        p = v / n * 100
        print(f"    {k:<12} {bar(p):<28} {p:5.1f}% ({v})")
    if int_days:
        print(f"\n  Internal detection: mean={mean(int_days):.1f}d, median={median(int_days):.1f}d")
    if ext_days:
        print(f"  External detection: mean={mean(ext_days):.1f}d, median={median(ext_days):.1f}d")
    ext_pct = types.get("external", 0) / n * 100
    print(f"\n  SOC INSIGHT: {ext_pct:.1f}% externally detected → {'detection gap exists' if ext_pct > 35 else 'detection acceptable'}")


def trend_analysis():
    print("\n" + "─" * 60)
    print("  YEAR-OVER-YEAR TRENDS")
    print("─" * 60)
    by_year = {}
    for inc in INCIDENTS:
        y = inc["timeline"]["incident"]["year"]
        by_year.setdefault(y, []).append(inc)
    for year in sorted(by_year):
        incs = by_year[year]
        acts = Counter(a for inc in incs for a in inc["action"])
        top = ", ".join(f"{k}({v})" for k, v in acts.most_common(3))
        print(f"  {year}: {len(incs):2d} incidents | {top}")


def executive_summary():
    print("\n" + "═" * 60)
    print("  EXECUTIVE THREAT LANDSCAPE SUMMARY")
    print("  Healthcare | 50 incidents | 3-year analysis")
    print("═" * 60)
    n = len(INCIDENTS)
    breaches = sum(1 for i in INCIDENTS if i.get("attribute", {}).get("confidentiality", {}).get("data_disclosure") in ["Yes", "Potentially"])
    action_cats = Counter(a for i in INCIDENTS for a in i["action"])
    actor_types = Counter(a for i in INCIDENTS for a in i["actor"])
    top_act = action_cats.most_common(1)[0]
    top_actor = actor_types.most_common(1)[0]
    print(f"\n  Incidents: {n} | Breaches: {breaches} ({breaches/n*100:.1f}%)")
    print(f"  Top actor: {top_actor[0]} ({top_actor[1]/n*100:.1f}%)")
    print(f"  Top action: {top_act[0]} ({top_act[1]/n*100:.1f}%)")
    print(f"\n  Top 3 Recommendations:")
    print(f"  1. Deploy MFA across all remote access channels")
    print(f"  2. Enhance email gateway with AI-based phishing detection")
    print(f"  3. Implement UBA/UEBA to reduce external discovery rate")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  VERIS Demo 03: DBIR-Style Analysis")
    print("  Healthcare Dataset — 50 incidents, 3 years")
    print("=" * 60)
    actor_analysis()
    action_analysis()
    attribute_analysis()
    discovery_analysis()
    trend_analysis()
    executive_summary()
