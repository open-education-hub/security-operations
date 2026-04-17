# Demo 03: Analyzing DBIR Findings and Extracting SOC Insights

**Duration:** 30 minutes

**Format:** Data analysis with Python; VCDB-style dataset simulation

**Difficulty:** Intermediate

**Directory:** `demos/demo-03-dbir-analysis/`

---

## Overview

This demo simulates the type of analysis performed for the Verizon DBIR.
You will work with a synthetic dataset of 50 VERIS-encoded incidents representing a fictional healthcare organization's three-year incident history.
The goal is to extract actionable SOC insights from the aggregated data.

---

## Learning Objectives

* Perform frequency analysis on VERIS dimensions
* Identify the most common incident patterns in a dataset
* Calculate time-to-discovery statistics
* Identify detection gaps from discovery method analysis
* Produce a threat landscape summary for a specific industry

---

## The Dataset

The dataset (`healthcare_incidents.json`) contains 50 synthetic incidents for a healthcare organization network (NAICS 622110).
Run the analysis script to load and analyze it.

---

## Setup

```console
cd demos/demo-03-dbir-analysis
python3 dbir_analysis.py
```

---

## Analysis Script

Save as `dbir_analysis.py`:

```python
#!/usr/bin/env python3
"""
VERIS Demo 03 - DBIR-Style Analysis
Session 11 | Security Operations Master Class
Simulates DBIR-style aggregate analysis of a VERIS incident dataset.
"""

import json
import random
from collections import Counter
from statistics import mean, median

# ─── Synthetic dataset generator ─────────────────────────────────
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
    ("external", "Customer", 0.30),
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

def weighted_choice(distribution):
    r = random.random()
    cumulative = 0
    for item in distribution:
        cumulative += item[-1]
        if r <= cumulative:
            return item
    return distribution[-1]

def generate_incident(i: int) -> dict:
    actor_entry = weighted_choice(ACTOR_DIST)
    action_entry = weighted_choice(ACTION_DIST)
    attr_entry = weighted_choice(ATTR_DIST)
    disc_entry = weighted_choice(DISCOVERY_DIST)

    year = random.choice([2022, 2023, 2024])
    disc_days = DISCOVERY_DAYS[disc_entry[0]]()

    incident = {
        "incident_id": f"demo-hc-{i:03d}",
        "security_incident": "Confirmed",
        "timeline": {
            "incident": {"year": year},
            "discovery": {"unit": "Days", "value": disc_days}
        },
        "victim": {
            "industry": "622110",
            "employee_count": random.choice(["101 to 1000", "1001 to 10000"]),
            "country": ["US"]
        },
        "actor": {
            actor_entry[0]: {
                "variety": [actor_entry[1]],
                "motive": [actor_entry[2]]
            }
        },
        "action": {
            action_entry[0]: {
                "variety": [action_entry[1]],
                "vector": [action_entry[2]]
            }
        },
        "asset": {
            "assets": [{"variety": "S - Database", "amount": 1}]
        },
        "attribute": {},
        "_discovery_method_type": disc_entry[0],
        "_discovery_method_variety": disc_entry[1]
    }

    # Attributes
    if attr_entry[0] == "confidentiality":
        incident["attribute"]["confidentiality"] = {
            "data_disclosure": "Yes",
            "data_total": random.randint(100, 50000),
            "data": [{"variety": attr_entry[1], "amount": random.randint(100, 50000)}]
        }
    elif attr_entry[0] == "availability":
        incident["attribute"]["availability"] = {
            "variety": [attr_entry[1]],
            "duration": {"unit": "Days", "value": random.randint(1, 14)}
        }
    elif attr_entry[0] == "integrity":
        incident["attribute"]["integrity"] = {
            "variety": [attr_entry[1]]
        }

    return incident

# Generate the dataset
INCIDENTS = [generate_incident(i) for i in range(1, 51)]

# ─── Analysis functions ───────────────────────────────────────────

def actor_analysis(incidents):
    print("\n" + "─" * 60)
    print("  ACTOR ANALYSIS")
    print("─" * 60)
    actor_types = Counter()
    actor_varieties = Counter()
    motives = Counter()
    for inc in incidents:
        for actor_type, data in inc.get("actor", {}).items():
            actor_types[actor_type] += 1
            for v in data.get("variety", []):
                actor_varieties[v] += 1
            for m in data.get("motive", []):
                motives[m] += 1

    total = len(incidents)
    print(f"\n  Actor Types ({total} incidents):")
    for k, v in actor_types.most_common():
        pct = v / total * 100
        bar = "█" * int(pct / 2)
        print(f"    {k:<12} {bar:<30} {pct:5.1f}% ({v})")

    print(f"\n  Top Actor Varieties:")
    for k, v in actor_varieties.most_common(6):
        print(f"    {k:<30} {v:3d} ({v/total*100:.1f}%)")

    print(f"\n  Top Motives:")
    for k, v in motives.most_common(5):
        print(f"    {k:<20} {v:3d} ({v/total*100:.1f}%)")

def action_analysis(incidents):
    print("\n" + "─" * 60)
    print("  ACTION ANALYSIS")
    print("─" * 60)
    action_cats = Counter()
    action_varieties = Counter()
    total = len(incidents)
    for inc in incidents:
        for action_type, data in inc.get("action", {}).items():
            action_cats[action_type] += 1
            for v in data.get("variety", []):
                action_varieties[v] += 1

    print(f"\n  Action Categories:")
    for k, v in action_cats.most_common():
        pct = v / total * 100
        bar = "█" * int(pct / 2)
        print(f"    {k:<14} {bar:<28} {pct:5.1f}% ({v})")

    print(f"\n  Top Action Varieties:")
    for k, v in action_varieties.most_common(8):
        print(f"    {k:<34} {v:3d} ({v/total*100:.1f}%)")

    # SOC insight
    phishing_pct = action_varieties.get("Phishing", 0) / total * 100
    cred_pct = action_varieties.get("Use of stolen credentials", 0) / total * 100
    print(f"\n  SOC INSIGHT: Phishing ({phishing_pct:.1f}%) and credential theft ({cred_pct:.1f}%)")
    print(f"  account for ~{phishing_pct+cred_pct:.1f}% of incidents.")
    print(f"  Priority: Email security controls + MFA enforcement.")

def attribute_analysis(incidents):
    print("\n" + "─" * 60)
    print("  ATTRIBUTE ANALYSIS (CIA Triad)")
    print("─" * 60)
    attr_types = Counter()
    data_types = Counter()
    total = len(incidents)
    breach_count = 0
    for inc in incidents:
        for attr, data in inc.get("attribute", {}).items():
            attr_types[attr] += 1
            if attr == "confidentiality":
                if data.get("data_disclosure") in ["Yes", "Potentially"]:
                    breach_count += 1
                for d in data.get("data", []):
                    data_types[d["variety"]] += 1

    print(f"\n  Attribute Distribution:")
    for k, v in attr_types.most_common():
        pct = v / total * 100
        print(f"    {k:<18} {v:3d} ({pct:.1f}%)")

    print(f"\n  Confirmed Data Breaches: {breach_count}/{total} ({breach_count/total*100:.1f}%)")

    print(f"\n  Data Types Disclosed:")
    for k, v in data_types.most_common():
        print(f"    {k:<25} {v:3d}")

def discovery_analysis(incidents):
    print("\n" + "─" * 60)
    print("  DISCOVERY METHOD ANALYSIS")
    print("─" * 60)
    discovery_types = Counter()
    discovery_varieties = Counter()
    internal_days = []
    external_days = []

    for inc in incidents:
        disc_type = inc.get("_discovery_method_type", "unknown")
        disc_variety = inc.get("_discovery_method_variety", "unknown")
        disc_days = inc.get("timeline", {}).get("discovery", {}).get("value", 0)
        discovery_types[disc_type] += 1
        discovery_varieties[disc_variety] += 1
        if disc_type == "internal":
            internal_days.append(disc_days)
        else:
            external_days.append(disc_days)

    total = len(incidents)
    print(f"\n  Discovery Type:")
    for k, v in discovery_types.most_common():
        pct = v / total * 100
        bar = "█" * int(pct / 2)
        print(f"    {k:<12} {bar:<28} {pct:5.1f}% ({v})")

    print(f"\n  Discovery Varieties (top 5):")
    for k, v in discovery_varieties.most_common(5):
        print(f"    {k:<25} {v:3d}")

    if internal_days:
        print(f"\n  Time to Discovery — Internally Detected:")
        print(f"    Mean:   {mean(internal_days):.1f} days")
        print(f"    Median: {median(internal_days):.1f} days")
        print(f"    Max:    {max(internal_days)} days")
    if external_days:
        print(f"\n  Time to Discovery — Externally Detected:")
        print(f"    Mean:   {mean(external_days):.1f} days")
        print(f"    Median: {median(external_days):.1f} days")
        print(f"    Max:    {max(external_days)} days")

    ext_pct = discovery_types.get("external", 0) / total * 100
    print(f"\n  SOC INSIGHT: {ext_pct:.1f}% of incidents discovered externally.")
    if ext_pct > 35:
        print(f"  ALERT: High external discovery rate indicates detection gaps.")
        print(f"  Recommendation: Improve SIEM detection rules and threat hunting.")

def trend_analysis(incidents):
    print("\n" + "─" * 60)
    print("  YEAR-OVER-YEAR TREND ANALYSIS")
    print("─" * 60)
    by_year = {}
    for inc in incidents:
        year = inc.get("timeline", {}).get("incident", {}).get("year", "Unknown")
        by_year.setdefault(year, []).append(inc)

    for year in sorted(by_year.keys()):
        incs = by_year[year]
        actions = Counter()
        for inc in incs:
            for a in inc.get("action", {}).keys():
                actions[a] += 1
        top_actions = ", ".join(f"{k}({v})" for k, v in actions.most_common(3))
        print(f"\n  {year}: {len(incs)} incidents | Top actions: {top_actions}")

def generate_executive_summary(incidents):
    print("\n" + "═" * 60)
    print("  EXECUTIVE THREAT LANDSCAPE SUMMARY")
    print("  Healthcare Industry (NAICS 622110) | 3-Year Analysis")
    print("═" * 60)

    total = len(incidents)
    breaches = sum(1 for inc in incidents
                   if inc.get("attribute", {}).get("confidentiality", {}).get("data_disclosure") in ["Yes", "Potentially"])

    action_cats = Counter()
    for inc in incidents:
        for a in inc.get("action", {}).keys():
            action_cats[a] += 1

    top_actor_types = Counter()
    for inc in incidents:
        for a in inc.get("actor", {}).keys():
            top_actor_types[a] += 1

    top1_action = action_cats.most_common(1)[0]
    top1_actor = top_actor_types.most_common(1)[0]

    print(f"""
  Total incidents analyzed: {total}
  Confirmed data breaches:  {breaches} ({breaches/total*100:.1f}%)

  Dominant actor:  {top1_actor[0].capitalize()} ({top1_actor[1]/total*100:.1f}% of incidents)
  Top action:      {top1_action[0].capitalize()} ({top1_action[1]/total*100:.1f}% of incidents)

  Key Risk Finding:
    Phishing and credential theft are the primary attack vectors.
    Combined with high external discovery rates, this indicates
    insufficient email security and authentication controls.

  Recommended Priorities:

    1. Deploy MFA for all remote access and web applications

    2. Enhance email filtering (DMARC, DKIM, SPF + AI-based scanning)
    3. Improve internal detection with user behavior analytics (UBA)
    4. Conduct phishing simulation training quarterly
    5. Implement privileged access management (PAM) to address misuse
""")

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  VERIS Demo 03: DBIR-Style Analysis")
    print("  Healthcare Incident Dataset — 50 incidents, 3 years")
    print("=" * 60)
    actor_analysis(INCIDENTS)
    action_analysis(INCIDENTS)
    attribute_analysis(INCIDENTS)
    discovery_analysis(INCIDENTS)
    trend_analysis(INCIDENTS)
    generate_executive_summary(INCIDENTS)
```

---

## Interpreting the Output

When you run the script, focus on these analytical questions:

### Question Set 1: Actor Profile

1. What percentage of incidents involve external actors? Does this match the DBIR industry average (~75%)?
1. What is the dominant motive? What security investments does this justify?
1. Are there any partner/vendor incidents? What does this imply about third-party risk?

### Question Set 2: Action Analysis

1. What are the top 3 action categories?
1. What percentage of incidents start with phishing? What would you recommend to reduce this?
1. Is there a significant Error category? What process improvements could reduce these?

### Question Set 3: CIA Triad

1. What percentage of incidents result in data breaches (Confidentiality)?
1. What data types are most frequently exposed? What regulations apply?
1. How does the Availability percentage map to ransomware threats?

### Question Set 4: Discovery Gaps

1. What percentage of incidents are discovered externally vs. internally?
1. What is the median time-to-discovery for internally detected incidents?
1. How does the mean time-to-discovery for externally discovered incidents compare? What does this gap tell you?

---

## SOC Action Items from This Analysis

Based on a typical output from this synthetic healthcare dataset:

| Finding | SOC Action |
|---------|-----------|
| ~28% phishing | Quarterly phishing simulation + email gateway tuning |
| ~30% external discovery | Enhance SIEM correlation rules; add UBA |
| ~45% PHI breaches | Review PHI access monitoring; HIPAA notification workflows |
| ~10% misuse | Deploy DLP and privileged access monitoring |
| ~5% partner-related | Strengthen vendor security assessment program |

---

*Demo 03 | Session 11 | Security Operations Master Class | Digital4Security*
