# Solution: Drill 01 (Intermediate) — DBIR Analysis

## Overview of Approach

This solution provides the analysis code and expected findings for the healthcare threat profile and cross-industry comparison tasks.

## Setup

The solution Jupyter notebook is at `solution_notebook.ipynb`.
To run it:

```console
docker compose up --build
```

Then open http://localhost:8888 (token: `veris2024`) and run `work/solution_notebook.ipynb`.

## Task 1: Healthcare Threat Profile — Reference Answers

Using the sample dataset, expected findings for Healthcare (35 incidents):

**Actor Distribution:**

* External: ~51% (18 incidents)
* Internal: ~39% (14 incidents)
* Partner: ~10% (3 incidents)

**Top 3 Action Types:**

1. Hacking (web apps, stolen creds) — ~40%
1. Error (misconfiguration, misdelivery) — ~30%
1. Malware (ransomware) — ~20%

**Top 3 Data Varieties (in breaches):**

1. Medical/PHI — in ~85% of confidentiality breaches
1. Personal (PII) — in ~70% of breaches
1. Credentials — in ~35% of breaches

**MTTD:**

* Mean: ~420 hours (~17.5 days)
* Median: ~240 hours (~10 days)

**Breach rate:** ~60% of healthcare incidents resulted in confirmed data disclosure

## Analysis Code

```python
import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# Load dataset
with open('/data/incidents_dataset.json') as f:
    all_incidents = json.load(f)

# Filter healthcare
healthcare = [i for i in all_incidents
              if i.get('victim', {}).get('industry') == 'Healthcare']

# Actor distribution
actor_types = []
for inc in healthcare:
    actor_types.extend(inc.get('actor', {}).keys())

actor_counts = Counter(actor_types)
print("Actor distribution:", dict(actor_counts))

# Action distribution
action_types = []
for inc in healthcare:
    action_types.extend(inc.get('action', {}).keys())

action_counts = Counter(action_types)
print("Top actions:", action_counts.most_common(3))

# Breach rate
breaches = [i for i in healthcare
            if i.get('attribute', {}).get('confidentiality', {}).get('data_disclosure') == 'Yes']
breach_rate = len(breaches) / len(healthcare) * 100
print(f"Breach rate: {breach_rate:.1f}%")

# MTTD calculation
def to_hours(timeline_field):
    if not timeline_field:
        return None
    unit = timeline_field.get('unit', '')
    value = timeline_field.get('value', None)
    if value is None or unit == 'Unknown':
        return None
    multipliers = {'Minutes': 1/60, 'Hours': 1, 'Days': 24, 'Weeks': 168, 'Months': 720}
    return value * multipliers.get(unit, None)

discovery_times = []
for inc in healthcare:
    disc = inc.get('timeline', {}).get('discovery')
    hours = to_hours(disc)
    if hours:
        discovery_times.append(hours)

if discovery_times:
    print(f"MTTD Mean: {sum(discovery_times)/len(discovery_times):.1f} hours")
    discovery_series = pd.Series(discovery_times)
    print(f"MTTD Median: {discovery_series.median():.1f} hours")
```

## Task 2: Cross-Industry Comparison — Reference Chart Code

```python
industries = ['Healthcare', 'Finance', 'Retail']
industry_data = {}

for industry in industries:
    incidents = [i for i in all_incidents
                 if i.get('victim', {}).get('industry') == industry]

    actors = Counter()
    for inc in incidents:
        actors.update(inc.get('actor', {}).keys())
    industry_data[industry] = {
        'external': actors.get('external', 0) / len(incidents) * 100,
        'internal': actors.get('internal', 0) / len(incidents) * 100,
        'partner': actors.get('partner', 0) / len(incidents) * 100,
        'total': len(incidents)
    }

# Plot
fig, ax = plt.subplots(figsize=(10, 6))
x = range(len(industries))
width = 0.25

ext_vals = [industry_data[i]['external'] for i in industries]
int_vals = [industry_data[i]['internal'] for i in industries]
par_vals = [industry_data[i]['partner'] for i in industries]

ax.bar([xi - width for xi in x], ext_vals, width, label='External', color='#58a6ff')
ax.bar(x, int_vals, width, label='Internal', color='#ffa657')
ax.bar([xi + width for xi in x], par_vals, width, label='Partner', color='#56d364')

ax.set_xlabel('Industry')
ax.set_ylabel('% of Incidents')
ax.set_title('Actor Type Distribution by Industry')
ax.set_xticks(list(x))
ax.set_xticklabels(industries)
ax.legend()
plt.tight_layout()
plt.savefig('/data/actor_by_industry.png', dpi=100)
plt.show()
```

## Task 5: Healthcare CISO Brief — Model Answer

**To:** Chief Information Security Officer

**From:** Security Analysis Team

**Re:** Healthcare Sector Threat Landscape — Data-Driven Priorities

**Top 3 Threats:**

1. **Ransomware via Phishing (20% of incidents)** — External organized crime groups target healthcare for ransom due to criticality of medical records and operational uptime requirements. Average disruption: 11 days. Recommended controls: Email gateway with URL scanning, endpoint detection and response (EDR), immutable backups, and network segmentation.

1. **Misconfiguration and Accidental Exposure (30% of actions)** — Internal error is disproportionately high in healthcare due to complex IT environments and limited security awareness. Average 420-hour MTTD means misconfigurations often persist for weeks. Recommended controls: Cloud Security Posture Management (CSPM), automated configuration scanning, and mandatory security review for new systems.

1. **Insider Access Misuse (39% of incidents involve internal actors)** — Healthcare workers have broad legitimate access to PHI, creating insider risk. Controls: Role-based access control (RBAC), user and entity behavior analytics (UEBA), and regular access reviews.

**Process Recommendation:** Implement a mandatory 72-hour GDPR/HIPAA notification drill annually to ensure the incident response team can meet regulatory timelines under pressure.

**Metric to Track:** Reduce MTTD from 420 hours to under 72 hours within 12 months, measured via VERIS timeline data on all closed incidents.
