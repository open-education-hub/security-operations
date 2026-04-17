# Demo 02 — Analyzing DBIR Data with Python

**Duration:** 25 minutes

**Format:** Docker-based Jupyter notebook

**Difficulty:** Beginner–Intermediate

---

## Overview

In this demo, we use a local Jupyter notebook environment to analyze a sample dataset of VERIS-coded incidents (inspired by DBIR-style data).
You will perform basic statistical analysis, generate visualizations, and answer questions similar to those found in the annual Verizon Data Breach Investigations Report.

---

## Learning Objectives

* Load and parse a collection of VERIS JSON records
* Calculate incident statistics by actor, action, and industry
* Produce bar charts and breakdowns similar to DBIR visualizations
* Interpret statistical findings in the context of security operations

---

## Setup

```console
cd demos/demo-02-dbir-analysis
docker compose up --build
```

Wait for the message:

```text
Jupyter Server is running at: http://127.0.0.1:8888/lab?token=...
```

Open the URL in your browser and navigate to `notebooks/dbir_analysis.ipynb`.

---

## Walk-through

### Step 1: Load the Dataset

```python
import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# Load all incident records
with open('/data/incidents.json') as f:
    incidents = json.load(f)

print(f"Total incidents: {len(incidents)}")
```

### Step 2: Extract Actor Types

```python
actor_types = []
for incident in incidents:
    for actor_type in incident.get('actor', {}).keys():
        actor_types.append(actor_type)

actor_counts = Counter(actor_types)
print("Actor breakdown:", dict(actor_counts))

plt.figure(figsize=(8, 5))
plt.bar(actor_counts.keys(), actor_counts.values(), color=['#58a6ff', '#ffa657', '#56d364'])
plt.title('Incidents by Actor Type')
plt.xlabel('Actor Type')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig('/data/actor_breakdown.png', dpi=100)
plt.show()
```

### Step 3: Identify Top Attack Vectors

```python
action_types = []
for incident in incidents:
    for action_type in incident.get('action', {}).keys():
        action_types.append(action_type)

action_counts = Counter(action_types)
print("Action breakdown:", dict(action_counts))

vectors = []
for incident in incidents:
    for action_type, details in incident.get('action', {}).items():
        for v in details.get('vector', []):
            vectors.append(v)

vector_counts = Counter(vectors)
print("\nTop 10 vectors:")
for v, c in vector_counts.most_common(10):
    print(f"  {v}: {c}")
```

### Step 4: Industry Breakdown

```python
industries = []
for incident in incidents:
    ind = incident.get('victim', {}).get('industry', 'Unknown')
    industries.append(ind)

industry_counts = Counter(industries)
top_industries = dict(industry_counts.most_common(8))

plt.figure(figsize=(10, 5))
plt.barh(list(top_industries.keys()), list(top_industries.values()), color='#ffa657')
plt.title('Incidents by Industry')
plt.xlabel('Count')
plt.tight_layout()
plt.savefig('/data/industry_breakdown.png', dpi=100)
plt.show()
```

### Step 5: Timeline Analysis — Mean Time to Detect

```python
discovery_times = []
for incident in incidents:
    timeline = incident.get('timeline', {})
    if 'discovery' in timeline:
        disc = timeline['discovery']
        if disc.get('unit') == 'Hours':
            discovery_times.append(disc['value'])
        elif disc.get('unit') == 'Days':
            discovery_times.append(disc['value'] * 24)
        elif disc.get('unit') == 'Minutes':
            discovery_times.append(disc['value'] / 60)

if discovery_times:
    mttd_hours = sum(discovery_times) / len(discovery_times)
    print(f"Mean Time to Detect: {mttd_hours:.1f} hours ({mttd_hours/24:.1f} days)")
    print(f"Min: {min(discovery_times):.1f} hours")
    print(f"Max: {max(discovery_times):.1f} hours")
```

### Step 6: Breach vs. Incident

```python
breaches = []
incidents_only = []

for record in incidents:
    disclosure = record.get('attribute', {}).get('confidentiality', {}).get('data_disclosure', 'No')
    if disclosure == 'Yes':
        breaches.append(record)
    else:
        incidents_only.append(record)

breach_rate = len(breaches) / len(incidents) * 100
print(f"Breach rate: {breach_rate:.1f}%")
print(f"Breaches: {len(breaches)}")
print(f"Incidents (no confirmed disclosure): {len(incidents_only)}")

total_records = 0
for breach in breaches:
    for data_item in breach.get('attribute', {}).get('confidentiality', {}).get('data', []):
        total_records += data_item.get('amount', 0)

print(f"\nTotal records exposed across all breaches: {total_records:,}")
```

### Step 7: Replicate a DBIR-Style Finding

```python
# "What percentage of breaches involved external actors?"
external_breaches = 0
for breach in breaches:
    if 'external' in breach.get('actor', {}):
        external_breaches += 1

pct = external_breaches / len(breaches) * 100 if breaches else 0
print(f"External actor in breaches: {pct:.0f}%")
print(f"(DBIR 2023 finding: ~83% of breaches involve external actors)")
```

---

## Discussion Points

1. **Sample size matters:** Our dataset has 50 records — the real DBIR analyzes thousands. How does sample size affect confidence in findings?

1. **Selection bias:** VCDB is built from publicly reported incidents. What types of incidents are likely under-represented?

1. **Trend vs. snapshot:** A single year's data is a snapshot. How would you look for trends over multiple years?

1. **Industry comparison:** Why might healthcare and finance appear frequently in breach data compared to agriculture?

---

## Clean Up

```console
docker compose down
```
