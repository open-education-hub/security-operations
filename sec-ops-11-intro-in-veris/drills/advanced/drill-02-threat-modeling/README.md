# Drill 02 (Advanced): Threat Modeling with VERIS Data

**Level:** Advanced

**Estimated time:** 60–75 minutes

---

## Objective

Use VERIS community data to build a comprehensive threat model for a given organization, including attack scenarios, likelihood estimates, and control recommendations — all grounded in empirical incident data.

---

## Background

Threat modeling is the process of identifying potential threats to an organization, assessing their likelihood and impact, and prioritizing countermeasures.
Traditional threat modeling (e.g., STRIDE, PASTA, OCTAVE) is often abstract.
VERIS data allows you to ground threat models in real incident statistics — moving from "what could happen" to "what actually happens."

---

## Setup

```console
cd drills/advanced/drill-02-threat-modeling
docker compose up --build
```

Access the analysis environment at: http://localhost:8888 (token: `veris2024`)

The full VCDB-sample dataset (500 records) is at `/data/vcdb_sample.json`.

---

## Target Organization Profile

You are a security consultant engaged by **FinTrust GmbH**, a German financial services company:

* **Industry:** Finance / Banking
* **Size:** 800 employees
* **Services:** Online banking, corporate lending, payment processing
* **Infrastructure:**
  * Public-facing web application (customer portal, mobile API)
  * On-premises data center (core banking system)
  * Azure cloud (analytics, development environments)
  * Remote workforce with VPN access
  * 120 branch employees with Windows desktops
  * Integration with 15 external payment partners
* **Regulatory obligations:** PSD2, GDPR, DORA (EU Digital Operational Resilience Act)

---

## Task 1: Data-Driven Threat Enumeration (25 points)

Using the VCDB sample dataset, identify the top 5 threat scenarios most relevant to FinTrust GmbH.

For each threat scenario:

1. Identify the specific VERIS pattern (actor + action + asset + attribute combination)
1. Show the frequency of this pattern in Finance sector incidents
1. Provide a real-world example scenario (1–2 sentences)
1. Map to one MITRE ATT&CK tactic

**Deliverable:** A table with 5 threat scenarios:

| # | Threat Scenario | VERIS Pattern | Frequency (%) | ATT&CK Tactic | Example |
|---|----------------|--------------|--------------|---------------|---------|

---

## Task 2: Attack Chain Modeling (30 points)

Select the **top 2 threat scenarios** from Task 1.
For each:

1. Draw (or describe) the full attack chain as a sequence diagram:
   * Initial access vector
   * Lateral movement (if any)
   * Target system/data
   * Exfiltration/impact method

1. Map each step to VERIS action varieties

1. Identify which step in the chain is the **critical control point** — where a single well-placed control would break the chain

1. Provide data: what % of similar incidents were stopped at this control point vs. not?

---

## Task 3: Likelihood and Impact Matrix (20 points)

For all 5 threat scenarios, build a risk matrix:

**Likelihood:** Based on VERIS frequency in Finance sector (High = >30% of incidents, Medium = 10–30%, Low = <10%)

**Impact:** Based on VERIS attribute data — consider:

* Financial impact (BEC, fraud)
* Regulatory impact (GDPR, PSD2 breach notification)
* Operational impact (availability incidents)
* Reputational impact (public disclosure)

Build a 3×3 risk matrix and position all 5 threats.
Justify each placement with data from the VERIS dataset.

---

## Task 4: Control Mapping and Residual Risk (25 points)

For the **top 3 highest-risk threats** from your matrix:

1. Identify the **current likely controls** FinTrust has (assume standard banking sector baseline):
   * Email gateway with spam/phishing filtering
   * Endpoint antivirus and EDR
   * WAF on public web application
   * MFA for employee VPN
   * Annual security awareness training
   * SOC with SIEM (8×5 monitoring)

1. For each threat, assess: **which existing controls reduce this risk, and how much?**

1. **Identify the residual risk** — what portion of this threat remains after existing controls?

1. Recommend **3 additional controls** that would have the highest combined risk reduction:
   * Cite the VERIS data that justifies each control choice
   * Estimate the % reduction in incident frequency each control would achieve
   * Consider cost and complexity

---

## Task 5: DORA Compliance Alignment (bonus, 10 points)

The EU Digital Operational Resilience Act (DORA) requires financial entities to perform threat-led penetration testing (TLPT) and ICT risk assessments.

Using your threat model:

1. Which of your 5 threat scenarios would be covered by DORA's TLPT requirements?
1. What VERIS-based metrics would you report to satisfy DORA's incident reporting obligations?
1. How would VERIS data support DORA's requirement for "ICT-related incident classification"?

---

## Analysis Code Template

```python
import json
import pandas as pd
from collections import Counter, defaultdict

# Load VCDB sample
with open('/data/vcdb_sample.json') as f:
    all_records = json.load(f)

# Filter Finance sector
finance = [r for r in all_records
           if r.get('victim', {}).get('industry') == 'Finance']

print(f"Total records: {len(all_records)}")
print(f"Finance records: {len(finance)}")

# Identify top VERIS patterns in Finance
# A "pattern" = dominant actor type + dominant action type + top attribute
patterns = []
for r in finance:
    actor = list(r.get('actor', {}).keys())[0] if r.get('actor') else 'unknown'
    actions = list(r.get('action', {}).keys())
    action = actions[0] if actions else 'unknown'
    attrs = list(r.get('attribute', {}).keys())
    attr = attrs[0] if attrs else 'unknown'
    patterns.append((actor, action, attr))

pattern_counts = Counter(patterns)
print("\nTop 5 Finance threat patterns:")
for pattern, count in pattern_counts.most_common(5):
    pct = count / len(finance) * 100
    print(f"  {pattern}: {count} ({pct:.1f}%)")
```

---

## Deliverable

A threat model report (can be in Jupyter notebook or Markdown) including:

1. Task 1 table (5 threat scenarios)
1. Task 2 attack chain descriptions (2 chains)
1. Task 3 risk matrix (visualization)
1. Task 4 control mapping and recommendations

See `solutions/drill-02-solution/` for a model report.
