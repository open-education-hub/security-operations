# Guide 01 (Intermediate): Trend Analysis Using VERIS Data

**Level:** Intermediate

**Estimated time:** 60 minutes

**Directory:** `guides/intermediate/guide-01-veris-analysis/`

**Prerequisites:** Basic guides 01–03, Python 3.8+, basic statistical concepts

---

## Purpose

This guide teaches you to perform threat landscape trend analysis using VERIS-encoded incident data.
You will learn how to load, clean, query, and visualize VERIS data to answer real analytical questions, produce actionable SOC insights, and create executive-level threat reports.

---

## 1. The Analytical Value of VERIS Data

When VERIS records are collected over time, they become a powerful analytical dataset.
Unlike raw log files or unstructured incident reports, VERIS data is structured, enumerated, and designed for statistical aggregation.

### Questions VERIS Trend Analysis Can Answer

**Tactical questions** (for SOC analysts):

* What are the most common initial access methods in the past 12 months?
* How has mean time-to-detection changed quarter over quarter?
* Are internal actor incidents increasing?
* Which asset types appear most frequently in high-severity incidents?

**Strategic questions** (for CISOs and management):

* How does our incident profile compare to industry benchmarks?
* What percentage of our incidents are preventable vs. unavoidable?
* Is our investment in email security reducing phishing-related incidents?
* What is our breach rate (incidents with data disclosure / total incidents)?

**Industry intelligence questions** (using VCDB/DBIR data):

* What attack patterns are most prevalent in our industry?
* How have threat actor profiles changed over the past 3 years?
* What DBIR Incident Classification Pattern matches most of our incidents?

---

## 2. Loading and Structuring VERIS Data

### 2.1 Loading VCDB Data

```python
import json
import os
from pathlib import Path

def load_vcdb_records(vcdb_dir: str) -> list:
    """Load all VERIS JSON records from a VCDB directory."""
    records = []
    vcdb_path = Path(vcdb_dir)
    for json_file in vcdb_path.glob("*.json"):
        try:
            with open(json_file) as f:
                record = json.load(f)
                records.append(record)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading {json_file}: {e}")
    return records

# Load records
records = load_vcdb_records("/path/to/VCDB/data/json/validated")
print(f"Loaded {len(records)} records")
```

### 2.2 Loading Internal Records

If you maintain an internal VERIS database (recommended), the structure is identical:

```python
def load_internal_records(records_dir: str) -> list:
    """Load internal VERIS records, adding a source tag."""
    records = load_vcdb_records(records_dir)
    for r in records:
        r["_source"] = "internal"
    return records
```

### 2.3 Flattening for Analysis

VERIS records are hierarchical JSON.
For tabular analysis, flatten the key dimensions:

```python
def flatten_record(record: dict) -> dict:
    """Extract key analytical fields into a flat dict."""
    flat = {
        "incident_id": record.get("incident_id", ""),
        "year": record.get("timeline", {}).get("incident", {}).get("year"),
        "month": record.get("timeline", {}).get("incident", {}).get("month"),
        "industry": record.get("victim", {}).get("industry", "Unknown"),
        "industry2": record.get("victim", {}).get("industry2", "Unknown"),
        "employee_size": record.get("victim", {}).get("employee_count", "Unknown"),
        "country": record.get("victim", {}).get("country", ["Unknown"])[0],
        "confidence": record.get("confidence", "Unknown"),
        "actor_types": list(record.get("actor", {}).keys()),
        "action_types": list(record.get("action", {}).keys()),
        "attribute_types": list(record.get("attribute", {}).keys()),
        "discovery_type": _get_discovery_type(record),
        "discovery_days": record.get("timeline", {}).get("discovery", {}).get("value"),
        "is_breach": _is_breach(record),
        "data_total": record.get("attribute", {}).get("confidentiality", {}).get("data_total"),
        "actor_varieties": _get_actor_varieties(record),
        "action_varieties": _get_action_varieties(record),
        "data_types": _get_data_types(record),
    }
    return flat

def _is_breach(record: dict) -> bool:
    conf = record.get("attribute", {}).get("confidentiality", {})
    return conf.get("data_disclosure") in ["Yes", "Potentially"]

def _get_discovery_type(record: dict) -> str:
    disc = record.get("discovery_method", {})
    if disc.get("internal"):
        return "internal"
    elif disc.get("external"):
        return "external"
    elif disc.get("partner"):
        return "partner"
    return "unknown"

def _get_actor_varieties(record: dict) -> list:
    varieties = []
    for actor_data in record.get("actor", {}).values():
        varieties.extend(actor_data.get("variety", []))
    return varieties

def _get_action_varieties(record: dict) -> list:
    varieties = []
    for action_data in record.get("action", {}).values():
        varieties.extend(action_data.get("variety", []))
    return varieties

def _get_data_types(record: dict) -> list:
    conf = record.get("attribute", {}).get("confidentiality", {})
    return [d.get("variety", "Unknown") for d in conf.get("data", [])]
```

---

## 3. Core Analytical Techniques

### 3.1 Frequency Analysis

The most fundamental analysis: how often does each value appear?

```python
from collections import Counter

def frequency_analysis(flat_records: list, field: str, top_n: int = 10):
    """Count frequency of values in a field (handles both scalar and list fields)."""
    counter = Counter()
    for rec in flat_records:
        val = rec.get(field)
        if isinstance(val, list):
            for item in val:
                counter[item] += 1
        elif val is not None:
            counter[val] += 1

    total = len(flat_records)
    print(f"\nFrequency Analysis: {field} (n={total})")
    print("─" * 50)
    for k, v in counter.most_common(top_n):
        pct = v / total * 100
        bar = "█" * int(pct / 2)
        print(f"  {k:<35} {bar:<25} {pct:5.1f}% ({v})")
    return counter

# Usage examples:
# frequency_analysis(flat_records, "actor_types")
# frequency_analysis(flat_records, "action_varieties", top_n=15)
# frequency_analysis(flat_records, "data_types")
```

### 3.2 Cross-Tabulation

Examine relationships between two dimensions:

```python
def cross_tabulation(flat_records: list, dim1: str, dim2: str):
    """Cross-tabulate two VERIS dimensions."""
    from collections import defaultdict

    table = defaultdict(Counter)
    for rec in flat_records:
        vals1 = rec.get(dim1, [])
        vals2 = rec.get(dim2, [])
        if not isinstance(vals1, list): vals1 = [vals1]
        if not isinstance(vals2, list): vals2 = [vals2]
        for v1 in vals1:
            for v2 in vals2:
                table[v1][v2] += 1

    print(f"\nCross-Tabulation: {dim1} × {dim2}")
    print("─" * 60)
    for v1, counts in sorted(table.items(), key=lambda x: -sum(x[1].values())):
        total = sum(counts.values())
        top_v2 = counts.most_common(3)
        print(f"  {v1:<20} (n={total:3d}) → {', '.join(f'{k}({v})' for k, v in top_v2)}")
    return table

# Example: "When external actor, what are the most common actions?"
# cross_tabulation(flat_records, "actor_types", "action_types")
```

### 3.3 Time-Series Analysis

Track changes over time:

```python
def time_series_analysis(flat_records: list, field: str, value: str):
    """Count occurrences of a specific value per year."""
    from collections import defaultdict

    by_year = defaultdict(int)
    total_by_year = defaultdict(int)

    for rec in flat_records:
        year = rec.get("year")
        if year is None:
            continue
        total_by_year[year] += 1
        vals = rec.get(field, [])
        if not isinstance(vals, list): vals = [vals]
        if value in vals:
            by_year[year] += 1

    print(f"\nTime Series: '{value}' in {field}")
    print("─" * 50)
    for year in sorted(total_by_year.keys()):
        count = by_year[year]
        total = total_by_year[year]
        pct = count / total * 100 if total > 0 else 0
        bar = "█" * int(pct / 3)
        print(f"  {year}: {bar:<35} {pct:5.1f}% ({count}/{total})")

    return by_year, total_by_year
```

### 3.4 Dwell Time Analysis

Analyze time-to-discovery patterns:

```python
from statistics import mean, median, stdev

def dwell_time_analysis(flat_records: list):
    """Analyze discovery time statistics."""
    all_days = [r["discovery_days"] for r in flat_records
                if r.get("discovery_days") and r["discovery_days"] > 0]
    int_days = [r["discovery_days"] for r in flat_records
                if r.get("discovery_days") and r["discovery_days"] > 0
                and r.get("discovery_type") == "internal"]
    ext_days = [r["discovery_days"] for r in flat_records
                if r.get("discovery_days") and r["discovery_days"] > 0
                and r.get("discovery_type") == "external"]

    def stats(days, label):
        if not days:
            return
        print(f"\n  {label} (n={len(days)}):")
        print(f"    Mean:   {mean(days):6.1f} days")
        print(f"    Median: {median(days):6.1f} days")
        print(f"    Min:    {min(days):6d} days")
        print(f"    Max:    {max(days):6d} days")
        if len(days) > 1:
            print(f"    StdDev: {stdev(days):6.1f} days")
        # Percentiles
        sorted_days = sorted(days)
        n = len(sorted_days)
        p50 = sorted_days[int(n * 0.50)]
        p75 = sorted_days[int(n * 0.75)]
        p90 = sorted_days[int(n * 0.90)]
        print(f"    P50/P75/P90: {p50}/{p75}/{p90} days")

    print("\nDwell Time Analysis")
    print("─" * 50)
    stats(all_days, "All incidents")
    stats(int_days, "Internally detected")
    stats(ext_days, "Externally detected")

    # Discovery gap
    if int_days and ext_days:
        gap = mean(ext_days) - mean(int_days)
        print(f"\n  Detection gap: {gap:.1f} days (ext_mean - int_mean)")
        print(f"  Externally detected incidents took {gap:.0f} more days to discover.")
```

---

## 4. Industry Benchmarking

### 4.1 Filtering by Industry

```python
def filter_by_industry(flat_records: list, naics_prefix: str) -> list:
    """Filter records by NAICS industry prefix (e.g., '62' for healthcare)."""
    return [r for r in flat_records
            if str(r.get("industry", "")).startswith(naics_prefix)]

def filter_by_year_range(flat_records: list, start: int, end: int) -> list:
    """Filter records by year range."""
    return [r for r in flat_records
            if r.get("year") and start <= r["year"] <= end]
```

### 4.2 Breach Rate Analysis

```python
def breach_rate_analysis(flat_records: list, group_by: str = None):
    """Calculate breach rate (incidents with data disclosure / total incidents)."""
    if group_by is None:
        total = len(flat_records)
        breaches = sum(1 for r in flat_records if r.get("is_breach"))
        pct = breaches / total * 100 if total > 0 else 0
        print(f"\nBreach Rate: {breaches}/{total} = {pct:.1f}%")
    else:
        from collections import defaultdict
        groups = defaultdict(list)
        for rec in flat_records:
            val = rec.get(group_by, "Unknown")
            if isinstance(val, list): val = val[0] if val else "Unknown"
            groups[val].append(rec)

        print(f"\nBreach Rate by {group_by}:")
        print("─" * 50)
        for group in sorted(groups, key=lambda g: -len(groups[g]))[:10]:
            recs = groups[group]
            total = len(recs)
            breaches = sum(1 for r in recs if r.get("is_breach"))
            pct = breaches / total * 100
            print(f"  {group:<30} {breaches:3d}/{total:3d} = {pct:5.1f}%")
```

---

## 5. Producing an Analytical Report

Here is a template for a complete VERIS trend analysis report:

```python
def produce_threat_landscape_report(records: list, org_name: str,
                                     industry_naics: str, years: list):
    """
    Produce a complete threat landscape report from VERIS records.
    records: list of flat VERIS records
    org_name: name of organization or industry label
    industry_naics: NAICS prefix for filtering (e.g., "52" for Finance)
    years: list of years to include
    """
    # Filter to industry and years
    industry_records = filter_by_industry(records, industry_naics)
    filtered = [r for r in industry_records if r.get("year") in years]

    print(f"\n{'=' * 65}")
    print(f"  THREAT LANDSCAPE REPORT: {org_name}")
    print(f"  Industry: NAICS {industry_naics} | Years: {min(years)}–{max(years)}")
    print(f"  Records analyzed: {len(filtered)}")
    print(f"{'=' * 65}")

    # 1. Executive Summary
    print(f"\n  EXECUTIVE SUMMARY")
    breach_rate_analysis(filtered)

    # 2. Actor Profile
    frequency_analysis(filtered, "actor_types", top_n=5)
    frequency_analysis(filtered, "actor_varieties", top_n=5)

    # 3. Action Profile
    frequency_analysis(filtered, "action_types", top_n=7)
    frequency_analysis(filtered, "action_varieties", top_n=10)

    # 4. Attribute Profile
    frequency_analysis(filtered, "attribute_types", top_n=3)
    frequency_analysis(filtered, "data_types", top_n=8)

    # 5. Dwell Time
    dwell_time_analysis(filtered)

    # 6. Key Trends
    for action_variety in ["Phishing", "Ransomware", "Use of stolen credentials"]:
        time_series_analysis(filtered, "action_varieties", action_variety)

    print(f"\n{'=' * 65}")
    print("  END OF REPORT")
    print(f"{'=' * 65}\n")
```

---

## 6. Practical Exercises

### Exercise 1: VCDB Healthcare Filter

1. Clone the VCDB repository: `git clone https://github.com/vz-risk/VCDB.git`
1. Load all records using the `load_vcdb_records()` function
1. Filter to healthcare (NAICS prefix "62")
1. Run frequency analysis on action_varieties
1. Compare to DBIR healthcare findings from the current year's report

### Exercise 2: Your Organization's Trend Report

1. Create VERIS records for your last 10 security incidents
1. Flatten them using `flatten_record()`
1. Run the full analytical report
1. Identify any anomalies vs. VCDB healthcare benchmarks

### Exercise 3: Attack Chain Analysis

Write a function that identifies incidents where Phishing (Social > Phishing) is followed by Use of stolen credentials (Hacking > Use of stolen credentials).
Count how many incidents follow this exact attack chain vs. other patterns.

---

## 7. Interpreting Results: Common Patterns

### Pattern: High External Discovery Rate

If more than 40% of incidents are discovered externally:

**What it means**: Your organization is not detecting incidents before attackers or third parties notify you.

**Root causes**: Insufficient SIEM coverage, lack of threat hunting, no UBA/UEBA, missing detection rules.

**Action**: Audit detection coverage against MITRE ATT&CK; implement threat hunting; review SIEM correlation rules.

### Pattern: Phishing Dominates Initial Access

If phishing accounts for >25% of incidents:

**What it means**: Email is your primary attack surface and current controls are insufficient.

**Root causes**: Inadequate email filtering, insufficient user training, no MFA to limit credential theft impact.

**Action**: Implement advanced email filtering; quarterly phishing simulations; enforce MFA on all internet-exposed services.

### Pattern: High Error Rate

If errors (misconfiguration, misdelivery) account for >20% of incidents:

**What it means**: Operational security controls and change management processes have gaps.

**Root causes**: No mandatory peer review for security configurations, missing DLP controls, insufficient training.

**Action**: Implement change management approval for cloud configurations; deploy DLP; train staff on data handling.

### Pattern: Rising Ransomware Frequency

Year-over-year increase in Malware > Ransomware:

**What it means**: Existing controls are not keeping pace with ransomware evolution.

**Root causes**: Insufficient email filtering, no EDR, inadequate backup validation, slow patching.

**Action**: Deploy EDR on all endpoints; test backup recovery; implement application whitelisting; accelerate patch cycles.

---

## 8. Data Quality Considerations

VERIS analysis is only as good as the underlying data.
When interpreting results, account for:

**Completeness bias**: Are all incidents being recorded, or only the "interesting" ones?
Missing Error incidents will skew action analysis toward malicious actors.

**Temporal bias**: Did recording practices change over time?
An apparent increase in phishing incidents might reflect better detection and recording, not an actual increase.

**Confidence weighting**: Records with confidence "Low" should be weighted differently than "High" confidence records in statistical analysis.

**Sample size warnings**: For samples below 30 incidents, statistical conclusions are unreliable.
Use narrative description rather than percentages.

---

## Key Takeaways

1. **VERIS data enables systematic threat landscape analysis** through frequency analysis, cross-tabulation, and time-series tracking.

1. **Flatten records for tabular analysis** but preserve the source JSON for detailed queries.

1. **Benchmark internally against VCDB/DBIR** to contextualize your organization's patterns.

1. **Discovery method analysis reveals detection gaps** — externally discovered incidents indicate program weaknesses.

1. **Trend analysis requires consistent recording** — gaps in recording quality undermine trend conclusions.

1. **Combine quantitative findings with qualitative narrative** for actionable reports.

---

*Guide 01 (Intermediate) | Session 11 | Security Operations Master Class | Digital4Security*
