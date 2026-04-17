# Drill 01 (Intermediate): DBIR Analysis — Industry Threat Profile

**Level:** Intermediate

**Estimated time:** 45 minutes

---

## Objective

Use a provided dataset of VERIS-coded incidents to build a comprehensive threat profile for a specific industry sector, and derive actionable security recommendations.

---

## Setup

```console
cd drills/intermediate/drill-01-dbir-analysis
docker compose up --build
```

Access the Jupyter notebook at: http://localhost:8888 (token: `veris2024`)

Open `work/threat_profile.ipynb` to begin.

---

## Dataset

The dataset is located at `/data/incidents_dataset.json` and contains 150 VERIS-coded incidents across multiple industries:

* Healthcare (35 incidents)
* Finance (30 incidents)
* Retail (25 incidents)
* Manufacturing (20 incidents)
* Education (20 incidents)
* Other (20 incidents)

---

## Tasks

### Task 1: Healthcare Threat Profile (25 points)

Using the dataset, answer these questions for the **Healthcare** sector:

1. What is the distribution of actor types (external vs. internal vs. partner)?
1. What are the top 3 action types by frequency?
1. What are the top 3 data varieties affected in confidentiality breaches?
1. What is the mean and median time to detect (MTTD) in hours?
1. What percentage of healthcare incidents resulted in confirmed data breaches?

Present your findings as both numeric values and a brief narrative (3–5 sentences).

### Task 2: Cross-Industry Comparison (20 points)

Compare the healthcare findings with **Finance** and **Retail**:

1. Create a bar chart comparing actor type distribution across all three industries
1. Create a bar chart comparing top 3 action types across all three industries
1. Write a 200-word analysis explaining the key differences and what they imply for security programs

### Task 3: MTTD Trend Analysis (15 points)

Analyze MTTD (time to detect) across all industries:

1. Which industry has the lowest (best) average MTTD?
1. Which has the highest (worst)?
1. What factors from the VERIS data might explain the difference? (Consider action types, asset types)

### Task 4: Detection-to-Containment Gap (15 points)

For incidents where both `discovery` and `containment` timeline fields are available:

1. Calculate the mean time from discovery to containment (MTTC)
1. Are there any incidents where containment took more than 30 days?
1. What action types are most associated with longer containment times?

### Task 5: Security Recommendations (25 points)

Based on your analysis, write a 400-word security brief for the CISO of a healthcare organization.
Include:

1. The top 3 threats your organization faces (backed by dataset numbers)
1. Three specific technical controls that address those threats
1. One process/policy recommendation
1. One metric to track improvement over time

---

## Hints

* Use `pandas` for data manipulation and `matplotlib` or `seaborn` for charts
* The dataset is a list of VERIS JSON objects — you may need to flatten nested structures for analysis
* When calculating MTTD, normalize time units (Minutes → Hours, Days → Hours, etc.)
* Not all records have complete timeline data — handle missing values appropriately
* Use `df.groupby()` for cross-industry comparisons

---

## Deliverable

A completed Jupyter notebook with all cells executed, charts embedded, and written analysis for Tasks 2, 3, 4, and 5.

See `solutions/drill-01-solution/` for the reference solution.
