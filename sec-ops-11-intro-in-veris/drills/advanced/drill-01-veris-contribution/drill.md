# Drill 01 (Advanced) — VERIS Contribution to VCDB

**Level:** Advanced

**Estimated time:** 60 minutes

---

## Objective

Contribute a complete, publication-quality VERIS record to a simulated VCDB workflow.
This includes sourcing incident information from public reports, coding the incident with full VERIS compliance, anonymizing the record, and submitting it through a pull-request-style workflow.

---

## Background

The VERIS Community Database (VCDB) accepts contributions from the community.
Contributors find publicly disclosed incidents (from news, regulatory filings, breach notification letters, etc.), code them using VERIS, and submit them via GitHub.
The VCDB maintainers review the submission for schema compliance, accuracy, and anonymization.

In this drill, you simulate this full workflow.

---

## Setup

```console
cd drills/advanced/drill-01-veris-contribution
docker compose up --build
```

Services:

* **VCDB Simulator:** http://localhost:9000
* **Schema validator CLI** inside the container:

```console
docker exec -it vcdb-simulator bash
python /tools/validate.py <path_to_your_record.json>
```

---

## The Workflow

### Step 1: Select an Incident

Choose one of the following published incident sources:

**Option A:** A European DPA's published breach notification decision.
Search your country's DPA website.
Examples: Irish DPC (dataprotection.ie), French CNIL (cnil.fr), German BSI (bsi.bund.de).

**Option B:** A breach notification in the HHS HIPAA Breach Portal (for US incidents): choose one with >500 records affected.

**Option C:** Use one of the curated incident summaries provided in `/data/source_incidents/` inside the container.
Three real incident summaries (anonymized) are available.

---

### Step 2: Research the Incident

Gather as much information as possible:

* Initial attack vector
* Timeline (dates of incident, discovery, notification)
* Victim organization profile (industry, size)
* Affected data types and approximate record count
* Response actions taken

---

### Step 3: Code the Incident

Produce a VERIS JSON record.
Requirements:

* Schema version: 1.3.7
* All required fields present
* Actor, action, asset, attribute sections complete
* Timeline with all available date/duration fields
* Confidence level justified

---

### Step 4: Validate the Record

```console
python /tools/validate.py your_record.json
```

Fix any validation errors before proceeding.

---

### Step 5: Anonymize the Record

For VCDB submission, victim organization names must be removed.
Replace with generic descriptors:

* Company name → "A [size] [industry] company based in [country]"
* Personal names → Remove entirely
* Specific addresses/domains → Remove or generalize

Your summary field must describe the incident without identifying the organization.

---

### Step 6: Write a Submission Rationale

Prepare a brief (200–300 word) document explaining:

1. What public source(s) you used
1. What information was confirmed vs. inferred
1. Your classification decisions for ambiguous fields
1. Why you set the confidence level you chose

---

### Step 7: Submit via the Simulator

```console
curl -X POST http://localhost:9000/submit \
  -H "Content-Type: application/json" \
  -d @your_record.json
```

The simulator will validate schema compliance, check for anonymization failures, and return feedback.

---

## Advanced Challenges

**Challenge A: Chain of Incidents**
If your chosen incident involves multiple organizations (e.g., a supply chain breach), code records for two victims.

**Challenge B: Confidence Calibration**
Write a second version of the same record at a lower confidence level.
Document which fields changed and why.

**Challenge C: Schema Extension**
Identify one aspect of your incident that VERIS doesn't capture well, and propose a schema addition or modification.
Consider backward compatibility.

---

## Deliverable

1. A validated, anonymized VERIS JSON record
1. A submission rationale document (200–300 words)
1. The simulator's validation response (screenshot or copy-paste)

See the solution in: `solutions/drill-01-solution/solution.md`
