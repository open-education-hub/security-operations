# Solution: Drill 01 (Advanced) — VERIS-Based Incident Tracking Program

**Level:** Advanced

**Directory:** `drills/advanced/solutions/drill-01-solution/`

---

## Part 1: Program Design Document — Model Answer

### 1.1 Scope and Objectives

**Recordable Incidents**: Any event that meets one or more of these criteria:

* Confirmed or suspected violation of Meridian's security or privacy policy
* Unauthorized access or disclosure of customer, employee, or organizational data
* Disruption of business systems with potential security cause
* Malware detection with successful execution (not blocked at gateway)
* Physical security breach involving IT assets

**Not recorded** in VERIS: Security events that were blocked at perimeter (firewall drops, AV blocks at gateway).
These are logged in SIEM but do not constitute incidents unless investigation confirms policy violation.

**Minimum to open a VERIS record**:

* incident_id (auto-generated)
* security_incident: "Suspected" initially, updated to "Confirmed" or "False positive" at close
* Summary (1 sentence minimum)
* Timeline: incident year and month
* At least preliminary Actor type and Action category

**Ownership**: SOC analyst opens record; SOC lead reviews within 24h; Legal/Compliance reviews all Confidentiality records; CISO approves "Major" impact records.

**Retention**: VERIS records retained for 7 years (meets SOX and GLBA requirements).

### 1.2 VERIS Record Lifecycle

| Stage | Fields Populated | Responsible | Timeline |
|-------|----------------|-------------|---------|
| Detection | incident_id, source_id, security_incident="Suspected", summary, timeline.incident, preliminary actor/action | Analyst on-call | Within 1 hour of detection |
| Triage | Actor type, Action category, Asset type, initial Attribute | Tier 1 analyst | Within 4 hours |
| Investigation | All 4A detailed fields, discovery_method, timeline.discovery | Tier 2 analyst | During active investigation |
| Encoding | All remaining fields, victim details, complete attribute data_types | Lead analyst | Within 48h of containment |
| Review | Confidence level, breach determination | SOC Lead + Legal | Within 72h |
| Close | impact, overall_rating, notes, lessons learned | SOC Lead | Within 5 business days |

### 1.3 Field Requirements

**Required for ALL records:**

* incident_id, source_id, security_incident, summary, confidence
* timeline.incident.year
* victim.industry
* actor (at least type)
* action (at least category)
* asset (at least variety)
* attribute (at least type)
* discovery_method

**Required ONLY for Breaches (Confidentiality.data_disclosure = Yes/Potentially):**

* attribute.confidentiality.data[].variety
* attribute.confidentiality.data_total
* attribute.confidentiality.data_victim
* timeline.discovery (for notification deadline calculation)
* impact.loss (for cost tracking)
* Notes: regulatory obligations applicable

**Optional but recommended:**

* All timeline sub-fields
* victim.employee_count, country
* actor.motive, actor.country
* action.vector for all actions
* action.cve (if applicable)
* asset.cloud
* impact.overall_rating

---

## Part 2: Classification Policy — Model Answer

### Meridian Financial Group — VERIS Incident Classification Policy (v1.0)

**2a.
Lost/Stolen Unencrypted Laptop**

A lost/stolen unencrypted laptop containing PII, financial data, or credentials is classified as:

* `action.error.variety: ["Loss"]`
* `attribute.confidentiality.data_disclosure: "Potentially"`

**Regulatory trigger**: GLBA requires a risk assessment.
If the risk assessment determines the data is "reasonably at risk" of compromise, GLBA notification is required.
State laws (many use a "reasonably believe" standard) may require notification.
Record as "Potentially" and document the risk assessment outcome.
Upgrade to "Yes" if evidence of access is found.

**2b.
Cloud Misconfiguration with Uncertain Data Access**

Record `data_disclosure: "Potentially"` when:

* Data was publicly accessible (bucket public read/write, open Elasticsearch, etc.)
* No confirmed evidence of access has been found

Upgrade to `data_disclosure: "Yes"` when:

* Access logs show external access
* The data was indexed by a search engine (confirms crawling)
* A security researcher or third party reports finding the data

Downgrade to `data_disclosure: "No"` only when:

* The exposed resource contained no actual sensitive data, OR
* Forensic analysis definitively shows no external access

**2c.
Blocked Phishing Emails**

**Do not record** in VERIS: phishing emails blocked entirely at the email gateway before delivery.

**Record in VERIS** if: The phishing email was delivered to user inboxes (even if no user clicked), the phishing email was clicked but payload blocked by endpoint protection, or the phishing email resulted in any user interaction.

Rationale: Blocked-at-gateway events are security events, not incidents.
Delivered phishing emails represent a security incident (policy violation) regardless of whether the payload was executed.

**2d.
Ransomware — Pre/Post Forensic Investigation**

At initial discovery (before forensics): Record ransomware with Integrity + Availability attributes.
Do NOT record Confidentiality unless evidence of exfiltration already exists.

After forensic investigation:

* If exfiltration confirmed: Add Confidentiality attribute, `data_disclosure: "Yes"`, update data types and amounts.
* If exfiltration definitively ruled out: Keep Integrity + Availability only.
* If exfiltration inconclusive: Consider adding Confidentiality `data_disclosure: "Potentially"` for double-extortion variants.

VERIS records can be updated post-investigation.
Document what changed and when.

**2e.
Nation-State vs.
Unknown Attribution**

Use `actor.external.variety: ["Nation-state"]` only when:

* Government attribution exists (official government statement, FBI/CISA advisory)
* Attribution based on TTP overlap with known nation-state groups (documented in threat intelligence platform) AND reviewed by senior analyst
* Pattern matches multiple nation-state indicators (custom tooling, long dwell time, strategic targeting)

Use `actor.external.variety: ["Unknown"]` when:

* Attribution is based on IP geolocation alone
* Attribution is speculation based on target type
* Attribution has not been confirmed by a qualified threat intelligence source

**Conservative attribution is always preferred.** False attribution has legal and diplomatic consequences.

---

## Part 3: Metrics Framework — Model Answer

| # | Metric Name | Formula | What It Measures | Target | Notes |
|---|------------|---------|-----------------|--------|-------|
| 1 | Breach Rate | `#(conf_disclosure=Yes) / #total_incidents` | What % of incidents result in confirmed data breaches | < 40% | High rates indicate data classification/DLP gaps |
| 2 | Mean Time to Detect (MTTD) | `mean(discovery.value)` normalized to days | How quickly incidents are discovered | < 7 days | Compare to DBIR industry average |
| 3 | Internal Detection Rate | `#(discovery_method.internal) / #total` | % discovered by own team vs. externally | > 70% | Higher is better; < 50% indicates major detection gap |
| 4 | External Actor Rate | `#(actor.external) / #total` | % of incidents from external threats | Benchmark vs. DBIR | Expected ~70–75%; higher may indicate poor internal controls |
| 5 | Error Incident Rate | `#(action.error) / #total` | % of incidents from unintentional actions | < 20% | High rate indicates training/process gaps |
| 6 | Phishing Initial Access Rate | `#(action.social.variety contains Phishing) / #total` | How often phishing is initial vector | < 15% (post-training) | Track reduction after phishing simulation program |
| 7 | PHI/PII Breach Rate | `#(attribute.confidentiality.data types contains Personal/Bank) / #breach_incidents` | % of breaches involving regulated data | Minimize | Drives regulatory notification burden |
| 8 | Mean Days to Contain (MTTC) | `mean(containment.value)` normalized to days | How quickly incidents are contained after discovery | < 1 day | Longer = higher risk of ongoing damage |

---

## Part 4: Python Implementation — Model Answer

```python
#!/usr/bin/env python3
"""
VERIS Incident Tracking Program — Meridian Financial Group
Drill 01 (Advanced) Solution
"""
import uuid
import json
from datetime import datetime
from statistics import mean
from collections import Counter

def generate_template(incident_type: str) -> dict:
    """Generate a pre-populated VERIS template for common incident types."""
    base = {
        "schema_version": "1.3.7",
        "incident_id": str(uuid.uuid4()),
        "source_id": "meridian-financial",
        "summary": f"[PLACEHOLDER: Describe the {incident_type} incident]",
        "confidence": "Low",
        "security_incident": "Suspected",
        "timeline": {
            "incident": {"year": datetime.now().year, "month": datetime.now().month}
        },
        "victim": {
            "industry": "522110",
            "employee_count": "1001 to 10000",
            "country": ["US"]
        }
    }

    templates = {
        "phishing": {
            "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
            "action": {"social": {"variety": ["Phishing"], "vector": ["Email"]}},
            "asset": {"assets": [{"variety": "P - End-user", "amount": 1}]},
            "attribute": {"confidentiality": {"data_disclosure": "Unknown", "data": []}}
        },
        "ransomware": {
            "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
            "action": {
                "social": {"variety": ["Phishing"], "vector": ["Email"]},
                "malware": {"variety": ["Ransomware"], "vector": ["Email attachment"]}
            },
            "asset": {"assets": [{"variety": "U - Desktop", "amount": -1}]},
            "attribute": {
                "integrity": {"variety": ["Software installation"]},
                "availability": {"variety": ["Encryption"], "duration": {"unit": "Unknown", "value": -1}}
            }
        },
        "misconfiguration": {
            "actor": {"internal": {"variety": ["System administrator"], "motive": ["Negligence"]}},
            "action": {"error": {"variety": ["Misconfiguration"], "vector": ["Unknown"]}},
            "asset": {"assets": [{"variety": "S - Database", "amount": 1}], "cloud": ["Yes"]},
            "attribute": {"confidentiality": {"data_disclosure": "Potentially", "data": []}}
        },
        "credential_theft": {
            "actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"]}},
            "action": {
                "social": {"variety": ["Phishing"], "vector": ["Email"]},
                "hacking": {"variety": ["Use of stolen credentials"], "vector": ["Web application"]}
            },
            "asset": {"assets": [{"variety": "S - Authentication", "amount": 1}]},
            "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": [{"variety": "Credentials", "amount": -1}]}}
        },
        "insider_misuse": {
            "actor": {"internal": {"variety": ["End-user"], "motive": ["Financial"]}},
            "action": {"misuse": {"variety": ["Privilege abuse"], "vector": ["Internal network access"]}},
            "asset": {"assets": [{"variety": "S - Database", "amount": 1}]},
            "attribute": {"confidentiality": {"data_disclosure": "Yes", "data": []}}
        },
        "lost_device": {
            "actor": {"external": {"variety": ["Unknown"], "motive": ["Unknown"]}},
            "action": {"physical": {"variety": ["Theft"], "vector": ["Unknown"]}},
            "asset": {"assets": [{"variety": "U - Laptop", "amount": 1}]},
            "attribute": {"confidentiality": {"data_disclosure": "Potentially", "data": []}}
        }
    }

    incident_data = templates.get(incident_type, {})
    base.update(incident_data)
    base["notes"] = f"Template auto-generated for {incident_type}. Review all fields before finalizing."
    return base

def determine_breach_status(record: dict) -> dict:
    """Determine breach status and regulatory triggers from a VERIS record."""
    conf = record.get("attribute", {}).get("confidentiality", {})
    disclosure = conf.get("data_disclosure", "Unknown")
    data_types = [d.get("variety", "") for d in conf.get("data", [])]

    is_confirmed = disclosure == "Yes"
    is_potential = disclosure == "Potentially"

    regulatory_triggers = []
    if any(dt in ["Medical (PHI)"] for dt in data_types):
        regulatory_triggers.append("HIPAA — 60-day HHS notification required")
    if any(dt in ["Personal", "Bank", "Credentials"] for dt in data_types):
        regulatory_triggers.append("GLBA — customer notification assessment required")
        regulatory_triggers.append("State breach notification laws — timing varies by state")
    if any(dt in ["Payment"] for dt in data_types):
        regulatory_triggers.append("PCI DSS — card brand and acquirer notification required")
    if any(dt in ["Classified"] for dt in data_types):
        regulatory_triggers.append("Federal classified data handling requirements apply")

    notification_required = is_confirmed and bool(regulatory_triggers)

    actions = []
    if is_confirmed and regulatory_triggers:
        actions.append("Initiate breach notification workflow immediately")
        actions.append("Notify Legal/Compliance within 24 hours")
    elif is_potential:
        actions.append("Conduct risk assessment to determine notification obligation")
        actions.append("Preserve forensic evidence; engage Privacy Officer")
    elif not is_confirmed:
        actions.append("Continue investigation to determine if disclosure occurred")

    return {
        "is_confirmed_breach": is_confirmed,
        "is_potential_breach": is_potential,
        "regulatory_triggers": regulatory_triggers,
        "notification_required": notification_required,
        "recommended_action": "; ".join(actions) if actions else "No action required"
    }

def quarterly_metrics(records: list, year: int, quarter: int) -> dict:
    """Calculate quarterly VERIS metrics."""
    # Quarter month ranges
    q_months = {1: [1, 2, 3], 2: [4, 5, 6], 3: [7, 8, 9], 4: [10, 11, 12]}
    months = q_months.get(quarter, [])

    filtered = [r for r in records
                if r.get("timeline", {}).get("incident", {}).get("year") == year
                and r.get("timeline", {}).get("incident", {}).get("month") in months]
    n = len(filtered)
    if n == 0:
        return {"error": f"No records for Q{quarter} {year}", "count": 0}

    breaches = sum(1 for r in filtered if r.get("attribute", {}).get("confidentiality", {}).get("data_disclosure") == "Yes")
    internal_disc = sum(1 for r in filtered if r.get("discovery_method", {}).get("internal"))
    external_actors = sum(1 for r in filtered if r.get("actor", {}).get("external"))
    error_actions = sum(1 for r in filtered if r.get("action", {}).get("error"))
    phishing = sum(1 for r in filtered if "Phishing" in str(r.get("action", {}).get("social", {}).get("variety", [])))
    regulated_breaches = sum(1 for r in filtered
                              if r.get("attribute", {}).get("confidentiality", {}).get("data_disclosure") == "Yes"
                              and any(d.get("variety") in ["Personal", "Bank", "Medical (PHI)", "Payment"]
                                      for d in r.get("attribute", {}).get("confidentiality", {}).get("data", [])))

    disc_days = [r["timeline"]["discovery"]["value"] for r in filtered
                  if r.get("timeline", {}).get("discovery", {}).get("value", 0) > 0]
    cont_days = [r["timeline"].get("containment", {}).get("value", 0) for r in filtered
                  if r.get("timeline", {}).get("containment", {}).get("value", 0) > 0]

    return {
        "period": f"Q{quarter} {year}",
        "total_incidents": n,
        "metrics": {
            "breach_rate": f"{breaches/n*100:.1f}% ({breaches}/{n})",
            "mttd_mean_days": f"{mean(disc_days):.1f}" if disc_days else "N/A",
            "internal_detection_rate": f"{internal_disc/n*100:.1f}% ({internal_disc}/{n})",
            "external_actor_rate": f"{external_actors/n*100:.1f}% ({external_actors}/{n})",
            "error_incident_rate": f"{error_actions/n*100:.1f}% ({error_actions}/{n})",
            "phishing_initial_access_rate": f"{phishing/n*100:.1f}% ({phishing}/{n})",
            "regulated_data_breach_rate": f"{regulated_breaches/n*100:.1f}% ({regulated_breaches}/{n})" if breaches > 0 else "0%",
            "mttc_mean_days": f"{mean(cont_days):.1f}" if cont_days else "N/A"
        }
    }

if __name__ == "__main__":
    # Demonstrate template generation
    for itype in ["phishing", "ransomware", "misconfiguration"]:
        t = generate_template(itype)
        print(f"\n=== Template: {itype} ===")
        print(json.dumps(t, indent=2)[:400] + "...")

    # Demonstrate breach determination
    sample_breach = generate_template("credential_theft")
    sample_breach["attribute"]["confidentiality"]["data"] = [
        {"variety": "Bank", "amount": 5000},
        {"variety": "Personal", "amount": 5000}
    ]
    result = determine_breach_status(sample_breach)
    print(f"\n=== Breach Determination ===")
    print(json.dumps(result, indent=2))
```

---

## Part 5: Sample Records — Key Decisions

### Record 1 (BEC phishing, blocked before wire transfer)

* Actor: External, Organized crime, Financial
* Action: Social > Phishing (attempt only — email delivered, wire transfer requested but blocked)
* Attribute: Consider whether any confidentiality impact occurred (email content visible to recipient). If no data disclosed: no Confidentiality attribute.
* This may be an incident with financial near-miss but no CIA breach.

### Record 2 (S3 misconfiguration — customer statements)

* Actor: Internal, System administrator, Negligence
* Action: Error > Misconfiguration
* Attribute: Confidentiality, Bank data, data_disclosure: "Potentially" (until access confirmed)
* GLBA risk assessment required

### Record 3 (Ransomware, 30 workstations)

* Actor: External, Organized crime, Financial
* Action: Social > Phishing + Malware > Ransomware
* Attribute: Integrity + Availability (NOT Confidentiality unless exfiltration confirmed)
* Update record post-forensics if exfiltration confirmed

### Record 4 (Insider misuse — loan officer)

* Actor: Internal, End-user (loan officer = Finance user), Financial
* Action: Misuse > Privilege abuse
* Attribute: Confidentiality, Bank data (competitor's customer info), data_disclosure: Yes

### Record 5 (Third-party vendor breach affecting Meridian customers)

* Actor: External (breached the vendor) + Partner (the vendor)
* Action: (whatever action affected the vendor — if unknown, Hacking > Unknown)
* Asset: S - Database (records at vendor)
* Attribute: Confidentiality, customer data type
* cloud: Yes (data at third party)

---

*Solution — Drill 01 (Advanced) | Session 11 | Security Operations Master Class | Digital4Security*
