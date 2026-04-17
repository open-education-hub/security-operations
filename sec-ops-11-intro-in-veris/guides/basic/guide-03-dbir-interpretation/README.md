# Guide 03: Interpreting DBIR Findings

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Guide 02 (4-A Classification)

---

## Objective

By the end of this guide, you will be able to:

* Understand the structure and purpose of the Verizon DBIR
* Interpret statistical claims made in the DBIR with appropriate context
* Identify the nine DBIR incident patterns
* Apply DBIR findings to improve security priorities in a given organization

---

## What is the DBIR?

The **Data Breach Investigations Report (DBIR)** is an annual report by Verizon that analyzes thousands of security incidents and data breaches using VERIS-coded data.
First published in 2008, it is one of the most widely cited sources of empirical security data.

Key characteristics:

* Based on real incident data (not surveys or self-reported estimates)
* Uses VERIS coding for consistency
* Provides industry-specific and geographic breakdowns
* Tracks trends over time

---

## Understanding DBIR Language

The DBIR uses precise statistical language.
Understanding it correctly prevents misinterpretation.

### "X% of breaches involved Y"

This means: In the dataset of confirmed breaches analyzed this year, X% had at least one occurrence of Y.

**Important caveats:**

* It does NOT mean X% of all breaches globally
* The sample has selection bias (Verizon customers, partners, public reports)
* "Involved" usually means "had at least one instance of" — not "caused by"

### Confidence Intervals

The DBIR often shows confidence intervals:

```text
"68% (±5%) of breaches involved a human element"
```

This means the true percentage (for this dataset) is likely between 63% and 73%.
Wider intervals = less data = less certainty.

### "n =" Sample Size Notation

Every chart in the DBIR includes `n = ` indicating how many incidents that finding is based on.
Low `n` = less reliable finding.

---

## The Nine DBIR Incident Patterns

The DBIR groups incidents into nine patterns based on predominant VERIS attributes:

| Pattern | Common VERIS Actions | Typical Actors |
|---------|---------------------|----------------|
| **Web Application Attacks** | Hacking (web), Social | External |
| **System Intrusion** | Hacking + Malware (multi-step) | External |
| **Social Engineering** | Social (phishing, BEC) | External |
| **Basic Web Application Attacks** | Hacking (simpler web attacks) | External |
| **Miscellaneous Errors** | Error | Internal |
| **Privilege Misuse** | Misuse | Internal |
| **Denial of Service** | Hacking (DoS/DDoS) | External |
| **Lost and Stolen Assets** | Physical | External/Internal |
| **Everything Else** | Various | Various |

### Mapping Incidents to Patterns

To assign a pattern to an incident:

1. Identify the dominant action type
1. Consider the actor type
1. Apply the pattern definition

**Example:** An external group uses spear-phishing to steal credentials and then logs into a VPN to exfiltrate data from a database.
This matches **System Intrusion** (multi-step, hacking + social).

---

## Reading a DBIR Chart

Let's walk through a typical DBIR-style finding:

### Example Finding: "83% of breaches involved external actors"

**Step 1: Accept the finding at face value.** External actors are the dominant source.

**Step 2: Look at the n value.** If n = 4,000, this is based on 4,000 analyzed breaches — a meaningful sample.

**Step 3: Consider what it means for defenses.**
If 83% of breaches are external, then:

* External threat monitoring is the highest priority
* Perimeter controls, EDR, phishing protection are most impactful
* But! Don't ignore internal threats — 17% is not zero

**Step 4: Check industry breakdown.**
This 83% number is for ALL industries.
In healthcare, the internal actor rate is historically higher (PHI misuse).

### Example Finding: "Phishing was involved in 36% of breaches"

**Step 1:** Phishing = major attack vector — affects more than 1 in 3 breaches.

**Step 2:** Implication: Email security and security awareness training have very high ROI.

**Step 3:** Contextual question: Of those 36%, what happened next?
(Most commonly: credential theft → unauthorized access)

**Step 4:** Defense chain:

1. Block phishing emails (email gateway, anti-phishing)
1. Detect credential use from unknown locations (SIEM, MFA)
1. Monitor for unusual database access (DLP, UEBA)

---

## Industry Analysis Exercise

Different industries face different threat profiles.
Use this exercise to practice reading DBIR-style data.

### Healthcare Sector Profile

Typical DBIR findings for Healthcare:

* **Top pattern**: System Intrusion, Miscellaneous Errors
* **Top actor**: External (51%), Internal (39%)
* **Top action**: Hacking (web apps), Error (misconfiguration, misdelivery)
* **Top data type**: Medical records (PHI), Personal data
* **Discovery time**: Often weeks or months

**Analysis questions:**

1. Why is the internal actor rate higher in healthcare than other industries?
1. What does "Miscellaneous Errors" tell us about healthcare IT practices?
1. What regulatory requirements (HIPAA, GDPR) are triggered by PHI disclosure?

### Finance Sector Profile

Typical DBIR findings for Finance:

* **Top pattern**: Web Application Attacks, Social Engineering
* **Top actor**: External (>90%)
* **Top action**: Hacking (use of stolen creds), Social (phishing, BEC)
* **Top data type**: Financial credentials, Payment card data
* **Financial impact**: High (direct fraud)

**Analysis questions:**

1. Why do external actors dominate in Finance vs. Healthcare?
1. Why are web application attacks so common in Finance?
1. What controls would address the top two patterns simultaneously?

---

## Applying DBIR Findings to Your Organization

### The Threat Profiling Process

1. **Identify your industry** from the DBIR industry breakdowns
1. **Extract top 3 patterns** for your industry
1. **Map patterns to VERIS actions and actors**
1. **Review your current controls** against those patterns
1. **Prioritize gaps** based on pattern frequency

### Exercise: Build a Threat Profile

**Scenario:** You are a security analyst at a European e-commerce company with 500 employees.
Using DBIR-style data, build a threat profile.

**Step 1:** Industry = Retail

**Step 2:** Top patterns for Retail:

1. Web Application Attacks (online store is external-facing)
1. System Intrusion (multi-step attacks targeting payment systems)
1. Social Engineering (BEC targeting finance, phishing employees)

**Step 3:** VERIS mapping:

* Hacking (SQLi, credential stuffing on web app) + External actor
* Malware + Hacking (multi-stage) + External actor
* Social (phishing, BEC) + External actor

**Step 4:** Current controls review:

* Do we have WAF (Web Application Firewall)?
* Do we have MFA on all external-facing accounts?
* Do we run phishing simulation training?
* Do we monitor for large data exports?

**Step 5:** Priority gaps:

* If no WAF → highest priority (addresses pattern 1)
* If no MFA → second priority (addresses all three patterns)
* If no phishing training → third priority (addresses pattern 3)

---

## DBIR Limitations to Keep in Mind

When using DBIR data, always consider:

1. **Sample bias**: Verizon sees a specific type of incident — their customer base and partners. Small organizations and non-US companies may be underrepresented.

1. **Publication lag**: DBIR data is collected the prior year and published ~12 months later. Emerging threats may not be reflected.

1. **"Unknown" dominance**: Many fields in VCDB have "Unknown" values. This is accurate but limits analytical precision.

1. **Incident ≠ Breach**: The DBIR analyzes both — make sure you are reading the right subset for your question.

1. **Causation vs. correlation**: Just because phishing is "involved" in 36% of breaches doesn't mean fixing phishing would prevent 36% of breaches — other factors are also at play.

---

## Summary

You have learned:

* The DBIR is an annual empirical analysis of VERIS-coded incident data
* How to read DBIR statistics carefully, considering n values and confidence intervals
* The nine DBIR incident patterns and their VERIS mappings
* How to apply DBIR findings to build an organization-specific threat profile
* The key limitations of DBIR data to keep in mind

**Next:** Proceed to the basic drills to practice your VERIS coding skills.
