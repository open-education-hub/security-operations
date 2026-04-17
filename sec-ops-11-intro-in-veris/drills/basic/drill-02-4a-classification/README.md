# Drill 02: 4-A Classification from Incident Reports

**Level:** Basic

**Estimated time:** 25 minutes

---

## Objective

Classify three incident report excerpts using the VERIS 4-A framework.
For each, fill in all four dimensions and explain any classification decisions involving ambiguity.

---

## Incident Reports

### Incident A: The Public Database

> Our security team was alerted by a third-party researcher who discovered that an internal MongoDB database was exposed to the internet without authentication. The database contained approximately 1.2 million customer records including names, email addresses, delivery addresses, and purchase history. Further investigation revealed the database was exposed for approximately 23 days. There is no evidence of unauthorized access beyond the researcher's discovery query — however, we cannot rule out prior access.

### Incident B: The Laptop Theft

> An employee's laptop was stolen from a café. The device contained unencrypted files including a spreadsheet with 450 employee salary records and HR notes. The employee had taken the laptop home for remote work without following the company's device security policy (full disk encryption was not enabled). Remote wipe was performed 6 hours after the theft was reported. The stolen data is assumed to have been accessible before the wipe completed.

### Incident C: The DoS Attack

> Our e-commerce website was targeted by a distributed denial-of-service (DDoS) attack lasting 4 hours and 20 minutes during peak shopping hours. The attack generated approximately 3.2 Gbps of traffic, overwhelming our upstream bandwidth. No data was accessed or exfiltrated. Customer checkout was unavailable for the full duration. Attackers are unknown; no ransom demand was received.

---

## Your Task

For **each** of the three incidents above:

1. Complete the VERIS 4-A classification:
   * Actor type and details
   * Action type(s) and varieties
   * Asset type(s) and varieties
   * Attributes (CIA) impacted

1. Note any **classification challenges** — fields where you needed to make a judgment call

1. Identify what information you would **mark as "Unknown"** and why

1. For Incident A only: Should this be coded as `security_incident: "Confirmed"` or `"Suspected"`? Why?

---

## Hints

* Incident A involves an `error` action — but by whom? Consider whether this is internal or external
* Incident B involves physical action AND a policy violation component — which action takes priority?
* Incident C: When no data was accessed, what CIA attributes apply?
* `data_disclosure: "Unknown"` is a valid and honest answer when there's no evidence either way

---

## Deliverable

Three VERIS JSON records (one per incident) plus a short written analysis (2–3 sentences each) explaining your key classification decisions.

See the solution directory: `solutions/drill-02-solution/`
