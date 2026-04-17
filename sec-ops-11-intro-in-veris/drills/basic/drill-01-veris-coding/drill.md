# Drill 01 — VERIS Coding Practice

**Level:** Basic

**Estimated time:** 20 minutes

---

## Objective

Apply the VERIS 4-A framework to classify a security incident from a narrative description and produce a valid VERIS JSON record.

---

## Scenario

> An employee at a mid-sized logistics company (300 employees) received an email appearing to be from the company's HR system, asking them to verify their payroll details. The employee clicked the link, which loaded a convincing fake HR portal, and entered their username and password. The attacker used these stolen credentials to log into the real HR portal over the following week and redirected the employee's salary payments to a fraudulent bank account. The attack was discovered when the employee noticed they had not received their monthly salary. Forensic review confirmed the credential theft occurred on a Tuesday morning; the first fraudulent transfer happened the next day. The company discovered the incident 31 days after the initial phishing email.

---

## Your Task

1. Identify the **actor type**, varieties, and motives
1. Identify all **action types** involved (may be more than one) with varieties and vectors
1. Identify the **assets** targeted (use VERIS prefixes: S, U, N, M, P, T)
1. Identify the **attributes** (CIA) that were impacted
1. Record the **timeline** fields you can derive from the narrative
1. Write a complete **VERIS JSON record** for this incident

---

## Hints

* This incident involves more than one action type — think about the attack chain
* Consider what system(s) the attacker accessed
* Was any data actually *disclosed* (confidentiality breach), or was this primarily a financial fraud?
* What timeline values can you extract from the narrative? Which must be marked as "Unknown"?
* The confidence level should reflect how clearly the narrative establishes facts

---

## Deliverable

A VERIS JSON record with all four 4-A sections completed, plus a brief (3–5 sentence) written explanation of your classification decisions.

See the solution in: `solutions/drill-01-solution/solution.md`
