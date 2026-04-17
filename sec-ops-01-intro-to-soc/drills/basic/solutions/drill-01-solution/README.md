# Drill 01 (Basic) — Solution: SOC Roles Identification

## Answers

**Task 1:** Alert triage for failed login attempts.

* **Role: Tier 1 (L1 Analyst)**
* Reason: Initial alert review and true/false positive classification is the primary Tier 1 function.

**Task 2:** Malware binary analysis.

* **Role: Tier 3 (L3 Analyst)**
* Reason: Malware reverse engineering requires advanced expertise. This is a core Tier 3 function.

**Task 3:** Proactive hunting for persistence mechanisms in historical logs.

* **Role: Tier 3 (L3 Analyst)**
* Reason: Threat hunting — proactively searching for threats without a specific alert — is a Tier 3 responsibility.

**Task 4:** Monthly SOC performance report for the CISO.

* **Role: SOC Manager**
* Reason: KPI reporting and executive communication is a management function.

**Task 5:** Full investigation of a compromised admin account.

* **Role: Tier 2 (L2 Analyst)**
* Reason: Deep-dive investigation of escalated incidents, building the case, and determining scope is Tier 2 work.

**Task 6:** Configure Splunk to receive WAF logs.

* **Role: SOC Manager / Security Engineer** (or Tier 3)
* Reason: Tool configuration and engineering is typically handled by a Security Engineer or senior analyst. In smaller SOCs, a senior Tier 3 may do this.

**Task 7:** Log a user report and create an initial ticket.

* **Role: Tier 1 (L1 Analyst)**
* Reason: Receiving user reports, creating tickets, and initial documentation is basic Tier 1 work.

## Learning Points

* The tiered model creates **specialization** — each tier focuses on what they do best.
* **Tier 1 handles volume**; Tier 3 handles complexity.
* In small SOCs, roles often overlap — one analyst may do Tier 1+2 work.
* The SOC Manager rarely does hands-on technical work but is critical for operations.
