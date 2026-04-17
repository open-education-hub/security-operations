# Drill 02 (Basic): Playbook Design for a Given Scenario

**Level**: Basic

**Estimated time**: 45-60 minutes

**Type**: Design exercise (no lab environment required)

---

## Learning Objectives

* Apply the standard playbook template to a new scenario
* Design decision trees for a real-world alert type
* Define escalation criteria and containment actions
* Identify appropriate SLA targets per severity
* Recognize which steps can later be automated

---

## Scenario: Credential Stuffing Attack

**Incident Background**:

MedCorp's Splunk detected the following pattern over the last 30 minutes:

* 847 failed login attempts across 23 different user accounts
* All attempts originate from 3 IP addresses: 91.108.4.1, 91.108.4.2, 91.108.4.3
* 2 of the 23 accounts had 1 SUCCESSFUL login following the failed attempts:
  * `n.santos` — workstation in billing department, accessed at 03:47 AM
  * `m.admin` — administrative account, accessed at 03:52 AM
* The source IPs are in the Netherlands (not a known MedCorp location)
* The billing department has access to patient billing records (PHI — HIPAA applies)
* `m.admin` has local admin rights on 12 workstations

**Alert rule that fired**:

* Rule Name: `Credential_Stuffing_Detected`
* Alert details include: source IPs, target usernames, success/fail counts, timestamps

**Available tools** (at MedCorp):

* Splunk (SIEM)
* Active Directory (on-premises)
* CrowdStrike Falcon (EDR) on all workstations
* Exchange Online (email)
* AbuseIPDB API (threat intel — free key available)
* Jira (ticketing)
* No SOAR platform currently deployed

---

## Tasks

### Task 1: Design the Playbook Decision Tree (20 min)

Create a visual decision tree for responding to this type of credential stuffing alert.
The tree must handle both cases:

1. Alert fires with ONLY failed attempts (no successful login) — likely earlier in the attack
1. Alert fires WITH successful login attempts (current scenario)

Your decision tree must include:

* At least 4 decision branches (yes/no or conditional)
* Clear escalation criteria
* Differentiation between service accounts, admin accounts, and regular users
* HIPAA-specific steps for when PHI-accessing accounts are involved
* Estimated time at each major stage

### Task 2: Write the Complete Playbook (30 min)

Using the standard playbook template from Guide 02, write a complete playbook for this alert type.
Include:

1. **Purpose and scope**
1. **Prerequisites** (access, tools)
1. **Trigger conditions** (when does this playbook activate)
1. **Procedure** (all steps, with decision points)
1. **Escalation criteria** (be explicit — list specific conditions)
1. **Containment actions** (with approval requirements)
1. **Evidence collection** (for HIPAA compliance, evidence preservation is critical)
1. **Communication** (particularly: HIPAA breach notification requirements)
1. **Closure criteria**
1. **Automation candidates** (which steps could be automated with SOAR)

### Task 3: Apply the Playbook to the Scenario (10 min)

Walk through your completed playbook using the specific alert data from the scenario.
Document what decision you would make at each branch point, and why.

Specifically answer:

1. What is your initial severity assignment and why?
1. What is the first containment action you take and why?
1. Does this meet the threshold for HIPAA breach notification? Why or why not?
1. What evidence must you preserve?
1. Would you declare an incident? At what point?

---

## HIPAA Reference (for this exercise)

HIPAA Breach Notification Rule requires notification when:

* PHI is accessed, acquired, used, or disclosed in an unauthorized manner
* The breach affects 500+ individuals → notify HHS and media within 60 days
* The breach affects any number → notify affected individuals within 60 days
* Internal breach → must evaluate: was PHI actually viewed, or just accessed?

**For this scenario**: `n.santos` (billing — PHI access) had a successful login.
You must determine if PHI was actually viewed/exfiltrated vs. just account access.

---

## Deliverables

1. Decision tree diagram (hand-drawn, ASCII, or diagramming tool)
1. Complete playbook using the standard template
1. Playbook walkthrough applying it to the specific scenario data

---

## Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Decision tree covers all major scenarios (success/fail, admin/user) | 20 |
| Playbook follows standard structure completely | 20 |
| Escalation criteria are explicit and measurable | 15 |
| HIPAA requirements correctly incorporated | 20 |
| Containment actions have appropriate approval levels | 10 |
| Automation candidates correctly identified | 15 |
| **Total** | **100** |

---

## Hints

* A successful login on an admin account at 3:52 AM from a Netherlands IP is almost certainly a compromise — your playbook branch should reflect this
* HIPAA breach determination requires investigation first — you can't know if it's a breach until you check what `n.santos` did during the unauthorized session
* `m.admin` with local admin rights on 12 workstations is a lateral movement risk — your playbook should address this specifically
* The 3-IP range suggests automated stuffing tool — blocking at the firewall is appropriate but check if those IPs also hit any other services
