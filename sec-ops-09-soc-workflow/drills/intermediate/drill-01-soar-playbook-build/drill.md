# Drill 01 (Intermediate) — Build a SOAR Playbook

## Scenario

**FinServe AG** is a German financial services company managing €2.3B in assets.
They have a 6-person SOC running 12×5 (08:00–20:00) with an on-call rotation for nights and weekends.

Their top alert type is **account lockout events** — they receive ~150 per day.
Currently, each lockout requires a Tier 1 analyst to:

1. Look up the account in Active Directory (3 min)
1. Check if the lockout IP is internal or external (2 min)
1. Check the source IP in threat intel (3 min)
1. Call or email the user to verify if they triggered the lockout themselves (5–10 min)
1. If legitimate: unlock account and close ticket (3 min)
1. If suspicious: escalate to Tier 2 (5 min)

**Total: 16–26 minutes per lockout × 150/day = up to 65 analyst-hours per day on just this one alert type.**

Your task is to design and implement a SOAR playbook that automates the majority of this process.

---

## Your Tasks

### Task 1: Design the Playbook (25 points)

Before writing code, design the playbook using a decision tree.

Your design must include:

* Trigger conditions
* All data enrichment steps (what APIs/sources to query)
* Decision points (with thresholds)
* Automated actions (what happens without analyst involvement)
* Human-in-the-loop actions (what requires analyst approval)
* Failure/fallback paths (what happens if an API is unavailable)
* Estimated time savings vs. manual process

Draw the decision tree (ASCII art acceptable) and explain each decision point.

### Task 2: Implement the Playbook (50 points)

Implement the playbook in Python.
Your implementation must:

1. Accept an alert input:

```python
alert = {
    "alert_id": "ALT-2025-12345",
    "username": "frank.mueller@finserve.ag",
    "source_ip": "45.33.32.156",
    "lockout_time": "2025-04-10T14:23:00Z",
    "failed_count": 5,
    "domain": "FINSERVE"
}
```

1. Perform these enrichments (simulate with mock functions):
   * AD lookup: is the account a service account, admin account, or standard user?
   * IP geolocation: is the source IP internal (192.168.x.x, 10.x.x.x) or external?
   * IP threat intel: is the IP known malicious? (simulate with a hardcoded list)
   * User context: has this user been locked out before? (simulate with a lookup table)
   * Time context: is this during business hours?

1. Apply decision logic:
   * **Auto-resolve**: lockout from internal IP + known-good user + business hours → unlock and close
   * **Escalate to Tier 2**: lockout from known malicious IP OR admin/service account OR 3+ lockouts in 24h
   * **Human review**: all other cases — present enrichment to analyst with recommended action

1. Simulate actions:
   * `unlock_account(username)` — print confirmation
   * `send_notification(user_email, message)` — print message
   * `create_ticket(alert_data, enrichment, decision)` — print ticket summary
   * `escalate_to_tier2(ticket_id, reason)` — print escalation notice

1. Include basic error handling: if any enrichment fails, log the failure but continue with available data.

### Task 3: Test Your Playbook (15 points)

Test your playbook with at least 4 distinct test cases covering:

* A clear false positive (internal IP, regular user, business hours)
* A clear true positive requiring immediate escalation (malicious IP, service account)
* An edge case requiring human review (external IP, first lockout, outside business hours)
* An error scenario (one enrichment API is unavailable)

Show the output for each test case and explain why the decision is correct.

### Task 4: Metrics and ROI Analysis (10 points)

Calculate:

1. How many analyst-hours per day does your playbook save compared to the manual process?
1. Assuming 60% of lockouts can be auto-resolved and 25% auto-escalated without Tier 1 review: what is the remaining Tier 1 workload for account lockouts?
1. What does this free the analysts to do instead?
1. What risks does this automation introduce and how would you mitigate them?

---

## Technical Requirements

* Language: Python 3
* No external libraries required (use only standard library + simulated APIs)
* Code must be runnable: `python account_lockout_playbook.py`
* Include comments explaining each decision point

## Hints

* Service accounts being locked out is often an attacker using a harvested password list — the lockout is a defender win, but the source IP needs investigation
* A user locked out from their home IP (ISP range) at 08:45 on a Monday is almost certainly just a forgotten weekend password change
* Admin account lockouts from any external IP are always critical regardless of threat intel score
* Consider: what if the email notification fails? Should the playbook continue or stop?
* The "human review" path should present the analyst with all enrichment data plus a recommendation, not just raw data
