# Guide 04 (Intermediate) — SOAR Playbook Design

## Objective

By the end of this guide you will be able to:

* Design a SOAR playbook using a structured methodology
* Identify automation opportunities and their boundaries
* Implement a complete playbook for a realistic scenario
* Add human approval gates and failure handling

**Estimated time:** 45 minutes

**Level:** Intermediate

**Prerequisites:** Guides 01–03, Demo 01–03

---

## Playbook Design Methodology

### The Five-Step Playbook Design Process

```text
1. Document the Manual Process

         ↓
2. Identify Automation Candidates
         ↓
3. Map Decision Points
         ↓
4. Define Integration Requirements
         ↓
5. Implement, Test, and Iterate
```

### Step 1: Document the Manual Process

Before writing any code, interview the Tier 2 analysts who currently handle the incident type and document exactly what they do.

Example for **Malware Alert Response:**

```text
1. Analyst reads SIEM alert

2. Analyst looks up host in CMDB (5 min)
3. Analyst looks up user in AD (3 min)
4. Analyst submits hash to VirusTotal (2 min)
5. Analyst checks if process was seen on other hosts (10 min SIEM query)
6. Analyst decides: FP or TP?
7. If TP: Analyst creates ticket (5 min)
8. If TP: Analyst submits EDR isolation request (5 min + wait)
9. If TP: Analyst sends notification to IT and user's manager (5 min)
10. Analyst documents findings in ticket (10 min)

Total: 45+ minutes per malware alert
```

### Step 2: Identify Automation Candidates

Go through each step and rate:

* **Fully automatable**: No judgment required, clear inputs/outputs
* **Partially automatable**: Can automate data gathering, human decides
* **Not automatable**: Requires context, judgment, or authority

| Step | Automation Level | Reason |
|------|-----------------|--------|
| Read SIEM alert | Fully | Webhook trigger |
| CMDB lookup | Fully | API call |
| AD lookup | Fully | API call |
| VirusTotal check | Fully | API call |
| SIEM prevalence check | Fully | API query |
| FP/TP decision | Partially | VT > 10: auto TP; < 5: human review |
| Create ticket | Fully | API call |
| EDR isolation | Partially | Auto for critical assets, human for others |
| Notification | Fully | API call |
| Documentation | Partially | Auto-populate template, human adds analysis |

### Step 3: Map Decision Points

Draw the decision tree before coding:

```text
Alert received
      |
STEP A: Enrich (CMDB + AD + VT + SIEM prevalence)
      |
DECISION 1: Is VT score > 10/92?
     / \
   Yes   No
   |      |
DECISION 2:     DECISION 3:
Asset critical?  Any other suspicious
   / \           context?
  Yes  No         /  \
  |    |         No   Yes
Auto   Human    Close  Human
isolate review   FP   review
  |
  ▼
STEP B: Create ticket (auto)
STEP C: Notify IT + Manager (auto)
STEP D: Document (auto-populate, human adds context)
```

### Step 4: Define Integration Requirements

| Integration | Tool | Auth Method | Rate Limit |
|-------------|------|-------------|------------|
| Alert source | SIEM (Splunk) | Token | 100 req/min |
| Asset lookup | CMDB (ServiceNow) | OAuth | 200 req/min |
| User lookup | Active Directory | LDAP bind | Unlimited |
| Threat intel | VirusTotal | API key | 4 req/min (free) |
| Prevalence | SIEM (Splunk) | Token | 100 req/min |
| Case creation | TheHive | API key | Unlimited |
| EDR isolation | CrowdStrike | OAuth | 100 req/min |
| Notification | Teams webhook | No auth | Unlimited |

---

## Implementing the Malware Response Playbook

We'll implement this in Python, simulating the integrations.

### Setup

```console
# Create working directory
mkdir -p malware-playbook
cd malware-playbook

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install requests python-dotenv
```

### The Playbook Implementation

```python
# malware_response_playbook.py
"""
Malware Alert Response Playbook
Demonstrates: enrichment, decision logic, approval gates, error handling
"""

import requests
import json
import time
from datetime import datetime, timezone
from enum import Enum

class AssetCriticality(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class TriageDecision(Enum):
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE_AUTO = "true_positive_auto"
    TRUE_POSITIVE_MANUAL = "true_positive_manual"
    NEEDS_REVIEW = "needs_review"

# ------- Simulated Integration Clients -------

class MockCMDB:
    """Simulates a Configuration Management Database."""

    ASSETS = {
        "WORKSTATION-042": {
            "hostname": "WORKSTATION-042",
            "owner": "jane.doe@globalbank.com",
            "department": "Finance",
            "criticality": AssetCriticality.HIGH,
            "os": "Windows 11",
            "last_patch": "2025-03-15"
        },
        "SERVER-WEB-01": {
            "hostname": "SERVER-WEB-01",
            "owner": "webops@globalbank.com",
            "department": "IT Operations",
            "criticality": AssetCriticality.CRITICAL,
            "os": "Ubuntu 22.04",
            "last_patch": "2025-04-01"
        }
    }

    def lookup(self, hostname):
        return self.ASSETS.get(hostname, {
            "hostname": hostname,
            "criticality": AssetCriticality.MEDIUM,
            "department": "Unknown",
            "owner": "unknown"
        })

class MockVirusTotal:
    """Simulates VirusTotal API."""

    KNOWN_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "malicious": 0, "suspicious": 0, "name": "empty_file"
        },
        "44d88612fea8a8f36de82e1278abb02f": {
            "malicious": 58, "suspicious": 12, "name": "WannaCry"
        },
        "b94f53a9d7439c59a6f26cc37a965c77": {
            "malicious": 12, "suspicious": 3, "name": "Cobalt Strike Beacon"
        },
        "a665a45920422f9d417e4867efdc4fb8": {
            "malicious": 3, "suspicious": 1, "name": "Possibly malicious"
        }
    }

    def lookup_hash(self, file_hash):
        result = self.KNOWN_HASHES.get(file_hash.lower(), {
            "malicious": 0, "suspicious": 0, "name": "Unknown"
        })
        return {"hash": file_hash, **result}

class MockSIEM:
    """Simulates SIEM prevalence query."""

    def prevalence_check(self, file_hash, days=7):
        """Returns number of hosts that ran this hash in last N days."""
        # Simulate: known bad hashes have been seen on multiple hosts
        high_prevalence = ["44d88612fea8a8f36de82e1278abb02f"]
        if file_hash.lower() in high_prevalence:
            return {"host_count": 7, "first_seen": "2025-04-08", "last_seen": "2025-04-10"}
        return {"host_count": 1, "first_seen": "2025-04-10", "last_seen": "2025-04-10"}

class MockEDR:
    """Simulates EDR platform (CrowdStrike/SentinelOne)."""

    def isolate_host(self, hostname, reason):
        print(f"  [EDR] Isolating {hostname}: {reason}")
        time.sleep(0.5)  # Simulate API latency
        return {"status": "isolated", "hostname": hostname, "isolation_id": f"ISO-{hostname[:6].upper()}-001"}

class MockNotifier:
    """Simulates notification (Teams/Slack/email)."""

    def notify(self, channel, message, severity="info"):
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}
        icon = severity_icons.get(severity, "⚪")
        print(f"  [NOTIFY → {channel}] {icon} {message}")

# ------- Human Approval Gate -------

def request_human_approval(context, action, timeout_seconds=30):
    """
    Simulates a human approval gate.
    In production: sends Teams message with approve/deny buttons,
    waits for webhook response.
    """
    print(f"\n  ⚠️  HUMAN APPROVAL REQUIRED")
    print(f"  Action: {action}")
    print(f"  Context: {context}")
    print(f"  (Simulating analyst approval after {timeout_seconds}s timeout)")

    # In demo: auto-approve after showing the gate
    # In production: block and wait for webhook
    return {"approved": True, "approver": "bob.tier2@globalbank.com", "timestamp": datetime.now(timezone.utc).isoformat()}

# ------- Playbook Logic -------

def run_malware_playbook(alert):
    """
    Full malware response playbook.

    alert = {
        "id": str,
        "hostname": str,
        "user": str,
        "process": str,
        "hash": str,
        "timestamp": str
    }
    """
    cmdb = MockCMDB()
    vt = MockVirusTotal()
    siem = MockSIEM()
    edr = MockEDR()
    notifier = MockNotifier()

    log = []

    def step(name, detail=None):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {name}"
        if detail:
            entry += f"\n         {detail}"
        print(entry)
        log.append(entry)

    print("\n" + "═"*65)
    print(f"  MALWARE RESPONSE PLAYBOOK — {alert['id']}")
    print(f"  Host: {alert['hostname']}  |  Hash: {alert['hash'][:16]}...")
    print("═"*65)

    # === PHASE 1: ENRICHMENT ===
    print("\n── PHASE 1: ENRICHMENT ─────────────────────────────────────")

    # 1a. Asset lookup
    asset = cmdb.lookup(alert["hostname"])
    step(f"CMDB: {alert['hostname']}",
         f"Owner: {asset['owner']} | Dept: {asset['department']} | Criticality: {asset['criticality'].name}")

    # 1b. VirusTotal hash check
    vt_result = vt.lookup_hash(alert["hash"])
    step(f"VirusTotal: {alert['hash'][:16]}...",
         f"Malicious: {vt_result['malicious']}/92 | Name: {vt_result['name']}")

    # 1c. SIEM prevalence
    prevalence = siem.prevalence_check(alert["hash"])
    step(f"SIEM Prevalence",
         f"Seen on {prevalence['host_count']} host(s) in last 7 days")

    # === PHASE 2: TRIAGE DECISION ===
    print("\n── PHASE 2: TRIAGE DECISION ─────────────────────────────────")

    vt_score = vt_result["malicious"]
    criticality = asset["criticality"]
    host_count = prevalence["host_count"]

    if vt_score >= 10:
        if criticality in (AssetCriticality.HIGH, AssetCriticality.CRITICAL):
            decision = TriageDecision.TRUE_POSITIVE_AUTO
            step("Decision: TRUE POSITIVE (AUTO)", f"VT={vt_score}/92 + High/Critical asset → auto-response")
        else:
            decision = TriageDecision.TRUE_POSITIVE_AUTO
            step("Decision: TRUE POSITIVE (AUTO)", f"VT={vt_score}/92 → confirmed malware")
    elif 3 <= vt_score < 10:
        decision = TriageDecision.TRUE_POSITIVE_MANUAL
        step("Decision: POSSIBLE TRUE POSITIVE (MANUAL REVIEW)", f"VT={vt_score}/92 — ambiguous, human review")
    elif vt_score < 3 and host_count == 1:
        decision = TriageDecision.FALSE_POSITIVE
        step("Decision: LIKELY FALSE POSITIVE", f"VT={vt_score}/92, single host, not in known bad lists")
    else:
        decision = TriageDecision.NEEDS_REVIEW
        step("Decision: NEEDS REVIEW", f"Multiple hosts but low VT — possible zero-day or FP")

    # === PHASE 3: RESPONSE ===
    print("\n── PHASE 3: RESPONSE ────────────────────────────────────────")

    if decision == TriageDecision.FALSE_POSITIVE:
        step("Action: CLOSE as false positive", "No further action required")
        step("Notify: Analyst", f"Alert {alert['id']} closed as FP")
        return {"decision": "false_positive", "actions": ["closed"], "log": log}

    elif decision == TriageDecision.TRUE_POSITIVE_MANUAL:
        approval = request_human_approval(
            context=f"VT score {vt_score}/92 on {alert['hostname']} ({criticality.name})",
            action="Create ticket and notify IT team"
        )
        if not approval["approved"]:
            step("Action: DECLINED by analyst — closing for now")
            return {"decision": "declined", "actions": [], "log": log}
        step("Approval granted", f"By: {approval['approver']}")

    # For TRUE_POSITIVE_AUTO and approved MANUAL cases:

    # 3a. Host isolation (for HIGH/CRITICAL assets — request approval)
    if criticality in (AssetCriticality.HIGH, AssetCriticality.CRITICAL):
        if decision == TriageDecision.TRUE_POSITIVE_AUTO:
            # Auto-isolate critical assets with confirmed malware
            isolation = edr.isolate_host(alert["hostname"], f"Malware: {vt_result['name']} (VT {vt_score}/92)")
            step(f"EDR: Isolated {alert['hostname']}", f"Isolation ID: {isolation['isolation_id']}")
        else:
            approval = request_human_approval(
                context=f"Isolate {alert['hostname']} — {criticality.name} asset",
                action=f"EDR host isolation"
            )
            if approval["approved"]:
                isolation = edr.isolate_host(alert["hostname"], f"Malware (VT {vt_score}/92)")
                step(f"EDR: Isolated {alert['hostname']}", f"Approved by {approval['approver']}")

    # 3b. Notify stakeholders
    severity_map = {
        AssetCriticality.CRITICAL: "critical",
        AssetCriticality.HIGH: "high",
        AssetCriticality.MEDIUM: "medium",
        AssetCriticality.LOW: "info"
    }
    notif_severity = severity_map[criticality]

    notifier.notify(
        "soc-alerts",
        f"Malware confirmed on {alert['hostname']} — {vt_result['name']} (VT {vt_score}/92)",
        notif_severity
    )
    notifier.notify(
        asset["owner"],
        f"Your workstation {alert['hostname']} has been isolated due to malware detection. IT will contact you.",
        "high"
    )
    step("Notifications sent", f"SOC channel + user {asset['owner']}")

    # 3c. Check for spread
    if host_count > 1:
        step(f"⚠ SPREAD DETECTED", f"Hash seen on {host_count} hosts — escalating to Tier 2")
        notifier.notify("soc-tier2", f"URGENT: Malware spread — {host_count} hosts affected", "critical")

    print("\n── PLAYBOOK COMPLETE ────────────────────────────────────────")
    step("Summary", f"Decision: {decision.value} | Actions: isolation + notification")

    return {
        "decision": decision.value,
        "asset_criticality": criticality.name,
        "vt_score": vt_score,
        "hosts_affected": host_count,
        "log": log
    }

# --- Test cases ---
if __name__ == "__main__":
    # Test case 1: High-confidence malware on critical asset
    print("\n\n{'='*65}")
    print("TEST CASE 1: WannaCry on Finance workstation")
    result1 = run_malware_playbook({
        "id": "ALT-2025-08847",
        "hostname": "WORKSTATION-042",
        "user": "jane.doe@globalbank.com",
        "process": "svchost.exe",
        "hash": "44d88612fea8a8f36de82e1278abb02f",
        "timestamp": "2025-04-10T10:42:33Z"
    })

    # Test case 2: Low VT score — false positive scenario
    print("\n\nTEST CASE 2: Low VT score — likely FP")
    result2 = run_malware_playbook({
        "id": "ALT-2025-08899",
        "hostname": "WORKSTATION-042",
        "user": "jane.doe@globalbank.com",
        "process": "custom_tool.exe",
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timestamp": "2025-04-10T11:00:00Z"
    })
```

### Run the playbook

```console
python malware_response_playbook.py
```

---

## Testing and Validation

### Test matrix

| Test Case | Hash | Asset | Expected Decision |
|-----------|------|-------|-----------------|
| High VT + Critical asset | WannaCry hash | SERVER-WEB-01 | Auto-isolate |
| High VT + Medium asset | Cobalt Strike hash | Unknown host | True positive |
| Low VT + single host | Empty file hash | WORKSTATION-042 | False positive |
| Medium VT | Possibly malicious hash | WORKSTATION-042 | Manual review |

### Questions to consider

1. **What happens if the CMDB is unreachable?** Add try/except around `cmdb.lookup()` and default to `AssetCriticality.MEDIUM`
1. **What if VirusTotal rate limit is hit?** Queue the request and retry with exponential backoff
1. **What if EDR isolation fails?** Log the failure, escalate to Tier 2, send urgent notification
1. **How do you prevent duplicate isolations?** Check EDR for existing isolation status before submitting

---

## Knowledge Check

1. Why should you document the manual process before building automation?
1. What is a human approval gate and when should you add one?
1. In the playbook above, why does a VT score of 3–10 require manual review instead of automatic response?
1. What additional step would you add to handle the case where the hash is seen on 7 hosts?
1. Why is error handling critical in SOAR playbooks?
