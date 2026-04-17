# Guide 01 (Intermediate): SOAR Playbook Design

## Objective

Design, document, and implement a SOAR playbook for a specific alert type.
By the end of this guide, you will have a working playbook definition that automates enrichment for a phishing email alert.

## Estimated Time

50–70 minutes

## Prerequisites

* Session 09 sections 7–9
* Basic Linux/Docker familiarity
* Shuffle SOAR running (see Demo 02)

---

## Playbook Design Process

### Phase 1: Define the Trigger (5 min)

Identify:

* **What alert type triggers this playbook?** Phishing email report
* **What data arrives with the trigger?** Subject, sender, recipient list, attachment hashes, URLs
* **How does the trigger arrive?** Webhook from email security gateway

### Phase 2: Map the Steps (10 min)

List all steps needed to fully handle this alert type:

1. Extract sender IP from email headers
1. Check sender IP against VirusTotal
1. Check sender IP against AbuseIPDB
1. Check attachment hashes against VirusTotal (if any)
1. Check URLs against URLScan.io (if any)
1. Score the risk based on enrichment results
1. If risk ≥ threshold → create TheHive case, assign to Tier 2
1. If risk < threshold → close as likely FP, notify reporter

### Phase 3: Identify Decision Gates (5 min)

Mark steps that require a human decision:

* **Automatic:** Steps 1–6 (pure data gathering)
* **Semi-automatic:** Step 7 (create case automatically, but analyst decides containment)
* **Manual only:** Blocking the sender domain (requires analyst judgment)

### Phase 4: Define Inputs and Outputs (5 min)

```yaml
inputs:
  - email_subject: string
  - sender_address: string
  - sender_ip: string (extracted from headers)
  - recipients: list[string]
  - attachment_sha256: list[string]  # may be empty
  - urls: list[string]               # may be empty

outputs:
  - risk_score: float (0.0–10.0)
  - enrichment_summary: string
  - thehive_case_id: string (if created)
  - action_taken: string ("escalated" | "closed_fp")
```

---

## Playbook Implementation in Shuffle

### Step 1: Install Shuffle

```console
git clone https://github.com/Shuffle/Shuffle.git
cd Shuffle
docker-compose up -d
```

Navigate to http://localhost:3001 and complete initial setup.

### Step 2: Create a New Workflow

1. Click **Workflows** → **New Workflow**
1. Name: "Phishing Email Enrichment"
1. Description: "Auto-enrich phishing reports and create TheHive cases when risk is high"

### Step 3: Add Trigger

1. Drag a **Webhook** trigger onto the canvas
1. Copy the webhook URL (you'll use this to test)

### Step 4: Add VirusTotal IP Check Node

1. Search for **VirusTotal** in the app search
1. Drag **Get IP report** onto canvas
1. Connect the trigger to this node
1. Set input: `$trigger.sender_ip`

### Step 5: Add Risk Scoring Node

1. Add a **Tools** → **Python script** node
1. Use this script:

```python
import json

vt_result = json.loads("""$nodes.VirusTotal.output""")
score = 0

# VT positives
positives = vt_result.get('positives', 0)
total = vt_result.get('total', 80)
if positives > 10:
    score += 4
elif positives > 3:
    score += 2
elif positives > 0:
    score += 1

# Return score and summary
result = {
    "risk_score": score,
    "vt_positives": positives,
    "vt_total": total,
    "high_risk": score >= 4
}
print(json.dumps(result))
```

### Step 6: Add Conditional Branch

1. Add a **Condition** node
1. Condition: `$nodes.RiskScoring.output.high_risk == true`
1. True branch → Create TheHive Case
1. False branch → Send "Clean" notification

### Step 7: Add TheHive Case Creation

In the True branch:

1. Add **TheHive** → **Create Case** node
1. Configure:
   * Title: `Phishing Email: $trigger.email_subject`
   * Severity: 2 (High)
   * Description: `Sender: $trigger.sender_address\nRisk Score: $nodes.RiskScoring.output.risk_score`
   * Tags: `["phishing", "auto-created"]`

### Step 8: Test the Playbook

```bash
# Test webhook
curl -X POST http://localhost:3001/api/v1/hooks/YOUR_WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -d '{
    "email_subject": "Urgent: Invoice #INV-20241114",
    "sender_address": "billing@evil-corp-fake.com",
    "sender_ip": "185.220.101.5",
    "recipients": ["cfo@company.com"],
    "attachment_sha256": [],
    "urls": ["http://evil-corp-fake.com/invoice.php"]
  }'
```

Watch the workflow execute in real-time.
Check the execution log for each node's output.

---

## Playbook Documentation Template

After building the playbook, document it:

```markdown
## Playbook: Phishing Email Enrichment
**Version:** 1.0
**Owner:** SOC Team
**Last Reviewed:** 2024-11-14
**SOAR Platform:** Shuffle

### Trigger
Webhook from email security gateway on phishing classification.

### Inputs Required
- email_subject, sender_address, sender_ip, recipients, attachment_sha256[], urls[]

### Steps
1. Query VirusTotal for sender IP

2. Calculate risk score
3. Branch: high risk → create TheHive case; low risk → close

### Human Approval Required For
- Blocking the sender domain in email gateway
- Quarantining recipient mailboxes

### SLA
Automated enrichment completes within 60 seconds of trigger.
Analyst review of created case: within P2 SLA (2 hours).

### Known Limitations
- Playbook does not handle IPv6 sender addresses (fallback: manual enrichment)
- VirusTotal API rate limit: 4 requests/minute (free tier)

### Testing
Test case: sender_ip = 185.220.101.5 → should trigger case creation
```

---

## Key Takeaways

1. Good playbook design starts on paper, not in the tool
1. Decision gates protect against automation causing harm
1. Every playbook needs documentation and a review schedule
1. Test with known-malicious inputs before going live
