# Solution: Drill 01 — Data Breach Investigation

## Part A: Investigation Scope

### Possible Card Data Capture Points

1. **Web application layer** — browser-to-server HTTPS (JS skimmer)
1. **Server-side application** — checkout processing code
1. **Database layer** — payment data stored or logged in DB
1. **Network layer** — unencrypted traffic between internal services
1. **Payment gateway API** — before/after encryption in API calls
1. **CDN/third-party scripts** — malicious script injected via CDN

### Logs Required

| Log Type | Needed For | Retention Issue? |
|----------|-----------|-----------------|
| Web application logs (IIS/Nginx) | Request patterns, web shell activity | 6 months — OK |
| Database audit logs | Stored procedure changes, query activity | 90 days — **partial** (4-month breach = 1 month gap) |
| EDR telemetry | File creation, process activity | 90 days — **partial** |
| Firewall logs | Exfiltration detection | 30 days — **significant gap** |

### Preservation Priority

1. Web server disk image (contains the IIS extension / web shell)
1. Database server full backup + transaction logs
1. Any remaining firewall/flow logs (age out soonest)
1. Web application source code (compare to known-good version)

### 4-Month Window Challenge

With only 90 days of database logs and 30 days of network logs, investigators cannot directly observe the initial intrusion or exfiltration.
This is why **log retention policies must account for typical breach dwell times** (industry average: 200+ days).
The DFIR investigation will need to rely on remaining artifacts (the web shell, modified stored procedure) to reconstruct the timeline.

---

## Part B: Forensic Timeline Reconstruction

### Attack Timeline

```text
[~4 months ago] Initial Access
  • Artifact 3: sp_capture_payment stored procedure modified
  • Artifact 4: 2.1 GB exfiltration to Netherlands IP
  → Most likely initial access via web shell (Artifact 2: global_asa.dll.bak)
  → Or via SQL injection exploiting checkout endpoint

[~4 months ago] Web Shell Planted
  • global_asa.dll.bak found in IIS web root
  • No change management record → unauthorized
  • This gave persistent server-side access

[~4 months ago] Lateral Movement to Database
  • Attacker moved from web tier to database tier
  • Modified sp_capture_payment to write card data to temp table

[4 months ago → present] Card Skimming
  • Every payment processed triggers sp_capture_payment
  • Card data written to temp table
  • Artifact 1: 14,200 large requests from internal IP → data retrieval

[Initial exfiltration]
  • 2.1 GB to Netherlands IP (confirmed by flow logs — now aged out)
  • Ongoing smaller exfiltrations via the 14,200 oversized API requests

[Total cards captured]
  • 15,000 cards over ~4 months = ~125 cards/day
  • Consistent with checkout transaction volume
```

---

## Part C: Root Cause and Attribution

### Attack Vector
Web application compromise via unknown initial access (web shell planted).
Most likely: SQL injection or exploitation of a known vulnerability in the e-commerce platform, possibly through an unpatched third-party component.

### Persistence
Web shell `global_asa.dll.bak` in IIS web root.
IIS sometimes auto-loads files with this naming convention.
Provided persistent server access for command execution.

### Data Capture Technique
SQL-level credit card skimmer: modified stored procedure (`sp_capture_payment`) intercepts card data before it reaches the payment processor.
Classic "SQL skimmer" technique used in Magecart-type attacks.

### Exfiltration Method
Two-stage:

1. Card data accumulated in database temp table
1. Retrieved via oversized API requests from internal IP (10.0.5.33) suggesting C2 or staging server
1. Bulk exfiltration of 2.1 GB to Netherlands IP (Artifact 4)

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|-----|---------|
| Exploit Public-Facing Application | T1190 | Web application compromise |
| Web Shell | T1505.003 | global_asa.dll.bak in web root |
| Modify Existing Service / Stored Procedures | T1543 / T1505 | sp_capture_payment modification |
| Data from Information Repositories | T1213 | Card data collected from DB |
| Exfiltration Over C2 Channel | T1041 | Large requests to internal staging |
| Exfiltration to External Site | T1567 | 2.1 GB to Netherlands IP |

---

## Part D: Regulatory and Business Response

### Notification Requirements

| Party | Deadline | Requirement |
|-------|---------|-------------|
| Acquiring Bank | Immediate (within 24h) | Mandatory per PCI DSS |
| Visa/Mastercard | Immediate | Card scheme rules |
| National DPA (GDPR) | 72 hours | Personal data breach (card + purchase data = personal data) |
| 15,000 affected customers | "Without undue delay" if high risk | GDPR Art. 34 |
| QSA Forensic Investigation | Mandatory | PCI DSS breach requires PFI investigation |

### PCI DSS Consequences

* Mandatory PFI (Payment Forensic Investigator) engagement
* Possible card reissuance (cost shared between RetailCorp and card brands)
* Fines from card brands (typically $5,000–$100,000+)
* Increased PCI audit frequency or potential loss of card acceptance privileges
* Potential loss of PCI DSS compliance certification

### Board Brief (Executive Summary)

```text
TO: Board of Directors
FROM: CISO
RE: Payment Card Data Breach Disclosure
DATE: [Date]

RetailCorp has confirmed a payment card data breach affecting 15,000 customer
accounts. An attacker gained unauthorized access to our checkout systems
approximately 4 months ago and installed malicious code that intercepted
payment card numbers before they were encrypted.

IMMEDIATE ACTIONS TAKEN:
- Malicious code removed and checkout system secured
- Forensic investigation initiated
- Acquiring bank and card brands notified
- Legal counsel engaged for regulatory notification

FINANCIAL IMPACT ESTIMATE:
- Card reissuance: $75,000 – $150,000 (customer side)
- PFI investigation: $50,000 – $150,000
- Regulatory fines: $50,000 – $500,000 (range)
- Potential card acceptance suspension risk: low if we cooperate fully

NEXT STEPS:
- Customer notification letters within 72 hours
- DPA notification by [date]
- Full security review and PCI re-assessment
- Next board update: [date]
```
