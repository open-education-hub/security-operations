# Guide 01 (Basic): Incident Classification

## Objective

Apply the NIST 800-61 classification approach to determine incident type, severity, and required response level.

## Estimated Time: 25–35 minutes

## Classification Dimensions

Every incident should be classified along 4 dimensions:

1. **Incident Type** (malware, unauthorized access, data breach, DoS, etc.)
1. **Severity** (P1–P4 based on impact and urgency)
1. **Scope** (single system, department, enterprise-wide)
1. **Data Classification** (public, internal, confidential, personal data)

## Severity Matrix

| Severity | NIST Category | Business Impact | SLA |
|----------|--------------|----------------|-----|
| P1 Critical | High | Ongoing damage, critical systems, data loss | 30 min response |
| P2 High | Medium-High | Confirmed compromise, limited scope | 2 hour response |
| P3 Medium | Medium | Suspected compromise, policy violation | 8 hour response |
| P4 Low | Low | Informational, failed attempts | 24 hour response |

## Guided Classification Exercise

### Incident A

**Description:** Your EDR detects that `notepad.exe` on CFO-LAPTOP-01 has injected shellcode into `explorer.exe` and established a connection to `52.188.19.33:443`.
No files have been encrypted.
The CFO is traveling internationally.

Walk through classification:

1. **Type?** Malware — possible RAT/backdoor
1. **Scope?** Single high-value endpoint (CFO laptop)
1. **Data at risk?** CFO may have sensitive business data, M&A documents
1. **Active?** Yes — active C2 connection
1. **Severity?** P1 — active compromise of executive device with sensitive data access

### Incident B

**Description:** A user reports receiving a suspicious email with an attachment.
They did not open the attachment.
Email security gateway did not block it.

1. **Type?** Attempted phishing (no execution)
1. **Scope?** Single user, no compromise
1. **Data at risk?** None (attachment not opened)
1. **Active?** No
1. **Severity?** P4 — no compromise, informational

### Incident C

**Description:** Monitoring detects 50 GB of data transferred from the employee files share to a personal Dropbox account by user T.
Novak (who gave notice 2 weeks ago and leaves on Friday).

1. **Type?** Data breach / Insider threat
1. **Scope?** Single user, large data volume
1. **Data at risk?** Possible confidential business data
1. **Active?** Transfer may still be in progress
1. **Severity?** P2 — insider data exfiltration, personal data may be involved

## Key Takeaways

1. Severity is based on potential impact, not just current damage
1. Asset value and data sensitivity always raise severity
1. The same attack type can be P1 or P4 depending on context
1. GDPR implications: Incident C may require notification within 72 hours
