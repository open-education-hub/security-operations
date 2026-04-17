# Drill 01 (Advanced): Data Breach Investigation

## Scenario

RetailCorp (e-commerce, 2M customers, processes credit card data) has received a notification from Visa that 15,000 card numbers appearing in underground forums trace back to transactions at RetailCorp's checkout system.
The first fraudulent transaction dates back 4 months.
RetailCorp was not aware of any breach.

## Challenge

Design and execute a full breach investigation plan.
RetailCorp believes they are PCI DSS compliant (last QSA audit: 6 months ago).

## Part A: Investigation Scope

Define your investigation scope:

1. Where could card data have been captured? (List all possible points in the payment flow)
1. What logs do you need to examine? (List with retention requirements)
1. What forensic evidence should be preserved immediately?
1. Why is a 4-month window particularly challenging?

## Part B: Forensic Timeline Reconstruction

Using the evidence list below, reconstruct the attack timeline:

**Evidence:**

* Web application logs: 6 months retained
* Database audit logs: 90 days retained
* EDR telemetry: 90 days retained
* Network flow logs: 30 days retained
* Firewall logs: 90 days retained

**Artifact 1:** Web server log shows 14,200 requests to `/api/checkout/process` from IP `10.0.5.33` (internal) over a 3-month period.
Each request was ~200 bytes larger than baseline.

**Artifact 2:** IIS extension file `global_asa.dll.bak` found in web root.
Creation date: 4 months ago.
No change management record.

**Artifact 3:** Database audit log shows 'stored procedure `sp_capture_payment` was MODIFIED 4 months ago.
Normal stored procedure was replaced with one that writes card data to a temp table before passing to payment processor.

**Artifact 4:** Net flow shows large outbound transfer (2.1 GB) to an IP in the Netherlands on the same date as the stored procedure modification.

## Part C: Root Cause and Attribution

Based on the artifacts:

1. Describe the attack vector (how did they get in?)
1. Describe the persistence mechanism
1. Describe the data capture technique
1. Describe the exfiltration method
1. Map to MITRE ATT&CK (minimum 5 techniques)

## Part D: Regulatory and Business Response

RetailCorp processes payments under PCI DSS:

1. Who must be notified and when? (Card brands, acquiring bank, regulators, customers)
1. What are the potential PCI DSS consequences?
1. Write an executive brief for the Board of Directors

## Hints

* The `global_asa.dll.bak` in the web root is a web shell or skimmer
* Stored procedure modification = SQL-level card skimmer
* 4-month dwell time with 15,000 cards over 4 months = roughly 125 cards/day
* The Netherlands IP may lead to attribution if traceable to known threat actors
* PCI DSS breach = mandatory Forensic Investigation by a QSA
