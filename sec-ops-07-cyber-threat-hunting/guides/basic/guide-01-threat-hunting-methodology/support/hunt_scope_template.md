# Hunt Scope Definition Template
# Security Operations Course - Session 07: Cyber Threat Hunting
# Guide 01: Step-by-Step Threat Hunting Methodology
#
# Instructions: Fill in all fields before beginning a hunt.
#               A complete scope definition prevents wasted effort and
#               ensures your results are defensible.
# =============================================================================

## Hunt Identification

Hunt ID:          HUNT-[YYYY]-[NNN]       # e.g., HUNT-2024-047
Hunt Name:        [Short descriptive name]
Date Initiated:   [YYYY-MM-DD]
Hunter(s):        [Your name(s)]
Hunt Status:      [ ] Planning  [ ] Active  [ ] Complete  [ ] Closed


## Trigger

Trigger Type:     [ ] Intelligence-driven   [ ] Environment-driven
                  [ ] Anomaly-driven        [ ] Compliance/Audit

Trigger Source:   [Source of trigger: ISAC advisory, internal alert, etc.]

Trigger Details:
  [Describe what triggered this hunt. Include:
   - The specific threat intel, advisory, or observation
   - Why it is relevant to your environment
   - Any IOCs or TTPs mentioned in the source]


## Hypothesis

Hypothesis (one sentence):
  "If [threat actor or technique] is active in [environment scope],
   then I would observe [specific indicator or behavior]
   in [data source] during [time window]."

Example:
  "If a threat actor is using DNS tunneling for C2 communication
   (T1071.004) in our corporate network, I would observe anomalously
   high volumes of TXT DNS queries with high-entropy subdomains from
   workstations in Sysmon DNS logs over the past 30 days."

ATT&CK Technique:    [T-code, e.g., T1071.004]
ATT&CK Tactic:       [Tactic, e.g., Command and Control]


## Scope

### Time Window
Start Date:       [YYYY-MM-DD]
End Date:         [YYYY-MM-DD]
Lookback Period:  [e.g., 30 days — must match data retention]

### Systems in Scope
In Scope:
  [ ] All corporate workstations
  [ ] All servers
  [ ] Specific subnet: _______________________
  [ ] Specific hosts: ________________________
  [ ] Cloud environments: ____________________
  [ ] OT/ICS systems (requires special approval)

Excluded:
  [ ] Development/test environments (reason: ____________)
  [ ] Lab systems (reason: ______________________________)
  [ ] OT/ICS systems (reason: ___________________________)
  [ ] Other: __________________________________________

### Data Sources Required
Mark each data source as Available / Partial / Unavailable:

| Data Source                          | Status      | Coverage % | Retention |
|--------------------------------------|-------------|------------|-----------|
| Sysmon (Process Create - EventID 1)  | [ ] Avail.  |            |           |
| Sysmon (Network Connect - EID 3)     | [ ] Avail.  |            |           |
| Sysmon (DNS Query - EventID 22)      | [ ] Avail.  |            |           |
| Sysmon (LSASS Access - EventID 10)   | [ ] Avail.  |            |           |
| Windows Security Event Logs          | [ ] Avail.  |            |           |
| PowerShell Script Block Logging      | [ ] Avail.  |            |           |
| Network Proxy Logs                   | [ ] Avail.  |            |           |
| DNS Query Logs                       | [ ] Avail.  |            |           |
| Firewall/NGFW Logs                   | [ ] Avail.  |            |           |
| Email Gateway Logs                   | [ ] Avail.  |            |           |
| Cloud Audit Logs (AWS/Azure/GCP)     | [ ] Avail.  |            |           |
| EDR Telemetry                        | [ ] Avail.  |            |           |


## Data Gaps

List any data sources that are required but unavailable or have
insufficient coverage. These gaps affect hunt completeness and
must be documented.

| Gap | Impact on Hunt | Follow-up Action |
|-----|----------------|-----------------|
|     |                |                 |


## Priority and Effort

Priority:         [ ] Critical  [ ] High  [ ] Medium  [ ] Low
Justification:    [Why this priority level?]

Estimated Effort: [X hours / X days]
Actual Effort:    [To be filled in at completion]


## Expected Evidence

If the hypothesis is TRUE, I expect to find:
  1. [Specific log entry pattern, field values, or behaviors]
  2. [Additional corroborating evidence]
  3. [Secondary indicators]

If the hypothesis is FALSE (negative hunt), I expect:
  - [What absence of evidence looks like in this data]
  - [How I'll confirm the negative is genuine vs. a data gap]


## Queries Planned

List the key queries you plan to run:

1. [Query name/description]
   Tool: [Splunk/Kibana/Sigma/etc.]
   Purpose: [What this query is designed to find]

2. [Query name/description]
   Tool: [Splunk/Kibana/Sigma/etc.]
   Purpose: [What this query is designed to find]


## Sign-off (Before Hunt Begins)

Hunter sign-off:      ________________  Date: __________
SOC Manager approval: ________________  Date: __________
Legal/HR approval:    ________________  Date: __________
  (Required for: employee-targeting hunts, covert investigations)
