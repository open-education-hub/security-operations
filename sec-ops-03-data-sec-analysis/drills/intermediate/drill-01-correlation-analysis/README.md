# Drill 01 (Intermediate): Correlation Analysis with Splunk

**Estimated time:** 45 minutes

**Difficulty:** Intermediate

**Tools required:** Splunk instance (use Demo 01 or Demo 03 environment)

## Objective

Write and execute multi-source correlation queries to detect attack patterns that span multiple event types.
You will detect a simulated attack using only log analysis.

## Setup

Start the Demo 03 environment:

```console
cd ../../demos/demo-03-splunk-correlation
docker compose up -d
# Wait ~3 minutes for attack simulator to load data
```

Access Splunk at http://localhost:8000 (admin / SecOpsDemo123!)

---

## Challenge 1: Find the Compromised Host (10 min)

The attack simulator has loaded events from a simulated compromise.
Your first task is to identify the compromised host using only log analysis — do not look at the attack simulator code.

**Write a Splunk query that:**

1. Identifies which host has the most anomalous activity (Office spawning shells + network connections to external IPs)
1. Shows a timeline of events for that host

**Starter query to modify:**

```spl
index=main sourcetype=attack_sim earliest=-2h
| [fill in the rest]
```

**Expected output:** You should identify host `WORKSTATION-042` with user `jsmith`.

---

## Challenge 2: Reconstruct the Attack Timeline (15 min)

Once you have identified the host, reconstruct the complete attack timeline in chronological order.

**Write a query that:**

* Shows all events for the compromised host in time order
* Highlights key attack stages
* Includes: timestamp, event type, process name, network destination (where applicable)

```spl
index=main sourcetype=attack_sim host="WORKSTATION-042" earliest=-2h
| [sort and format the timeline]
```

Fill in the table below with what you find:

| Time (T+X sec) | Event Type | What Happened | Attack Stage |
|---------------|-----------|---------------|-------------|
| T+0 | ? | ? | ? |
| T+12 | ? | ? | ? |
| T+15 | ? | ? | ? |
| T+45 | ? | ? | ? |
| T+60 | ? | ? | ? |
| T+70 | ? | ? | ? |

---

## Challenge 3: Write a Correlation Rule for This Attack (15 min)

Based on what you found, write a correlation rule that would detect this specific attack pattern.
The rule must:

1. Trigger when an Office process spawns PowerShell **AND** PowerShell makes an outbound connection within 5 minutes
1. Must correlate events from the same host
1. Must use a time window constraint
1. Output: host, user, office_process, shell_process, c2_ip, time_span

Write your SPL rule below and explain each section:

```spl
# Write your correlation rule here
```

---

## Challenge 4: Hunt for Other Indicators (5 min)

The attack left behind additional persistence mechanisms.
Using the data in Splunk:

1. Find the scheduled task that was created
1. Find the filename of the malware that was dropped
1. Find the registry path if any registry persistence was used

```spl
# Find persistence mechanisms
index=main sourcetype=attack_sim (EventID=4698 OR EventID=11 OR EventID=13) earliest=-2h
| [complete the query]
```

---

## Deliverables

Write up your findings in the following format:

```text
Incident Summary:
- Compromised Host:
- Compromised User:
- Initial Access Time:
- First Malicious Event:
- C2 Server IP/Domain:
- Persistence Mechanism:
- Estimated Impact:

Correlation Rule (SPL):
[paste your rule]

MITRE ATT&CK Mapping:
- TA0001 Initial Access:
- TA0002 Execution:
- TA0011 Command and Control:
- TA0003 Persistence:
```

See `../solutions/drill-01-solution/README.md` for the complete walkthrough.
