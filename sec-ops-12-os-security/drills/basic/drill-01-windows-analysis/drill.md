# Drill 01 (Basic): Analyze Windows Event Logs for Compromise

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Session 12 reading (Sections 2–5), Guide 01

---

## Scenario

You are a SOC analyst at a financial services company.
Your SIEM generated an alert: **"Multiple failed logons followed by successful logon — potential brute force success"** on workstation `FINANCE-WS-04`.

You have been given a PowerShell access to the system and a pre-exported event log sample.
Your task is to investigate whether this is a true compromise and document your findings.

---

## Setup

```console
cd drills/basic/drill-01-windows-analysis
docker compose up --build
docker compose run win-drill pwsh
```

---

## Investigation Tasks

### Task 1: Analyze Authentication Events

Load the sample data and identify the attack:

```powershell
. /scripts/load-drill.ps1

# Examine the authentication events
Show-AuthEvents
```

**Questions to answer:**

1. How many failed logon attempts occurred in the incident window?
1. Which user account was targeted?
1. What was the source IP address of the attack?
1. At what time did the successful logon occur?
1. What Logon Type was used? What does it indicate?

---

### Task 2: Review Process Execution After Logon

```powershell
Show-ProcessEvents -After "14:47:00"
```

**Questions to answer:**

1. Were any high-risk processes created after the successful logon?
1. What command-line arguments indicate malicious intent?
1. Identify any LOLBin usage (certutil, mshta, regsvr32, etc.)

---

### Task 3: Check for Persistence Indicators

```powershell
Show-PersistenceEvents
```

**Questions to answer:**

1. Was a new service installed? If so, what was its name and executable path?
1. Was a scheduled task created? What does it do?
1. Was the audit log cleared? If so, when?

---

### Task 4: LSASS Access Detection

```powershell
Show-SysmonEvents -Filter "lsass"
```

**Questions to answer:**

1. Did any process access LSASS? Which one?
1. What GrantedAccess value was used?
1. What does access mask 0x1010 indicate?
1. Is this a credential dump attempt?

---

### Task 5: Write Your SIEM Alert Triage Summary

Complete the following template based on your findings:

```text
Alert: Multiple failed logons + success (SIEM Alert ID: ALT-2024-001)
Analyst: [Your Name]
Date: [Today]

VERDICT: [ ] True Positive  [ ] False Positive  [ ] Benign True Positive

SUMMARY:
At [TIME], an attacker from IP [IP] performed a brute-force attack against
user [USER] on workstation [HOSTNAME], resulting in [OUTCOME].

POST-COMPROMISE ACTIVITY:
- [describe what happened after login]

PERSISTENCE:
- [list any persistence mechanisms found]

RECOMMENDED ACTIONS:

1.

2.
3.

IOCs:
- IP:
- Hash:
- File path:
```

**Compare your answers to:** `solutions/drill-01-solution/solution.md`

---

## Clean Up

```console
docker compose down
```
