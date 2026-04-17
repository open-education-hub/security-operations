# Drill 01: Windows Security Audit

**Level:** Basic

**Estimated time:** 25 minutes

---

## Objective

Perform a security audit of a simulated Windows system, identify security issues, and produce a prioritized remediation plan.

---

## Setup

```console
cd drills/basic/drill-01-windows-audit
docker compose up --build
docker compose run win-audit pwsh
```

The container has a simulated Windows system configuration with several deliberately introduced security issues.

---

## Scenario

You have been asked to perform a quick security audit of a Windows workstation at a small company.
The machine is used by an office manager who occasionally needs administrator access for software installations.
Your goal is to identify security issues and recommend fixes.

---

## Your Tasks

### Task 1: Enumerate Users and Groups

Run commands to determine:

1. How many local user accounts exist?
1. Which accounts are members of the Administrators group?
1. Are there any accounts with passwords that never expire?
1. Is the Guest account enabled?

Document your findings.

### Task 2: Service Audit

Check for:

1. Are there any high-risk services running (Telnet, RemoteRegistry, SNMP)?
1. Are there any services running from unusual paths (outside of System32, Program Files)?
1. How many services are configured to start automatically at boot?

### Task 3: Firewall Status

Verify:

1. Is Windows Firewall enabled on all profiles (Domain, Private, Public)?
1. What is the default inbound action on each profile?
1. Are there any inbound rules that allow broad access (Any source, Any destination)?

### Task 4: Legacy Protocol Check

Check:

1. Is SMBv1 enabled?
1. Is the Remote Registry service enabled?
1. Is AutoRun/AutoPlay disabled?

### Task 5: Registry Persistence Check

Examine the Run keys for suspicious entries:

1. What entries exist in `HKCU\...\Run`?
1. What entries exist in `HKLM\...\Run`?
1. Are there any entries pointing to unusual locations (C:\Temp, %APPDATA%, etc.)?

---

## Deliverable

1. A table listing all findings with: Issue, Location, Severity (High/Medium/Low), and Recommended Fix
1. A prioritized top 3 remediation actions — in order of what to fix first

**Severity guidance:**

* High: Exploitable immediately, significant impact
* Medium: Creates attack surface, requires specific conditions to exploit
* Low: Best practice violation, minor risk

See `solutions/drill-01-solution/` for reference.
