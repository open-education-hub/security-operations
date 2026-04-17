# Drill 01 (Basic) — Windows Security Audit

**Level:** Basic

**Estimated time:** 25 minutes

---

## Objective

Perform a security audit of a Windows system (simulated in Docker using PowerShell Core) and identify misconfigurations against the CIS Benchmark for Windows.

---

## Setup

```console
cd drills/basic/drill-01-windows-audit
docker compose up --build
docker compose run win-audit
```

---

## Scenario

You are a new SOC analyst who has been asked to perform a baseline security check on a Windows workstation before it is added to the domain.
The IT manager has asked you to verify it meets minimum security requirements.

The Docker container simulates a Windows system with several intentional misconfigurations.

---

## Tasks

### Task 1: User Account Audit

Using PowerShell, answer these questions:

1. How many local user accounts exist?
1. Are any unexpected accounts in the Administrators group?
1. Are there any accounts with passwords that never expire?
1. Is the Guest account enabled?

```powershell
# Start here:
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"
```

---

### Task 2: Service Security Check

Identify any high-risk services that are running:

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"} |
  Select-Object Name, DisplayName, StartType
```

**Question:** Which services from the high-risk list are running that should be disabled?

---

### Task 3: Firewall Check

Verify the Windows Firewall configuration:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
```

**Question:** Are all three firewall profiles (Domain, Private, Public) enabled with inbound blocking?

---

### Task 4: Legacy Protocol Check

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
```

**Question:** Is SMBv1 enabled?
Why is this dangerous?

---

### Task 5: Registry Persistence Check

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null
```

**Question:** Are there any suspicious entries in the Run keys?

---

## Deliverable

Write a brief security audit report (in a text file or as console output) with:

1. Findings for each task
1. Whether each finding is a PASS, WARN, or FAIL
1. Recommended remediation for each FAIL/WARN

**Hint:** Compare your findings against the CIS Benchmark requirements covered in Guide 01.

See the solution in: `solutions/drill-01-solution/solution.md`
