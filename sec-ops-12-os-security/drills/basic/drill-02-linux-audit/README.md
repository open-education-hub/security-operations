# Drill 02: Linux Security Audit

**Level:** Basic

**Estimated time:** 25 minutes

---

## Objective

Perform a security audit of a Linux system, identify misconfigurations and vulnerabilities, and produce a remediation checklist.

---

## Setup

```console
cd drills/basic/drill-02-linux-audit
docker compose up --build
docker compose exec linux-audit bash
```

The container has a deliberately misconfigured Ubuntu system with several security issues to find.

---

## Scenario

You are a new SOC analyst at a company.
You've been asked to audit a Linux web server that was set up by a developer six months ago.
It's been running since then with no security review.
Your job is to identify what's wrong and what needs to be fixed before it can be considered production-ready.

---

## Your Tasks

### Task 1: User Account Audit

1. List all user accounts with interactive login shells
1. Check if root direct login is allowed via SSH
1. Identify any accounts in the sudo/wheel group — are all of them expected?
1. Check if any account has an empty password

### Task 2: SSH Configuration Review

Review `/etc/ssh/sshd_config` and identify:

1. Is root login permitted?
1. Is password authentication enabled?
1. What is the MaxAuthTries setting?
1. Is X11 forwarding enabled?

Document each finding with: Current Value, Recommended Value, Risk if not fixed.

### Task 3: SUID Binary Audit

1. Run a SUID binary scan
1. List all SUID binaries found
1. Research which ones are expected (hint: passwd, sudo, su, mount are normal)
1. Flag any unexpected SUID binaries

### Task 4: Network Services Audit

1. List all ports currently listening
1. For each listening port, identify the service
1. Flag any services that should not be externally accessible
1. Are there any services listening on all interfaces that should only be on localhost?

### Task 5: Log Review

1. Check the last 5 failed SSH login attempts
1. Check the last 5 successful logins
1. Are there any sudo commands logged in the last 24 hours?
1. Is auditd running and configured?

---

## Deliverable

1. A security audit report with findings organized by category (Users, SSH, File Permissions, Network, Logs)
1. For each finding: Current State, Expected State, Risk Level (H/M/L), Remediation Command

See `solutions/drill-02-solution/` for reference.
