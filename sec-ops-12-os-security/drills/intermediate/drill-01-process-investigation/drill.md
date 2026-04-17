# Drill 01 (Intermediate) — Process Investigation

**Level:** Intermediate

**Estimated time:** 40 minutes

---

## Objective

Investigate a suspicious process on a compromised Linux system.
Using only standard OS tools, identify the full scope of the attacker's activity and produce an incident report with IOCs.

---

## Setup

```console
cd drills/intermediate/drill-01-process-investigation
docker compose up --build
docker compose exec investigation bash
```

The container has been "compromised" — several malicious processes and artifacts have been pre-planted.

---

## Scenario

You are an on-call SOC analyst.
An EDR alert fired at 03:47 UTC:

> **Alert:** Unusual outbound network connection from process `python3` to `198.51.100.44:4443`
> **Host:** `webapp-prod-03`
> **Severity:** High

The system is a production web application server.
SSH access has been provided for investigation.
You must determine what happened and contain the threat.

---

## Task 1: Initial Process Triage

Start by understanding what is running:

```console
ps auxf
```

1. Find the suspicious `python3` process and note its PID.
1. What is the full command line?
1. What is the parent process? Is the parent also suspicious?
1. What is the process's working directory?

**Hint:** Check `/proc/<PID>/cmdline` and `/proc/<PID>/cwd`.

---

## Task 2: Network Connection Analysis

```console
ss -tnp
ss -tlnp
```

1. Confirm the outbound connection to `198.51.100.44:4443`.
1. Are there any additional connections or listening ports that are suspicious?
1. What PID owns each suspicious connection?

---

## Task 3: File System Forensics

```console
# Investigate the files associated with the suspicious process
ls -la /proc/<PID>/
ls -la /proc/<PID>/fd/
```

1. What files does the process have open?
1. Is the executable still on disk, or has it been deleted?
1. If deleted, how would you recover the binary for analysis?

---

## Task 4: Persistence Check

The attacker likely established persistence.
Check all common Linux persistence locations:

1. Cron jobs for all users
1. Systemd user services in `/home/*/` directories
1. SSH authorized keys for all users
1. `/etc/ld.so.preload`

Document every persistence mechanism found.

---

## Task 5: Timeline Reconstruction

Using `/var/log/auth.log` and any other available logs:

1. When did the attacker first gain access?
1. What was the initial access vector (SSH brute force? Exploit? Legitimate credential?)
1. What commands did they run after gaining access?
1. When did the suspicious process start (compare to process start time in `/proc/<PID>/stat`)?

---

## Task 6: Containment

List the containment actions you would take (in order):

1. Immediate network containment (without shutting down the system)
1. Stopping malicious processes without destroying evidence
1. Disabling persistence mechanisms
1. Preserving evidence for forensics

**Important:** Do NOT simply reboot the system — that destroys volatile memory evidence.

---

## Deliverable

An incident report covering:

1. **Summary:** What happened in 2–3 sentences
1. **IOC List:** All indicators of compromise found (IPs, file paths, process names, hashes)
1. **Timeline:** Chronological sequence of attacker actions
1. **Root Cause:** How the attacker got in
1. **Containment Actions:** Steps taken or recommended

See the solution in: `solutions/drill-01-solution/solution.md`
