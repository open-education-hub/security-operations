# Drill 02 (Basic) — Linux Security Audit

**Level:** Basic

**Estimated time:** 25 minutes

---

## Objective

Perform a basic security audit of a Linux system inside Docker, identify misconfigurations, and apply basic hardening fixes.

---

## Setup

```console
cd drills/basic/drill-02-linux-audit
docker compose up --build
docker compose run linux-audit bash
```

---

## Scenario

You are auditing a newly provisioned Ubuntu server that will be used as an internal file server.
The system was installed by a contractor who may have left insecure defaults in place.
Your job is to assess and document the security posture before it goes into production.

---

## Tasks

### Task 1: User Account Review

```console
# Identify all users with interactive shells
grep -v "nologin\|false" /etc/passwd
```

**Questions:**

1. How many accounts can log in interactively?
1. Is there any account besides `root` with UID 0?
1. Are there any accounts that should not exist on a file server?

---

### Task 2: SSH Configuration Assessment

```console
grep -E "^PermitRootLogin|^PasswordAuthentication|^MaxAuthTries|^X11Forwarding" \
  /etc/ssh/sshd_config
```

**Questions:**

1. Is root login permitted?
1. Is password authentication enabled?
1. What is the maximum number of authentication attempts?

---

### Task 3: Find SUID Binaries

```console
find / -perm -4000 -type f 2>/dev/null
```

**Questions:**

1. List all SUID binaries found.
1. Which ones are expected and which are suspicious?

---

### Task 4: Check Network Listeners

```console
ss -tlnp
```

**Questions:**

1. What services are listening?
1. Are any services listening on all interfaces (0.0.0.0) that should not be exposed to the network?

---

### Task 5: Check Kernel Parameters

```console
sysctl kernel.randomize_va_space
sysctl net.ipv4.ip_forward
sysctl net.ipv4.tcp_syncookies
```

**Questions:**

1. Is ASLR enabled (value = 2)?
1. Is IP forwarding disabled (value = 0)?
1. Is SYN cookie protection enabled (value = 1)?

---

### Task 6: Apply Fixes

For any finding that is non-compliant, apply the appropriate fix using the commands from Guide 02.

Document:

* What was wrong
* The command you ran to fix it
* How you verified the fix was applied

---

## Deliverable

A simple audit report in this format for each task:

```text
Task 1 — User Accounts
  Finding: [what you found]
  Status: PASS / WARN / FAIL
  Remediation: [what you changed or recommend]
```

See the solution in: `solutions/drill-02-solution/solution.md`
