# Drill 01 (Intermediate): Privilege Escalation Simulation

**Level:** Intermediate

**Estimated time:** 45 minutes

---

## Objective

Explore common Linux privilege escalation techniques from a low-privilege starting point, understand how they work, then implement the defensive countermeasures to prevent them.

---

## Important Note

This drill uses a **deliberately vulnerable Docker container**.
All activities must be performed inside the provided container only.
Never attempt these techniques on real systems you don't own.

---

## Setup

```console
cd drills/intermediate/drill-01-privilege-escalation
docker compose up --build
# Start as a low-privilege user
docker compose exec --user student privesc-lab bash
```

You start as user `student` with no sudo privileges.
Your goal is to find and exploit privilege escalation paths, then document them and implement fixes.

---

## Challenges

### Challenge 1: SUID Binary Exploitation (20 points)

```console
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

There is a non-standard SUID binary on this system.
Research it to find if it has a privilege escalation path.

**Hint:** Check https://gtfobins.github.io/ for known SUID binary escalation techniques.

Once you find it, use it to get a shell as root.
Document:

1. Which binary?
1. What was the technique?
1. How do you fix it?

### Challenge 2: Sudo Misconfiguration (20 points)

```console
# Check sudo privileges
sudo -l
```

The `student` account has sudo permissions for specific commands.
One of these can be abused for privilege escalation.

**Hint:** Some commands allow spawning shells or executing arbitrary code even when constrained by sudo rules.

Document:

1. What sudo rule is misconfigured?
1. How can it be exploited?
1. How do you write a safe sudo rule?

### Challenge 3: World-Writable Script in PATH (20 points)

```bash
# Check PATH
echo $PATH

# Find world-writable files in PATH directories
for dir in $(echo $PATH | tr ':' ' '); do
  find $dir -perm -0002 2>/dev/null
done
```

There is a world-writable script in a PATH directory that is executed periodically by root's cron job.

Document:

1. Which script?
1. How can you exploit it?
1. What is the fix?

### Challenge 4: Weak File Permissions on Sensitive Files (20 points)

```console
# Check permissions on critical files
ls -la /etc/passwd /etc/shadow /etc/sudoers
ls -la /etc/cron*
```

A sensitive file has overly permissive settings.

Document:

1. Which file?
1. What are the incorrect permissions?
1. What should the permissions be?
1. What command fixes it?

---

## Defensive Countermeasures (20 points)

For each vulnerability you found, document:

1. The vulnerability description
1. The attack technique
1. The defensive fix (specific command or configuration)
1. CIS Benchmark recommendation that covers this issue (if applicable)

---

## Hints

* GTFOBins (https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited
* `sudo -l` shows what you can run with sudo
* Writable scripts in cron are classic persistence + escalation paths
* Many escalations combine multiple weaknesses

---

## Deliverable

A report covering all 4 challenges:

* How you found each vulnerability
* The exploit technique
* The defensive fix

See `solutions/drill-01-solution/` for reference.
