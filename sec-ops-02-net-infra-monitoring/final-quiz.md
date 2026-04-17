# Final Quiz — Session 02: Network Infrastructure and Security Monitoring Tools

**Purpose:** Assess comprehension of session content

**Time limit:** 15 minutes

**Instructions:** Choose the single best answer for each question.

---

## Question 1

You are analysing a Zeek `conn.log` and see many entries with `conn_state = S0` from the same source IP to many different destination ports.
What does this most likely indicate?

A) Normal web browsing with many simultaneous downloads
B) A TCP port scan — SYN packets sent with no response received ✓
C) A DDoS attack flooding the network with UDP packets
D) DNS resolution failures due to a misconfigured resolver

---

## Question 2

An analyst configures Snort with the rule:

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 \
    (flags:S; threshold: type threshold, track by_src, count 5, seconds 60; \
     msg:"SSH Brute Force"; sid:1000002; rev:1;)
```

When will this rule generate an alert?

A) On every SSH SYN packet from an external source
B) After the 5th SSH SYN packet from the same source IP within 60 seconds ✓
C) Only when an SSH connection is successfully established
D) When 5 different external IPs connect to SSH within 60 seconds

---

## Question 3

What is the key advantage of a hardware Network TAP over a SPAN (mirror) port for traffic capture?

A) TAPs are cheaper to deploy than SPAN ports
B) TAPs can be configured remotely while SPAN requires physical access
C) TAPs capture all frames including errors and cannot be detected or impacted by network problems ✓
D) TAPs support more simultaneous monitoring connections than SPAN

---

## Question 4

A Zeek `dns.log` shows the following queries from a single internal host within 30 seconds:

```text
aXpK2mNr9qLw4vT7uYo1bZf6cDh5gEi.c2domain.ru   TXT
bYqL3nOs0rMx5wU8vZp2cAg7dEi6hFj.c2domain.ru   TXT
cZrM4oTp1sNy6xV9wAq3dBh8eJj7iGk.c2domain.ru   TXT
```

What does this pattern most likely represent?

A) A misconfigured DNS client sending duplicate queries
B) A user browsing multiple Russian websites
C) DNS tunnelling for Command and Control (C2) communication ✓
D) A DNS server performing recursive lookups for zone transfer

---

## Question 5

Under GDPR, what is the legal time limit for notifying the supervisory authority after discovering a personal data breach?

A) 24 hours
B) 48 hours
C) 72 hours ✓
D) 7 days

---

## Question 6

Which of the following best describes the difference between **Zeek** and **Snort**?

A) Zeek is a firewall while Snort is an IDS
B) Zeek generates structured logs for all traffic while Snort generates alerts only for traffic matching rules ✓
C) Zeek can block traffic while Snort cannot
D) Zeek works only with PCAP files while Snort requires live network access

---

## Question 7

An analyst reviewing NetFlow data notices the following pattern from a workstation (`10.10.5.50`):

* 1440 flows to `185.220.101.50:443` over 24 hours
* Each flow lasts exactly 1 second
* All flows transfer exactly 256 bytes outbound and 512 bytes inbound
* One flow occurs every 60 seconds

What is the most accurate characterisation of this traffic?

A) Normal HTTPS browsing to a busy cloud service
B) A malware implant beaconing to a Command and Control server ✓
C) A legitimate automated backup process
D) A botnet DDoS attack targeting the destination IP

---

## Answer Key

| Q | Answer | Topic tested |
|---|--------|-------------|
| 1 | B | Zeek conn.log — connection states |
| 2 | B | Snort — threshold option |
| 3 | C | Collection — TAP vs SPAN |
| 4 | C | DNS — tunnelling detection |
| 5 | C | Legal — GDPR breach notification |
| 6 | B | NSM tools — Zeek vs Snort |
| 7 | B | NetFlow — beaconing detection |

## Scoring

| Score | Performance |
|-------|------------|
| 7/7 | Excellent — strong grasp of all session concepts |
| 5–6/7 | Good — minor gaps to review |
| 3–4/7 | Adequate — revisit the reading and demos |
| 0–2/7 | Below expectations — redo the session materials |
