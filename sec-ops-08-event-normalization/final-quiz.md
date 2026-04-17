# Final Quiz — Session 08: Event Correlation and Normalization

**Instructions:** Select the single best answer for each question.

**Time:** 15 minutes

**Passing score:** 70% (5/7 correct)

---

## Question 1

In the CEF log format: `CEF:0|Cisco|ASA|9.8|106023|Deny IP|8|src=10.0.1.5 spt=44321 dst=192.168.100.5 dpt=443 proto=TCP act=Deny`

What is the correct ECS field mapping for the CEF `spt` field?

* A) `source.address`
* B) `source.port`
* C) `network.port`
* D) `destination.port`

**Correct answer: B**

*Explanation: CEF `spt` = source port → ECS `source.port`.
CEF `dpt` = destination port → ECS `destination.port`.*

---

## Question 2

Which Logstash filter is most appropriate for parsing a log line with a known key=value pair structure like `user=jdoe action=login src_ip=10.0.1.5 result=failed`?

* A) `grok` with a complex regex pattern
* B) `csv` with column headers defined
* C) `kv` (key-value) with appropriate split characters
* D) `mutate` with field renaming

**Correct answer: C**

*Explanation: The `kv` filter is specifically designed for key=value formatted data.
It automatically extracts all key-value pairs without requiring you to write individual regex patterns for each field.*

---

## Question 3

A Sigma rule has the following detection section:

```yaml
detection:
  selection:
    event.outcome: failure
    event.category: authentication
  timeframe: 5m
  condition: selection | count() by source.ip > 10
```

What type of correlation rule is this?

* A) Single-event rule detecting one specific event
* B) Sequence rule requiring events to occur in order
* C) Threshold (aggregation) rule counting events over time
* D) Behavioral anomaly rule comparing to a baseline

**Correct answer: C**

*Explanation: The `timeframe` and `count() > 10` syntax defines a threshold rule — it counts matching events (grouped by source.ip) within a 5-minute window and fires when the count exceeds 10.
This is classic brute-force detection.*

---

## Question 4

What is the primary advantage of the **Sigma rule format** over writing queries directly in a SIEM's native language?

* A) Sigma rules execute faster than native SIEM queries
* B) Sigma rules can be compiled/transpiled to multiple SIEM query languages, making rules portable
* C) Sigma rules automatically tune themselves to reduce false positives
* D) Sigma supports machine learning models that native SIEM languages do not

**Correct answer: B**

*Explanation: Sigma is a vendor-neutral rule format that can be compiled to Splunk SPL, Elasticsearch KQL, Microsoft Sentinel KQL, Chronicle YARA-L, and many others.
Write once, deploy anywhere.*

---

## Question 5

Your detection rule for `net.exe` domain enumeration fires 500 times per day, mostly from IT administrators.
You add the following filter to the Sigma rule:

```yaml
filter_it_admins:
  user.name|endswith:
    - '_admin'
    - '_ops'
```

An attacker compromises the account `network_ops` (which matches `_ops`).
What detection failure has occurred?

* A) False negative — the rule fires but is incorrect
* B) False positive — the rule correctly fires on benign activity
* C) False negative — the rule fails to fire on a real attack
* D) True positive — the rule correctly detects the attack

**Correct answer: C**

*Explanation: A false negative is when a rule fails to fire on a real attack.
By whitelisting all accounts ending in `_ops`, you've created a gap that an attacker can exploit by compromising an `_ops` account.
This is why whitelists must be account-specific and regularly reviewed.*

---

## Question 6

In the context of UEBA (User and Entity Behavior Analytics), what does **peer group analysis** mean?

* A) Comparing a user's behavior to all other users in the organization
* B) Comparing a user's behavior to other users with similar job roles or attributes
* C) Requiring two analysts to review every alert before it is actionable
* D) Analyzing behavior during non-peak hours only

**Correct answer: B**

*Explanation: Peer group analysis compares a user's behavior to a group of similar users (same department, job function, or access level).
This allows detection of outliers within a peer group without assuming all users should behave identically.*

---

## Question 7

Which of the following is the BEST approach to managing the 7-year log retention requirement for compliance, while minimizing storage costs?

* A) Store all logs in a single high-performance SSD cluster for 7 years
* B) Delete logs older than 90 days and rely on summary reports for compliance
* C) Implement tiered storage: hot (0-30 days), warm (31-90 days), cold/archive (91 days-7 years)
* D) Encrypt and compress all logs into a single archive file annually

**Correct answer: C**

*Explanation: Tiered storage optimizes cost by matching storage type to access frequency.
Recent logs (hot) need fast SSD for investigations.
Medium-age logs (warm) can use slower, cheaper storage.
Compliance-only retention (cold) can use very cheap object storage (S3 Glacier, Azure Archive) where retrieval latency is acceptable.*
