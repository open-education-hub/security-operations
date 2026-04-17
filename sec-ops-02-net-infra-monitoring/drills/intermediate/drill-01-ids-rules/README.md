# Drill 01 (Intermediate): Writing Snort/Suricata IDS Rules

**Level:** Intermediate

**Duration:** 45–60 minutes

**Prerequisites:** Demo 04 (Snort Intro), Session 02 Reading

---

## Instructions

For each of the 5 attack scenarios below, write a **Snort 3 compatible IDS rule** that would detect it.
Each rule must include:

* Correct rule header (action, protocol, source, direction, destination)
* Appropriate content matchers
* Threshold settings where applicable
* A meaningful `msg` field
* Correct `sid` (use 2000001–2000010 for your rules)
* A `rev` number
* A `classtype`

After writing each rule, explain in 2–3 sentences:

1. How the rule detects the attack
1. One potential source of false positives
1. How you would tune the rule to reduce false positives

---

## Attack Scenario 1: Telnet Login to a Network Device

**Attack description:**
An attacker is attempting to authenticate to a Cisco router using Telnet (port 23).
The Telnet protocol transmits credentials in cleartext.
You want to:

1. Alert on any Telnet connection to devices in the management network (10.0.99.0/24)
1. Specifically detect when a username (`Username:`) prompt is seen, indicating the auth phase

**Network context:**

* Management network: `10.0.99.0/24`
* Source: Any (both internal and external are suspicious for Telnet)
* The `$HOME_NET` variable covers `10.0.0.0/8`

**Write the rule here:**

```text
# Your rule:
alert ??? ??? ??? -> ??? ??? \
    (msg:"???"; ???; sid:2000001; rev:1; classtype:???;)
```

---

## Attack Scenario 2: HTTP Directory Traversal Attempt

**Attack description:**
An attacker is sending HTTP requests to a web server in the DMZ, trying path traversal to read system files.
The requests contain `../` sequences in the URI to navigate outside the web root.

**Example malicious requests:**

```text
GET /images/../../../etc/passwd HTTP/1.1
GET /css/../../../../etc/shadow HTTP/1.1
GET /scripts/%2E%2E%2F%2E%2E%2Fetc%2Fpasswd HTTP/1.1
```

**Network context:**

* DMZ web servers: `10.0.1.0/24`
* Web traffic: TCP port 80
* The literal string `../` or URL-encoded `%2E%2E%2F` should be detected

**Write the rule(s) here:**

```text
# Rule to detect literal ../
alert ??? ??? ??? -> ??? ??? \
    (msg:"???"; ???; sid:2000002; rev:1; classtype:???;)

# Rule to detect URL-encoded traversal
alert ??? ??? ??? -> ??? ??? \
    (msg:"???"; ???; sid:2000003; rev:1; classtype:???;)
```

---

## Attack Scenario 3: Outbound FTP Password Transmission

**Attack description:**
A compromised internal host is connecting to an external FTP server and transmitting credentials over FTP's cleartext control channel.
You want to detect the `PASS` command being sent from internal to external hosts.

**Protocol context:**

* FTP control channel: TCP port 21
* The `PASS` command format: `PASS <password>\r\n`
* Direction: Internal hosts (`$HOME_NET`) connecting outbound

**Write the rule here:**

```text
# Your rule:
alert ??? ??? ??? -> ??? ??? \
    (msg:"???"; ???; sid:2000004; rev:1; classtype:???;)
```

---

## Attack Scenario 4: DNS Query for a Known Malicious Domain

**Attack description:**
Your threat intelligence team has identified three domains being used by ransomware for C2:

* `update.malware-c2.xyz`
* `beacon.evil-ops.net`
* `checkin.badactor.io`

You want to write **one rule** for each domain that alerts when an internal host queries for it.
For extra credit, propose a more scalable approach using Zeek's intel framework instead.

**Network context:**

* DNS queries: UDP port 53 to any destination
* Source: Internal hosts (`$HOME_NET`)

**Write the three rules:**

```text
# Domain 1:
alert ??? ??? ??? -> any ??? \
    (msg:"???"; ???; sid:2000005; rev:1; classtype:???;)

# Domain 2:
alert ??? ??? ??? -> any ??? \
    (msg:"???"; ???; sid:2000006; rev:1; classtype:???;)

# Domain 3:
alert ??? ??? ??? -> any ??? \
    (msg:"???"; ???; sid:2000007; rev:1; classtype:???;)
```

---

## Attack Scenario 5: SMB EternalBlue Exploit (MS17-010)

**Attack description:**
EternalBlue is the exploit used by WannaCry ransomware, targeting the Windows SMB service (port 445).
The exploit sends a specific SMB transaction request containing a distinct byte pattern.

**Key detection details:**

* Protocol: TCP
* Destination port: 445
* Signature byte sequence (in the SMB transaction): `\x00\x00\x00\x23\xff\x53\x4d\x42`
  * This is a specifically malformed SMB_COM_TRANSACTION2 packet
* The exploit also uses a specific NT Trans request with `Trans2` opcode

**Write a rule that detects this pattern:**

```text
# EternalBlue detection rule:
alert ??? ??? ??? -> ??? ??? \
    (msg:"???"; ???; sid:2000008; rev:1; classtype:???;)
```

---

## Bonus: Rule Improvement Exercise

The following Snort rule has **four problems**.
Identify each problem and rewrite the corrected rule.

```text
alert ip any any -> any any (msg:"Detect Nmap"; content:"nmap"; nocase; sid:9999;)
```

Problems:

1. ?
1. ?
1. ?
1. ?

Corrected rule:

```text
# Write your corrected rule here
```

---

## Scoring

| Rule | Points |
|------|--------|
| Scenario 1 | 8 |
| Scenario 2 | 8 |
| Scenario 3 | 8 |
| Scenario 4 | 8 |
| Scenario 5 | 8 |
| Bonus | 10 |
| **Total** | **50** |

Passing: 35/50

### Rule scoring criteria (per rule):

* Correct protocol and direction: 2 pts
* Correct content/detection logic: 3 pts
* Appropriate threshold/metadata: 1 pt
* Valid explanation: 2 pts

---

## Reference

* Snort 3 User Manual: https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_v3_User_Manual.pdf
* Snort rule classtype options: `attempted-admin`, `attempted-recon`, `attempted-user`, `policy-violation`, `trojan-activity`, `web-application-attack`, `shellcode-detect`
