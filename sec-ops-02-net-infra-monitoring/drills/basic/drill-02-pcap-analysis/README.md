# Drill 02 (Basic): PCAP Description Analysis

**Level:** Basic

**Duration:** 30–45 minutes

**Format:** Analysis scenario — no tools required

**Prerequisites:** Guide 01 (Wireshark), Guide 02 (Protocol Analysis)

---

## Instructions

Read the following PCAP analysis report carefully.
It describes the contents of a 15-minute packet capture from a corporate network perimeter.
Answer the investigation questions that follow.

You do **not** have access to the actual PCAP file — work from the description and statistics provided.

---

## Scenario: Argus Tech Corp — Perimeter Capture

**Capture details:**

* Interface: `eth0` (internet-facing interface, after the outer firewall)
* Capture start: `2024-01-16 09:47:00 UTC`
* Capture end: `2024-01-16 10:02:00 UTC`
* Total duration: 15 minutes
* Total packets: 87,432
* Total bytes: 124,891,022 (≈ 119 MB)
* Interface speed: 1 Gbps

---

## Protocol Hierarchy (from Wireshark → Statistics → Protocol Hierarchy)

```text
Protocol            Packets   %      Bytes    %
Ethernet            87,432    100%   124.9 MB 100%
  IPv4              87,102    99.6%  124.8 MB 99.9%
    TCP             80,234    91.7%  120.3 MB 96.2%
      HTTP          41,023    46.9%   61.2 MB 49.0%
        HTTP/XML    12,003    13.7%   18.4 MB 14.7%
      TLS           32,011    36.6%   56.1 MB 44.9%
        TLS handshake 1,203    1.4%    1.8 MB  1.4%
      TCP data       7,200     8.2%    3.0 MB  2.4%
    UDP              6,868     7.9%    4.5 MB  3.6%
      DNS            6,501     7.4%    2.1 MB  1.7%
        DNS query    3,247     3.7%    1.0 MB  0.8%
        DNS response 3,254     3.7%    1.1 MB  0.9%
      UDP other       367     0.4%    2.4 MB  1.9%
    ICMP              680     0.8%  43,520 B   0.0%
  ARP                 330     0.4%   19,800 B  0.0%
```

---

## Conversation Statistics (Top 10 by bytes — from Statistics → Conversations)

```text
Rank  Src IP          Dst IP          Sport   Dport  Proto  Bytes       Duration
 1    10.0.1.10       203.0.113.50    56234   443    TCP    42,891,504  14m 52s
 2    10.0.1.10       198.18.0.77     48001   80     TCP    28,304,128   2m 15s
 3    10.0.2.5        8.8.8.8         51234   53     UDP       124,800   0m 30s
 4    10.0.2.5        8.8.8.8         51235   53     UDP       124,800   0m 30s
 5    10.0.2.5        8.8.8.8         51236   53     UDP       124,800   0m 30s
 6    10.0.2.5        8.8.8.8         51237   53     UDP       124,800   0m 30s
 7    10.0.2.5        8.8.8.8         51238   53     UDP       124,800   0m 30s
 8    10.0.2.5        8.8.8.8         51239   53     UDP       124,800   0m 30s
 9    10.0.2.5        8.8.8.8         51240   53     UDP       124,800   0m 30s
10   203.0.113.100   10.0.0.1        33789    22     TCP        24,320   0m 00s

[Rows 3-9 continue with incrementing ports from 51234 to 51256 — 24 rows total]
```

---

## DNS Log Summary (from dns.log / filter: dns.flags.response == 0)

```text
Count  Query                                               Type  Resolver
 1,234  www.google.com                                     A     8.8.8.8
   892  mail.google.com                                    A     8.8.8.8
   756  cdn.example-corp.com                               A     8.8.8.8
   124  aKe8mNp3xQr5vLt2wZy7bDs4fGh1jCu.c2track.net      TXT   8.8.8.8
   119  bMr6nKe9mPt3xQs8vLu2wZy5bDs1fGh.c2track.net      TXT   8.8.8.8
   118  cNt7oLf0nRu4yMs9wPv3xZz6cEt2gHi.c2track.net      TXT   8.8.8.8
    89  accounts.google.com                                A     8.8.8.8
    22  c2track.net                                        A     8.8.8.8
    18  _domainkey.c2track.net                             TXT   8.8.8.8
     1  passwd.internal.argustech.com                     A     8.8.8.8
```

---

## HTTP Request Summary (from http.log / filter: http.request)

```text
Count  Method  Host                   URI                        Status  User-Agent
12,003  GET    cdn.example-corp.com   /assets/*                 200     Chrome/120.0
 1,234  GET    www.google.com         /                         200     Chrome/120.0
   892  GET    mail.google.com        /mail/u/0/                200     Chrome/120.0
   124  POST   198.18.0.77            /api/v2/collect           200     go-http-client/2.0
   119  POST   198.18.0.77            /api/v2/collect           200     go-http-client/2.0
    18  POST   198.18.0.77            /api/v2/collect           200     go-http-client/2.0
     4  GET    198.18.0.77            /api/v2/cmds              200     go-http-client/2.0
     1  GET    10.0.0.1               /admin/backup.zip         200     python-requests/2.31
```

---

## TCP Flag Statistics (from Wireshark Expert Info)

```text
SYN packets (new connection attempts):     4,312
SYN-ACK responses:                         2,108
RST responses to SYN:                      2,203   ← (4312 - 2108 ≈ 2204 unanswered)
FIN packets (clean close):                 2,001
RST packets (abrupt close):                3,891
Retransmissions detected:                    234
Duplicate ACKs:                              189
TCP Zero Window:                              12
```

---

## TLS Certificate Summary (from ssl.log / x509.log)

```text
Server Name            Version    Cipher             Valid  Issuer
www.google.com         TLSv1.3    TLS_AES_256_GCM    Yes    Google Trust Services
mail.google.com        TLSv1.3    TLS_AES_256_GCM    Yes    Google Trust Services
203.0.113.50           TLSv1.2    RC4-MD5             No    Self-signed
c2track.net            TLSv1.2    TLS_RSA_WITH_3DES   No    Self-signed
```

---

## Questions

### Section A: Basic Analysis (3 points each)

**Question 1:** Looking at the Protocol Hierarchy, what percentage of traffic is plaintext HTTP vs. encrypted TLS?
What security implication does the HTTP percentage have?

**Question 2:** In the Conversation Statistics, rows 3-9 show multiple UDP flows from `10.0.2.5` to `8.8.8.8:53`.
What is unusual about these flows?
What might this indicate?

**Question 3:** The DNS log shows queries for `aKe8mNp3xQr5vLt2wZy7bDs4fGh1jCu.c2track.net` of type TXT.
What type of attack does this suggest?
What is `c2track.net` likely used for?

### Section B: Threat Identification (5 points each)

**Question 4:** Rank the following observed events from most to least severe, and justify your ranking:

* (a) HTTP traffic to `198.18.0.77` with User-Agent `go-http-client/2.0`
* (b) The self-signed certificate on `203.0.113.50` with RC4-MD5 cipher
* (c) The DNS query for `passwd.internal.argustech.com` going to `8.8.8.8`
* (d) The GET request for `/admin/backup.zip` with `python-requests` user-agent

**Question 5:** Conversation row 1 shows `10.0.1.10 → 203.0.113.50:443` transferring **42.9 MB** over **14 minutes and 52 seconds**.
The TLS certificate is self-signed and uses RC4-MD5.
What scenario(s) could explain this conversation?
Which is most likely, and why?

**Question 6:** The TCP flag statistics show 2,203 RST responses to SYN packets.
Cross-referencing with the conversation table, what is likely causing this?
What additional information would you want to investigate?

### Section C: Investigation Planning (8 points each)

**Question 7:** Write an investigation plan for the `c2track.net` activity.
Include:

* What you already know from the logs
* What additional data you need to collect
* Who you would notify
* What containment actions you would take immediately

**Question 8:** Create a timeline of the most critical events in this capture, ordered chronologically.
Identify the likely sequence of the attack (if one is present).

**Question 9:** Assuming this is a confirmed security incident, what evidence would you preserve and how would you ensure chain of custody?

---

## Scoring

| Section | Points available |
|---------|----------------|
| Section A (3 questions × 3 pts) | 9 |
| Section B (3 questions × 5 pts) | 15 |
| Section C (3 questions × 8 pts) | 24 |
| **Total** | **48** |

Passing score: 36/48 (75%)

---

## Hints

* The `c2track.net` domain name is not accidental — consider what "c2" stands for
* TLS cipher `RC4-MD5` has been broken since 2013 and is deprecated; its use suggests an outdated or deliberately weak implementation
* `go-http-client/2.0` is the default User-Agent for the Go programming language's HTTP library — not a browser
* `python-requests` is the User-Agent for the popular Python `requests` library — not a browser
* UDP flows to port 53 with identical byte counts from different source ports within the same second suggest automated/scripted behaviour
* `passwd.internal.argustech.com` — why would an internal hostname be queried against an external DNS server (`8.8.8.8`)?
