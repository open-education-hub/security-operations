# Drill 01 (Basic): Protocol Identification

**Level:** Basic

**Duration:** 30–45 minutes

**Format:** 10 identification exercises

**No tools required** — pen-and-paper (or text editor)

---

## Instructions

For each of the 10 snippets below, you are given a packet header excerpt, a log line, or a partial protocol exchange.
Your task is to:

1. **Identify the protocol** (e.g., HTTP, DNS, ARP, SSH, FTP, SMTP, TCP SYN scan, etc.)
1. **State the security relevance**: Is this normal, potentially suspicious, or definitely malicious? Why?
1. **Identify what action an analyst should take** (ignore, investigate, escalate, block)

Write your answers in the provided answer template.

---

## Snippet 1

```text
Frame: 74 bytes
Ethernet: Src=00:1a:2b:3c:4d:5e, Dst=ff:ff:ff:ff:ff:ff
IP: 192.168.1.100 → 192.168.1.1
Protocol: [non-IP / Layer 2 only]
Payload (hex): 00 01 08 00 06 04 00 01
               00 1a 2b 3c 4d 5e
               c0 a8 01 64
               00 00 00 00 00 00
               c0 a8 01 01
```

* Destination MAC: `ff:ff:ff:ff:ff:ff`
* The payload begins with `00 01` (opcode) and `08 00 06 04` (hardware/protocol type fields)

---

## Snippet 2

```text
TCP: 192.168.5.200:49123 → 10.0.0.1:22
Flags: SYN
Seq: 1234567890, Ack: 0
Window: 29200

[Response from server]
TCP: 10.0.0.1:22 → 192.168.5.200:49123
Flags: RST, ACK

[0.5 seconds later]
TCP: 192.168.5.200:49123 → 10.0.0.1:23
Flags: SYN
Seq: 1234567891, Ack: 0

[Response from server]
TCP: 10.0.0.1:23 → 192.168.5.200:49123
Flags: RST, ACK

[Pattern continues for ports 24, 25, 26, ... 1024]
```

---

## Snippet 3

```text
UDP: 10.10.5.23:51234 → 8.8.8.8:53
Payload (decoded):
  Transaction ID: 0xabcd
  Flags: Standard query, Recursion Desired
  Questions: 1
    Query: www.google.com
    Type: A (Host Address)
    Class: IN (Internet)
```

---

## Snippet 4

```text
UDP: 10.10.5.23:51235 → 8.8.8.8:53
Transaction ID: 0xabce
Query: xK7mN2pQ9rL4vW1eY8uI3oA6sD5fG0h.evil-domain.ru
Type: TXT
Class: IN

[Response]
Status: NOERROR
Answer: "ACK:cmd:whoami:result:cm9vdA=="
```

---

## Snippet 5

```text
TCP: 10.20.1.50:54321 → 203.0.113.10:21
[SYN/SYN-ACK/ACK — connection established]

Server → Client: "220 ProFTPD Server ready."
Client → Server: "USER bob"
Server → Client: "331 Password required for bob"
Client → Server: "PASS p@ssw0rd123"
Server → Client: "230 User bob logged in"
Client → Server: "RETR /etc/passwd"
Server → Client: "150 Opening BINARY mode data connection"
```

---

## Snippet 6

```text
TCP: 10.10.1.100:55000 → 10.10.2.200:3389
Flags: SYN
[SYN-ACK received]
[ACK — connection established]
[TLS handshake — content encrypted]
Duration: 3 hours 22 minutes
Bytes transferred: 45 MB
```

---

## Snippet 7

```text
syslog message:
<11>Jan 15 03:14:28 web-server sshd[2345]: Failed password for root from 203.0.113.50 port 12341 ssh2
<11>Jan 15 03:14:29 web-server sshd[2345]: Failed password for root from 203.0.113.50 port 12342 ssh2
<11>Jan 15 03:14:30 web-server sshd[2345]: Failed password for root from 203.0.113.50 port 12343 ssh2
<11>Jan 15 03:14:31 web-server sshd[2345]: Failed password for root from 203.0.113.50 port 12344 ssh2
<11>Jan 15 03:14:32 web-server sshd[2345]: Failed password for root from 203.0.113.50 port 12345 ssh2
<86>Jan 15 03:14:33 web-server sshd[2345]: Accepted password for root from 203.0.113.50 port 12346 ssh2
```

---

## Snippet 8

```text
HTTP: 192.168.100.50:50001 → 10.0.0.80:80

GET /index.php?id=1'+UNION+SELECT+username,password,3+FROM+users-- HTTP/1.1
Host: shop.internal.corp
User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)
Accept: */*

[Response]
HTTP/1.1 500 Internal Server Error
Content-Length: 2341
X-Powered-By: PHP/7.4.33

<b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax...
```

---

## Snippet 9

```text
Zeek conn.log entries for host 10.10.5.77 over 24 hours:

ts          id.orig_h   id.resp_h      id.resp_p  proto  duration  orig_bytes  resp_bytes  conn_state
1705363200  10.10.5.77  185.220.101.50  443        tcp    0.45      256         512         SF
1705363260  10.10.5.77  185.220.101.50  443        tcp    0.42      256         512         SF
1705363320  10.10.5.77  185.220.101.50  443        tcp    0.41      256         512         SF
1705363380  10.10.5.77  185.220.101.50  443        tcp    0.44      256         512         SF
1705363440  10.10.5.77  185.220.101.50  443        tcp    0.43      256         512         SF
[... identical pattern every 60 seconds for 24 hours ...]
```

---

## Snippet 10

```text
NetFlow record:
Date flow start          Dur   Proto  Src IP:Port          Dst IP:Port         Fl  Tos  Pkts  Bytes
2024-01-15 23:59:00.000  30.0  TCP    10.10.3.100:50500 -> 52.1.2.3:443      UAPRSF   0  2847  4198305

[Context: 10.10.3.100 is a Finance department workstation.
 52.1.2.3 resolves to an S3 bucket: backup-finance-q4.s3.amazonaws.com]
```

---

## Answer Template

Copy and fill in the following for each snippet:

```text
Snippet [N]:
  Protocol:
  Normal / Suspicious / Malicious:
  Evidence:
  Recommended action:
```

---

## Scoring

* 1 point for correct protocol identification
* 1 point for correct security assessment
* 1 point for appropriate recommended action

Maximum: 30 points
Passing score: 22/30

---

## Reference

Refer to:

* Session 02 Reading, Section 3 (TCP/IP Stack and Key Protocols)
* Guide 02: Protocol Analysis
