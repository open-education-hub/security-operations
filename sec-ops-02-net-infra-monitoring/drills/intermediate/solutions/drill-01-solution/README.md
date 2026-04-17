# Drill 01 Solution (Intermediate): IDS Rule Writing

---

## Scenario 1 Solution: Telnet to Management Network

```text
alert tcp any any -> 10.0.99.0/24 23 \
    (msg:"Telnet Connection Attempt to Management Network"; \
     flow:to_server,established; \
     content:"Username:"; nocase; \
     sid:2000001; rev:1; \
     classtype:attempted-admin; priority:1;)
```

**Alternative (detect the connection itself, not just the auth prompt):**

```text
alert tcp any any -> 10.0.99.0/24 23 \
    (msg:"Telnet Connection to Management Network - Cleartext Protocol"; \
     flow:to_server; \
     flags:S; \
     sid:2000001; rev:2; \
     classtype:policy-violation; priority:2;)
```

**Explanation:**

* The first rule matches the string `"Username:"` in the payload, which Cisco IOS routers send at the login prompt. This confirms a Telnet session has reached the authentication stage.
* The second, simpler rule alerts on any TCP SYN to port 23 on the management network — this is broader and will fire on every attempt, not just authenticated ones.

**Potential false positives:** Legitimate administrators using Telnet for emergency access (if SSH is unavailable).
However, even this is a policy violation — Telnet should never be used on production management networks.

**Tuning:** Create a whitelist of authorised management workstations and use a `pass` rule with higher priority for those sources.
Change `classtype` to `policy-violation` since even "authorised" Telnet is a security risk.

---

## Scenario 2 Solution: HTTP Directory Traversal

```text
# Rule to detect literal ../
alert tcp $EXTERNAL_NET any -> 10.0.1.0/24 80 \
    (msg:"HTTP Path Traversal Attempt - Literal ../"; \
     flow:to_server,established; \
     content:"../"; http_uri; nocase; \
     sid:2000002; rev:1; \
     classtype:web-application-attack; priority:1;)

# Rule to detect URL-encoded traversal (%2E%2E%2F)
alert tcp $EXTERNAL_NET any -> 10.0.1.0/24 80 \
    (msg:"HTTP Path Traversal Attempt - URL Encoded"; \
     flow:to_server,established; \
     content:"%2E%2E%2F"; http_uri; nocase; \
     sid:2000003; rev:1; \
     classtype:web-application-attack; priority:1;)

# Bonus: detect double-encoded traversal (%252E%252E%252F)
alert tcp $EXTERNAL_NET any -> 10.0.1.0/24 80 \
    (msg:"HTTP Path Traversal Attempt - Double URL Encoded"; \
     flow:to_server,established; \
     content:"%252E%252E"; http_uri; nocase; \
     sid:2000009; rev:1; \
     classtype:web-application-attack; priority:1;)
```

**Explanation:**

* Rule 2000002 uses `http_uri` to apply the content match only to the URI portion of the HTTP request (not headers or body), reducing false positives.
* Rule 2000003 catches URL-encoded traversal where `../` is encoded as `%2E%2E%2F` (period=`%2E`, slash=`%2F`).
* The `nocase` modifier ensures detection regardless of capitalisation (`%2e%2e%2f` vs `%2E%2E%2F`).

**Potential false positives:**

* Legitimate URLs occasionally contain `../` in CDN or redirect paths (rare)
* Static file servers that allow canonical paths

**Tuning:** Add `http_uri` buffer and look for `etc/passwd` or `windows/system32` as a second content match to require both traversal AND a sensitive file reference (reduces false positives at the cost of possibly missing obfuscated paths):

```text
content:"../"; http_uri; content:"passwd"; nocase; http_uri; distance:0;
```

---

## Scenario 3 Solution: FTP Password Transmission

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 \
    (msg:"FTP Cleartext Password Transmission to External Server"; \
     flow:to_server,established; \
     content:"PASS "; offset:0; depth:5; nocase; \
     sid:2000004; rev:1; \
     classtype:policy-violation; priority:2;)
```

**Explanation:**

* `flow:to_server,established` ensures we only look at established connections (after the TCP handshake), and only in the client→server direction.
* `content:"PASS "; offset:0; depth:5;` looks for the literal string `PASS ` at the start of the TCP payload (FTP commands always start at the beginning of a TCP data segment after stream reassembly).
* `$HOME_NET any -> $EXTERNAL_NET 21` ensures we only fire on outbound FTP connections (internal host to external FTP server), not on inbound FTP traffic to your own servers.

**Potential false positives:**

* Internal-to-internal FTP (if you want to allow it) — but this rule only applies to `$EXTERNAL_NET` destinations, so internal FTP is not affected
* FTPS (FTP over TLS) — the `PASS` command would be encrypted and not visible; this rule only catches cleartext FTP

**Tuning:** Add a second rule for the `USER` command to detect the username too:

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 \
    (msg:"FTP Cleartext Username to External Server"; \
     flow:to_server,established; content:"USER "; offset:0; depth:5; nocase; \
     sid:2000010; rev:1; classtype:policy-violation; priority:3;)
```

---

## Scenario 4 Solution: Known Malicious Domain Detection

```text
# Domain 1: update.malware-c2.xyz
alert udp $HOME_NET any -> any 53 \
    (msg:"DNS Query for Known Malicious Domain - malware-c2.xyz"; \
     content:"|07|malware|02|c2|03|xyz|00|"; \
     sid:2000005; rev:1; \
     classtype:trojan-activity; priority:1;)

# Domain 2: beacon.evil-ops.net
alert udp $HOME_NET any -> any 53 \
    (msg:"DNS Query for Known Malicious Domain - evil-ops.net"; \
     content:"|08|evil|2d|ops|03|net|00|"; \
     sid:2000006; rev:1; \
     classtype:trojan-activity; priority:1;)

# Domain 3: checkin.badactor.io
alert udp $HOME_NET any -> any 53 \
    (msg:"DNS Query for Known Malicious Domain - badactor.io"; \
     content:"|09|badactor|02|io|00|"; \
     sid:2000007; rev:1; \
     classtype:trojan-activity; priority:1;)
```

**Note on DNS content matching:**
DNS queries use a label encoding where each label (domain component) is preceded by a byte indicating its length.
For example, `malware-c2.xyz` is encoded as:

* `\x07malware-c2` (7-character label: `malware` is 7 chars) — wait, `malware` = 7 chars, `-c2` adds 3 more = `malware-c2` = 10 chars

* Correction: `malware-c2` = 10 chars → `|0a|malware-c2|03|xyz|00|`

Simpler approach using hex-agnostic content:

```text
alert udp $HOME_NET any -> any 53 \
    (msg:"DNS Query for Known Malicious Domain - malware-c2.xyz"; \
     content:"malware-c2"; nocase; \
     sid:2000005; rev:2; classtype:trojan-activity; priority:1;)
```

**Zeek intel framework (scalable alternative):**

```text
# intel/bad-domains.txt
#fields   indicator          indicator_type    meta.source        meta.desc
malware-c2.xyz               Intel::DOMAIN     ThreatIntel-Team   Ransomware C2
evil-ops.net                 Intel::DOMAIN     ThreatIntel-Team   Ransomware C2
badactor.io                  Intel::DOMAIN     ThreatIntel-Team   Ransomware C2

# Zeek script (load-intel.zeek)
@load base/frameworks/intel
redef Intel::read_files += { "/intel/bad-domains.txt" };
```

**Why Zeek is more scalable:** Adding a new malicious domain requires only adding a line to the text file, not writing and deploying a new rule.
Zeek automatically generates a Notice when any query matches the intel file.

**Potential false positives:** None for exact domain matching.
If you use substring matching (e.g., `content:"evil-ops"`), legitimate domains with similar strings could trigger.

---

## Scenario 5 Solution: EternalBlue / MS17-010

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 \
    (msg:"EXPLOIT EternalBlue MS17-010 SMB Transaction2 Exploit Attempt"; \
     flow:to_server,established; \
     content:"|00 00 00 23 ff 53 4d 42|"; \
     depth:8; offset:4; \
     sid:2000008; rev:1; \
     classtype:shellcode-detect; priority:1;)
```

**Additional rule for the NT Trans variant:**

```text
alert tcp any any -> $HOME_NET 445 \
    (msg:"EXPLOIT EternalBlue MS17-010 NT Trans Exploit Attempt"; \
     flow:to_server,established; \
     content:"|ff 53 4d 42 a0|"; nocase; \
     sid:2000009; rev:1; \
     classtype:shellcode-detect; priority:1;)
```

**Explanation:**

* `\xff\x53\x4d\x42` = `\xffSMB` — the SMB header magic bytes
* The `\x00\x00\x00\x23` prefix indicates a specific packet length/type combination in the malformed EternalBlue request
* `depth:8; offset:4;` positions the search correctly within the SMB packet structure

**Note:** In production, use the official Snort/Emerging Threats EternalBlue rules (SID 41978, 42329, 42330, etc.) which have been extensively tested and tuned.
This is for educational purposes.

**Potential false positives:** Essentially none — this byte sequence does not appear in legitimate SMB traffic.
However, different exploit variants may have slightly different signatures.

---

## Bonus Solution: Rule Problems

**Original rule:**

```text
alert ip any any -> any any (msg:"Detect Nmap"; content:"nmap"; nocase; sid:9999;)
```

**Problems:**

1. **SID conflict:** `sid:9999` is in the range 1-999999 which may conflict with official Snort rules. Custom rules should use SID ≥ 1,000,000.
1. **Overly broad rule:** `ip any any -> any any` matches all IP traffic in both directions, which will generate an enormous number of alerts and consume significant CPU.
1. **Unreliable detection:** Nmap does not typically put the string "nmap" in packet payloads. This rule will rarely fire on actual Nmap scans. Nmap can be detected via TCP flag patterns (see Scenario 2 in Demo 04), not by content matching.
1. **Missing `rev:`** — The rule lacks a revision number, which is required for proper rule management.

**Corrected rule:**

```text
# More effective Nmap SYN scan detection using TCP flag analysis
alert tcp $EXTERNAL_NET any -> $HOME_NET any \
    (msg:"Possible Nmap SYN Port Scan"; \
     flags:S,!APUR; \
     threshold: type both, track by_src, count 20, seconds 5; \
     sid:1000003; rev:2; \
     classtype:attempted-recon; priority:2;)

# Nmap default User-Agent in HTTP requests (when scanning web servers)
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
    (msg:"Nmap HTTP Scan - Nmap User-Agent"; \
     flow:to_server,established; \
     content:"User-Agent: Nmap Scripting Engine"; http_header; \
     sid:1000010; rev:1; \
     classtype:attempted-recon; priority:2;)
```
