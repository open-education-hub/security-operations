# Final Practice Quiz — Session 04: Fundamentals of Cryptography

> **Purpose:** Deep-dive practice with short answer and extended response questions
> **Format:** 5 short answer (1–3 sentences each) + 2 long answer (1–2 paragraphs each)
> **Time:** 45 minutes
> **Passing:** Instructor assessed — see grading rubric

---

## Instructions

Answer each question thoughtfully.
Short answer questions should be precise and concise (1–3 sentences).
Long answer questions should demonstrate understanding of concepts and their practical implications.
Bullet points are acceptable for short answers.

---

## Short Answer Questions (5 × 4 points = 20 points)

---

**Question 1** (4 points)

Explain what a "padding oracle attack" is and name one TLS vulnerability that exploited it.

*Your answer:*

___

**Model Answer:**

A padding oracle attack exploits a system that tells an attacker whether decrypted data has valid padding, allowing the attacker to iteratively decrypt ciphertext byte by byte without knowing the encryption key.
The attacker submits modified ciphertext and uses the valid/invalid padding response as an "oracle" to deduce plaintext bits.

**TLS vulnerability example:** POODLE (Padding Oracle On Downgraded Legacy Encryption, 2014) forced TLS clients to downgrade to SSL 3.0 and exploited its CBC padding oracle, allowing decryption of session cookies and auth tokens.

**Grading:** 2 points for correct explanation of padding oracle, 2 points for correctly naming a relevant attack (POODLE, BEAST, or similar CBC padding attack).

---

**Question 2** (4 points)

What is the difference between a hash collision and a preimage attack?
Which is harder to achieve, and why does this matter for SHA-256?

*Your answer:*

___

**Model Answer:**

A **collision** means finding any two different inputs M1 ≠ M2 such that H(M1) = H(M2).
A **preimage attack** means finding any input M that produces a specific target hash value h (i.e., H(M) = h).
Preimage attacks are harder than collision attacks because they require matching a specific target, while collisions only require finding any matching pair.

For an n-bit hash, collision resistance requires ~2^(n/2) operations (birthday paradox), while preimage resistance requires ~2^n operations.
For SHA-256: collisions require ~2^128 operations (infeasible), preimages require ~2^256 (extremely infeasible).
This matters because SHA-256 is considered secure for both purposes.

**Grading:** 2 points for correctly distinguishing the two attacks, 2 points for explaining the difficulty relationship and birthday bound.

---

**Question 3** (4 points)

You are a SOC analyst.
Encrypted HTTPS traffic is flowing from a workstation to an external IP.
You cannot see the payload.
List three specific pieces of information you CAN obtain from the TLS metadata that might indicate malicious activity.

*Your answer:*

___

**Model Answer (any 3 of the following):**

1. **SNI (Server Name Indication):** The target domain name sent in plaintext in the ClientHello — reveals which domain the workstation is connecting to (even though the payload is encrypted)
1. **Certificate details:** Subject CN/SAN, issuer, validity period — a self-signed cert, very new cert, or cert from an unusual CA is suspicious
1. **JA3 fingerprint:** Hash of TLS ClientHello parameters identifies the specific client implementation — can match known malware fingerprints from threat intel
1. **Beaconing pattern:** Regular connection intervals (e.g., exactly every 60 seconds) suggest automated C2 check-ins
1. **Data volume asymmetry:** Much more data sent than received suggests exfiltration
1. **Certificate age:** A certificate issued hours/days ago on an unknown domain is a red flag

**Grading:** 4 points for any three correct, specific answers (not generic).
"IP address" alone is insufficient — must be specific to TLS metadata.

---

**Question 4** (4 points)

RSA-2048 is described as providing "112-bit security." What does "bits of security" mean, and why does a 2048-bit key only provide 112 bits of security?

*Your answer:*

___

**Model Answer:**

"Bits of security" is a standardized measure of how computationally expensive an attack is.
An algorithm with n bits of security requires approximately 2^n operations to break.
A 2048-bit RSA key does NOT mean 2048 bits of security because **RSA can be attacked without trying all 2^2048 possible keys** — instead, attackers factor the 2048-bit modulus (n = p × q).
The best known classical factoring algorithm (General Number Field Sieve) is sub-exponential in the key size; for a 2048-bit modulus, this takes approximately 2^112 operations — hence 112 bits of security.
This is why RSA keys must be much larger than symmetric keys to achieve comparable security levels.

**Grading:** 2 points for correct definition of bits of security, 2 points for correctly explaining why the attack complexity is much less than 2^2048 (factoring attack, not brute-force).

---

**Question 5** (4 points)

What is Certificate Transparency (CT) and give one specific way a SOC team can use CT logs for threat detection.

*Your answer:*

___

**Model Answer:**

Certificate Transparency is a public logging system where all publicly-trusted Certificate Authorities must submit every certificate they issue to publicly verifiable CT logs.
This creates an immutable, auditable record of every public TLS certificate issued.

**SOC use case (any one valid answer):**

* **Phishing detection:** Monitor CT logs for newly-issued certificates on typosquatted domains (e.g., "paypa1.com", "arnazon.com") that target your organization's customers or employees. Tools like crt.sh allow searching for wildcards.
* **Unauthorized certificate detection:** Set up alerts for any new certificate for `*.yourdomain.com` that you didn't issue — could indicate an attacker compromised your domain registrar or DNS.
* **Attack surface discovery:** Use CT logs to enumerate all subdomains with public certificates, identifying forgotten or shadow IT assets.

**Grading:** 2 points for correct CT explanation, 2 points for a specific actionable SOC use case.

---

## Long Answer Questions (2 × 15 points = 30 points)

---

**Question 6** (15 points)

A colleague argues: "We use HTTPS everywhere — that means our organization's network traffic is secure and private.
Even if the network is compromised, attackers can't see what our employees are doing."

Describe the limitations of this view.
Your answer should address:

1. What HTTPS actually protects (and what it does NOT protect)
1. At least THREE specific ways a SOC analyst can still extract threat-relevant information from encrypted HTTPS traffic
1. The trade-off between privacy and security visibility when an organization deploys TLS inspection

*Your answer:*

___

**Model Answer:**

**What HTTPS protects:**
HTTPS (TLS) encrypts the application payload — the HTTP request path, headers, body, cookies, and credentials.
An observer on the network cannot read the content of web requests.
It also authenticates the server (via certificate) and provides integrity (data cannot be tampered in transit without detection).
These are real and important protections.

**What HTTPS does NOT protect:**

* The **destination IP address and port** are always visible (they must be, for routing)
* The **Server Name Indication (SNI)** is sent in plaintext in the ClientHello — revealing which domain the user is visiting even though the path/content is encrypted
* The **certificate** (in TLS 1.2) or its fingerprint is visible, revealing the server's identity
* **Flow metadata:** connection duration, total bytes sent/received, packet sizes, and timing patterns are visible
* **DNS queries:** unless DNS over HTTPS (DoH) is used, name resolution queries reveal intended destinations

**Three ways to extract threat intelligence from encrypted HTTPS:**

1. **JA3/JA3S fingerprinting:** The TLS ClientHello contains the TLS version, cipher suite list, extensions, and supported groups. The MD5 hash of these fields (JA3) uniquely identifies specific TLS client implementations. Malware families tend to have consistent JA3 signatures different from normal browsers. A JA3 match against threat intel can identify Cobalt Strike, Metasploit, and other C2 tools even without decrypting the payload.

1. **Beaconing and behavioral analysis:** Malware C2 typically checks in at regular intervals (e.g., every 60 seconds for Cobalt Strike default). Statistical analysis of connection timing patterns can identify beaconing behavior that doesn't occur in normal human browsing. Tools like RITA (Real Intelligence Threat Analytics) or Zeek scripts automate this detection.

1. **Certificate and domain analysis:** Newly registered domains (<30 days), brand-new certificates (<7 days), self-signed certificates, and suspicious domain patterns (DGAs, typosquats) are all visible in TLS metadata without decrypting content. Correlating these with threat intelligence databases provides high-confidence malware infrastructure identification.

**TLS Inspection Trade-offs:**

TLS inspection (MITM proxy) provides full decryption capability — enabling DLP, malware scanning, and URL filtering.
However, it introduces significant trade-offs:

*Benefits:* Full payload visibility; ability to detect malware communicating over HTTPS; DLP for confidential data exfiltration; URL filtering beyond just domain-level.

*Costs and risks:* (1) Privacy: the organization (and any attacker who compromises the proxy) can read all employee communications, including personal email and banking if done on work devices.
This raises GDPR/privacy concerns.
(2) Certificate pinning: mobile apps and some software reject connections when the certificate doesn't match the expected pinned value — TLS inspection breaks these.
(3) Security risk: the proxy becomes a high-value target; compromise of the proxy gives attackers access to all decrypted traffic.
(4) Trust: Employees must trust the organization's proxy certificate, which means installing an enterprise root CA on all devices.
(5) Encrypted tunnel evasion: sophisticated attackers can use certificate pinning, DNS over HTTPS, or non-standard ports to evade inspection.

The balanced approach: use TLS metadata analysis (JA3, beaconing, cert analysis, DNS) for threat detection without full decryption, and apply TLS inspection selectively to highest-risk scenarios with appropriate privacy controls.

**Grading rubric:**

* 4 points: Correct description of HTTPS limitations
* 6 points: Three specific, technically accurate methods (2 pts each)
* 5 points: Balanced trade-off discussion covering both benefits and risks

---

**Question 7** (15 points)

You are briefing a development team that has proposed using the following cryptographic design for a new application:

* Passwords: stored as `MD5(username + password)`
* Session tokens: `SHA-256(user_id + timestamp)`
* API authentication: JWT signed with `HS256` using the secret `"api_secret"`
* Sensitive data: encrypted with AES-128-ECB using a hardcoded key in the source code
* Outbound TLS connections: certificate verification disabled for "simplicity"

Analyze this cryptographic design.
For each component, identify the vulnerability, explain the real-world risk, and provide a concrete, correct replacement implementation or approach.

*Your answer:*

___

**Model Answer:**

**1.
Password Storage: MD5(username + password)**

*Vulnerability:* MD5 is broken (collision attacks since 2004) and extremely fast (~10 billion hashes/second on GPU).
Using the username as a salt is better than no salt but is deterministic (predictable salt) and known to attackers.
MD5 speed enables rapid dictionary/brute-force attacks.

*Real-world risk:* If the database is breached, an attacker can crack most passwords in hours using a GPU and common wordlists.
Common passwords like "Password1" or "Summer2024" would fall immediately.

*Fix:* Use `bcrypt(password, work_factor=12)` or `Argon2id(password, unique_random_salt)`.
Both generate a unique random salt per user automatically.
The work factor/iterations makes each hash computation take ~100ms, reducing attack speed from billions/second to ~10/second.

**2.
Session Tokens: SHA-256(user_id + timestamp)**

*Vulnerability:* Tokens are entirely predictable from known or guessable inputs.
An attacker who knows a user's ID (often sequential integers) and approximately when they logged in can compute valid session tokens by trying timestamps in a window.

*Real-world risk:* Account takeover.
If the attacker can guess when a user logged in (within a 1-hour window, that's only 3600 possible timestamps), they can forge valid session tokens.

*Fix:* Use cryptographically secure random tokens: `secrets.token_urlsafe(32)` (Python) or equivalent. 32 bytes = 256 bits of randomness, making brute force computationally infeasible.

**3.
JWT: HS256 with secret "api_secret"**

*Vulnerability:* (a) Trivially guessable secret — "api_secret" is in any wordlist.
(b) If the code accepts `alg:none` (common JWT library misconfiguration), attackers can forge any JWT without knowing the secret.

*Real-world risk:* (a) The HMAC key can be brute-forced from any JWT token in seconds.
(b) An attacker who knows the JWT format can craft an admin-role token with `alg:none`, bypassing all authentication.

*Fix:* Use a cryptographically random secret (`secrets.token_hex(32)` — 256-bit), loaded from environment variables or a secrets manager.
Explicitly reject `alg:none` in JWT verification code.
Consider RS256/ES256 (asymmetric) for better key management.
Validate all claims including `exp`, `iat`, `aud`.

**4.
AES-128-ECB with hardcoded key**

*Vulnerabilities:* (a) ECB mode leaks patterns — identical plaintext blocks produce identical ciphertext blocks.
(b) Hardcoded key in source code means anyone with code access (developers, CI/CD systems, compromised repositories) has the decryption key.
(c) AES-128 provides 64-bit quantum security — use AES-256 for sensitive data.

*Real-world risk:* ECB enables pattern analysis (e.g., detecting which users share the same password or account balance).
Hardcoded key means a GitHub breach or insider threat immediately exposes all encrypted data.

*Fix:* Use `AES-256-GCM` with a per-record random nonce (12 bytes).
Load the key from a secrets manager (AWS Secrets Manager, HashiCorp Vault) or environment variable — NEVER hardcode.
Store nonce with ciphertext (it doesn't need to be secret).

**5.
TLS: Certificate Verification Disabled**

*Vulnerability:* Disabling certificate verification means the application will accept ANY certificate for any server — including certificates presented by an attacker during a MITM attack.

*Real-world risk:* Any attacker on the network path (ISP, rogue Wi-Fi, compromised router) can intercept all supposedly "encrypted" API communications.
They see all requests, responses, API keys, tokens, and data.
The TLS encryption is effectively useless.

*Fix:* Enable certificate verification: `ctx.verify_mode = ssl.CERT_REQUIRED; ctx.check_hostname = True; ctx.load_default_certs()`.
Never disable verification in production.
If using internal/self-signed certificates, add them to a custom CA bundle rather than disabling verification entirely.

**Overall design assessment:**

This cryptographic design has NO secure components.
Every single element has critical vulnerabilities.
The combination is especially dangerous: weak password storage enables credential theft, predictable tokens enable session hijacking, weak JWT enables privilege escalation, ECB+hardcoded key enables data exposure, and disabled TLS verification enables MITM.
A thorough security review and full rewrite of the cryptographic layer is required before any production deployment.

**Grading rubric:**

* 10 points: 5 × 2 points each — 1 point for correct vulnerability identification, 1 point for correct fix
* 3 points: Correct risk explanation (demonstrating real-world impact understanding)
* 2 points: Overall design assessment showing synthesis of findings

---

## Total Score: __ / 50 points

| Range | Grade |
|-------|-------|
| 45–50 | Excellent — ready for advanced content |
| 38–44 | Strong Pass |
| 30–37 | Pass — some gaps to address |
| 20–29 | Borderline — revisit key topics |
| < 20 | Fail — complete re-study required |
