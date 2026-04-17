# Final Quiz — Session 04: Fundamentals of Cryptography

> **Purpose:** Assess mastery of session content
> **Questions:** 7 multiple choice
> **Time:** 15 minutes
> **Passing score:** 5/7

---

## Instructions

Select the best answer for each question.
These questions assess your understanding of the cryptographic concepts covered in Session 04.

---

**Question 1**

A developer stores encrypted database records using AES-128-ECB mode.
An attacker gets read access to the encrypted database.
Which of the following statements is true?

* A) The attacker cannot learn anything because AES-128 is unbreakable by brute force
* B) The attacker can identify records that contain the same plaintext in the same position, even without the key
* C) ECB is actually stronger than CBC because it has no IV dependency
* D) The attacker must break SHA-256 first before exploiting ECB mode

**Correct Answer:** B

**Explanation:** ECB mode encrypts each 16-byte block independently with the same key.
Identical plaintext blocks produce identical ciphertext blocks.
An attacker can identify patterns (e.g., 100 records with the same account balance or same name) without knowing the key.
The famous "ECB penguin" illustrates this visually.

---

**Question 2**

A security team discovers that the corporate VPN has PFS (Perfect Forward Secrecy) disabled.
The VPN server's RSA private key is later stolen in a breach.
What is the security impact compared to a PFS-enabled VPN?

* A) No difference; RSA private key theft only affects future sessions
* B) Only sessions established after the theft are compromised
* C) ALL previously recorded VPN sessions can now be decrypted by anyone who recorded the traffic
* D) Only the authentication is affected; session data remains encrypted

**Correct Answer:** C

**Explanation:** Without PFS, the RSA private key is used to protect the session keys for all past sessions.
If an attacker recorded encrypted VPN traffic (as nation-state adversaries routinely do), they can now decrypt all historical sessions using the stolen key.
With PFS (ephemeral DH/ECDHE), each session uses a unique key that is deleted after use, so past sessions remain secure.

---

**Question 3**

A SIEM rule triggers on outbound HTTPS connections from a workstation with these characteristics: connection interval exactly 60 seconds, certificate issued 1 day ago, domain registered 3 days ago.
What is the MOST likely explanation?

* A) A scheduled Windows Update check
* B) A legitimate cloud backup service with a new certificate
* C) A malware C2 (command-and-control) beacon
* D) A misconfigured network monitoring agent

**Correct Answer:** C

**Explanation:** The combination of: (1) exact 60-second interval (Cobalt Strike default beacon), (2) brand-new certificate (1 day old), and (3) very recently registered domain (malware infrastructure is set up quickly) are classic indicators of malware C2 communication.
Legitimate services use established domains with older certificates, and don't connect at perfectly regular intervals.

---

**Question 4**

Which of the following describes the CORRECT use of cryptographic hash functions for password storage?

* A) Hash passwords with SHA-256 and store the hash; compare hashes on login
* B) Encrypt passwords with AES-256 and store the ciphertext
* C) Use bcrypt or Argon2 with a unique random salt per user; store the hash with the salt
* D) Hash passwords with MD5 and use a fixed salt applied to all passwords

**Correct Answer:** C

**Explanation:** SHA-256 is too fast (billions/second on GPU), making brute-force trivial.
AES encryption stores a recoverable password (key compromise = all passwords exposed).
MD5 is broken. bcrypt/Argon2 are intentionally slow (making brute force impractical), use per-user salts (preventing rainbow tables), and are the industry standard for password hashing.

---

**Question 5**

During a TLS handshake analysis, you see the SNI field contains "secure-banking.paypa1.com" and the certificate was issued 2 hours ago by Let's Encrypt.
What should you conclude?

* A) This is normal — Let's Encrypt issues certificates within minutes, and all HTTPS is equally secure
* B) This is a potential phishing site: the domain is a typosquat of "paypal.com" with a very fresh certificate
* C) The connection is safe because Let's Encrypt only issues certificates to legitimate businesses
* D) The "1" instead of "l" is insignificant since browsers handle IDN normalization

**Correct Answer:** B

**Explanation:** "paypa1.com" (with the number 1) is a typosquat of "paypal.com" — a domain designed to trick users.
Let's Encrypt issues certificates purely based on domain control verification; it does not verify business identity or intent.
A 2-hour-old certificate on a lookalike domain is a high-confidence phishing indicator.
SOC analysts should monitor CT logs for newly-issued certificates on typosquatted domains.

---

**Question 6**

An organization's critical data (25-year retention) is protected with RSA-2048 encryption.
In the context of post-quantum cryptography, what is the MOST accurate risk assessment?

* A) No risk — RSA-2048 provides 112-bit security which is sufficient for any foreseeable threat
* B) The data is at risk from "harvest now, decrypt later" attacks — adversaries recording encrypted data today could decrypt it with quantum computers before the 25-year retention ends
* C) Only real-time attacks are relevant; stored encrypted data cannot be retroactively decrypted
* D) RSA-2048 is quantum-resistant because it uses a 2048-bit key, which exceeds the 128-bit Grover threshold

**Correct Answer:** B

**Explanation:** "Harvest now, decrypt later" is the key risk for long-retention data.
If quantum computers capable of running Shor's algorithm emerge in 5-15 years (before the 25-year retention period ends), all RSA-2048-protected data collected today becomes retroactively decryptable.
Data retained 25 years from 2024 remains sensitive until 2049 — well into the period when quantum threats are plausible.
RSA is broken by Shor's algorithm regardless of key size (not Grover's, which affects symmetric crypto).

---

**Question 7**

A file's SHA-256 hash is checked against a vendor-published checksum and they match.
Which of the following statements is MOST accurate?

* A) The file is definitely authentic and unmodified since the vendor released it
* B) The file content matches the state when the checksum was computed, BUT you cannot be certain the checksum itself wasn't compromised unless it was obtained from a trusted source independently
* C) SHA-256 collision resistance guarantees authenticity regardless of how the checksum was distributed
* D) The file is safe to execute since SHA-256 is secure and cannot be forged

**Correct Answer:** B

**Explanation:** A matching SHA-256 hash proves the file content matches what was hashed when the checksum was created.
However, if an attacker can modify both the file AND the checksum file (e.g., they control the distribution server), they can provide a matching checksum for malicious content.
Integrity is only as strong as the trust in the checksum's origin.
This is why checksums should be GPG-signed and/or distributed through a separate trusted channel.
Additionally, a clean hash does not mean a file is safe — only that it wasn't modified from the hashed version.

---

## Score Interpretation

| Score | Grade | Action |
|-------|-------|--------|
| 7/7 | Excellent | Excellent mastery. Ready for advanced content. |
| 6/7 | Strong Pass | Very good. Review the missed concept. |
| 5/7 | Pass | Adequate. Review weak areas before moving on. |
| 3-4/7 | Borderline | Re-read the reading.md and retry. |
| 0-2/7 | Fail | Full re-study of session required. |
