# Session 04: Fundamentals of Cryptography

> **Estimated reading time:** 2 hours
> **Prerequisites:** Sessions 01–03 completed
> **Tools referenced:** OpenSSL, sha256sum, GPG, Wireshark, CyberChef

---

## Table of Contents

1. [Introduction: Why Cryptography Matters in Security Operations](#1-introduction)
1. [A Brief History of Cryptography](#2-history)
1. [Core Cryptographic Goals](#3-core-goals)
1. [Symmetric Encryption](#4-symmetric-encryption)
1. [Asymmetric Encryption](#5-asymmetric-encryption)
1. [Cryptographic Hash Functions](#6-hashing)
1. [Digital Signatures and Certificates](#7-signatures-certificates)
1. [Public Key Infrastructure (PKI)](#8-pki)
1. [Cryptography in Practice](#9-cryptography-in-practice)
1. [Cryptographic Attacks](#10-cryptographic-attacks)
1. [Post-Quantum Cryptography](#11-post-quantum)
1. [SOC Analyst Perspective: Encryption and Visibility](#12-soc-perspective)
1. [Summary and Key Takeaways](#13-summary)
1. [References](#14-references)

---

## 1. Introduction: Why Cryptography Matters in Security Operations {#1-introduction}

Cryptography is the mathematical science of securing information.
As a SOC analyst, you will encounter cryptography in virtually every corner of the network — HTTPS traffic, VPN tunnels, encrypted email, signed software packages, and increasingly, malware that encrypts its own communications to evade detection.

Understanding cryptography is not just an academic exercise.
It directly impacts:

* **What you can see:** Encrypted traffic is opaque to traditional DPI (deep packet inspection). You cannot read the payload of a TLS session without the keys.
* **What you can trust:** Digital signatures tell you whether software or a document has been tampered with.
* **How attackers operate:** Ransomware encrypts victim data. C2 (command-and-control) channels use TLS to blend in with normal traffic. Data exfiltration increasingly uses encrypted channels.
* **Your forensic capabilities:** Encrypted disk volumes, encrypted archives, and certificate-based authentication all affect incident response procedures.

The goal of this session is to give you a practical, working understanding of cryptography — enough to recognize its use in the wild, reason about its security properties, and explain it to colleagues and stakeholders.

---

## 2. A Brief History of Cryptography {#2-history}

### 2.1 Classical Ciphers

The story begins thousands of years ago.
The ancient Egyptians used hieroglyphic substitutions as early as 1900 BCE.
Julius Caesar famously shifted each letter of the alphabet by 3 positions to obscure military communications — this is the **Caesar cipher**, the most well-known classical substitution cipher.

**Caesar cipher example:**

```text
Plaintext:  ATTACK AT DAWN
Key:        3 (shift right by 3)
Ciphertext: DWWDFN DW GDZQ
```

The weakness is obvious: there are only 25 possible keys (shifts).
An attacker trying all shifts — what we now call a **brute-force attack** — breaks it in seconds.

More sophisticated classical ciphers followed:

* **Vigenère cipher** (16th century): Uses a repeating keyword to apply different Caesar shifts at each position. Stronger than Caesar but still breakable through frequency analysis.
* **Transposition ciphers**: Rearrange the order of letters rather than substituting them.
* **Substitution ciphers**: Replace each letter with another according to a fixed mapping (26! ≈ 4×10²⁶ possible keys — but frequency analysis still breaks them).

A key insight: classical ciphers fail because they preserve statistical patterns from the plaintext.
The letter 'E' appears most frequently in English; if 'Q' appears most frequently in your ciphertext, 'Q' probably maps to 'E'.

### 2.2 The Enigma Machine and World War II

The German Enigma machine, used extensively during World War II, was an electromechanical rotor cipher device.
It combined multiple rotating substitution wheels, a plugboard for additional substitutions, and a reflector, producing a cipher that changed with each keystroke.

The key space was enormous — estimated at over 10¹⁵⁸ combinations for some configurations.
Yet Alan Turing, Gordon Welchman, and the team at Bletchley Park broke Enigma by exploiting:

1. **Known plaintext attacks:** German weather reports began with predictable text ("WETTER" — weather).
1. **Cribs:** Known phrases at predictable positions.
1. **Operator mistakes:** Sending the same message twice with different settings, using predictable key setup procedures.

The breaking of Enigma is estimated to have shortened World War II by 2–4 years.
It also established a fundamental principle: **the security of a cipher should not depend on secrecy of the algorithm, only on secrecy of the key** (Kerckhoffs's principle, stated in 1883).

### 2.3 The Modern Era: Mathematical Cryptography

The post-war era saw cryptography transform from an art into a rigorous mathematical discipline.

**1949: Shannon's Information Theory.** Claude Shannon published "Communication Theory of Secrecy Systems," establishing the mathematical foundations.
He proved that the **one-time pad** (XORing plaintext with a truly random key of equal length, used only once) is perfectly secure — information-theoretically unbreakable.
The problem: key distribution.

**1976: Diffie-Hellman Key Exchange.** Whitfield Diffie and Martin Hellman published "New Directions in Cryptography," introducing the concept of **public-key cryptography**.
Two parties can establish a shared secret over an insecure channel without prior contact.
This was revolutionary — it solved the key distribution problem that had plagued symmetric cryptography for centuries.

**1977: RSA.** Ron Rivest, Adi Shamir, and Leonard Adleman published the first practical public-key cryptosystem, based on the difficulty of factoring large prime numbers.

**1977: DES.** The Data Encryption Standard, developed by IBM and standardized by NIST, became the first widely used symmetric cipher.
It used 56-bit keys — considered secure in 1977 but broken by brute force by 1998 (EFF's "Deep Crack" project).

**2001: AES.** Following a public competition, the Advanced Encryption Standard replaced DES.
Based on the Rijndael algorithm (by Joan Daemen and Vincent Rijmen), it supports 128, 192, and 256-bit keys and remains the gold standard for symmetric encryption.

**2009: Bitcoin.** Satoshi Nakamoto's cryptocurrency used elliptic curve cryptography (ECC) and SHA-256 hashing in a novel distributed ledger.
Cryptography went mainstream.

---

## 3. Core Cryptographic Goals {#3-core-goals}

Modern cryptography aims to provide four fundamental security properties:

### 3.1 Confidentiality

Information should only be accessible to those authorized to see it.
This is the most intuitive goal — preventing eavesdroppers from reading your messages.

**How it's achieved:** Encryption.
You transform plaintext into ciphertext using a key; only those with the correct key can reverse the process.

**SOC relevance:** Encrypted traffic (HTTPS, VPN) provides confidentiality for users — and for attackers.
Malware using encrypted C2 channels exploits your inability to read the payload.

### 3.2 Integrity

Information should not be modified without detection.
Even if an attacker cannot read your data, they might be able to flip bits in transit, potentially causing serious harm (e.g., changing a bank transfer amount).

**How it's achieved:** Cryptographic hash functions and Message Authentication Codes (MACs).
A hash of the data serves as a fingerprint; any change to the data changes the fingerprint.

**SOC relevance:** File integrity monitoring tools (like Tripwire or AIDE) use hashes to detect unauthorized changes to system files.
Incident response often involves verifying file hashes against known-good baselines.

### 3.3 Authenticity

You should be able to verify that a message or piece of data comes from who it claims to come from.
Without authenticity, an attacker could impersonate a trusted party.

**How it's achieved:** Digital signatures (using asymmetric cryptography) and certificates.
A sender signs a message with their private key; anyone with the sender's public key can verify the signature.

**SOC relevance:** Code signing ensures software comes from legitimate vendors.
TLS certificates authenticate web servers.
Email authentication (DKIM, S/MIME) verifies sender identity.

### 3.4 Non-Repudiation

The sender cannot later deny having sent a message.
This is important in legal, financial, and contractual contexts.

**How it's achieved:** Digital signatures with a trusted timestamp from a Certificate Authority.
The private key used to sign is (supposedly) known only to the sender.
If the signature is valid, the sender cannot claim they didn't create it.

**Difference from authenticity:** Authenticity says "this message came from Alice." Non-repudiation adds "and Alice cannot later deny it."

### 3.5 Additional Properties

Two more properties appear in modern cryptographic protocols:

* **Availability:** Sometimes considered separately; cryptography itself doesn't provide availability, but Denial-of-Service attacks can target cryptographic operations (e.g., SSL/TLS negotiation is CPU-intensive).
* **Forward Secrecy (Perfect Forward Secrecy - PFS):** Even if an attacker records encrypted traffic now and later obtains the long-term private key, they cannot decrypt past sessions. Achieved using ephemeral key exchange (like ECDHE in TLS 1.3).

---

## 4. Symmetric Encryption {#4-symmetric-encryption}

Symmetric encryption uses the **same key** for both encryption and decryption.
It's fast and suitable for bulk data encryption.

```text
     Encrypt                    Decrypt
Plaintext → [Key + Algorithm] → Ciphertext → [Key + Algorithm] → Plaintext
```

### 4.1 DES and 3DES (Legacy)

**DES (Data Encryption Standard):**

* Block cipher, 64-bit block size, 56-bit effective key length
* Published 1977, broken in 1998 (22 hours using distributed computing + custom hardware)
* The 56-bit key space allows only 2⁵⁶ ≈ 7.2×10¹⁶ possible keys — a brute-force search is feasible with modern hardware
* **Status: Completely broken. Do not use.**

**3DES (Triple DES):**

* Applies DES three times: Encrypt(K1) → Decrypt(K2) → Encrypt(K3)
* Effective key length: 112 bits (with 2-key 3DES) or 168 bits (with 3-key 3DES)
* Slow: three passes through DES per block
* Vulnerable to meet-in-the-middle attacks reducing effective security
* NIST deprecated 3DES in 2019; its use is officially disallowed since 2023
* **Status: Deprecated. Migrate to AES.**

### 4.2 AES (Advanced Encryption Standard)

AES is the current standard for symmetric encryption.
It is a **substitution-permutation network (SPN)** block cipher:

* **Block size:** 128 bits (fixed)
* **Key sizes:** 128, 192, or 256 bits
* **Rounds:** 10 (AES-128), 12 (AES-192), 14 (AES-256)

**How AES works (simplified):**

AES operates on a 4×4 matrix of bytes (the "state").
Each round consists of four operations:

1. **SubBytes:** Each byte is replaced using a fixed lookup table (S-Box), providing non-linearity.
1. **ShiftRows:** Rows of the state are cyclically shifted left by different amounts.
1. **MixColumns:** Each column is treated as a polynomial and multiplied modulo a fixed polynomial (provides diffusion — changes spread across the state).
1. **AddRoundKey:** The current round key (derived from the main key) is XORed with the state.

The last round omits MixColumns.

**AES key sizes and security:**

| Key Size | Rounds | Brute Force Effort       | Security Level |
|----------|--------|--------------------------|----------------|
| 128-bit  | 10     | 2¹²⁸ ≈ 3.4×10³⁸ ops     | Secure         |
| 192-bit  | 12     | 2¹⁹² ≈ 6.2×10⁵⁷ ops     | Secure         |
| 256-bit  | 14     | 2²⁵⁶ ≈ 1.2×10⁷⁷ ops     | Secure (PQ)    |

For reference: a computer performing 10¹² operations per second would take ~10¹⁸ years to brute-force AES-128.
The universe is ~1.4×10¹⁰ years old.

**AES-256** provides security against future quantum computers using Grover's algorithm (which provides a quadratic speedup for brute force, effectively halving the key length to 128 bits for quantum adversaries — still secure).

### 4.3 Block Cipher Modes of Operation

AES is a block cipher — it encrypts exactly 128 bits at a time.
Real data is almost never exactly 128 bits. **Modes of operation** define how a block cipher handles data of arbitrary length.

#### ECB (Electronic Codebook) — Do Not Use

The simplest mode: encrypt each block independently with the same key.

```text
Block 1 → AES-ECB(K) → Ciphertext Block 1
Block 2 → AES-ECB(K) → Ciphertext Block 2
...
```

**Fatal flaw:** Identical plaintext blocks produce identical ciphertext blocks.
This leaks patterns.
The famous "ECB penguin" illustrates this: encrypting a solid-color image with ECB produces a ciphertext that still shows the outline of the original image.

**Status: Never use ECB for real data.**

#### CBC (Cipher Block Chaining)

Each block is XORed with the previous ciphertext block before encryption.
Requires an **Initialization Vector (IV)** for the first block.

```text
C₀ = IV (random, not secret)
Cᵢ = Encrypt(Pᵢ XOR Cᵢ₋₁)
Pᵢ = Decrypt(Cᵢ) XOR Cᵢ₋₁
```

**Advantages:** Identical plaintext blocks produce different ciphertext blocks (because they're XORed with different previous ciphertext blocks).

**Disadvantages:**

* Sequential encryption (cannot parallelize encryption)
* Susceptible to **padding oracle attacks** if not implemented carefully (POODLE, BEAST attacks exploited this in TLS)
* Requires padding to align data to block boundaries; padding must be verified carefully

**The IV must be random and unpredictable, never reused with the same key.**

#### CTR (Counter Mode)

Turns AES into a stream cipher.
A counter value is encrypted to produce a keystream, which is XORed with the plaintext.

```text
Keystream_i = Encrypt(Nonce || Counter_i)
Cᵢ = Pᵢ XOR Keystream_i
```

**Advantages:**

* Parallelizable (both encryption and decryption)
* No padding required
* Random access to any block

**Disadvantages:**

* Provides confidentiality only — no integrity protection
* **Never reuse nonce+key combination** (XOR two ciphertexts to get XOR of two plaintexts)

#### GCM (Galois/Counter Mode) — Recommended

Combines CTR mode encryption with a **Galois field multiplication** for authentication.
Produces both ciphertext and an **authentication tag** (usually 128 bits).

```text
(Ciphertext, AuthTag) = AES-GCM-Encrypt(Key, Nonce, Plaintext, AAD)
```

Where AAD (Additional Authenticated Data) is data that should be authenticated but not encrypted (e.g., packet headers).

**Advantages:**

* Authenticated encryption: provides both confidentiality AND integrity/authenticity
* Parallelizable
* No padding required
* Widely used in TLS 1.3, SSH, and other modern protocols

**Requirements:**

* Nonce must be unique for each encryption with the same key (96 bits, often sequential or random)
* Nonce reuse is catastrophic: allows recovery of the authentication key and potentially plaintext

**Recommendation:** Use AES-256-GCM for new applications.

### 4.4 Key Management in Symmetric Cryptography

The Achilles' heel of symmetric encryption is **key distribution**: how do you securely share the key with your intended recipient before communicating?
If you could already communicate securely, you wouldn't need encryption.

This is solved in practice by:

1. Using asymmetric cryptography to exchange a symmetric key (hybrid encryption — used in TLS)
1. Out-of-band key exchange (physically meeting, trusted courier)
1. Key Derivation Functions (KDFs) to derive keys from passwords (PBKDF2, bcrypt, Argon2)

---

## 5. Asymmetric Encryption {#5-asymmetric-encryption}

Asymmetric encryption uses a mathematically linked **key pair**: a public key (freely distributed) and a private key (kept secret).
Data encrypted with the public key can only be decrypted with the private key, and vice versa.

```text
Encrypt: Plaintext → [Recipient's PUBLIC key] → Ciphertext
Decrypt: Ciphertext → [Recipient's PRIVATE key] → Plaintext
```

### 5.1 RSA (Rivest-Shamir-Adleman)

RSA is the most widely known asymmetric algorithm, based on the mathematical difficulty of **factoring large integers**.

**Key generation:**

1. Choose two large prime numbers p and q (each hundreds of digits long)
1. Compute n = p × q (the modulus; this is public)
1. Compute φ(n) = (p-1)(q-1)
1. Choose e such that gcd(e, φ(n)) = 1 (typically e = 65537)
1. Compute d such that e×d ≡ 1 (mod φ(n)) (the private exponent)

**Public key:** (n, e)

**Private key:** (n, d) [keep p, q, φ(n) secret too]

**Encryption:** C = Mᵉ mod n

**Decryption:** M = Cᵈ mod n

**Security:** Breaking RSA requires finding p and q given n.
The best known classical algorithm (General Number Field Sieve) requires sub-exponential time.
For n = 2048 bits, factoring requires roughly 2¹¹² operations — computationally infeasible today.

**Key sizes and security:**

| RSA Key Size | Security Level | Notes                           |
|-------------|----------------|----------------------------------|
| 1024-bit    | ~80 bits       | Broken. Do not use.             |
| 2048-bit    | ~112 bits      | Minimum acceptable today        |
| 3072-bit    | ~128 bits      | Recommended                     |
| 4096-bit    | ~140 bits      | High security, slower           |

**Important:** RSA is very slow compared to AES (100-1000× slower).
It is **not used for bulk data encryption**.
Instead, it is used to encrypt a symmetric key, which then encrypts the actual data (**hybrid encryption**).

**RSA for signatures:**

* Sign: S = Mᵈ mod n (sign with private key)
* Verify: M = Sᵉ mod n (verify with public key)
* In practice, you sign the hash of M, not M itself

**PKCS#1 padding and OAEP:**
Raw RSA (textbook RSA) is not secure in practice — it has mathematical properties that allow attacks.
Real RSA implementations use padding schemes:

* **PKCS#1 v1.5:** Older padding; vulnerable to Bleichenbacher's attack if implemented carelessly
* **OAEP (Optimal Asymmetric Encryption Padding):** Modern, provably secure padding for RSA encryption
* **PSS (Probabilistic Signature Scheme):** Modern padding for RSA signatures

### 5.2 ECC (Elliptic Curve Cryptography)

ECC is based on the mathematical difficulty of the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.
An elliptic curve is a set of points satisfying the equation:

```text
y² = x³ + ax + b (mod p)
```

Adding two points on an elliptic curve is easy; finding how many times a point was added to itself (discrete logarithm) is computationally hard.

**Advantages over RSA:**

* Much smaller key sizes for equivalent security:

| ECC Key Size | RSA Equivalent | Notes              |
|-------------|----------------|--------------------|
| 256-bit     | 3072-bit RSA   | NIST P-256         |
| 384-bit     | 7680-bit RSA   | NIST P-384         |
| 521-bit     | 15360-bit RSA  | NIST P-521         |

* Faster computations (especially for mobile/IoT devices)
* Smaller keys and signatures → less bandwidth
* Used in Bitcoin, TLS 1.3, SSH, WhatsApp (Signal Protocol)

**Common ECC curves:**

* **NIST P-256 (secp256r1):** Most widely used; used in TLS certificates and HTTPS
* **Curve25519:** Designed by Daniel Bernstein; considered more conservative (no NSA influence concerns); used in Signal, WireGuard, SSH
* **secp256k1:** Used in Bitcoin

### 5.3 Diffie-Hellman Key Exchange

Diffie-Hellman (DH) is not an encryption algorithm but a **key agreement protocol**.
Two parties can establish a shared secret over an insecure channel without prior shared secrets.

**Classical DH (discrete logarithm based):**

1. Agree on public parameters: prime p and generator g
1. Alice chooses secret a, computes A = gᵃ mod p, sends A to Bob
1. Bob chooses secret b, computes B = gᵇ mod p, sends B to Alice
1. Alice computes shared secret: s = Bᵃ mod p = gᵃᵇ mod p
1. Bob computes shared secret: s = Aᵇ mod p = gᵃᵇ mod p

An eavesdropper sees g, p, A, B but cannot compute gᵃᵇ from this without solving the discrete logarithm problem.

**ECDH (Elliptic Curve DH):** Same principle but using elliptic curve operations.
Smaller key sizes, faster.

**ECDHE (Elliptic Curve DH Ephemeral):** New DH key pair is generated for each session.
This provides **Perfect Forward Secrecy (PFS)**: compromising the long-term private key does not compromise past sessions because the ephemeral keys are discarded after use.
Required in TLS 1.3.

---

## 6. Cryptographic Hash Functions {#6-hashing}

A cryptographic hash function takes an input of arbitrary length and produces a fixed-length output (the **hash**, **digest**, or **fingerprint**).
It's a one-way function — easy to compute, computationally infeasible to reverse.

```text
Hash("Hello, World!") → a591a6d40bf420404a011733cfb7b190...  (SHA-256)
Hash("hello, world!") → 3fa85f64...                          (SHA-256, completely different!)
```

### 6.1 Properties of Cryptographic Hash Functions

1. **Deterministic:** Same input always produces same output.
1. **One-way (Preimage resistance):** Given H(M), it is computationally infeasible to find M.
1. **Second preimage resistance:** Given M₁, it is computationally infeasible to find M₂ ≠ M₁ such that H(M₁) = H(M₂).
1. **Collision resistance:** It is computationally infeasible to find any M₁ ≠ M₂ such that H(M₁) = H(M₂).
1. **Avalanche effect:** A small change in input produces a completely different hash. Changing one bit flips ~50% of output bits.

**Note on collision resistance:** For a hash with n-bit output, finding a collision requires approximately 2^(n/2) operations by the birthday paradox (not 2^n).
For SHA-256, that's 2¹²⁸ operations — still infeasible, but this is why MD5 and SHA-1 (with shorter outputs) fell first.

### 6.2 Common Hash Functions

#### MD5 (Message Digest 5)

* Output: 128 bits (32 hex characters)
* Designed by Ron Rivest in 1992
* **Broken:** Full collision attacks found in 2004. Two different files can be found that produce the same MD5 hash. Security researchers have created malicious certificates, software packages, and PDF files with identical MD5 hashes to a legitimate file.
* Example collision: `md5(file_A) = md5(file_B)` where file_A is safe software and file_B is malware
* **Status: Do not use for security purposes. Only for non-security checksums/legacy compatibility.**

#### SHA-1 (Secure Hash Algorithm 1)

* Output: 160 bits (40 hex characters)
* Designed by NSA, published by NIST in 1995
* **Broken:** Theoretical weaknesses known since 2005. In 2017, Google's SHAttered attack produced the first practical collision (two different PDF files with the same SHA-1 hash) using 9.2×10¹⁸ SHA-1 computations.
* **Status: Deprecated. Browsers no longer accept SHA-1 TLS certificates. Not suitable for security use.**

#### SHA-256 (SHA-2 family)

* Output: 256 bits (64 hex characters)
* Part of SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512)
* Designed by NSA, published by NIST in 2001
* No known practical attacks; widely used
* Used in: Bitcoin, TLS certificates, code signing, package managers, SSL/TLS
* **Status: Recommended. Use for all new applications.**

```console
echo -n "Hello, World!" | sha256sum
# Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986d  -
```

#### SHA-3 (Keccak)

* Output: 224, 256, 384, or 512 bits
* Winner of NIST's SHA-3 competition (2012)
* Completely different internal design from SHA-2 (sponge construction vs. Merkle-Damgård)
* Provides structural diversity: if weaknesses are found in SHA-2's design, SHA-3 is unlikely to be affected
* Also provides SHAKE (variable-length output) variants
* **Status: Secure. Use when SHA-2 diversity is desired.**

#### BLAKE2 and BLAKE3

* Not NIST-standardized but widely respected and used in practice
* Faster than SHA-256 on modern hardware while maintaining security
* BLAKE3: extremely fast, parallelizable; used in many modern tools and languages
* **Status: Secure for most applications; less universally supported than SHA-2.**

### 6.3 Use Cases for Hash Functions

| Use Case | Recommended Hash | Notes |
|----------|-----------------|-------|
| File integrity verification | SHA-256 | Standard for checksums |
| Digital signatures | SHA-256 or SHA-384 | Hash the document, then sign |
| TLS certificates | SHA-256 | Minimum; SHA-1 is deprecated |
| Password storage | Bcrypt, Argon2 | NOT SHA-256 directly (too fast!) |
| HMAC authentication | SHA-256 | Keyed hash |
| Blockchain / Bitcoin | SHA-256 (double) | Domain-specific choice |

### 6.4 Why Not Use Hash Functions for Passwords?

Cryptographic hash functions are designed to be **fast**.
For password hashing, you want the opposite — a function that is intentionally **slow** and memory-intensive, making brute-force and dictionary attacks impractical.

Specialized password hashing functions include:

* **bcrypt:** Uses Blowfish cipher with a configurable work factor; has been standard for 25+ years
* **scrypt:** Memory-hard; requires significant RAM to compute, defeating GPU attacks
* **Argon2:** Winner of Password Hashing Competition (2015); modern standard, memory-hard, supports parallel computation

Using SHA-256 directly to hash passwords is a serious security mistake: GPU can compute billions of SHA-256 hashes per second, making dictionary attacks trivial.

### 6.5 HMAC (Hash-based Message Authentication Code)

A HMAC combines a hash function with a secret key to provide both integrity and authenticity:

```text
HMAC(Key, Message) = H((Key XOR opad) || H((Key XOR ipad) || Message))
```

Where opad and ipad are fixed padding constants. This construction avoids length extension attacks that would affect a naive `H(Key || Message)` approach.

HMACs are used in:

* JWT (JSON Web Tokens) — HMAC-SHA256 is common
* API authentication
* TLS record-layer integrity (pre-TLS 1.3)
* IPSec

---

## 7. Digital Signatures and Certificates {#7-signatures-certificates}

### 7.1 Digital Signatures

A digital signature is the asymmetric cryptography equivalent of a handwritten signature — it's unique, unforgeable (given key security), and provides non-repudiation.

**Signing process:**

```text
1. Hash the document: H = SHA-256(document)

2. Sign the hash: Signature = RSA-Sign(PrivateKey, H)
   (or: Signature = ECDSA-Sign(PrivateKey, H))
3. Distribute: document + signature
```

**Verification process:**

```text
1. Hash the document: H' = SHA-256(document)

2. Verify signature: H = RSA-Verify(PublicKey, Signature)
3. If H == H', signature is valid → document is authentic and untampered
```

Why hash first?
Asymmetric operations are slow; signing only the hash is much faster.
Also, signing the hash avoids mathematical attacks possible when signing large documents directly.

### 7.2 Common Signature Algorithms

* **RSA-PSS:** RSA with Probabilistic Signature Scheme padding. Modern, recommended.
* **ECDSA (Elliptic Curve Digital Signature Algorithm):** ECC-based signatures. Used in Bitcoin, TLS certificates. Warning: ECDSA requires a unique random nonce per signature; reusing nonces allows private key recovery (this famously broke the Sony PlayStation 3's DRM).
* **EdDSA (Edwards-curve Digital Signature Algorithm):** Based on twisted Edwards curves. Ed25519 is the most common instantiation. Deterministic (no random nonce required), fast, and secure. Used in modern SSH, WireGuard, and Signal.

### 7.3 X.509 Certificates

A digital certificate is a signed document that binds a public key to an identity.
The most common format is **X.509** (used in TLS/SSL).

**X.509 certificate fields:**

```text
Version: 3
Serial Number: 01:23:45:67...
Issuer: CN=DigiCert Global Root CA, O=DigiCert Inc, C=US
Validity: Not Before: 2024-01-01, Not After: 2025-01-01
Subject: CN=*.example.com, O=Example Corp, C=US
Subject Public Key Info:
  Algorithm: id-ecPublicKey (secp256r1)
  Public Key: 04:ab:cd:...
Extensions:
  Subject Alternative Names: DNS:*.example.com, DNS:example.com
  Key Usage: Digital Signature, Key Encipherment
  Extended Key Usage: TLS Web Server Authentication
  Basic Constraints: CA:FALSE
Signature Algorithm: sha256WithRSAEncryption
Signature: 3a:bc:...
```

The certificate is signed by a **Certificate Authority (CA)**.
When you connect to example.com, your browser:

1. Receives the server's certificate
1. Checks the CA's signature using the CA's public key (built into the browser/OS)
1. Verifies the domain name matches
1. Verifies the certificate hasn't expired or been revoked

---

## 8. Public Key Infrastructure (PKI) {#8-pki}

PKI is the system of policies, processes, and technologies that manages digital certificates and public keys.
It solves the **key distribution problem** for asymmetric cryptography: how do you know that a public key actually belongs to who claims it does?

### 8.1 Certificate Authorities (CAs)

A **Certificate Authority (CA)** is a trusted third party that signs certificates, binding public keys to identities.

**Types of CAs:**

* **Root CA:** Self-signed certificate; the trust anchor. Root CA certificates are pre-installed in operating systems and browsers (the "trust store"). Examples: DigiCert, Let's Encrypt, Comodo, sectigo.
* **Intermediate CA:** Signed by the root CA. Issues certificates to end entities. Using intermediates limits exposure of the root private key (the root can be kept offline).
* **End-entity certificate:** Issued to servers, users, or devices. This is what websites have.

### 8.2 Certificate Chains

Trust flows through a chain from root to end-entity:

```text
Root CA Certificate (self-signed)
  └── Intermediate CA Certificate (signed by Root)
        └── End-Entity Certificate (signed by Intermediate)
```

When a browser validates a TLS connection:

1. The server sends its certificate + intermediate certificate(s)
1. The browser verifies the end-entity cert is signed by the intermediate
1. The browser verifies the intermediate cert is signed by (or chains up to) a trusted root
1. The browser checks the root cert is in its trust store

This is called **chain of trust** or **certificate chain validation**.

### 8.3 Certificate Validation Levels

CAs offer different levels of identity verification:

| Type | Validation | Display | Use Case |
|------|-----------|---------|----------|
| Domain Validated (DV) | Proves domain control only | Padlock only | Most HTTPS sites, Let's Encrypt |
| Organization Validated (OV) | Verifies organization identity | O= field populated | Business sites |
| Extended Validation (EV) | Strict identity verification | Company name (formerly shown in green bar) | High-assurance sites |

**Note:** Modern browsers have removed the green bar EV display.
All three show the same padlock.
DV certificates (free from Let's Encrypt) are now standard.

### 8.4 Certificate Revocation

What happens if a private key is compromised?
The certificate must be **revoked** — declared invalid before its expiry date.

**CRL (Certificate Revocation List):**

* Periodically published list of revoked serial numbers
* Browser downloads the CRL and checks if the certificate's serial is in it
* Problem: CLs can be large, are only updated periodically, and have latency

**OCSP (Online Certificate Status Protocol):**

* Real-time query to CA's OCSP server: "Is serial 01:23:45... still valid?"
* Faster but creates privacy issue (CA can see which sites you visit) and creates availability dependency

**OCSP Stapling:**

* Server pre-fetches its own OCSP response from the CA and includes it in the TLS handshake
* Solves privacy and availability issues; modern best practice

**OCSP Must-Staple:**

* Certificate extension that tells browsers: only accept this cert if accompanied by a valid stapled OCSP response
* Strongest revocation mechanism; prevents serving revoked certificates

### 8.5 Certificate Transparency (CT)

Certificate Transparency is a public log of all certificates issued by CAs.
All publicly-trusted CAs must submit certificates to CT logs (requirement since 2018 for Chrome).

**Benefits:**

* Anyone can monitor CT logs for unauthorized certificates for their domain
* Enables detection of misissued or rogue certificates
* Used by organizations to detect phishing domains with lookalike certificates

**Tools:**

* `crt.sh` — search CT logs for domains
* Google's Certificate Transparency Monitor

### 8.6 Private PKI

Organizations can run their own internal PKI:

* Internal root CA (certificate not trusted by public browsers)
* Issue certificates for internal servers, VPN clients, machine authentication
* Microsoft Active Directory Certificate Services is common in enterprises
* OpenSSL can be used to build a simple PKI (see intermediate guide)

---

## 9. Cryptography in Practice {#9-cryptography-in-practice}

### 9.1 TLS/SSL (Transport Layer Security)

TLS is the protocol that secures HTTPS, SMTPS, IMAPS, and many other TCP-based protocols.
Understanding TLS is essential for SOC analysts — it's the most common encryption you'll encounter.

#### TLS 1.3 Handshake

TLS 1.3 (RFC 8446, 2018) dramatically simplified the handshake compared to TLS 1.2.
Here's what happens when you connect to https://example.com:

```text
Client                                           Server
  |                                                |
  |---- ClientHello -------------------------------->|
  |     (TLS version, supported cipher suites,     |
  |      key_share: ECDH public key, extensions)   |
  |                                                |
  |<--- ServerHello ---------------------------------|
  |     (chosen cipher suite, key_share: ECDH pub) |
  |                                                |
  |  [Both derive shared secret from ECDH]         |
  |  [All subsequent messages are ENCRYPTED]       |
  |                                                |
  |<--- {EncryptedExtensions} ----------------------|
  |<--- {Certificate} ------------------------------|
  |<--- {CertificateVerify} ------------------------|
  |<--- {Finished} ----------------------------------|
  |                                                |
  |---- {Finished} --------------------------------->|
  |                                                |
  |<--- [Application Data] ------------------------->|
  |---- [Application Data] ------------------------->|
```

**Key points:**

* TLS 1.3 requires only **1 round trip** to establish an encrypted connection (vs. 2 in TLS 1.2)
* The server's certificate is sent **encrypted** (unlike TLS 1.2)
* Only ECDHE key exchange is supported (no static RSA key exchange) → PFS is mandatory
* Cipher suites are simplified: TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256

#### Cipher Suites

A cipher suite specifies which algorithms to use for key exchange, authentication, encryption, and MAC:

```text
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
│      │    │        │       │    └── MAC/Hash (SHA-384)
│      │    │        │       └── Encryption mode (GCM)
│      │    │        └── Encryption algorithm (AES-256)
│      │    └── Authentication (server cert signed with RSA)
│      └── Key exchange (ECDHE = ephemeral ECDH)
└── Protocol (TLS)
```

**Weak cipher suites to watch for:**

* Anything with `NULL` (no encryption)
* Anything with `EXPORT` (weakened for 1990s US export laws)
* Anything with `RC4` (broken stream cipher)
* Anything with `DES` or `3DES`
* Anything with `MD5` or `SHA` (SHA-1) as MAC
* Anything with `ANON` (no authentication → MITM trivial)

#### TLS Versions

| Version | Status | Notes |
|---------|--------|-------|
| SSL 2.0 | Broken | Multiple severe vulnerabilities |
| SSL 3.0 | Broken | POODLE attack (2014) |
| TLS 1.0 | Deprecated | BEAST attack, padding oracles |
| TLS 1.1 | Deprecated | NIST deprecated 2021 |
| TLS 1.2 | Acceptable | Still widely used; strong if configured properly |
| TLS 1.3 | Recommended | Best performance, security, PFS by default |

**SOC alert:** Detection of TLS 1.0/1.1 connections may indicate older systems or active downgrade attacks.

### 9.2 VPNs

VPNs (Virtual Private Networks) create encrypted tunnels over untrusted networks.

#### IPSec

IPSec is a suite of protocols for securing IP communications:

* **IKE/IKEv2 (Internet Key Exchange):** Negotiates and establishes security associations (SAs) and keys
* **ESP (Encapsulating Security Payload):** Encrypts and authenticates IP packets
* **AH (Authentication Header):** Authenticates IP packets (no encryption; rarely used)
* **Modes:** Transport mode (encrypts payload only) vs. Tunnel mode (encrypts entire IP packet — used for VPN gateways)

IPSec uses symmetric encryption (AES) after IKE establishes keys.
Strong when configured correctly.
Widely used in enterprise site-to-site VPNs and some client VPNs.

#### OpenVPN

OpenVPN uses the TLS protocol to secure its control channel and OpenSSL for data channel encryption.
Runs over UDP (preferred) or TCP.
Uses certificate-based authentication.
Highly configurable; open-source.

#### WireGuard

Modern VPN protocol using state-of-the-art cryptography: Curve25519 (ECDH), ChaCha20-Poly1305 (encryption), BLAKE2s (hashing), SipHash24 (hashtable keys), HKDF (key derivation).
Extremely simple (around 4,000 lines of code vs.
OpenVPN's ~600,000).
Built into the Linux kernel since 5.6.

### 9.3 Disk Encryption

**BitLocker (Windows):**

* AES-256 in CBC or XTS mode
* Keys protected by TPM (Trusted Platform Module), PIN, USB key, or combination
* Transparent to the user when logged in; data at rest is encrypted

**VeraCrypt:**

* Open-source, cross-platform successor to TrueCrypt
* Supports creating encrypted containers (files) or full disk encryption
* Supports hidden volumes (plausible deniability)
* Algorithms: AES, Serpent, Twofish, and combinations

**LUKS (Linux Unified Key Setup):**

* Standard for Linux disk encryption
* Typically uses AES-256-XTS
* Managed with `cryptsetup`
* Keys can be unlocked with passphrase, keyfile, or hardware token

**XTS mode:** Used specifically for disk encryption.
Handles the fixed-block-size constraint of disk sectors without a traditional IV, resistant to specific attacks on disk encryption.

### 9.4 End-to-End Encryption (E2EE)

E2EE means only the communicating endpoints can read messages — not the service provider.

**Signal Protocol:**

* Used in Signal, WhatsApp, and other messengers
* Combines X3DH (Extended Triple Diffie-Hellman) for initial key agreement + Double Ratchet for ongoing messages
* Provides: forward secrecy, break-in recovery (future secrecy), deniability
* Each message uses a new encryption key derived from the ratchet

**PGP/GPG (Pretty Good Privacy):**

* Email encryption and signing
* Hybrid encryption: encrypt message with random AES key, encrypt AES key with recipient's RSA/ECC public key
* Web of trust: users sign each other's public keys (decentralized vs. hierarchical CA model)

---

## 10. Cryptographic Attacks {#10-cryptographic-attacks}

Understanding attacks helps you recognize when cryptography is being abused or when systems are misconfigured.

### 10.1 Brute Force Attacks

Try all possible keys until finding the correct one.

**Effectiveness depends on key length:**

* 40-bit key: 2⁴⁰ ≈ 10¹² operations — feasible with a laptop in seconds
* 56-bit key (DES): 2⁵⁶ — broken in 22 hours in 1998
* 128-bit key (AES): 2¹²⁸ — computationally infeasible

**Rainbow tables:** Precomputed tables of (password → hash) pairs, enabling fast reverse lookups.
Defense: use **salts** (random values appended to password before hashing).

**GPU acceleration:** Modern GPUs can compute ~10¹⁰ SHA-256 hashes/second.
For unsalted MD5 passwords, this enables cracking short passwords in minutes.

### 10.2 Man-in-the-Middle (MITM) Attacks

An attacker positions themselves between two communicating parties, intercepting and potentially modifying communication.

**Against unauthenticated Diffie-Hellman:**

```text
Alice → [MITM poses as Bob] → Bob
Alice thinks she's talking to Bob, Bob thinks he's talking to Alice.
MITM can read/modify all traffic.
```

**Defense:** Certificate-based authentication in TLS; PKI prevents MITM by requiring the server to prove it owns the private key corresponding to the certificate.

**SSLstrip attack:** Attacker downgrades HTTPS to HTTP before the user notices.
Defense: HSTS (HTTP Strict Transport Security) — browser refuses HTTP connections to known HTTPS sites.

**Certificate pinning:** Application ships with a hardcoded copy of the expected certificate or public key.
Prevents MITM even if a rogue CA issues a certificate for your domain.
Used in mobile apps; complicates corporate TLS inspection.

### 10.3 Birthday Attacks and Hash Collisions

The **birthday paradox** states that in a group of 23 people, there's a >50% chance two share a birthday.
Applied to hashing: for an n-bit hash, you need only 2^(n/2) hashes to find a collision with >50% probability.

**MD5 collisions:** The first practical MD5 collision was found in 2004.
By 2008, researchers demonstrated creating two different X.509 certificates with the same MD5 hash — one for a legitimate CA, one for a rogue CA — meaning the rogue CA's certificate was valid and trusted by all browsers.

**SHA-1 SHAttered attack (2017):** Two different PDF files with the same SHA-1 hash, using 6,500 CPU-years of computation.
Now practically cheap.

**Implications:** Software that uses MD5 or SHA-1 to verify file integrity can be fooled by a collision attack.
An attacker provides a file that has the same hash as a trusted file but different content.

### 10.4 Padding Oracle Attacks

A **padding oracle** is any system that tells you whether decrypted data has valid padding.
In CBC mode, this allows an attacker to decrypt ciphertext without the key, one byte at a time.

**Famous attacks:**

* **POODLE (2014):** Exploited SSL 3.0 CBC padding oracle, forcing downgrade from TLS 1.2
* **BEAST (2011):** Exploited TLS 1.0 CBC vulnerability
* **Lucky 13:** Timing side-channel in HMAC-CBC

**Defense:** Authenticated encryption (AES-GCM) authenticates before decrypting; padding is never checked on unauthenticated data.

### 10.5 Key Reuse Attacks

**Nonce reuse in stream ciphers/CTR mode:**

* If the same key + nonce is used twice: C1 = P1 XOR K, C2 = P2 XOR K
* Attacker computes C1 XOR C2 = P1 XOR P2 — the key cancels out
* With knowledge of some plaintext, the other can be recovered
* **Real-world examples:** Microsoft Xbox 360 system (nonce reuse allowed reverse engineering of the cipher), various IoT devices

**ECDSA nonce reuse:**

* Sony PlayStation 3: Used the same nonce for all ECDSA signatures
* Allowed recovery of the private signing key
* Enabled piracy and homebrew applications on the PS3

### 10.6 Downgrade Attacks

Attacker forces use of a weaker protocol or cipher suite than both parties support.

* **POODLE:** Forced SSL 3.0 downgrade from TLS 1.2
* **FREAK (2015):** Forced use of EXPORT-grade RSA (512-bit), then factored the key
* **Logjam (2015):** Forced use of weak 512-bit DH groups (from EXPORT regulations)

**Defense in TLS 1.3:** All previous negotiation values are included in the Finished message hash; any tampering with cipher suite selection is detected.

### 10.7 Timing Attacks (Side-Channel Attacks)

Information leaks through timing differences in cryptographic operations.
An attacker measures how long an operation takes and infers information about the secret.

**Examples:**

* **RSA private key recovery:** If modular exponentiation takes different time depending on key bits, timing measurements can recover the key
* **Password comparison timing:** `"password" == user_input` exits early on first mismatch — timing reveals how many characters are correct

**Defense:** Constant-time implementations; never use `==` to compare secrets — use `crypto.timingSafeEqual()` or equivalent.

---

## 11. Post-Quantum Cryptography {#11-post-quantum}

### 11.1 The Quantum Threat

Quantum computers, exploiting quantum mechanical phenomena (superposition, entanglement), can solve certain mathematical problems exponentially faster than classical computers.

**Shor's algorithm** (1994): A quantum algorithm that can factor large integers and solve discrete logarithm problems in polynomial time.
This would break:

* **RSA** (based on integer factoring)
* **Diffie-Hellman** (based on discrete logarithm)
* **ECDH/ECDSA** (based on elliptic curve discrete logarithm)
* Effectively, all currently deployed asymmetric cryptography

**Grover's algorithm** (1996): A quantum algorithm that provides a quadratic speedup for searching, equivalent to halving the key length.
This would affect:

* **AES-128** → reduced to ~64-bit security (may need AES-256)
* **SHA-256** → reduced to ~128-bit collision resistance
* AES-256 and SHA-256 are considered quantum-resistant for most purposes

**Timeline:** Current quantum computers (NISQ era) cannot run Shor's algorithm on cryptographically relevant key sizes.
Experts estimate cryptographically relevant quantum computers could emerge in the 2030s.
The threat is real but not immediate — but **harvest now, decrypt later** attacks are already relevant (adversaries may be recording encrypted traffic today to decrypt in the future).

### 11.2 NIST Post-Quantum Standardization

NIST ran a multi-year competition to standardize post-quantum algorithms.
In 2024, NIST published the first post-quantum standards:

**FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation Mechanism):**

* Based on the Module Learning With Errors (MLWE) problem
* Replaces RSA/ECDH for key encapsulation (key exchange)
* Previously known as CRYSTALS-Kyber

**FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm):**

* Based on module lattices
* Replaces RSA/ECDSA for digital signatures
* Previously known as CRYSTALS-Dilithium

**FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm):**

* Based solely on hash functions (conservative choice)
* Larger signatures than ML-DSA
* Previously known as SPHINCS+

**FIPS 206 — FN-DSA:**

* Based on NTRU lattices
* Previously known as FALCON

### 11.3 Hybrid Approaches

During the transition period, it's recommended to use **hybrid** schemes combining classical and post-quantum algorithms:

* `X25519+ML-KEM-768` for key exchange: break both classical ECDH AND post-quantum to compromise
* Used in experimental TLS deployments, Chrome, and Cloudflare

### 11.4 Migration Challenges

* **Certificate infrastructure:** Billions of RSA/ECC certificates need migration
* **Embedded systems/IoT:** May have hardware limitations for post-quantum algorithms (larger keys, more computation)
* **Crypto agility:** Systems need to be designed to swap algorithms without major rearchitecting
* **Timeline:** NIST recommends beginning migration planning now; critical infrastructure should prioritize post-quantum readiness

---

## 12. SOC Analyst Perspective: Encryption and Visibility {#12-soc-perspective}

This is where cryptography directly intersects with security operations.

### 12.1 Encryption as a Double-Edged Sword

Encryption protects legitimate users' privacy and security.
It also:

* **Hides malware command-and-control (C2) traffic** from network monitoring
* **Hides data exfiltration** — an attacker exfiltrating your intellectual property over HTTPS is invisible to traditional DLP
* **Hides lateral movement** — internal encrypted traffic (RDP, SSH, HTTPS to internal servers) is opaque
* **Enables malware delivery** — malicious payloads can be delivered over HTTPS, bypassing signature-based inspection

### 12.2 What SOC Analysts Can Still See

Even without decrypting traffic, metadata and TLS information provide significant visibility:

**TLS metadata:**

* **SNI (Server Name Indication):** The domain name the client is connecting to, sent in the ClientHello (plaintext in TLS 1.2; encrypted in TLS 1.3 ECH)
* **Certificate information:** Subject, issuer, SAN fields, validity period
* **JA3/JA3S fingerprinting:** Fingerprint TLS ClientHello parameters (cipher suites, extensions, elliptic curves) to identify specific TLS client implementations, including malware families
* **JARM:** Active TLS fingerprinting of servers; identifies C2 server implementations

**Network metadata (even over TLS):**

* Source/destination IP, port, timing, packet sizes, flow duration
* DNS queries (who is the client resolving names for?)
* Certificate CN/SAN (what domain is this certificate for?)
* Certificate issuer (self-signed? issued by unknown CA? Let's Encrypt on suspicious domain?)

**Behavioral analysis:**

* Beaconing patterns (regular intervals of outbound connections = potential C2)
* Long connection durations
* Unusually large uploads to unknown external hosts
* Connections to newly registered domains (high entropy domain names)
* Connections at unusual times

### 12.3 TLS Inspection (SSL/TLS Interception)

Many enterprises deploy TLS inspection proxies (also called SSL inspection, MITM proxies, or TLS break-and-inspect):

1. Client connects to proxy (trusting its certificate, installed via enterprise root CA)
1. Proxy establishes a separate TLS connection to the server
1. Proxy decrypts, inspects, potentially re-encrypts traffic

**Detection tools used with TLS inspection:** URL filtering, malware scanning, DLP, CASB.

**Limitations and risks:**

* Reduces privacy for employees
* Can break certificate pinning (mobile apps, some SaaS)
* Requires the proxy certificate to be trusted by all endpoints
* Introduces a single point of failure; if the proxy is compromised, all traffic is exposed
* May violate regulations (GDPR, HIPAA) if inspecting personal traffic
* Cannot inspect traffic on networks/devices outside your control

### 12.4 Identifying Suspicious Cryptography

**Red flags for SOC analysts:**

| Observation | Possible Implication |
|-------------|---------------------|
| Self-signed certificate on public internet | Malware C2, improper setup |
| Certificate with very short validity (1-2 days) | Automated malware infrastructure |
| Domain registered < 30 days with TLS cert | Phishing, malware infrastructure |
| TLS 1.0/1.1 in use | Old system, possible downgrade attack |
| Weak cipher suite (RC4, DES, NULL) | Misconfiguration or attack |
| JA3 hash matching known malware | Malware TLS implementation identified |
| Large data transfer to unusual external IP | Possible exfiltration |
| DNS over HTTPS (DoH) to non-corporate resolver | Potential DNS tunneling or privacy tool |
| Unusually high entropy in DNS names | Possible DNS tunneling |

### 12.5 Encrypted Malware C2

Modern malware increasingly uses standard TLS for C2 communication to blend with legitimate traffic:

* **Cobalt Strike:** Malleable C2 profiles can mimic legitimate software; uses HTTPS by default
* **Emotet, TrickBot, Qakbot:** Use HTTPS C2
* **Metasploit HTTPS listener:** Standard pen testing tool

**Detection approaches without decryption:**

1. **Threat intel:** Block known C2 IP addresses/domains
1. **JA3 fingerprinting:** Compare TLS fingerprints against threat intel
1. **Behavioral analytics:** Detect beaconing (Cobalt Strike beacons every 60 seconds by default)
1. **DNS analytics:** Detect domain generation algorithms (DGAs), fast flux DNS
1. **Proxy logs / DNS logs:** Even if content is encrypted, you can see which domains are accessed
1. **Certificate analysis:** Unusual certificate attributes, self-signed certs, certificate age

### 12.6 Cryptographic Hygiene Checklist for SOC

When assessing or auditing systems:

* [ ] TLS 1.3 supported and TLS 1.0/1.1 disabled
* [ ] No weak cipher suites (NULL, EXPORT, RC4, DES, 3DES)
* [ ] Certificates signed with SHA-256 (not SHA-1 or MD5)
* [ ] RSA keys ≥ 2048-bit (preferably 4096-bit or ECC)
* [ ] Certificates within validity period and not expiring soon
* [ ] HSTS enabled with long max-age
* [ ] OCSP stapling enabled
* [ ] Certificate Transparency logging compliant
* [ ] No use of MD5 for integrity verification
* [ ] Passwords stored with bcrypt/scrypt/Argon2 (not SHA-256 or MD5)
* [ ] Disk encryption enabled on endpoints
* [ ] VPN using strong protocols (WireGuard, IPSec IKEv2 with AES-256-GCM)

---

## 13. Summary and Key Takeaways {#13-summary}

### Essential Concepts to Remember

1. **Symmetric encryption** (AES) is fast and used for bulk data. Use AES-256-GCM. Never use DES, 3DES, or ECB mode.

1. **Asymmetric encryption** (RSA, ECC) solves key distribution but is slow. Used for key exchange and digital signatures, not bulk encryption.

1. **Hybrid encryption** combines both: asymmetric to exchange a symmetric key, then symmetric for data. This is how TLS, PGP, and most modern crypto systems work.

1. **Hash functions** provide integrity and are used in signatures. SHA-256 is the minimum standard. MD5 and SHA-1 are broken for security purposes.

1. **Digital signatures** provide authenticity and non-repudiation. They sign a hash of data using the sender's private key.

1. **PKI** makes asymmetric cryptography practical by providing a trusted mechanism to bind public keys to identities.

1. **TLS 1.3** is the current standard for secure communications. All cipher suites provide forward secrecy. Analyze TLS metadata (JA3, SNI, certificates) for threat detection.

1. **Encryption creates blind spots** for SOC analysts. Compensate with metadata analysis, behavioral analytics, threat intel, and selective TLS inspection.

1. **Post-quantum threat** is approaching. AES-256 is quantum-resistant; RSA and ECC are not. Migration to ML-KEM/ML-DSA is underway.

1. **Cryptographic failures are often implementation failures**, not mathematical weaknesses: nonce reuse, padding oracle attacks, timing attacks, weak random number generation.

### Common Mistakes to Avoid

* Using MD5 or SHA-1 for security-relevant hashing
* Using ECB mode with any block cipher
* Reusing IVs or nonces with the same key
* Using raw/textbook RSA without proper padding
* Hashing passwords with fast hash functions (use bcrypt/Argon2)
* Assuming encryption provides integrity (use AEAD modes like GCM)
* Ignoring certificate validation (don't disable certificate verification!)

---

## 14. References {#14-references}

### Books

* Schneier, B. (1996). *Applied Cryptography* (2nd ed.). Wiley. — Comprehensive introduction, accessible.
* Ferguson, N., Schneier, B., & Kohno, T. (2010). *Cryptography Engineering*. Wiley. — Practical focus.
* Paar, C., & Pelzl, J. (2010). *Understanding Cryptography*. Springer. — Mathematical but accessible.
* Boneh, D. & Shoup, V. *A Graduate Course in Applied Cryptography* (free online). — Rigorous treatment.

### Standards

* **NIST FIPS 197** — Advanced Encryption Standard (AES): https://csrc.nist.gov/publications/detail/fips/197/final
* **NIST SP 800-175B** — Guide to Secure Use of Cryptographic Standards in Federal Government
* **NIST FIPS 203/204/205** — Post-Quantum Cryptography Standards (2024)
* **RFC 8446** — TLS 1.3 specification
* **RFC 5652** — Cryptographic Message Syntax (CMS)

### Tools

* **OpenSSL:** https://www.openssl.org/ — Swiss army knife for cryptographic operations
* **CyberChef:** https://gchq.github.io/CyberChef/ — Browser-based cryptographic toolkit
* **GPG (GNU Privacy Guard):** https://gnupg.org/ — PGP implementation
* **Wireshark:** https://www.wireshark.org/ — Network protocol analyzer with TLS dissection
* **crt.sh:** https://crt.sh/ — Certificate Transparency log search

### Online Learning

* Cryptography I & II — Dan Boneh, Stanford (Coursera)
* Crypto101 — https://crypto101.io/ — Free introductory book

---

*End of Session 04 Reading — Fundamentals of Cryptography*
