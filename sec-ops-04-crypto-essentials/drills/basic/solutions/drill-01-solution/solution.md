# Solution: Drill 01 (Basic) — Cipher and Hash Identification

---

## Question 1: What hashing algorithm was used in the password database?

**Answer:** MD5

**Reasoning:**

* The hashes are 32 hexadecimal characters long
* 32 hex chars × 4 bits = 128 bits → this is the MD5 output length

* You can verify: `echo -n "admin123" | md5sum` → `0192023a7bbd73250516f069df18b500`

**Verification:**

```console
echo -n "admin123" | md5sum
# d41d8cd98f00b204e9800998ecf8427e is MD5 of empty string
```

---

## Question 2: Are these passwords secure?

**Answer:** No — doubly insecure.

**Reasoning:**

1. **MD5 is broken** — collisions exist and it's computationally trivial to reverse
1. **No salt** — same password always produces the same MD5 hash; rainbow tables work
1. **GPU cracking speed** — modern GPUs compute ~10 billion MD5/second
1. Common passwords like "admin123" are in every rainbow table

**Correct approach:** Use bcrypt, scrypt, or Argon2 with per-user random salts.

---

## Question 3: What encoding is Artifact 2?

**Answer:** Base64 encoding — NOT encryption

**Reasoning:**

* Character set: A-Z, a-z, 0-9, +, / and = padding → classic Base64 alphabet
* Base64 expands 3 bytes to 4 characters; the length and = padding confirm it
* Base64 is **encoding**, not encryption — no key required to reverse it

**Decode:**

```console
echo "U0VDUkVUIENPTkZJR1VSQVRJT046IEFQSV9LRVk9eEs5bVAzcVI3c1Qy" | base64 -d
# OUTPUT: SECRET CONFIGURATION: API_KEY=xK9mP3qR7sT2
```

---

## Question 4: What is the decoded value?

**Answer:** `SECRET CONFIGURATION: API_KEY=xK9mP3qR7sT2`

**Security finding:** Storing sensitive configuration values as Base64 is **not security** — Base64 provides zero protection.
This is security theater.
The API key is effectively in plaintext.

---

## Question 5: What encryption tool created the file in Artifact 3?

**Answer:** OpenSSL `enc` command

**Reasoning:**

* The `Salted__` ASCII header (bytes `53 61 6c 74 65 64 5f 5f`) is the exact header written by `openssl enc` when using password-based encryption with salt
* The next 8 bytes are the random salt value

```console
# Verify: encrypt a file and check the header
openssl enc -aes-256-cbc -pbkdf2 -in /dev/null -out test.enc -pass pass:x
xxd test.enc | head -2
# First 8 bytes will be "Salted__"
```

---

## Question 6: What does the Salted__ header tell you?

**Answer:** The encryption used password-based key derivation with a random salt.

**Meaning:**

* The salt prevents rainbow table attacks against the password
* The AES key was derived from a password + salt using PBKDF1 or PBKDF2
* Without knowing the password, the data cannot be decrypted
* The salt IS stored (it's the 8 bytes after `Salted__`) — it doesn't need to be secret

**SOC implication:** If you find encrypted files with this header on a suspect machine, the attacker used OpenSSL with a password.
Key investigation question: where is the password/key?

---

## Question 7: Algorithm identification by output length

| File | Hex chars | Bits | Algorithm |
|------|-----------|------|-----------|
| File A | 32 | 128 bits | **MD5** |
| File B | 40 | 160 bits | **SHA-1** |
| File C | 64 | 256 bits | **SHA-256** |
| File D | 128 | 512 bits | **SHA-512** |

**Rule:** hex_chars × 4 = bits

**Security assessment:**

* File A (MD5): BROKEN — collisions exist since 2004
* File B (SHA-1): BROKEN — collision demonstrated by SHAttered (2017)
* File C (SHA-256): SECURE — use for all security purposes
* File D (SHA-512): SECURE — higher security margin

---

## Additional Task: Algorithm Identification

```console
echo -n "test" | openssl dgst -md5   # 098f6bcd...  (32 hex) = MD5
echo -n "test" | openssl dgst -sha1  # a94a8fe5...  (40 hex) = SHA-1
echo -n "test" | openssl dgst -sha256 # 9f86d081... (64 hex) = SHA-256
echo -n "test" | openssl dgst -sha512 # ee26b0dd... (128 hex) = SHA-512
```

---

## Bonus Challenge Solution

```console
echo "aGVsbG8gd29ybGQgZnJvbSBtYWx3YXJl" | base64 -d
# OUTPUT: hello world from malware
```

**Answer:** Base64 encoding. **Fully recoverable** without any key — this is not encryption.

---

## Scoring

| Question | Points | Topic |
|----------|--------|-------|
| Q1 | 1 | Algorithm identification by output length |
| Q2 | 1 | Security assessment of MD5 for passwords |
| Q3 | 1 | Base64 encoding vs encryption distinction |
| Q4 | 1 | Practical decoding |
| Q5 | 1 | OpenSSL file format recognition |
| Q6 | 1 | Salt and PBKDF understanding |
| Q7 | 1 | All 4 algorithms × 0.25 = 1 point |
| **Total** | **7** | |

**Pass:** 6/7 with reasoning
