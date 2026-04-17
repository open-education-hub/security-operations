# Drill 01 (Basic): Cipher and Hash Identification

> **Level:** Basic
> **Time:** 20–30 minutes
> **Tools:** Docker, OpenSSL, CyberChef, sha256sum
> **No hints unless stuck**

---

## Scenario

You are a junior SOC analyst.
The incident response team has collected artifacts from a potentially compromised workstation.
Your task is to identify what encryption and hashing algorithms were used in various artifacts.

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl python3 xxd 2>/dev/null | tail -3
mkdir -p /drill && cd /drill
```

Run the setup script to generate the challenge artifacts:

```bash
python3 << 'EOF'
import hashlib, base64, os, subprocess

# Artifact 1: A hash found in a password database backup
passwords = ["admin123", "Summer2024!", "P@ssword"]
print("=== ARTIFACT 1: Password Database Backup ===")
print("Found in /var/db/users.bak:")
print()
for pwd in passwords:
    h = hashlib.md5(pwd.encode()).hexdigest()
    print(f"  user_hash: {h}")
print()
print("Question 1: What hashing algorithm was used? How do you know?")
print("Question 2: Are these passwords secure? Why or why not?")
print()

# Artifact 2: A file with unknown encoding
data = b"SECRET CONFIGURATION: API_KEY=xK9mP3qR7sT2"
b64 = base64.b64encode(data).decode()
print("=== ARTIFACT 2: Unknown Encoded String ===")
print("Found in environment variable ENCODED_CONFIG:")
print(f"  {b64}")
print()
print("Question 3: What encoding is this? Is it encryption?")
print("Question 4: What is the decoded value?")
print()

# Artifact 3: OpenSSL encrypted file header
import struct
# AES-256-CBC encrypted file starts with "Salted__" header
salted = b"Salted__" + os.urandom(8)
print("=== ARTIFACT 3: Encrypted File Header ===")
print("xxd output from encrypted_config.enc (first 32 bytes):")
hex_str = salted.hex()
for i in range(0, len(hex_str), 32):
    offset = i // 2
    chunk = hex_str[i:i+32]
    hex_groups = ' '.join(chunk[j:j+8] for j in range(0, len(chunk), 8))
    print(f"  {offset:08x}:  {hex_groups}")
print()
print("Question 5: What encryption tool created this file?")
print("Question 6: What does the 'Salted__' header tell you about the encryption?")
print()

# Artifact 4: Hash lengths for identification
hashes = {
    "File A hash": "d41d8cd98f00b204e9800998ecf8427e",
    "File B hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "File C hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "File D hash": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
}
print("=== ARTIFACT 4: File Hashes from Threat Intel Report ===")
for name, h in hashes.items():
    print(f"  {name} ({len(h)} hex chars): {h[:32]}...")
print()
print("Question 7: Identify the hash algorithm for each file hash (A, B, C, D).")
print("Hint: Count the hex characters and multiply by 4 to get bits.")
EOF
```

---

## Tasks

Answer all 7 questions above.
For each answer, explain HOW you identified it.

### Additional Task: Live Identification

Run the following commands and identify the algorithm used for each:

```bash
# Hash 1: Identify this algorithm
echo -n "test" | openssl dgst -md5 | awk '{print $2}'

# Hash 2: Identify this algorithm
echo -n "test" | openssl dgst -sha1 | awk '{print $2}'

# Hash 3: Identify this algorithm
echo -n "test" | openssl dgst -sha256 | awk '{print $2}'

# Hash 4: Identify this algorithm
echo -n "test" | openssl dgst -sha512 | awk '{print $2}'

# Challenge: Given only the OUTPUT LENGTH, determine the algorithm:
echo "Output has 32 hex chars (128 bits)  → Algorithm: ???"
echo "Output has 40 hex chars (160 bits)  → Algorithm: ???"
echo "Output has 64 hex chars (256 bits)  → Algorithm: ???"
echo "Output has 128 hex chars (512 bits) → Algorithm: ???"
```

---

## Bonus Challenge

```console
# The following string was found in malware C2 traffic.
# What encoding/encryption is used? Is it recoverable without a key?
MYSTERY="aGVsbG8gd29ybGQgZnJvbSBtYWx3YXJl"
echo "Mystery string: $MYSTERY"
echo ""
echo "Hint: Try: echo '$MYSTERY' | base64 -d"
```

---

## Submission

For each question, provide:

1. Your answer (algorithm name)
1. Your reasoning (how you identified it)
1. Security assessment (is this algorithm secure for this use case?)

**Time limit:** 30 minutes

**Pass criteria:** 6/7 questions correct with reasoning
