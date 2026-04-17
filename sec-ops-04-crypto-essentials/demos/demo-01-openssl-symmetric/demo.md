# Demo 01: Symmetric Encryption with OpenSSL (AES-256)

> **Duration:** ~20 minutes
> **Difficulty:** Beginner
> **Tools:** Docker, OpenSSL
> **Concepts:** AES-256-GCM, CBC mode, key derivation, encryption/decryption

---

## Overview

This demo walks through symmetric encryption using OpenSSL inside a Docker container.
You will:

1. Encrypt a file using AES-256-CBC
1. Encrypt using the stronger AES-256-GCM (authenticated encryption)
1. Observe how different modes affect the ciphertext
1. Decrypt and verify the original content
1. See what happens when you use the wrong key

---

## Prerequisites

* Docker installed (`docker --version`)
* Basic terminal familiarity

---

## Step 1: Start the Docker Environment

```console
docker run --rm -it --name crypto-demo-01 \
  -v "$(pwd)/workspace:/workspace" \
  ubuntu:22.04 bash
```

Inside the container, install OpenSSL:

```console
apt-get update -q && apt-get install -y openssl xxd file 2>/dev/null | tail -5
echo "OpenSSL version: $(openssl version)"
```

**Expected output:**

```text
OpenSSL 3.0.x  (date)
```

Create a working directory:

```console
mkdir -p /demo && cd /demo
```

---

## Step 2: Create the Plaintext File

```bash
cat > secret_report.txt << 'EOF'
INCIDENT REPORT - CONFIDENTIAL
Date: 2024-01-15
Incident ID: IR-2024-0042

Summary: Suspicious outbound connections detected from workstation WS-042.
Destination: 185.220.101.47:443 (Known Tor exit node)
Duration: 3 hours 42 minutes
Data transferred: ~2.3 GB

Recommended action: Isolate workstation, preserve forensic image.
EOF

echo "File created:"
cat secret_report.txt
echo ""
echo "File size: $(wc -c < secret_report.txt) bytes"
```

---

## Step 3: AES-256-CBC Encryption

### 3a: Encrypt with a password (password-based key derivation)

```bash
# Encrypt using AES-256-CBC with password-based key derivation (PBKDF2)
openssl enc -aes-256-cbc \
  -pbkdf2 \
  -iter 100000 \
  -in secret_report.txt \
  -out report_cbc.enc \
  -pass pass:SecretPass123!

echo "Encrypted file created: report_cbc.enc"
echo "Size: $(wc -c < report_cbc.enc) bytes"
echo ""
echo "First 32 bytes (hex):"
xxd report_cbc.enc | head -4
```

**Explanation:**

* `-aes-256-cbc`: Use AES-256 in CBC mode
* `-pbkdf2 -iter 100000`: Derive a key from the password using PBKDF2 with 100,000 iterations (slow = harder to brute-force)
* The file is NOT readable — it's binary ciphertext

### 3b: Examine the ciphertext

```console
echo "Can we read the encrypted file?"
cat report_cbc.enc 2>/dev/null || echo "(binary garbage - unreadable)"

echo ""
echo "What does 'file' think it is?"
file report_cbc.enc
```

### 3c: Decrypt

```bash
openssl enc -d -aes-256-cbc \
  -pbkdf2 \
  -iter 100000 \
  -in report_cbc.enc \
  -out report_decrypted.txt \
  -pass pass:SecretPass123!

echo "Decryption successful!"
echo ""
echo "Decrypted content:"
cat report_decrypted.txt
```

### 3d: Try with the wrong password

```console
echo "--- Testing wrong password ---"
openssl enc -d -aes-256-cbc \
  -pbkdf2 \
  -iter 100000 \
  -in report_cbc.enc \
  -out report_wrong.txt \
  -pass pass:WRONGPASSWORD 2>&1 || echo "Decryption FAILED with wrong password"
```

---

## Step 4: AES-256-GCM Encryption (Authenticated Encryption)

GCM provides both confidentiality AND integrity/authenticity.
This is the recommended mode.

```bash
# Generate a proper random 256-bit key and 96-bit IV/nonce
KEY=$(openssl rand -hex 32)   # 32 bytes = 256 bits
IV=$(openssl rand -hex 12)    # 12 bytes = 96 bits (GCM standard nonce size)

echo "Generated key (keep this secret!):"
echo "KEY=$KEY"
echo "IV=$IV"
echo ""

# Encrypt with AES-256-GCM
openssl enc -aes-256-gcm \
  -K "$KEY" \
  -iv "$IV" \
  -in secret_report.txt \
  -out report_gcm.enc

echo "GCM encrypted file: report_gcm.enc"
echo "Size: $(wc -c < report_gcm.enc) bytes"
```

```console
# Decrypt GCM
openssl enc -d -aes-256-gcm \
  -K "$KEY" \
  -iv "$IV" \
  -in report_gcm.enc \
  -out report_gcm_dec.txt

echo "GCM decrypted content:"
cat report_gcm_dec.txt
```

---

## Step 5: ECB Mode — Why It's Dangerous

This demonstrates why ECB mode leaks patterns and should NEVER be used.

```console
# Create a file with repeated blocks to show ECB weakness
python3 -c "
data = b'BLOCK_OF_DATA_XY' * 6  # 6 identical 16-byte blocks
with open('repeated_data.bin', 'wb') as f:
    f.write(data)
print(f'Created file: {len(data)} bytes of repeated blocks')
print(f'Content (hex): {data.hex()[:64]}...')
"
```

```bash
# Encrypt with ECB mode (DO NOT USE IN PRODUCTION)
openssl enc -aes-256-ecb \
  -K "$(openssl rand -hex 32)" \
  -nosalt \
  -in repeated_data.bin \
  -out repeated_ecb.enc

echo "ECB ciphertext (hex):"
xxd repeated_ecb.enc | head

echo ""
echo "Notice: identical input blocks produce identical ciphertext blocks!"
echo "An attacker can see the PATTERN even without the key."
```

```bash
# Compare: same file with CBC mode
KEY2=$(openssl rand -hex 32)
IV2=$(openssl rand -hex 16)

openssl enc -aes-256-cbc \
  -K "$KEY2" \
  -iv "$IV2" \
  -nosalt \
  -in repeated_data.bin \
  -out repeated_cbc.enc

echo "CBC ciphertext (hex):"
xxd repeated_cbc.enc | head
echo ""
echo "CBC: identical input blocks produce DIFFERENT ciphertext blocks"
```

---

## Step 6: Key Derivation Functions (KDF)

Real-world systems derive encryption keys from passwords using KDFs that are intentionally slow.

```bash
# Demonstrate PBKDF2 key derivation
echo "Deriving a 256-bit key from password using PBKDF2..."

openssl kdf \
  -keylen 32 \
  -kdfopt digest:SHA256 \
  -kdfopt pass:MySecurePassword \
  -kdfopt salt:$(openssl rand -hex 16) \
  -kdfopt iter:100000 \
  PBKDF2 2>/dev/null | xxd | head -3

echo ""
echo "Same password + different salt = different key (rainbow tables ineffective)"
```

---

## Step 7: Summary and Verification

```bash
echo "=== DEMO 01 SUMMARY ==="
echo ""
echo "Files created:"
ls -la /demo/
echo ""
echo "Key takeaways:"
echo "1. AES-256 with a strong password is extremely difficult to brute-force"
echo "2. CBC mode requires a random, unique IV for each encryption"
echo "3. GCM mode adds authentication — detects if ciphertext is tampered"
echo "4. ECB mode LEAKS PATTERNS — never use for real data"
echo "5. Use PBKDF2/bcrypt/Argon2 to derive keys from passwords"
echo ""
echo "Encryption algorithm security:"
echo "  DES (56-bit)   : BROKEN - brute-forceable in seconds"
echo "  3DES (112-bit) : DEPRECATED - migrate to AES"
echo "  AES-128        : Secure for most uses"
echo "  AES-256        : Secure + quantum-resistant"
```

---

## Cleanup

```console
exit  # Exit the container
# Container is auto-removed (--rm flag)
```

---

## Discussion Questions

1. Why does CBC mode require a random IV but the IV doesn't need to be secret?
1. What is the difference between confidentiality (provided by AES-CBC) and authenticated encryption (provided by AES-GCM)?
1. If you encrypt the same file twice with AES-256-CBC using the same password, will you get the same ciphertext? Why or why not?
1. A developer stores the encryption key in the same file as the encrypted data. What is wrong with this approach?

---

## Quick Reference

```bash
# Encrypt a file with AES-256-CBC (password-based)
openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
  -in plaintext.txt -out encrypted.enc -pass pass:YourPassword

# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -in encrypted.enc -out decrypted.txt -pass pass:YourPassword

# Encrypt with explicit key and IV (hex)
openssl enc -aes-256-cbc -K <32-byte-hex-key> -iv <16-byte-hex-iv> \
  -in plaintext.txt -out encrypted.enc -nosalt

# List all available cipher algorithms
openssl enc -list
```
