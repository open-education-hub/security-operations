# Demo 02: Asymmetric Encryption with OpenSSL (RSA)

> **Duration:** ~25 minutes
> **Difficulty:** Beginner-Intermediate
> **Tools:** Docker, OpenSSL
> **Concepts:** RSA key generation, public/private key pairs, hybrid encryption, key formats

---

## Overview

This demo explores asymmetric cryptography using RSA with OpenSSL.
You will:

1. Generate RSA key pairs (2048-bit and 4096-bit)
1. Examine the structure of public and private keys
1. Encrypt data with a public key and decrypt with the private key
1. Implement hybrid encryption (RSA + AES — as used in real protocols)
1. Compare RSA performance vs AES performance

---

## Step 1: Start the Docker Environment

```console
docker run --rm -it --name crypto-demo-02 ubuntu:22.04 bash
```

```console
apt-get update -q && apt-get install -y openssl python3 time 2>/dev/null | tail -3
mkdir -p /demo && cd /demo
```

---

## Step 2: Generate RSA Key Pairs

### 2a: Generate a 2048-bit RSA key pair

```console
echo "Generating 2048-bit RSA private key..."
time openssl genrsa -out private_key_2048.pem 2048

echo ""
echo "Key generated. File size:"
wc -c private_key_2048.pem
echo ""
echo "Key in PEM format (first 10 lines):"
head -10 private_key_2048.pem
```

**Expected output:**

```text
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
...
-----END PRIVATE KEY-----
```

### 2b: Extract the public key

```console
openssl rsa -in private_key_2048.pem -pubout -out public_key_2048.pem

echo "Public key:"
cat public_key_2048.pem
echo ""
echo "Public key size: $(wc -c < public_key_2048.pem) bytes"
echo "Private key size: $(wc -c < private_key_2048.pem) bytes"
```

### 2c: Inspect the key structure

```console
echo "=== RSA Key Details ==="
openssl rsa -in private_key_2048.pem -text -noout 2>/dev/null | head -20

echo ""
echo "Key components:"
echo "  n (modulus):  product of two large primes p and q"
echo "  e (public exponent): typically 65537"
echo "  d (private exponent): secret, used for decryption"
echo "  p, q: the secret prime factors of n"
```

### 2d: Generate a 4096-bit key and compare

```console
echo "Generating 4096-bit RSA key (takes longer)..."
time openssl genrsa -out private_key_4096.pem 4096 2>/dev/null

echo ""
echo "Key sizes:"
echo "  2048-bit: $(wc -c < private_key_2048.pem) bytes"
echo "  4096-bit: $(wc -c < private_key_4096.pem) bytes"
openssl rsa -in private_key_4096.pem -pubout -out public_key_4096.pem
```

---

## Step 3: Encrypt and Decrypt with RSA

**Important:** RSA can only encrypt data smaller than its key size minus padding overhead.
For 2048-bit RSA with OAEP padding: max ~214 bytes.

### 3a: Encrypt a small message

```console
echo -n "TOP SECRET: Server admin password is P@ssw0rd#2024!" > small_message.txt
echo "Message: $(cat small_message.txt)"
echo "Message length: $(wc -c < small_message.txt) bytes"
```

```bash
# Encrypt with the PUBLIC key (anyone with the public key can encrypt)
openssl pkeyutl -encrypt \
  -inkey public_key_2048.pem \
  -pubin \
  -in small_message.txt \
  -out message_rsa.enc

echo "Encrypted message: $(wc -c < message_rsa.enc) bytes"
echo "Ciphertext (hex):"
xxd message_rsa.enc | head -4
```

### 3b: Decrypt with the private key

```console
# Decrypt with the PRIVATE key (only the key owner can decrypt)
openssl pkeyutl -decrypt \
  -inkey private_key_2048.pem \
  -in message_rsa.enc \
  -out message_decrypted.txt

echo "Decrypted: $(cat message_decrypted.txt)"
```

### 3c: Try decrypting with the wrong key

```console
echo "Generating a different key pair..."
openssl genrsa -out wrong_key.pem 2048 2>/dev/null

echo "Attempting decryption with wrong private key..."
openssl pkeyutl -decrypt \
  -inkey wrong_key.pem \
  -in message_rsa.enc \
  -out /dev/null 2>&1 || echo "FAILED: Cannot decrypt with wrong private key"
```

---

## Step 4: Hybrid Encryption (How TLS Actually Works)

RSA alone cannot encrypt large files.
Real systems use **hybrid encryption**: RSA encrypts a random symmetric key, AES uses that key to encrypt the actual data.

```bash
# Create a large document to encrypt
python3 -c "
content = 'CLASSIFIED NETWORK TOPOLOGY\n' + ('Router: 10.0.{}.1/24\n'.format(i) for i in range(1, 50)).__class__([f'Router: 10.0.{i}.1/24' for i in range(1, 50)])
import random, string
# Generate a realistic 'large' document
doc = 'CLASSIFIED NETWORK DIAGRAM AND ASSET INVENTORY\n' + '='*50 + '\n'
for i in range(1, 30):
    doc += f'Host {i:03d}: 192.168.{i//10}.{i%10} - Role: {[\"Server\",\"Workstation\",\"Router\",\"Switch\"][i%4]}\n'
with open('large_document.txt', 'w') as f:
    f.write(doc)
print(f'Created: large_document.txt ({len(doc)} bytes)')
"
```

```bash
echo "=== HYBRID ENCRYPTION ==="
echo ""

# Step 1: Generate a random AES-256 session key
SESSION_KEY=$(openssl rand -hex 32)
SESSION_IV=$(openssl rand -hex 16)
echo "1. Generated random AES-256 session key: ${SESSION_KEY:0:8}...${SESSION_KEY: -8}"

# Step 2: Encrypt the session key with RSA public key
echo "$SESSION_KEY" > session_key.txt
openssl pkeyutl -encrypt \
  -inkey public_key_2048.pem \
  -pubin \
  -in session_key.txt \
  -out session_key.enc

echo "2. Session key encrypted with RSA public key ($(wc -c < session_key.enc) bytes)"

# Step 3: Encrypt the actual data with AES using the session key
openssl enc -aes-256-cbc \
  -K "$SESSION_KEY" \
  -iv "$SESSION_IV" \
  -nosalt \
  -in large_document.txt \
  -out document.enc

echo "3. Document encrypted with AES-256-CBC ($(wc -c < document.enc) bytes)"

echo ""
echo "=== FILES TO SEND SECURELY ==="
echo "  session_key.enc  - RSA-encrypted AES key  (only recipient can decrypt)"
echo "  document.enc     - AES-encrypted content   (large, fast)"
echo "  $SESSION_IV  - IV (not secret)"
```

```bash
echo ""
echo "=== HYBRID DECRYPTION ==="

# Step 1: Decrypt the session key with RSA private key
openssl pkeyutl -decrypt \
  -inkey private_key_2048.pem \
  -in session_key.enc \
  -out session_key_decrypted.txt

RECOVERED_KEY=$(cat session_key_decrypted.txt)
echo "1. Session key recovered: ${RECOVERED_KEY:0:8}...${RECOVERED_KEY: -8}"

# Step 2: Decrypt the document with the recovered AES key
openssl enc -d -aes-256-cbc \
  -K "$RECOVERED_KEY" \
  -iv "$SESSION_IV" \
  -nosalt \
  -in document.enc \
  -out document_decrypted.txt

echo "2. Document decrypted!"
echo ""
diff large_document.txt document_decrypted.txt && \
  echo "Files are IDENTICAL — decryption successful!"
```

---

## Step 5: RSA Performance Comparison

```bash
echo "=== PERFORMANCE TEST ==="
echo "Comparing RSA vs AES speed..."
echo ""

# RSA signature speed test
echo "RSA-2048 sign/verify operations per second:"
openssl speed rsa2048 2>&1 | grep -E "sign|verify" | head -4

echo ""

# AES speed test
echo "AES-256 throughput:"
openssl speed aes-256-cbc 2>&1 | grep -E "256 cbc" | head -4

echo ""
echo "Conclusion: AES is THOUSANDS of times faster than RSA."
echo "This is why hybrid encryption exists."
```

---

## Step 6: Key Formats

```bash
echo "=== KEY FORMAT REFERENCE ==="
echo ""
echo "PEM format (Base64, human readable headers):"
head -3 private_key_2048.pem
echo "..."
tail -1 private_key_2048.pem

echo ""
echo "Convert to DER format (binary):"
openssl rsa -in private_key_2048.pem -outform DER -out private_key.der 2>/dev/null
echo "DER file size: $(wc -c < private_key.der) bytes (binary, not human readable)"

echo ""
echo "Check key fingerprint (useful for verification):"
openssl rsa -in public_key_2048.pem -pubin -outform DER 2>/dev/null | sha256sum
```

---

## Step 7: ECC Key Generation (Comparison)

```bash
echo "=== ECC vs RSA Key Sizes ==="

# Generate P-256 ECC key (equivalent security to RSA-3072)
openssl ecparam -name prime256v1 -genkey -noout -out ecc_p256_key.pem
openssl ec -in ecc_p256_key.pem -pubout -out ecc_p256_pub.pem 2>/dev/null

echo "ECC P-256 private key: $(wc -c < ecc_p256_key.pem) bytes"
echo "RSA-2048 private key:  $(wc -c < private_key_2048.pem) bytes"
echo "RSA-4096 private key:  $(wc -c < private_key_4096.pem) bytes"
echo ""
echo "ECC P-256 provides ~RSA-3072 security in a MUCH smaller key!"

# ECC key generation speed
echo ""
echo "Key generation speed comparison:"
echo -n "RSA-2048: "
time openssl genrsa 2048 2>/dev/null > /dev/null
echo -n "ECC P-256: "
time openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null > /dev/null
```

---

## Summary

```bash
echo "=== DEMO 02 SUMMARY ==="
ls -lh /demo/
echo ""
echo "Key concepts demonstrated:"
echo "1. RSA key pairs: public key encrypts, private key decrypts"
echo "2. RSA max message size limited by key size"
echo "3. Hybrid encryption: RSA for key exchange + AES for data"
echo "4. ECC provides equivalent security with smaller keys"
echo "5. RSA is ~1000x slower than AES — use hybrid encryption"
```

---

## Discussion Questions

1. If someone gets your public key, what can they do? What can they NOT do?
1. Why do we use hybrid encryption instead of just RSA or just AES?
1. What does "forward secrecy" mean and why is ephemeral key exchange (ECDHE) important?
1. An email is signed with Bob's private key. What does this prove?
1. A developer generates a 512-bit RSA key. What is the problem?
