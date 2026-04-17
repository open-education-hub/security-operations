# Guide 01: Encrypting Files with AES Using OpenSSL

> **Level:** Basic
> **Time:** 30 minutes
> **Prerequisites:** Demo 01 completed, basic terminal skills
> **Tools:** Docker, OpenSSL

---

## Learning Objectives

By the end of this guide you will be able to:

* Encrypt and decrypt files using AES-256-CBC and AES-256-GCM with OpenSSL
* Understand the importance of Initialization Vectors (IVs)
* Choose appropriate encryption parameters for different use cases
* Recognize common mistakes in symmetric encryption

---

## Setup

```console
docker run --rm -it --name aes-guide ubuntu:22.04 bash
```

```console
# Install dependencies
apt-get update -q && apt-get install -y openssl python3 xxd 2>/dev/null | tail -3
mkdir -p /guide && cd /guide
```

---

## Exercise 1: Basic File Encryption

### Task

Encrypt the following configuration file containing database credentials:

```console
cat > db_config.env << 'EOF'
DB_HOST=internal-db.corp.local
DB_PORT=5432
DB_NAME=incident_tracker
DB_USER=soc_analyst
DB_PASSWORD=Tr0ub4dor&3_secure_pw
DB_SSL_MODE=require
EOF
```

### Step-by-Step Encryption

**Step 1:** Always create a strong, random encryption key (not a weak password):

```bash
# For production: use a random key derived from a strong passphrase
PASSPHRASE="ThisIsAVeryLongAndSecurePassphrase2024!"

# Option A: Password-based (easier to remember, slightly weaker)
openssl enc -aes-256-cbc \
  -pbkdf2 \
  -iter 600000 \
  -in db_config.env \
  -out db_config.enc \
  -pass pass:"$PASSPHRASE"

echo "Encrypted file: $(wc -c < db_config.enc) bytes"
```

**Step 2:** Verify the encrypted file is not readable:

```console
# This should show binary garbage
file db_config.enc
xxd db_config.enc | head -3
```

**Step 3:** Decrypt and verify:

```bash
openssl enc -d -aes-256-cbc \
  -pbkdf2 \
  -iter 600000 \
  -in db_config.enc \
  -out db_config_restored.env \
  -pass pass:"$PASSPHRASE"

# Verify content matches original
diff db_config.env db_config_restored.env && echo "SUCCESS: Files are identical"
cat db_config_restored.env
```

---

## Exercise 2: Understanding the IV (Initialization Vector)

The IV is critical for CBC mode security.
Let's see what happens with different IVs.

```bash
# Use an explicit key for this demonstration
KEY=$(openssl rand -hex 32)
echo "Using key: $KEY"

# Encrypt same file with three different random IVs
for i in 1 2 3; do
  IV=$(openssl rand -hex 16)
  openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" -nosalt \
    -in db_config.env -out "encrypted_$i.enc"
  echo "Encryption $i (IV=$IV): $(xxd "encrypted_$i.enc" | head -1 | awk '{print $2$3$4}')"
done

echo ""
echo "Three encryptions of SAME file with SAME key but DIFFERENT IVs:"
echo "Each ciphertext is different → IV provides necessary randomness"
```

```bash
# Now: what happens if we REUSE the IV? (This is dangerous)
FIXED_IV="0000000000000000"  # Terrible IV — all zeros, never do this in production

for i in 1 2; do
  openssl enc -aes-256-cbc -K "$KEY" -iv "$FIXED_IV" -nosalt \
    -in db_config.env -out "fixed_iv_$i.enc"
done

if diff fixed_iv_1.enc fixed_iv_2.enc &>/dev/null; then
  echo "WARNING: Reusing IV with same key produces IDENTICAL ciphertext!"
  echo "An attacker can detect that two messages have the same content."
fi
```

**Key rule:** The IV does NOT need to be secret, but it MUST be random and unique for each encryption with the same key.

---

## Exercise 3: AES-GCM — Authenticated Encryption

AES-GCM is the recommended mode because it provides both confidentiality AND integrity.

```bash
KEY=$(openssl rand -hex 32)
NONCE=$(openssl rand -hex 12)   # 96-bit nonce for GCM

# Encrypt
openssl enc -aes-256-gcm \
  -K "$KEY" \
  -iv "$NONCE" \
  -in db_config.env \
  -out db_config_gcm.enc

echo "GCM encrypted: $(wc -c < db_config_gcm.enc) bytes"

# Decrypt
openssl enc -d -aes-256-gcm \
  -K "$KEY" \
  -iv "$NONCE" \
  -in db_config_gcm.enc \
  -out db_config_gcm_dec.env

diff db_config.env db_config_gcm_dec.env && echo "GCM decryption successful"
```

```bash
# GCM tamper detection
# Flip one byte in the ciphertext
python3 -c "
import os
data = open('db_config_gcm.enc', 'rb').read()
# Modify byte 10 of the ciphertext
tampered = data[:10] + bytes([data[10] ^ 0xFF]) + data[11:]
open('db_config_gcm_tampered.enc', 'wb').write(tampered)
print(f'Tampered 1 byte in ciphertext ({len(data)} bytes total)')
"

echo "Attempting to decrypt tampered GCM ciphertext..."
openssl enc -d -aes-256-gcm \
  -K "$KEY" \
  -iv "$NONCE" \
  -in db_config_gcm_tampered.enc \
  -out /dev/null 2>&1 && echo "Decrypted (unexpected!)" || echo "TAMPER DETECTED: GCM authentication failed"
```

---

## Exercise 4: Securely Storing the Key

The hardest problem in symmetric encryption is **key management**.
Here are practical patterns:

### Pattern A: Environment Variable

```bash
# Store key as environment variable (not in files alongside encrypted data)
export DB_ENC_KEY=$(openssl rand -hex 32)
echo "Key stored in env: ${DB_ENC_KEY:0:8}..."

openssl enc -aes-256-gcm \
  -K "$DB_ENC_KEY" \
  -iv "$(openssl rand -hex 12)" \
  -in db_config.env \
  -out db_config_secure.enc

echo "Encrypted with key from environment variable"
```

### Pattern B: Key File (separate location)

```console
# Store key in a protected key file
openssl rand -hex 32 > /secure_key.bin
chmod 600 /secure_key.bin   # Only owner can read

KEY_FROM_FILE=$(cat /secure_key.bin)
echo "Key would be stored in /secure_key.bin (600 permissions)"
echo "In practice: use a Hardware Security Module (HSM) or secrets manager"
```

### Pattern C: Key Derivation from Master Password

```bash
# Derive encryption key from a master password (PBKDF2)
MASTER_PASSWORD="MySecureMasterPassword2024"
SALT=$(openssl rand -hex 16)

# Derive key
DERIVED_KEY=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
  -kdfopt pass:"$MASTER_PASSWORD" \
  -kdfopt salt:"$SALT" \
  -kdfopt iter:600000 \
  PBKDF2 2>/dev/null | tr -d '\n' | xxd -r -p | xxd -p | tr -d '\n')

echo "Derived key: ${DERIVED_KEY:0:8}..."
echo "Salt (store alongside encrypted data): $SALT"
echo "Password: NOT stored — must be entered by operator"
```

---

## Exercise 5: Practical Scenarios

### Scenario A: Encrypt a Directory of Evidence Files

```bash
# Create mock evidence directory
mkdir -p /evidence
echo "Packet capture from IR-2024-042" > /evidence/network.pcap.txt
echo "Process list at time of incident" > /evidence/processes.txt
echo "Registry key: HKLM\SOFTWARE\Microsoft\Windows\Run" > /evidence/registry.txt

# Create a compressed archive
tar czf /evidence_bundle.tar.gz /evidence/ 2>/dev/null

# Encrypt the evidence bundle
EVIDENCE_KEY=$(openssl rand -hex 32)
EVIDENCE_IV=$(openssl rand -hex 16)

openssl enc -aes-256-cbc \
  -K "$EVIDENCE_KEY" \
  -iv "$EVIDENCE_IV" \
  -pbkdf2 \
  -in /evidence_bundle.tar.gz \
  -out /evidence_bundle.enc

echo "Evidence encrypted."
echo "KEY: $EVIDENCE_KEY  (store separately!)"
echo "IV:  $EVIDENCE_IV   (store with encrypted file)"
echo "Encrypted bundle: $(wc -c < /evidence_bundle.enc) bytes"
```

### Scenario B: Detecting Weak OpenSSL Commands (Common Mistakes)

```bash
echo "=== Common Mistakes in AES Encryption ==="

echo "MISTAKE 1: Using DES instead of AES (broken!)"
echo "  Bad:  openssl enc -des -in file.txt -out file.enc"
echo "  Good: openssl enc -aes-256-gcm -in file.txt -out file.enc"
echo ""

echo "MISTAKE 2: Not using -pbkdf2 (weak key derivation)"
echo "  Bad:  openssl enc -aes-256-cbc -in file.txt -out file.enc -pass pass:pw"
echo "  Good: openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -in file.txt -out file.enc -pass pass:pw"
echo ""

echo "MISTAKE 3: Using -nosalt without explicit random key/IV"
echo "  Without -nosalt, you must provide -K and -iv explicitly"
echo ""

echo "MISTAKE 4: Storing key and encrypted file together"
echo "  Never: encrypted_file.enc + encryption_key.txt in same location"
echo ""

echo "MISTAKE 5: Using a short/weak password"
echo "  Bad:  -pass pass:123456"
echo "  Good: -pass pass:$(openssl rand -hex 16)  (random) or long passphrase"
```

---

## Summary

| Mode | Confidentiality | Integrity | Speed | Use Case |
|------|----------------|-----------|-------|---------|
| AES-CBC | Yes | No | Fast | General purpose, use with separate HMAC |
| AES-GCM | Yes | Yes | Fast | **Preferred** — authenticated encryption |
| AES-ECB | Yes (badly) | No | Fast | **NEVER** — leaks patterns |
| AES-CTR | Yes | No | Very fast | Stream cipher mode; pair with HMAC |

### Quick Reference Commands

```bash
# Encrypt file (password-based, recommended for humans)
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 \
  -in plaintext.txt -out encrypted.enc -pass pass:YourPassphrase

# Decrypt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -in encrypted.enc -out plaintext.txt -pass pass:YourPassphrase

# Encrypt with random key+IV (recommended for automated systems)
KEY=$(openssl rand -hex 32); IV=$(openssl rand -hex 16)
openssl enc -aes-256-cbc -K "$KEY" -iv "$IV" -nosalt \
  -in plaintext.txt -out encrypted.enc

# Use AES-GCM (best for production)
KEY=$(openssl rand -hex 32); NONCE=$(openssl rand -hex 12)
openssl enc -aes-256-gcm -K "$KEY" -iv "$NONCE" \
  -in plaintext.txt -out encrypted.enc
```

---

## Self-Check Questions

1. You encrypted a file with AES-256-CBC and lost the IV. Can you still decrypt it? Why or why not?
1. What is the maximum security benefit of using AES-256 vs AES-128? When does it matter?
1. A script stores the encryption key in the same directory as the encrypted file. What is wrong with this?
1. Why is AES-GCM preferred over AES-CBC for new applications?
1. What does `-pbkdf2 -iter 600000` do, and why is the iteration count important?
