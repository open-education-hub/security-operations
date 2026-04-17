# Demo 03: Hashing Files and Digital Signatures

> **Duration:** ~20 minutes
> **Difficulty:** Beginner
> **Tools:** Docker, sha256sum, sha1sum, md5sum, openssl dgst
> **Concepts:** Hash properties, tamper detection, MD5 collision, digital signatures, HMAC

---

## Overview

This demo covers cryptographic hash functions and digital signatures.
You will:

1. Hash files with MD5, SHA-1, and SHA-256
1. Observe the avalanche effect
1. Detect file tampering using hashes
1. Demonstrate why MD5 is broken (collision)
1. Create and verify digital signatures (Ed25519)
1. Use HMAC for message authentication

---

## Quick Start

```console
# Option 1: Docker (recommended)
docker build -t demo-03-hashing . && docker run --rm -it demo-03-hashing

# Option 2: Run script directly (requires openssl, python3)
bash demo.sh

# Option 3: Interactive Docker shell
docker run --rm -it ubuntu:22.04 bash
# Inside: apt-get update -q && apt-get install -y openssl python3 xxd && bash
```

---

## Manual Walkthrough

### 1. Basic Hashing

```console
echo -n "Hello, World!" | md5sum
echo -n "Hello, World!" | sha1sum
echo -n "Hello, World!" | sha256sum
echo -n "Hello, World!" | sha512sum
```

### 2. Hash a File

```console
sha256sum /etc/hostname
# Create a sha256 checksum file
sha256sum important_file.txt > important_file.txt.sha256
# Later verify:
sha256sum --check important_file.txt.sha256
```

### 3. Avalanche Effect

```console
echo -n "password" | sha256sum
echo -n "Password" | sha256sum  # Only 'p' → 'P'
# Notice: completely different output from one-character change
```

### 4. Digital Signature (Ed25519)

```console
# Generate key pair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Sign
openssl dgst -sha256 -sign private.pem -out doc.sig document.txt

# Verify
openssl dgst -sha256 -verify public.pem -signature doc.sig document.txt
```

### 5. HMAC

```console
echo -n "message body" | openssl dgst -sha256 -hmac "shared_secret"
```

---

## Key Concepts

| Hash | Output | Status | Use |
|------|--------|--------|-----|
| MD5 | 128-bit | BROKEN | Legacy only |
| SHA-1 | 160-bit | BROKEN | Legacy only |
| SHA-256 | 256-bit | Secure | General purpose |
| SHA-512 | 512-bit | Secure | High security |

**Digital Signatures:** Sign with private key → verify with public key → proves authenticity + integrity

**HMAC:** `H(key || H(key || message))` — provides both integrity and authenticity using a shared secret
