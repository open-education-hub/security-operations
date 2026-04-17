#!/bin/bash
# Demo 02: RSA Asymmetric Encryption with OpenSSL
set -e

BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'

banner() { echo -e "\n${CYAN}════════════════════════════════════════════${RESET}\n${BOLD}${CYAN}  $1${RESET}\n${CYAN}════════════════════════════════════════════${RESET}"; }

mkdir -p /demo && cd /demo

banner "DEMO 02: RSA Asymmetric Encryption"
echo -e "${YELLOW}Demonstrating: Key generation, encrypt/decrypt, hybrid encryption${RESET}"

banner "Step 1: Generate RSA Key Pair (2048-bit)"
echo "Generating RSA-2048 private key..."
openssl genrsa -out private_key.pem 2048 2>/dev/null
openssl rsa -in private_key.pem -pubout -out public_key.pem 2>/dev/null

echo -e "${GREEN}✓ Private key: $(wc -c < private_key.pem) bytes${RESET}"
echo -e "${GREEN}✓ Public key:  $(wc -c < public_key.pem) bytes${RESET}"
echo ""
echo "Public key (safe to share with anyone):"
cat public_key.pem

banner "Step 2: Encrypt with Public Key, Decrypt with Private Key"
echo -n "TOP SECRET: AES session key = a8f3c1e9..." > secret.txt
echo "Message: $(cat secret.txt)"

openssl pkeyutl -encrypt -inkey public_key.pem -pubin \
  -in secret.txt -out secret.enc

echo -e "${GREEN}✓ Encrypted: $(wc -c < secret.enc) bytes${RESET}"

openssl pkeyutl -decrypt -inkey private_key.pem \
  -in secret.enc -out secret_dec.txt

echo -e "${GREEN}✓ Decrypted: $(cat secret_dec.txt)${RESET}"
diff secret.txt secret_dec.txt && echo -e "${GREEN}✓ Files match!${RESET}"

banner "Step 3: Hybrid Encryption (RSA + AES)"
# Simulate large data
python3 -c "
doc = 'NETWORK ASSET INVENTORY\n' + '='*40 + '\n'
for i in range(1, 25):
    doc += f'Host {i:03d}: 10.0.{i//10}.{i%10} - {[\"Server\",\"WS\",\"Router\"][i%3]}\n'
open('network_inventory.txt','w').write(doc)
print(f'Created network_inventory.txt ({len(doc)} bytes)')
"

SESSION_KEY=$(openssl rand -hex 32)
SESSION_IV=$(openssl rand -hex 16)
echo "$SESSION_KEY" > aes_key.txt

openssl pkeyutl -encrypt -inkey public_key.pem -pubin \
  -in aes_key.txt -out aes_key_encrypted.enc

openssl enc -aes-256-cbc -K "$SESSION_KEY" -iv "$SESSION_IV" -nosalt \
  -in network_inventory.txt -out inventory_encrypted.enc

echo -e "${GREEN}✓ AES key encrypted with RSA: $(wc -c < aes_key_encrypted.enc) bytes${RESET}"
echo -e "${GREEN}✓ Data encrypted with AES:    $(wc -c < inventory_encrypted.enc) bytes${RESET}"
echo ""
echo "=== Decrypting ==="

openssl pkeyutl -decrypt -inkey private_key.pem \
  -in aes_key_encrypted.enc -out aes_key_recovered.txt

RECOVERED=$(cat aes_key_recovered.txt)
openssl enc -d -aes-256-cbc -K "$RECOVERED" -iv "$SESSION_IV" -nosalt \
  -in inventory_encrypted.enc -out inventory_decrypted.txt

diff network_inventory.txt inventory_decrypted.txt && \
  echo -e "${GREEN}✓ Hybrid decryption successful — data integrity verified!${RESET}"

banner "Step 4: ECC Key Size Comparison"
openssl ecparam -name prime256v1 -genkey -noout -out ecc_key.pem 2>/dev/null
openssl ec -in ecc_key.pem -pubout -out ecc_pub.pem 2>/dev/null

echo "Key size comparison (equivalent ~128-bit security):"
echo "  ECC P-256 private key:  $(wc -c < ecc_key.pem) bytes"
echo "  RSA-2048  private key:  $(wc -c < private_key.pem) bytes"
echo ""
echo -e "${GREEN}ECC provides same security in ~10x smaller key${RESET}"

banner "Summary"
echo "1. Public key  → anyone can encrypt data FOR you"
echo "2. Private key → only YOU can decrypt data"
echo "3. RSA is slow → use hybrid encryption for real data"
echo "4. ECC = smaller keys, faster operations, same security"
echo ""
echo -e "${GREEN}Demo 02 complete!${RESET}"
