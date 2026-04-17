#!/bin/bash
# SSH Hardening Script
# Applies CIS Benchmark SSH hardening settings
# Run inside the demo container to observe before/after difference.

set -e

echo "========================================================"
echo "  SSH Security Hardening"
echo "========================================================"
echo ""

SSHD_CONFIG="/etc/ssh/sshd_config"
HARDENING_CONF="/etc/ssh/sshd_config.d/99-hardening.conf"

# -------------------------------------------------------
# Step 1: Show current (insecure) configuration
# -------------------------------------------------------
echo "[*] Current SSH security settings (BEFORE hardening):"
echo ""
for setting in PermitRootLogin PasswordAuthentication MaxAuthTries X11Forwarding AllowAgentForwarding LoginGraceTime ClientAliveInterval; do
    current=$(sshd -T 2>/dev/null | grep -i "^${setting}" | head -1 || echo "  (not found in sshd -T)")
    echo "    $current"
done

echo ""

# -------------------------------------------------------
# Step 2: Apply hardening
# -------------------------------------------------------
echo "[*] Applying hardening configuration to $HARDENING_CONF ..."

mkdir -p /etc/ssh/sshd_config.d/

cat > "$HARDENING_CONF" << 'EOF'
# SSH Hardening Configuration — CIS Benchmark aligned
# Applied by harden-ssh.sh

# Disallow root login (use sudo from a regular account instead)
PermitRootLogin no

# Require SSH key authentication; disable password-based login
PasswordAuthentication no
ChallengeResponseAuthentication no

# Limit login attempts per connection to reduce brute-force surface
MaxAuthTries 3

# Disconnect clients that don't complete authentication within 30 seconds
LoginGraceTime 30

# Disconnect idle sessions after 5 minutes × 2 checks = 10 minutes
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable X11 forwarding (not needed on servers, attack surface)
X11Forwarding no

# Disable agent forwarding (prevents credential relay)
AllowAgentForwarding no

# Disable TCP forwarding unless explicitly needed
AllowTcpForwarding no

# Prevent privilege escalation via SSH environment variables
PermitUserEnvironment no

# Only allow SSH protocol 2 (protocol 1 is cryptographically broken)
# Protocol 2  # Deprecated directive in OpenSSH 7.6+, protocol 2 is the only option

# Limit SSH to specific users (add your admin users here)
# AllowUsers alice devops

# Log verbosity for audit trail
LogLevel VERBOSE

# Use only modern, secure MAC algorithms
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Use only modern ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# Key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521
EOF

echo "    Written: $HARDENING_CONF"

# -------------------------------------------------------
# Step 3: Validate the configuration
# -------------------------------------------------------
echo ""
echo "[*] Validating SSH configuration syntax..."
if sshd -t 2>&1; then
    echo "    SSH config: VALID"
else
    echo "    SSH config: ERRORS FOUND — please review $HARDENING_CONF"
    exit 1
fi

# -------------------------------------------------------
# Step 4: Show new configuration
# -------------------------------------------------------
echo ""
echo "[*] New SSH security settings (AFTER hardening):"
echo ""
for setting in PermitRootLogin PasswordAuthentication MaxAuthTries X11Forwarding AllowAgentForwarding LoginGraceTime ClientAliveInterval; do
    current=$(sshd -T 2>/dev/null | grep -i "^${setting}" | head -1 || echo "  (not found)")
    echo "    $current"
done

echo ""
echo "[*] Hardening complete."
echo "    In production: reload SSH with: systemctl reload ssh"
echo "    IMPORTANT: Test SSH key login from another session BEFORE disconnecting!"
echo "    Setting PasswordAuthentication no will lock you out if you have no SSH key!"
