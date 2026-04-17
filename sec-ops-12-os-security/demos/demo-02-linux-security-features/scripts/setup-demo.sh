#!/bin/bash
# Linux Security Features Demo - Setup Script
# Sets up the demo environment with both secure and insecure configurations
# to illustrate the contrast during the walkthrough.

set -e

echo "=== Linux Security Features Demo Setup ==="
echo ""

# -------------------------------------------------------
# 1. Create demo users with various privilege levels
# -------------------------------------------------------
echo "[+] Configuring user accounts..."

# Ensure alice exists (may already exist from Dockerfile)
id alice &>/dev/null || useradd -m -s /bin/bash alice
id bob &>/dev/null   || useradd -m -s /bin/bash bob

# Create a service account (no shell, no password)
id webapp &>/dev/null || useradd --system --shell /usr/sbin/nologin --home /var/www --no-create-home webapp
echo "    Created: webapp (service account, nologin)"

# Create a user with weak sudo config (intentional for demo)
id devops &>/dev/null || useradd -m -s /bin/bash devops
echo "devops ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/devops-demo
echo "    Created: devops (NOPASSWD sudo — insecure, for demo purposes)"

# -------------------------------------------------------
# 2. Add a non-standard SUID binary for demo purposes
# -------------------------------------------------------
echo ""
echo "[+] Adding non-standard SUID binary for analysis exercise..."
cp /usr/bin/python3 /usr/local/bin/python3-suid 2>/dev/null || cp $(which python3) /usr/local/bin/python3-suid
chmod u+s /usr/local/bin/python3-suid
echo "    Created: /usr/local/bin/python3-suid (SUID — intentional vuln for demo)"

# -------------------------------------------------------
# 3. Create world-writable file (intentional misconfiguration)
# -------------------------------------------------------
echo ""
echo "[+] Creating world-writable files for demo..."
mkdir -p /opt/demo-app
echo "#!/bin/bash" > /opt/demo-app/healthcheck.sh
echo "echo 'OK'" >> /opt/demo-app/healthcheck.sh
chmod 0777 /opt/demo-app/healthcheck.sh
echo "    Created: /opt/demo-app/healthcheck.sh (world-writable — misconfiguration demo)"

# -------------------------------------------------------
# 4. Set up SSH in insecure state first (students will harden it)
# -------------------------------------------------------
echo ""
echo "[+] Configuring SSH in insecure baseline state..."
mkdir -p /etc/ssh/sshd_config.d/
cat > /etc/ssh/sshd_config.d/demo-insecure.conf << 'EOF'
# INSECURE BASELINE — students will harden this during the demo
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 6
X11Forwarding yes
AllowAgentForwarding yes
LogLevel INFO
EOF
echo "    SSH configured with insecure baseline (PermitRootLogin yes, PasswordAuth yes)"

# -------------------------------------------------------
# 5. Create a dummy sensitive file to trigger audit events
# -------------------------------------------------------
echo ""
echo "[+] Creating demo audit targets..."
echo "root:x:0:0:root:/root:/bin/bash" >> /etc/passwd 2>/dev/null || true
echo "alice:secret_api_key_12345" > /root/sensitive_config.txt
chmod 600 /root/sensitive_config.txt
echo "    Created: /root/sensitive_config.txt (will be used in auditd demo)"

# -------------------------------------------------------
# 6. Pre-populate auth.log with some events
# -------------------------------------------------------
echo ""
echo "[+] Pre-populating /var/log/auth.log with sample events..."
mkdir -p /var/log
cat > /var/log/auth.log << 'AUTHLOG'
Jan 14 08:00:01 server sshd[1000]: Server listening on 0.0.0.0 port 22.
Jan 14 08:30:15 server sshd[1100]: Failed password for alice from 10.10.5.50 port 48222 ssh2
Jan 14 08:30:16 server sshd[1101]: Failed password for alice from 10.10.5.50 port 48223 ssh2
Jan 14 08:30:17 server sshd[1102]: Failed password for alice from 10.10.5.50 port 48224 ssh2
Jan 14 08:31:00 server sshd[1110]: Accepted publickey for alice from 192.168.1.5 port 50001 ssh2
Jan 14 08:31:00 server sshd[1110]: pam_unix(sshd:session): session opened for user alice by (uid=0)
Jan 14 09:15:03 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Jan 14 09:15:03 server sudo: pam_unix(sudo:session): session opened for user root by alice(uid=1000)
Jan 14 09:15:04 server sudo: pam_unix(sudo:session): session closed for user root
Jan 14 10:02:44 server sshd[1200]: Failed password for invalid user admin from 185.220.11.47 port 33981 ssh2
Jan 14 10:02:45 server sshd[1201]: Failed password for invalid user administrator from 185.220.11.47 port 33982 ssh2
Jan 14 10:02:46 server sshd[1202]: Failed password for root from 185.220.11.47 port 33983 ssh2
Jan 14 10:02:47 server sshd[1203]: Failed password for root from 185.220.11.47 port 33984 ssh2
Jan 14 10:02:48 server sshd[1204]: Failed password for root from 185.220.11.47 port 33985 ssh2
Jan 14 10:03:00 server sshd[1205]: Maximum authentication attempts exceeded for root from 185.220.11.47 port 33986 ssh2 [preauth]
Jan 14 11:30:00 server su[2001]: Successful su for root by alice
Jan 14 11:30:00 server su[2001]: + pts/0 alice:root
Jan 14 11:35:15 server su[2001]: pam_unix(su:session): session closed for user root
Jan 14 12:00:00 server cron[2100]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 14 12:00:01 server CRON[2101]: (root) CMD (/usr/local/sbin/backup.sh)
Jan 14 12:00:02 server cron[2100]: pam_unix(cron:session): session closed for user root
AUTHLOG
echo "    Created: /var/log/auth.log with 21 sample entries"

# -------------------------------------------------------
# 7. Start required services
# -------------------------------------------------------
echo ""
echo "[+] Starting services..."
service ssh start 2>/dev/null || true
echo "    SSH service started (or already running)"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Available scripts:"
echo "  /scripts/audit-suid.sh      - Find and classify SUID binaries"
echo "  /scripts/harden-ssh.sh      - Apply SSH hardening configuration"
echo "  /scripts/setup-auditd.sh    - Configure auditd monitoring rules"
echo "  /scripts/check-permissions.sh - Check for world-writable files and weak permissions"
echo ""
