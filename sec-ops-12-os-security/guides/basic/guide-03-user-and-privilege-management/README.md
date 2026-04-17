# Guide 03: User and Privilege Management

**Level:** Basic

**Estimated time:** 30 minutes

**Prerequisites:** Guides 01 and 02

---

## Objective

By the end of this guide, you will be able to:

* Apply the principle of least privilege on both Windows and Linux
* Configure user accounts with appropriate access levels
* Audit and remediate excessive privileges
* Implement sudo/UAC controls correctly

---

## The Principle of Least Privilege

**Definition:** Every user, process, and system should have only the minimum access necessary to perform their function.

This is the most impactful single security control for OS security.
Violations create:

* Insider threat risk (accidental or deliberate)
* Privilege escalation paths for attackers
* Higher blast radius when accounts are compromised

---

## Linux: User and Privilege Management

### Step 1: Audit Current sudo Configuration

```console
# List who has sudo access
cat /etc/sudoers | grep -v "^#\|^$"
ls /etc/sudoers.d/ && cat /etc/sudoers.d/*

# Check who is in the sudo group
getent group sudo
getent group wheel  # RHEL/CentOS equivalent

# See effective sudo rights for a user
sudo -l -U username
```

### Step 2: Restrict sudo to Specific Commands

Instead of granting full sudo access:

```console
# /etc/sudoers.d/webadmin
# Allow webadmin to restart web services only
webadmin ALL=(root) /usr/bin/systemctl restart nginx, /usr/bin/systemctl restart apache2

# Allow backup user to run backup script only
backupuser ALL=(root) NOPASSWD: /usr/local/bin/backup.sh
```

**Principle:** Only grant what is needed, and only to who needs it.

### Step 3: Create a Service Account Correctly

```bash
# Create a service account for a web application
# - No login shell (cannot SSH in)
# - No password (cannot authenticate)
# - Specific home directory

useradd --system --shell /usr/sbin/nologin --home /var/www --no-create-home webapp

# Verify
id webapp
grep webapp /etc/passwd
# webapp:x:999:999::/var/www:/usr/sbin/nologin
# ^^^ /usr/sbin/nologin means this account cannot interactively log in
```

### Step 4: Use SSH Keys, Not Passwords

```bash
# Generate SSH key pair (on the user's machine)
ssh-keygen -t ed25519 -C "user@company.com"

# Copy public key to server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Or manually:
cat ~/.ssh/id_ed25519.pub >> /home/user/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys
chmod 700 /home/user/.ssh/

# Then disable password authentication
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/keys-only.conf
systemctl reload sshd
```

### Step 5: Disable Unused Accounts

```bash
# Lock an account (disable login but keep the account)
usermod -L username
# The 'L' locks the password (adds ! prefix to shadow entry)

# Or set expiry to the past
usermod -e 1970-01-01 username

# Verify locked
passwd -S username
# Output: username L [date] (password locked)

# Check for accounts not logged in for > 90 days
lastlog | awk '$4 ~ /[0-9]/ { ... }'
# Consider disabling accounts not used for 90+ days
```

---

## Windows: Privilege Management

### Step 1: Review the Administrators Group

```powershell
# Who is in the local Administrators group?
Get-LocalGroupMember -Group "Administrators"

# Are there any unexpected members?
# Expected: Built-in Administrator (disabled), Domain Admins (if domain-joined)
# Unexpected: Regular user accounts, service accounts
```

### Step 2: Apply Least Privilege with Standard User Accounts

```powershell
# Check if a user has admin rights
$user = "alice"
$adminGroup = "Administrators"
$members = Get-LocalGroupMember -Group $adminGroup
if ($members.Name -match $user) {
  Write-Host "$user has admin rights - verify if needed" -ForegroundColor Yellow
}
```

**Guidance:**

* Regular users should NOT be local administrators
* If a user needs to install software occasionally, use a dedicated admin account they switch to
* Service accounts should run with minimum required privileges

### Step 3: Configure UAC Correctly

```powershell
# Check UAC setting (registry)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin

# EnableLUA = 1 (UAC enabled - required)
# ConsentPromptBehaviorAdmin = 2 (prompt for credentials)
# DO NOT set ConsentPromptBehaviorAdmin = 0 (disables UAC prompts for admins)
```

**UAC levels:**

* 0: Never notify (UAC effectively disabled — insecure)
* 1: Notify only when apps try to make changes (default)
* 2: Always notify (most secure)

### Step 4: Use Separate Admin Accounts

**Best practice:** Never use admin accounts for daily work.

Create two accounts:

* `alice` — standard user for email, web browsing, documents
* `alice-admin` — local or domain admin account, only for admin tasks

This limits exposure: even if `alice` is compromised (phishing, malware), the attacker only has standard user privileges.

### Step 5: Audit Privilege Use with Event Logs

```powershell
# Find events where elevated privileges were used (Event ID 4672)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 4672
  StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Cross-Platform: The Tiered Admin Model

For organizations, implement a tiered model:

```text
TIER 0: Domain Controllers, PKI, AD — Only Tier 0 admin accounts
         ↓ (no admin delegation upward)
TIER 1: Servers (DB, App, File) — Only Tier 1 admin accounts
         ↓ (no admin delegation upward)
TIER 2: Workstations, User Devices — Standard helpdesk
```

**Rule:** Admin credentials for a lower tier should never be used on a higher tier.
A compromised helpdesk account should not be able to reach domain controllers.

---

## Summary

You have learned:

* How to audit sudo and local admin access
* How to create service accounts with minimal privileges
* How to configure SSH key-based authentication
* How to apply UAC correctly on Windows
* The tiered admin model for enterprise environments

Least privilege is not a one-time fix — it requires regular audits as systems and roles change.
