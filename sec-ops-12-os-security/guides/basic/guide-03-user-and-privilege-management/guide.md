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

**Definition:** Every user, process, and system should have only the minimum access necessary to perform its function.

This is the single most impactful OS security control.
Violations create:

* Insider threat risk (accidental or deliberate)
* Privilege escalation paths for attackers
* Higher blast radius when accounts are compromised

---

## Linux: User and Privilege Management

### Step 1: Audit sudo Configuration

```console
# List who has sudo access
grep -v "^#\|^$" /etc/sudoers 2>/dev/null
ls /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null

# Who is in the sudo group?
getent group sudo
getent group wheel  # RHEL/CentOS

# Effective sudo rights for a specific user
sudo -l -U username
```

---

### Step 2: Restrict sudo to Specific Commands

Instead of granting full `ALL=(ALL) ALL`, grant only what is needed:

```console
# /etc/sudoers.d/webadmin
# Allow webadmin to restart web services only
webadmin ALL=(root) /usr/bin/systemctl restart nginx, \
                    /usr/bin/systemctl restart apache2

# Allow backup user to run backup script without password
backupuser ALL=(root) NOPASSWD: /usr/local/bin/backup.sh
```

---

### Step 3: Create a Service Account Correctly

```bash
# Create a service account for a web application:
# - No interactive shell (cannot SSH in)
# - No password (cannot authenticate)
# - Specific home directory, no home creation

useradd --system \
        --shell /usr/sbin/nologin \
        --home /var/www \
        --no-create-home \
        webapp

# Verify
id webapp
grep webapp /etc/passwd
# webapp:x:999:999::/var/www:/usr/sbin/nologin
```

---

### Step 4: Use SSH Keys, Not Passwords

```bash
# Generate an Ed25519 key pair (on the user's workstation)
ssh-keygen -t ed25519 -C "user@company.com"

# Copy the public key to the server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Or manually append:
cat ~/.ssh/id_ed25519.pub >> /home/user/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys
chmod 700 /home/user/.ssh/

# Then disable password authentication on the server
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/keys-only.conf
```

---

### Step 5: Disable Unused Accounts

```console
# Lock an account (disables login, keeps account for audit trail)
usermod -L username

# Set expiry to the past (hard disable)
usermod -e 1970-01-01 username

# Verify the lock
passwd -S username
# Output: username L [date] (password locked)
```

---

## Windows: Privilege Management

### Step 1: Review the Administrators Group

```powershell
# Who is in the local Administrators group?
Get-LocalGroupMember -Group "Administrators"

# Expected: Built-in Administrator (disabled), Domain Admins (if domain-joined)
# Unexpected: Regular user accounts, service accounts
```

---

### Step 2: Apply Least Privilege with Standard User Accounts

```powershell
# Check if a specific user has admin rights
$user = "alice"
$members = Get-LocalGroupMember -Group "Administrators"
if ($members.Name -match $user) {
  Write-Host "$user has admin rights - verify if needed" -ForegroundColor Yellow
}
```

**Guidance:**

* Regular users should NOT be local administrators
* If a user needs to install software occasionally, use a separate admin account they switch to
* Service accounts should run with minimum required privileges (Network Service, not SYSTEM)

---

### Step 3: Configure UAC Correctly

```powershell
# Check UAC configuration
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin

# EnableLUA = 1            (UAC enabled — required)
# ConsentPromptBehaviorAdmin = 2  (prompt for credentials — most secure)
```

**UAC levels:**

* 0: Never notify — UAC effectively disabled (insecure)
* 1: Notify only when apps make changes — default
* 2: Always notify — most secure

---

### Step 4: Use Separate Admin Accounts for Daily Work

**Best practice:** Never perform daily work with admin credentials.

Create two accounts per person who needs admin access:

* `alice` — standard user for email, web, documents
* `alice-admin` — local/domain admin account used only for specific admin tasks

If `alice` is phished or infected with malware, the attacker gets only standard user privileges — not admin.

---

### Step 5: Audit Privilege Use with Event Logs

```powershell
# Find events where elevated privileges were used (Event ID 4672)
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4672
  StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Cross-Platform: The Tiered Admin Model

For organizations with multiple system tiers, implement admin account separation:

```text
TIER 0: Domain Controllers, PKI, AD
        └── Only Tier 0 admin accounts can touch these
TIER 1: Servers (application, database, file)
        └── Only Tier 1 admin accounts can touch these
TIER 2: Workstations, user devices
        └── Standard helpdesk accounts
```

**Rule:** Admin credentials for a lower tier must never be used on a higher tier.
A compromised helpdesk account should not be able to reach a domain controller.

---

## Summary

You have learned:

* How to audit sudo and local admin access
* How to create service accounts with minimal privileges
* How to configure SSH key-based authentication
* How to apply UAC correctly on Windows
* The tiered admin model for enterprise environments

Least privilege is not a one-time fix — it requires regular audits as systems, roles, and responsibilities change.
