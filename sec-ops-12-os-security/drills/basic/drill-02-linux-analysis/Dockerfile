FROM ubuntu:22.04

LABEL description="Linux Analysis Drill - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    sudo openssh-server libcap2-bin python3 less procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create users with intentional security issues
RUN useradd -m -s /bin/bash alice && echo "alice:password" | chpasswd
RUN useradd -m -s /bin/bash bob && echo "bob:password123" | chpasswd
RUN useradd -m -s /bin/bash deploy && echo "deploy:deploy" | chpasswd

# Add backdoor UID 0 account (students should find this)
RUN useradd -o -u 0 -g 0 -m -s /bin/bash sysadmin && echo "sysadmin:admin123" | chpasswd

# Dangerous sudo configuration
RUN echo "alice ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "bob ALL=(root) NOPASSWD: /bin/bash" >> /etc/sudoers
RUN echo "deploy ALL=(ALL) /usr/bin/apt-get" >> /etc/sudoers

# Create a suspicious SUID binary
RUN cp /usr/bin/python3 /usr/local/bin/python3-helper && chmod u+s /usr/local/bin/python3-helper

# World-writable cron file (dangerous!)
RUN mkdir -p /etc/cron.d && echo "# backup job" > /etc/cron.d/backup && chmod 777 /etc/cron.d/backup

# World-writable /etc/passwd (very dangerous)
RUN chmod 666 /etc/passwd

# SSH configuration with dangerous defaults
RUN mkdir /run/sshd && ssh-keygen -A
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

# Backdoor SSH key
RUN mkdir -p /root/.ssh && echo "ssh-rsa AAAA...backdoor== attacker@malicious.com" > /root/.ssh/authorized_keys

CMD ["/bin/bash"]
