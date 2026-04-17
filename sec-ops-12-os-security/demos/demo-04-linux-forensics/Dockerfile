FROM ubuntu:22.04

LABEL description="Linux Forensics Basics Demo - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    auditd \
    audispd-plugins \
    procps \
    iproute2 \
    net-tools \
    wget \
    curl \
    python3 \
    sudo \
    cron \
    sysstat \
    less \
    util-linux \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create demo users
RUN useradd -m -s /bin/bash alice && echo "alice:password" | chpasswd
RUN useradd -m -s /bin/bash backdoor_user && echo "backdoor_user:P@ssw0rd2024!" | chpasswd

# Set up realistic audit environment
RUN echo "-w /etc/passwd  -p wa -k identity"  >> /etc/audit/rules.d/audit.rules && \
    echo "-w /etc/shadow  -p wa -k identity"  >> /etc/audit/rules.d/audit.rules && \
    echo "-w /etc/sudoers -p wa -k identity"  >> /etc/audit/rules.d/audit.rules && \
    echo "-w /etc/cron.d/ -p wa -k scheduled-jobs" >> /etc/audit/rules.d/audit.rules && \
    echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged-sudo" >> /etc/audit/rules.d/audit.rules

# Populate bash histories with forensic evidence
COPY scripts/setup-forensics.sh /tmp/setup-forensics.sh
RUN chmod +x /tmp/setup-forensics.sh && /tmp/setup-forensics.sh

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh 2>/dev/null || true

WORKDIR /

CMD ["/bin/bash"]
