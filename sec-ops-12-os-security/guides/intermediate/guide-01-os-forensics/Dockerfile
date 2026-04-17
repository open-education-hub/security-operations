FROM ubuntu:22.04

LABEL description="OS Forensics Investigation Guide - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    auditd \
    audispd-plugins \
    python3 \
    python3-pip \
    procps \
    iproute2 \
    net-tools \
    lsof \
    cron \
    less \
    wget \
    curl \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /scripts /evidence

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh /scripts/*.py 2>/dev/null || true

# Set up forensic evidence
RUN useradd -m -s /bin/bash alice && echo "alice:password" | chpasswd
RUN useradd -m -s /bin/bash backdoor_user && echo "backdoor_user:P@ssw0rd" | chpasswd

WORKDIR /

CMD ["/bin/bash"]
