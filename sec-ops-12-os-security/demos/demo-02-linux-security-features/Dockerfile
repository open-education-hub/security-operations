FROM ubuntu:22.04

LABEL description="Linux Security Features Demo - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    auditd \
    audispd-plugins \
    sudo \
    openssh-server \
    openssh-client \
    libpam-runtime \
    libpam-modules \
    iptables \
    apparmor \
    apparmor-utils \
    libcap2-bin \
    python3 \
    curl \
    wget \
    net-tools \
    iproute2 \
    procps \
    less \
    && rm -rf /var/lib/apt/lists/*

# Create demo users
RUN useradd -m -s /bin/bash alice && echo "alice:password123" | chpasswd
RUN useradd -m -s /bin/bash bob && echo "bob:password456" | chpasswd
RUN echo "alice ALL=(ALL) /usr/bin/systemctl, /usr/sbin/service" >> /etc/sudoers
RUN echo "bob ALL=(ALL) NOPASSWD: /usr/bin/apt-get update" >> /etc/sudoers

# Configure SSH
RUN mkdir /run/sshd && ssh-keygen -A

# Copy scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh 2>/dev/null || true

WORKDIR /

CMD ["/bin/bash"]
