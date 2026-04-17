FROM ubuntu:22.04

LABEL description="Linux Security Hardening Guide - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    lynis \
    auditd \
    libpam-pwquality \
    openssh-server \
    iproute2 \
    procps \
    sysstat \
    less \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash alice && echo "alice:weak" | chpasswd
RUN useradd -m -s /bin/bash bob && echo "bob:password" | chpasswd

# Intentionally insecure defaults for students to fix
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN mkdir -p /run/sshd && ssh-keygen -A

WORKDIR /

CMD ["/bin/bash"]
