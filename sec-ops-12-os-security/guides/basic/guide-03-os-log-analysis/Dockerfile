FROM ubuntu:22.04

LABEL description="OS Log Analysis Guide - Session 12"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    auditd \
    python3 \
    python3-pip \
    less \
    iproute2 \
    procps \
    cron \
    systemd \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /scripts /var/log/samples

COPY scripts/ /scripts/
COPY samples/ /var/log/samples/

RUN chmod +x /scripts/*.py /scripts/*.sh 2>/dev/null || true

WORKDIR /

CMD ["/bin/bash"]
