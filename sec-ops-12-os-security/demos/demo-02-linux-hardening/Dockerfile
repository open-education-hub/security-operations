FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    lynis \
    auditd \
    openssh-server \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
