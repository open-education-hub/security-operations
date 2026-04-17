FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    auditd \
    grep \
    gawk \
    && rm -rf /var/lib/apt/lists/*

# Create demo log directory with pre-populated logs
RUN mkdir -p /var/log/demo

COPY logs/ /var/log/demo/

CMD ["/bin/bash"]
