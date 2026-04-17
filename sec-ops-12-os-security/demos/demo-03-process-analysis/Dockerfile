FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    python3 \
    procps \
    iproute2 \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Plant simulated malware artifacts
RUN mkdir -p /tmp/.hidden && \
    echo '#!/usr/bin/env python3\nimport time\nwhile True:\n    time.sleep(60)' > /tmp/.hidden/updater.py && \
    chmod +x /tmp/.hidden/updater.py

# Add suspicious cron entry
RUN echo "* * * * * root /tmp/.hidden/updater.py" > /etc/cron.d/systemupdate

# Start the "malware" process
CMD ["/tmp/.hidden/updater.py"]
