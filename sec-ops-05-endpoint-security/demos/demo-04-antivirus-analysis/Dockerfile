FROM clamav/clamav:latest

# Install yara for custom rule testing
RUN apt-get update && apt-get install -y --no-install-recommends yara && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY scan_targets/ /scan_targets/
COPY custom_rules.yara run_demo.sh ./
RUN chmod +x run_demo.sh

CMD ["bash", "/app/run_demo.sh"]
