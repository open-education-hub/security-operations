FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir awscli boto3

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh 2>/dev/null || true

WORKDIR /workspace
