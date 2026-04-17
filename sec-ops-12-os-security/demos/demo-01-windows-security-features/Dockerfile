FROM mcr.microsoft.com/powershell:latest

LABEL description="Windows Security Features Demo - Session 12"

# Install Python for supplementary scripts
RUN apt-get update && apt-get install -y python3 python3-pip jq && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /scripts /data /reports

# Copy scripts and data
COPY scripts/ /scripts/
COPY data/ /data/

# Make scripts executable
RUN chmod +x /scripts/*.ps1 2>/dev/null || true

WORKDIR /data

CMD ["pwsh", "-NoExit", "-Command", ". /scripts/load-data.ps1; Write-Host 'Windows Security Demo loaded. Type Show-Help for available commands.'"]
