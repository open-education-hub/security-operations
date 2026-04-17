FROM mcr.microsoft.com/powershell:latest

LABEL description="Windows Forensics Basics Demo - Session 12"

RUN apt-get update && apt-get install -y python3 python3-pip jq && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /scripts /data /reports

COPY scripts/ /scripts/
COPY data/ /data/

RUN chmod +x /scripts/*.ps1 2>/dev/null || true

WORKDIR /data

CMD ["pwsh", "-NoExit", "-Command", ". /scripts/load-forensics.ps1; Write-Host 'Windows Forensics Demo loaded. Type Show-ForensicsHelp for commands.'"]
