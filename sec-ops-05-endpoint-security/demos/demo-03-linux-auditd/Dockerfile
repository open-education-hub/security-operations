FROM python:3.11-slim
WORKDIR /app
COPY analyze_audit.py audit.log.sample audit.rules ./
CMD ["python3", "analyze_audit.py", "--file", "audit.log.sample", "--detect"]
