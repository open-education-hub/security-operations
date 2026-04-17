FROM python:3.11-slim

LABEL maintainer="SOC Lab Project 01"
LABEL description="Log generator for SecureMed SOC simulation"

# Install dependencies
RUN pip install --no-cache-dir requests==2.31.0

WORKDIR /app

COPY generate_events.py .

# DEMO_MODE=fast  → events compressed to ~2 minutes (default for quick demos)
# DEMO_MODE=normal → events spread over 30 minutes (realistic simulation)
ENV DEMO_MODE=fast
ENV ELASTICSEARCH_URL=http://elasticsearch:9200
ENV PATIENT_PORTAL_URL=http://patient-portal:80

CMD ["python", "-u", "generate_events.py"]
