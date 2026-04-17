FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY sysmon_simulator.sh parse_sysmon.py ./
RUN chmod +x sysmon_simulator.sh
CMD ["bash", "-c", "bash /app/sysmon_simulator.sh && python3 /app/parse_sysmon.py --file /var/log/sysmon_events.xml --detect-suspicious"]
