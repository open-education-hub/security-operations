FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir rich
COPY edr_analyzer.py sample_events.jsonl ./
CMD ["python3", "edr_analyzer.py", "--mode", "timeline"]
