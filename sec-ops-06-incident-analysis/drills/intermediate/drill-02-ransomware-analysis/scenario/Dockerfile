FROM python:3.11-slim
RUN pip install --no-cache-dir requests
WORKDIR /app
COPY load_scenario.py .
CMD ["python3", "load_scenario.py"]
