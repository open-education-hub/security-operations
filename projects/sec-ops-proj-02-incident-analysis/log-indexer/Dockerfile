FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    elasticsearch==8.13.0 \
    python-dateutil==2.9.0

COPY index_logs.py .

CMD ["python", "index_logs.py"]
