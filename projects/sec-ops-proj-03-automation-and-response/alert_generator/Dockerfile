FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY generate.py /app/generate.py

ENV PYTHONUNBUFFERED=1

CMD ["python", "generate.py"]
