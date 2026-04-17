FROM python:3.11-slim

RUN pip install --no-cache-dir flask

COPY app/ /app/
WORKDIR /app

CMD ["python3", "app.py"]
