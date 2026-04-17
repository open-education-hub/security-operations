FROM python:3.11-slim

RUN pip install requests elasticsearch

WORKDIR /app

COPY entrypoint.py /app/entrypoint.py
COPY tools/ /tools/

RUN mkdir -p /var/log/simulated /evidence /data

CMD ["python3", "/app/entrypoint.py"]
