FROM python:3.11-slim

RUN pip install mitreattack-python requests stix2

WORKDIR /app

COPY tools/ /tools/

RUN mkdir -p /output /data

CMD ["sleep", "infinity"]
