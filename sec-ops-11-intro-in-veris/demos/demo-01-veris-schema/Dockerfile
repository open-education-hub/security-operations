FROM python:3.11-slim

RUN pip install --no-cache-dir jsonschema

WORKDIR /app
COPY scripts/ /scripts/
COPY samples/ /data/samples/

CMD ["python", "-i", "/scripts/explore.py"]
