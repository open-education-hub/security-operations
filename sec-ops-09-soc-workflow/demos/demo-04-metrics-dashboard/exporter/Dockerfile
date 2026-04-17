FROM python:3.11-slim
RUN pip install prometheus_client
COPY exporter.py /exporter.py
CMD ["python", "/exporter.py"]
