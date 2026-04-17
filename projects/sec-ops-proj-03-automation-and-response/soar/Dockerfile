FROM python:3.11-slim

WORKDIR /app

COPY soar/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the soar package into the container.
# The docker-compose volume mount will overlay this at runtime,
# so local edits are reflected immediately without rebuilding.
COPY soar/ /app/soar/

# Ensure /data and /reports directories exist (volumes will be mounted here)
RUN mkdir -p /data /reports /app/soar/notifications

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "soar/app.py"]
