FROM python:3.11-slim
RUN pip install requests elasticsearch
WORKDIR /app
COPY load_scenario.py /app/load_scenario.py
COPY tools/ /tools/
CMD ["python3", "/app/load_scenario.py"]
