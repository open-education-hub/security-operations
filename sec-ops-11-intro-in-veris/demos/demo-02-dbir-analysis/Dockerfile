FROM jupyter/base-notebook:latest

USER root
RUN pip install --no-cache-dir pandas matplotlib seaborn jsonschema

USER jovyan
COPY data/ /home/jovyan/data/
COPY notebooks/ /home/jovyan/work/

EXPOSE 8888
