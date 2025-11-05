FROM python:3.12-slim

WORKDIR /app

COPY unison-storage/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir redis python-jose[cryptography] bleach httpx

COPY unison-storage/src ./src
COPY unison-common/src/unison_common ./src/unison_common

ENV PYTHONPATH=/app/src

EXPOSE 8082
CMD ["python", "src/server.py"]
