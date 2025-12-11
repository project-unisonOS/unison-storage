FROM ghcr.io/project-unisonos/unison-common-wheel:latest AS common_wheel
FROM python:3.14-slim@sha256:fd2aff39e5a3ed23098108786a9966fb036fdeeedd487d5360e466bb2a84377b

ARG REPO_PATH="unison-storage"
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY ${REPO_PATH}/constraints.txt ./constraints.txt
COPY ${REPO_PATH}/requirements.txt ./requirements.txt
COPY --from=common_wheel /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir -c ./constraints.txt /tmp/wheels/unison_common-*.whl \
    && pip install --no-cache-dir -c ./constraints.txt -r requirements.txt

COPY ${REPO_PATH}/src ./src
COPY ${REPO_PATH}/tests ./tests

ENV PYTHONPATH=/app/src
EXPOSE 8082
CMD ["python", "src/server.py"]
