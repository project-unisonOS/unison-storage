FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS common_wheel

ARG UNISON_COMMON_REF="8ef6b9971900ebfe105ca4e9cd5909f76428bb9d"
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /tmp/wheels \
       "git+https://github.com/project-unisonOS/unison-common.git@${UNISON_COMMON_REF}"

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG REPO_PATH="."
WORKDIR /app

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY ${REPO_PATH}/constraints.txt ./constraints.txt
COPY ${REPO_PATH}/requirements.txt ./requirements.txt
COPY --from=common_wheel /tmp/wheels /tmp/wheels
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 \
    && pip install --no-cache-dir -c ./constraints.txt /tmp/wheels/unison_common-*.whl \
    && pip install --no-cache-dir -c ./constraints.txt -r requirements.txt \
    && pip uninstall -y pip setuptools wheel \
    && rm -rf /tmp/wheels

COPY ${REPO_PATH}/src ./src
COPY ${REPO_PATH}/tests ./tests

ENV PYTHONPATH=/app/src
EXPOSE 8082
CMD ["python", "src/server.py"]
