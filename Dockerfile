FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

WORKDIR /app

RUN groupadd --gid 1000 lab \
    && useradd --uid 1000 --gid lab --create-home --home-dir /home/lab \
       --shell /usr/sbin/nologin lab

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY tests /app/tests
COPY evaluation /app/evaluation
COPY docker /app/docker
COPY figures /app/figures
COPY docs /app/docs
COPY kernel-lab /app/kernel-lab

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]" \
    && chmod 0755 /app/docker/reproduce.sh \
    && chown -R lab:lab /app

USER lab

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib \
    XDG_CACHE_HOME=/tmp \
    EVADEAGENT_REPEATS=200 \
    EVADEAGENT_SEED=20260911

WORKDIR /app
