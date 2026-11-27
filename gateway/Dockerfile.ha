FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/device-control/src:/srv/device-control/gateway/src

WORKDIR /srv/device-control
COPY pyproject.toml ./
COPY src ./src
COPY gateway/pyproject.toml ./gateway/pyproject.toml
COPY gateway/src ./gateway/src
COPY scripts ./scripts
RUN pip install --no-cache-dir . ./gateway

RUN groupadd --gid 10003 haworker \
    && useradd --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin haworker
USER 10003:10003

CMD ["python", "scripts/ha_adapter_worker.py"]
