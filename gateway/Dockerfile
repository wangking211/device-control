FROM python:3.12-slim

# The adapter contract is tested against a stubbed adb binary in CI. The
# production image installs a real platform-tools package; pin/verify the
# vendor and version in your supply chain if the Debian package is not
# acceptable for your fleet.
RUN apt-get update \
    && apt-get install -y --no-install-recommends adb \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_GATEWAY_ADAPTER=android \
    DEVICE_GATEWAY_DB=/data/gateway-ledger.sqlite3

RUN groupadd --gid 10002 devicegw \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin devicegw \
    && mkdir -p /data \
    && chown -R 10002:10002 /data

WORKDIR /srv/device-gateway
COPY gateway/pyproject.toml ./
COPY gateway/src ./src
RUN pip install --no-cache-dir .

USER 10002:10002
VOLUME ["/data"]
# Outbound-only: no ports are published.
CMD ["python", "-m", "device_gateway.main"]
