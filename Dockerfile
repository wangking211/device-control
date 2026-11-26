FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEVICE_CONTROL_ENV=production \
    DEVICE_CONTROL_DB=/data/device-control.sqlite3

RUN groupadd --gid 10001 devicecontrol \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin devicecontrol \
    && mkdir -p /data /srv/device-control \
    && chown -R 10001:10001 /data /srv/device-control

WORKDIR /srv/device-control
COPY pyproject.toml ./
COPY src ./src
COPY contracts ./contracts
RUN pip install --no-cache-dir .

USER 10001:10001
EXPOSE 8085
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8085/health/live', timeout=3)"

CMD ["uvicorn", "device_control.app:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8085"]
