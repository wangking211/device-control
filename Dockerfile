FROM python:3.12-slim
WORKDIR /srv/device-control
COPY pyproject.toml ./
COPY src ./src
COPY contracts ./contracts
RUN pip install --no-cache-dir .
EXPOSE 8085
USER 10001:10001
CMD ["uvicorn", "device_control.app:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8085"]
