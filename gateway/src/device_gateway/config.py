"""Gateway runtime configuration from environment / operator CLI.

ADB path, serial and app allowlist are operator configuration. Nothing in a
command envelope can change them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class GatewaySettings:
    control_url: str
    gateway_id: str
    credential: str
    db_path: str
    adapter: str
    adb_path: str
    serial: str
    allowed_apps: frozenset[str]
    queue_capacity: int
    heartbeat_interval_seconds: float
    poll_interval_seconds: float
    batch_size: int


def from_env(env: dict[str, str] | None = None) -> GatewaySettings:
    values = os.environ if env is None else env
    adapter = (values.get("DEVICE_GATEWAY_ADAPTER") or "null").strip().lower()
    allowed = frozenset(
        item.strip() for item in (values.get("DEVICE_GATEWAY_ALLOWED_APPS") or "").split(",")
        if item.strip()
    )
    settings = GatewaySettings(
        control_url=(values.get("DEVICE_CONTROL_URL") or "").strip(),
        gateway_id=(values.get("DEVICE_GATEWAY_ID") or "").strip(),
        credential=(values.get("DEVICE_GATEWAY_CREDENTIAL") or "").strip(),
        db_path=(values.get("DEVICE_GATEWAY_DB") or "./var/gateway-ledger.sqlite3").strip(),
        adapter=adapter,
        adb_path=(values.get("DEVICE_GATEWAY_ADB_PATH") or "adb").strip(),
        serial=(values.get("DEVICE_GATEWAY_SERIAL") or "").strip(),
        allowed_apps=allowed,
        queue_capacity=int(values.get("DEVICE_GATEWAY_QUEUE_SIZE") or 32),
        heartbeat_interval_seconds=float(values.get("DEVICE_GATEWAY_HEARTBEAT_SECONDS") or 30),
        poll_interval_seconds=float(values.get("DEVICE_GATEWAY_POLL_SECONDS") or 2),
        batch_size=int(values.get("DEVICE_GATEWAY_BATCH_SIZE") or 5),
    )
    _validate(settings)
    return settings


def _validate(settings: GatewaySettings) -> None:
    if not settings.control_url.startswith(("http://", "https://")):
        raise ValueError("DEVICE_CONTROL_URL must be an http(s) URL")
    if not settings.gateway_id:
        raise ValueError("DEVICE_GATEWAY_ID is required")
    if len(settings.credential) < 32:
        raise ValueError("DEVICE_GATEWAY_CREDENTIAL is required and must be high entropy")
    if settings.adapter not in {"fake", "android", "null"}:
        raise ValueError("DEVICE_GATEWAY_ADAPTER must be fake, android or null")
    if settings.adapter == "android":
        if not settings.adb_path:
            raise ValueError("DEVICE_GATEWAY_ADB_PATH is required for the android adapter")
        if not settings.serial:
            raise ValueError("DEVICE_GATEWAY_SERIAL is required for the android adapter")
        if not settings.allowed_apps:
            raise ValueError("DEVICE_GATEWAY_ALLOWED_APPS is required for the android adapter")
    if settings.queue_capacity < 1:
        raise ValueError("DEVICE_GATEWAY_QUEUE_SIZE must be positive")
