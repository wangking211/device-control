"""Gateway runtime configuration from environment / operator CLI.

ADB path, serial and app allowlist are operator configuration. Nothing in a
command envelope can change them.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
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
    endpoint_id: str
    device_id: str
    device_fingerprint: str
    redaction_key: str
    redaction_key_id: str
    manifest_path: str
    manifest_hmac_key: str
    manifest_public_key: str
    manifest_require_signature: bool
    manifest_key_ids: frozenset[str]
    process_isolation: bool
    state_max_age_seconds: float


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
        endpoint_id=(values.get("DEVICE_GATEWAY_ENDPOINT_ID") or "").strip(),
        device_id=(values.get("DEVICE_GATEWAY_DEVICE_ID") or "").strip(),
        device_fingerprint=(values.get("DEVICE_GATEWAY_DEVICE_FINGERPRINT") or "").strip(),
        redaction_key=(values.get("DEVICE_GATEWAY_REDACTION_HMAC_KEY") or "").strip(),
        redaction_key_id=(values.get("DEVICE_GATEWAY_REDACTION_KEY_ID") or "").strip(),
        manifest_path=(values.get("DEVICE_GATEWAY_MANIFEST") or "").strip(),
        manifest_hmac_key=(values.get("DEVICE_GATEWAY_MANIFEST_HMAC_KEY") or "").strip(),
        manifest_public_key=_read_key(values.get("DEVICE_GATEWAY_MANIFEST_PUBLIC_KEY") or "",
                                      values.get("DEVICE_GATEWAY_MANIFEST_PUBLIC_KEY_PATH") or ""),
        manifest_require_signature=(values.get("DEVICE_GATEWAY_MANIFEST_REQUIRE_SIGNATURE") or "")
        .strip().lower() in {"1", "true", "yes"},
        manifest_key_ids=frozenset(
            item.strip() for item in (values.get("DEVICE_GATEWAY_MANIFEST_KEY_IDS") or "").split(",")
            if item.strip()
        ),
        process_isolation=(values.get("DEVICE_GATEWAY_PROCESS_ISOLATION") or "1").lower()
        in {"1", "true", "yes"},
        state_max_age_seconds=float(values.get("DEVICE_GATEWAY_STATE_MAX_AGE_SECONDS") or 15),
    )
    _validate(settings, values)
    return settings


def _read_key(inline: str, path: str) -> str:
    if inline.startswith("-----BEGIN"):
        return inline
    if path:
        try:
            from pathlib import Path

            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return ""
    return ""


def _validate(settings: GatewaySettings, values: Mapping[str, str]) -> None:
    if not settings.control_url.startswith(("http://", "https://")):
        raise ValueError("DEVICE_CONTROL_URL must be an http(s) URL")
    loopback = settings.control_url.startswith(("http://127.0.0.1", "http://localhost"))
    dev_profile = (values.get("DEVICE_GATEWAY_ENV") or "").strip().lower() in {"dev", "test"}
    allow_insecure = (values.get("DEVICE_GATEWAY_ALLOW_INSECURE_HTTP") or "").lower() in {
        "1", "true", "yes",
    }
    if settings.control_url.startswith("http://") and not loopback and not (
        dev_profile and allow_insecure
    ):
        raise ValueError("DEVICE_CONTROL_URL must use HTTPS outside loopback")
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
        if not settings.endpoint_id:
            raise ValueError("DEVICE_GATEWAY_ENDPOINT_ID is required for the android adapter")
        if not settings.device_fingerprint:
            raise ValueError("DEVICE_GATEWAY_DEVICE_FINGERPRINT is required for the android adapter")
        if len(settings.redaction_key.encode("utf-8")) < 32:
            raise ValueError("DEVICE_GATEWAY_REDACTION_HMAC_KEY is required for the android adapter")
    if settings.queue_capacity < 1:
        raise ValueError("DEVICE_GATEWAY_QUEUE_SIZE must be positive")
