"""Runtime configuration, resolved from the environment on every call.

The service has three profiles:

* ``local``   - developer loop. The bootstrap admin token is allowed for
  provisioning only. HMAC identity is optional.
* ``test``    - same as local, used by the test suite.
* ``production`` - platform-issued identities are mandatory. The bootstrap
  token is never accepted, even if it is configured.

Resolving settings on every call (instead of caching at import time) keeps
tests and short-lived CLI processes honest and makes a missing secret a
request-time, fail-closed condition rather than an import-time surprise.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROFILES = {"local", "test", "production"}
PRODUCTION = "production"
DEFAULT_DB = "./var/device-control.sqlite3"


def profile() -> str:
    value = (os.environ.get("DEVICE_CONTROL_ENV") or "local").strip().lower()
    return value if value in PROFILES else "local"


def is_production() -> bool:
    return profile() == PRODUCTION


def bootstrap_token() -> str:
    """Bootstrap token used for local provisioning only."""

    return os.environ.get("DEVICE_CONTROL_ADMIN_TOKEN", "")


def bootstrap_allowed() -> bool:
    return not is_production() and len(bootstrap_token()) >= 16


def identity_secret() -> str:
    return os.environ.get("MINDOS_IDENTITY_HMAC_KEY", "")


def identity_issuer() -> str | None:
    value = os.environ.get("MINDOS_IDENTITY_ISSUER", "").strip()
    return value or None


def identity_audience() -> str | None:
    value = os.environ.get("DEVICE_CONTROL_IDENTITY_AUDIENCE", "").strip()
    return value or None


def manifest_hmac_key() -> str:
    return os.environ.get("DEVICE_CONTROL_MANIFEST_HMAC_KEY", "")


def manifest_public_key() -> str:
    value = os.environ.get("DEVICE_CONTROL_MANIFEST_PUBLIC_KEY", "")
    if value.startswith("-----BEGIN"):
        return value
    path = os.environ.get("DEVICE_CONTROL_MANIFEST_PUBLIC_KEY_PATH", "")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return ""
    return ""


def manifest_require_signature() -> bool:
    raw = (os.environ.get("DEVICE_CONTROL_MANIFEST_REQUIRE_SIGNATURE") or "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes"}
    return is_production()


def manifest_allowed_key_ids() -> set[str]:
    raw = os.environ.get("DEVICE_CONTROL_MANIFEST_KEY_IDS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def manifest_allow_hmac() -> bool:
    raw = (os.environ.get("DEVICE_CONTROL_MANIFEST_ALLOW_HMAC") or "").strip().lower()
    return raw in {"1", "true", "yes"}


def redaction_hmac_key() -> str:
    return os.environ.get("DEVICE_CONTROL_REDACTION_HMAC_KEY", "")


def require_https() -> bool:
    value = (os.environ.get("DEVICE_CONTROL_REQUIRE_HTTPS") or "").strip().lower()
    return value in {"1", "true", "yes"} or is_production()


def database_path() -> Path:
    configured = os.environ.get("DEVICE_CONTROL_DB")
    if configured:
        return Path(configured)
    if is_production():
        # The container image creates /data with the service UID. Falling back
        # to a relative path in production would silently write into the image
        # layer and lose data on redeploy.
        return Path("/data/device-control.sqlite3")
    return Path(DEFAULT_DB)


def approval_ttl_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_APPROVAL_TTL_SECONDS", 300, 30, 3600)


def enrollment_token_ttl_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_ENROLLMENT_TTL_SECONDS", 300, 30, 900)


def gateway_credential_ttl_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_GATEWAY_CREDENTIAL_TTL_SECONDS", 86400, 300, 604800)


def endpoint_credential_ttl_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_ENDPOINT_CREDENTIAL_TTL_SECONDS", 30 * 86400, 300, 365 * 86400)


def command_max_ttl_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_COMMAND_MAX_TTL_SECONDS", 3600, 5, 86400)


def max_request_bytes() -> int:
    return _bounded_int("DEVICE_CONTROL_MAX_REQUEST_BYTES", 262144, 4096, 4 * 1024 * 1024)


def rate_limit_per_minute() -> int:
    return _bounded_int("DEVICE_CONTROL_RATE_LIMIT_PER_MINUTE", 240, 10, 100000)


def stale_after_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_STALE_AFTER_SECONDS", 90, 15, 3600)


def writes_enabled() -> bool:
    """Physical writes are off by default in production.

    Enabling them requires an explicit deployment decision; a development
    fallback is never used. Local/test remain writable so the test suite and
    the pilot can exercise the command path.
    """

    raw = (os.environ.get("DEVICE_CONTROL_ENABLE_WRITES") or "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes"}
    return not is_production()


def production_configuration_errors() -> list[str]:
    """Missing production secrets are startup failures, not request surprises."""

    if not is_production():
        return []
    errors: list[str] = []
    if len(identity_secret()) < 32:
        errors.append("MINDOS_IDENTITY_HMAC_KEY")
    if len(redaction_hmac_key()) < 32:
        errors.append("DEVICE_CONTROL_REDACTION_HMAC_KEY")
    if manifest_allow_hmac():
        if len(manifest_hmac_key()) < 32:
            errors.append("DEVICE_CONTROL_MANIFEST_HMAC_KEY")
    elif not manifest_public_key():
        errors.append("DEVICE_CONTROL_MANIFEST_PUBLIC_KEY")
    if not manifest_allowed_key_ids():
        errors.append("DEVICE_CONTROL_MANIFEST_KEY_IDS")
    return errors


def validate_production() -> None:
    errors = production_configuration_errors()
    if errors:
        raise RuntimeError(
            "production configuration is incomplete: " + ", ".join(sorted(errors))
        )


def event_retention_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_EVENT_RETENTION_SECONDS", 7 * 86400, 3600, 90 * 86400)


def evidence_dir() -> Path:
    configured = os.environ.get("DEVICE_CONTROL_EVIDENCE_DIR")
    if configured:
        return Path(configured)
    return Path("/data/evidence") if is_production() else Path("./var/evidence")


def evidence_max_bytes() -> int:
    return _bounded_int("DEVICE_CONTROL_EVIDENCE_MAX_BYTES", 8 * 1024 * 1024, 1024, 32 * 1024 * 1024)


def evidence_default_retention_seconds() -> int:
    return _bounded_int("DEVICE_CONTROL_EVIDENCE_RETENTION_SECONDS", 7 * 86400, 3600, 90 * 86400)


@dataclass(frozen=True)
class SettingsSnapshot:
    """A read-only view used by health/readiness endpoints and docs."""

    profile: str
    production: bool
    bootstrap_enabled: bool
    identity_configured: bool
    database_path: str
    max_request_bytes: int


def snapshot() -> SettingsSnapshot:
    return SettingsSnapshot(
        profile=profile(),
        production=is_production(),
        bootstrap_enabled=bootstrap_allowed(),
        identity_configured=len(identity_secret()) >= 32,
        database_path=str(database_path()),
        max_request_bytes=max_request_bytes(),
    )


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))
