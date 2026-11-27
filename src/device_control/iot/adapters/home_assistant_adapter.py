"""Home Assistant adapter implementation of the Device Control SPI.

REST is used for discovery/state/service calls. WebSocket event subscription is
deliberately not implemented yet (TBD in DC-012); polling/read-back verification
is the pilot path. The adapter only translates; Device Control remains the
authority for risk, approval, leases and command state.

Security:
- token is resolved from a secret reference at connect time and never logged;
- allowlisted HTTP(S) base URL; external HTTP requires explicit local/dev policy;
- service success is not verification: state is re-read and compared.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ..home_assistant import HADevice, build_command, map_entity, verify_state
from ..spi import (
    AdapterError,
    AdapterHealth,
    CapabilityMapping,
    DiscoveredDevice,
    DiscoveryPage,
    ExecutionResult,
    Observation,
    PlatformConfig,
    TelemetryPoint,
)

MAX_STATES = 5000


class HTTPTransport(Protocol):
    def request(self, method: str, url: str, headers: dict[str, str],
                body: dict[str, Any] | None = None) -> tuple[int, Any]:
        ...


@dataclass
class UrllibHTTPTransport:
    timeout_seconds: float = 15.0

    def request(self, method: str, url: str, headers: dict[str, str],
                body: dict[str, Any] | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        context = _tls_context(url)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds,
                                        context=context) as response:  # nosec B310
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            return exc.code, _safe_body(exc)
        except urllib.error.URLError as exc:
            raise AdapterError("transport_unavailable", str(exc.reason),
                               retryable=True) from exc


def _safe_body(exc: urllib.error.HTTPError) -> Any:
    try:
        raw = exc.read()
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001 - never leak HTML/body
        return {}


def _tls_context(url: str) -> ssl.SSLContext | None:
    if not url.startswith("https://"):
        return None
    cafile = os.environ.get("DEVICE_ADAPTER_TLS_CA") or None
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class HomeAssistantAdapter:
    adapter_id = "home-assistant"
    api_version = "1.0"

    def __init__(self, transport: HTTPTransport | None = None) -> None:
        self.transport = transport or UrllibHTTPTransport()
        self._config: PlatformConfig | None = None
        self._token: str | None = None
        self._devices: dict[str, HADevice] = {}

    # -- lifecycle ------------------------------------------------------

    def validate_config(self, config: PlatformConfig) -> list[str]:
        errors: list[str] = []
        parsed = urllib.parse.urlparse(config.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            errors.append("endpoint must be an http(s) URL")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
            if (os.environ.get("DEVICE_ADAPTER_ALLOW_INSECURE_HTTP") or "").lower() not in {
                "1", "true", "yes",
            }:
                errors.append("HTTPS is required for non-loopback Home Assistant")
        if not config.secret_refs.get("token"):
            errors.append("token secret_ref is required")
        return errors

    def connect(self, config: PlatformConfig, resolve_secret: Callable[[str], str]) -> None:
        errors = self.validate_config(config)
        if errors:
            raise AdapterError("invalid_config", "; ".join(errors))
        ref = config.secret_refs["token"]
        token = resolve_secret(ref)
        if not token or len(token) < 20:
            raise AdapterError("invalid_secret", "Home Assistant token is missing")
        self._config = config
        self._token = token
        status, payload = self._request("GET", "/api/")
        if status != 200:
            self._token = None
            raise AdapterError("authentication_failed", f"HTTP {status}")

    def disconnect(self) -> None:
        self._token = None
        self._config = None

    def health(self) -> AdapterHealth:
        if not self._token or not self._config:
            return AdapterHealth(status="unavailable", detail={"reason": "not_connected"})
        status, payload = self._request("GET", "/api/")
        if status == 200 and str(payload.get("message", "")).startswith("API running"):
            return AdapterHealth(status="ok", version=self._config.platform_version)
        return AdapterHealth(status="degraded", detail={"http_status": status})

    # -- discovery/observation -----------------------------------------

    def discover(self, cursor: str | None = None,
                 filters: dict[str, Any] | None = None) -> DiscoveryPage:
        status, payload = self._request("GET", "/api/states")
        if status != 200 or not isinstance(payload, list):
            raise AdapterError("discovery_failed", f"HTTP {status}", retryable=status >= 500)
        domains = set((filters or {}).get("domains") or [])
        offset = int(cursor or 0)
        items = [item for item in payload if isinstance(item, dict)]
        if domains:
            items = [item for item in items
                     if str(item.get("entity_id", "")).split(".", 1)[0] in domains]
        page = items[offset:offset + 200]
        devices: list[DiscoveredDevice] = []
        for item in page[:MAX_STATES]:
            device = map_entity(self._config.tenant_id if self._config else "", item,
                                area=item.get("attributes", {}).get("area_id"))
            self._devices[device.native_id] = device
            devices.append(DiscoveredDevice(
                native_id=device.native_id,
                native_type=device.device_type,
                display_name=device.display_name,
                capabilities=tuple(CapabilityMapping(**capability) for capability in device.capabilities),
                area=device.area,
                native_ref={"platform": "homeassistant"},
                trusted=False,
            ))
        next_cursor = str(offset + 200) if offset + 200 < len(items) else None
        return DiscoveryPage(devices=tuple(devices), cursor=next_cursor)

    def get_device(self, native_id: str) -> DiscoveredDevice | None:
        device = self._devices.get(native_id)
        if device is None:
            return None
        return DiscoveredDevice(
            native_id=device.native_id, native_type=device.device_type,
            display_name=device.display_name,
            capabilities=tuple(CapabilityMapping(**capability) for capability in device.capabilities),
            area=device.area, trusted=False,
        )

    def get_capabilities(self, native_id: str) -> list[CapabilityMapping]:
        device = self._devices.get(native_id)
        if device is None:
            return []
        return [CapabilityMapping(**capability) for capability in device.capabilities]

    def observe(self, native_id: str) -> Observation:
        status, payload = self._request("GET", f"/api/states/{urllib.parse.quote(native_id)}")
        if status == 404:
            raise AdapterError("not_found", native_id, native_id=native_id)
        if status != 200 or not isinstance(payload, dict):
            raise AdapterError("observe_failed", f"HTTP {status}", retryable=status >= 500)
        state = str(payload.get("state"))
        properties = {"state": state, **(payload.get("attributes") or {})}
        canonical = json.dumps(properties, sort_keys=True, separators=(",", ":"))
        return Observation(
            native_id=native_id,
            observed_at=str(payload.get("last_updated") or payload.get("last_changed") or ""),
            properties=properties,
            connectivity="online" if state not in {"unavailable", "unknown"} else "offline",
            quality="good" if state not in {"unavailable", "unknown"} else "bad",
            state_hash=hashlib.sha256(canonical.encode()).hexdigest(),
            state_version="v1:" + hashlib.sha256(canonical.encode()).hexdigest()[:16],
            native_ref={"entity_id": native_id},
        )

    # -- execution ------------------------------------------------------

    def execute(self, command: dict[str, Any]) -> ExecutionResult:
        native_id = str(command.get("native_id") or command.get("entity_id") or "")
        if not native_id:
            raise AdapterError("invalid_command", "native_id is required")
        before = self.observe(native_id)
        mapped = build_command(command, {"state": before.properties.get("state")})
        status, payload = self._request(
            "POST", mapped["endpoint"], body=mapped["payload"],
        )
        accepted = status in {200, 201}
        if not accepted:
            return ExecutionResult(
                native_id=native_id, accepted=False, executed=False, verified=False,
                status="rejected" if status in {400, 401, 403, 404} else "failed",
                error=f"http_{status}", native_response={"status": status},
            )
        after = self.observe(native_id)
        expected = command.get("expected_state")
        verified = verify_state(expected, after.properties.get("state"))
        return ExecutionResult(
            native_id=native_id,
            accepted=True,
            executed=True,
            verified=verified,
            status="succeeded" if verified else "executed_unverified",
            observed=after,
            error=None if verified else "state_not_verified",
            native_response={"status": status, "changed_states": len(payload) if isinstance(payload, list) else 0},
        )

    def subscribe(self, event_types: list[str], cursor: str | None = None
                  ) -> tuple[list[dict[str, Any]], str | None]:
        # WebSocket subscription is a DC-012 item; callers must poll/re-observe.
        return [], cursor

    def get_telemetry(self, native_id: str, cursor: str | None = None,
                      limit: int = 100) -> tuple[list[TelemetryPoint], str | None]:
        observation = self.observe(native_id)
        value = observation.properties.get("state")
        try:
            numeric = float(str(value))
        except (TypeError, ValueError):
            return [], None
        return [TelemetryPoint(
            native_id=native_id, metric=str(observation.properties.get("device_class") or native_id),
            value=numeric, unit=observation.properties.get("unit_of_measurement"),
            source_timestamp=observation.observed_at,
            ingest_timestamp=observation.observed_at, quality="good",
        )], None

    def reconcile(self, mapping_state: dict[str, Any]) -> dict[str, Any]:
        result = dict(mapping_state)
        result.setdefault("adapter_id", self.adapter_id)
        result["connected"] = bool(self._token)
        return result

    # -- plumbing -------------------------------------------------------

    def _request(self, method: str, path: str, *, body: dict[str, Any] | None = None
                 ) -> tuple[int, Any]:
        if not self._config or not self._token:
            raise AdapterError("not_connected")
        url = f"{self._config.endpoint.rstrip('/')}{path}"
        return self.transport.request(
            method, url,
            {"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            body,
        )
