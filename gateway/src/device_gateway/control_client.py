"""Gateway → control-plane HTTP client.

The gateway only makes outbound requests; it never listens on a public port.
Control, telemetry and evidence are separate paths on the same credential so a
future transport (WebSocket/gRPC) can replace HTTP without changing the domain
objects.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol


class ControlPlaneError(RuntimeError):
    def __init__(self, status: int, code: str, detail: Any = None) -> None:
        super().__init__(f"control plane error {status}: {code}")
        self.status = status
        self.code = code
        self.detail = detail


class Transport(Protocol):
    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str], raw: bytes | None = None) -> tuple[int, dict[str, Any]]:
        ...


class UrllibTransport:
    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self.timeout = timeout_seconds
        self._ssl_context = _tls_context()

    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str], raw: bytes | None = None) -> tuple[int, dict[str, Any]]:
        scheme = urllib.parse.urlparse(url).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ControlPlaneError(0, "unsupported_url_scheme")
        data = raw if raw is not None else (
            json.dumps(body).encode("utf-8") if body is not None else None
        )
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        if data is not None and raw is None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(  # nosec B310
                request, timeout=self.timeout, context=self._ssl_context
            ) as response:
                payload = response.read()
                return response.status, json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                detail = json.loads(payload) if payload else {}
            except json.JSONDecodeError:
                detail = {}
            raise ControlPlaneError(exc.code, str(detail.get("code") or "http_error"),
                                    detail) from exc
        except urllib.error.URLError as exc:
            raise ControlPlaneError(0, "transport_unavailable", str(exc.reason)) from exc


def _sha256(data: bytes) -> str:
    return sha256(data).hexdigest()


def _tls_context() -> ssl.SSLContext | None:
    cafile = os.environ.get("DEVICE_GATEWAY_TLS_CA") or None
    certfile = os.environ.get("DEVICE_GATEWAY_TLS_CERT") or None
    keyfile = os.environ.get("DEVICE_GATEWAY_TLS_KEY") or None
    if not (cafile or certfile):
        return None
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if certfile:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


@dataclass(frozen=True)
class ControlPlaneClient:
    base_url: str
    gateway_id: str
    credential: str
    transport: Transport | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "transport", self.transport or UrllibTransport())

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return f"ControlPlaneClient(base_url={self.base_url!r}, gateway_id={self.gateway_id!r})"

    # -- API ------------------------------------------------------------

    def heartbeat(self, *, status: str, adapter_inventory: list[dict[str, Any]],
                  agent_version: str, health: dict[str, Any] | None = None,
                  manifest_digest: str | None = None,
                  manifest_version: str | None = None,
                  endpoint_id: str | None = None,
                  device_id: str | None = None,
                  device_fingerprint: str | None = None,
                  queue_depth: int | None = None,
                  queue_age_seconds: float | None = None) -> dict[str, Any]:
        return self._request("POST", f"/v1/gateways/{self.gateway_id}/heartbeat", {
            "status": status,
            "protocol_version": "v1",
            "agent_version": agent_version,
            "adapter_inventory": adapter_inventory,
            "health": health or {},
            "manifest_digest": manifest_digest,
            "manifest_version": manifest_version,
            "endpoint_id": endpoint_id,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
            "queue_depth": queue_depth,
            "queue_age_seconds": queue_age_seconds,
        })

    def pull(self, limit: int = 10) -> list[dict[str, Any]]:
        payload = self._request(
            "GET", f"/v1/gateways/{self.gateway_id}/commands?limit={max(1, min(50, limit))}", None
        )
        return list(payload.get("items") or [])

    def progress(self, command_id: str, status: str) -> dict[str, Any]:
        return self._request(
            "POST", f"/v1/gateways/{self.gateway_id}/commands/{command_id}/progress",
            {"status": status},
        )

    def result(self, command_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST", f"/v1/gateways/{self.gateway_id}/commands/{command_id}/result", payload
        )

    def upload_evidence(self, command_id: str, data: bytes, *, evidence_type: str,
                        mime_type: str, redaction_status: str,
                        retention_seconds: int | None = None,
                        captured_at: str | None = None,
                        redaction_headers: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.credential}",
            "Content-Type": mime_type,
            "X-Evidence-Type": evidence_type,
            "X-Content-SHA256": _sha256(data),
            "X-Redaction-Status": redaction_status,
        }
        for name, value in (redaction_headers or {}).items():
            if value:
                headers[name] = value
        if retention_seconds:
            headers["X-Retention-Seconds"] = str(int(retention_seconds))
        if captured_at:
            headers["X-Captured-At"] = captured_at
        transport = self.transport or UrllibTransport()
        status, payload = transport.request(
            "POST",
            f"{self.base_url.rstrip('/')}/v1/gateways/{self.gateway_id}/commands/"
            f"{command_id}/evidence",
            None,
            headers,
            raw=data,
        )
        if status >= 400:
            raise ControlPlaneError(status, str(payload.get("code") or "http_error"), payload)
        return payload

    # -- plumbing -------------------------------------------------------

    def _request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        transport = self.transport or UrllibTransport()
        status, payload = transport.request(
            method,
            f"{self.base_url.rstrip('/')}{path}",
            body,
            {"Authorization": f"Bearer {self.credential}"},
        )
        if status >= 400:
            raise ControlPlaneError(status, str(payload.get("code") or "http_error"), payload)
        return payload
