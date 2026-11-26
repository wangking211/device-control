"""Gateway → control-plane HTTP client.

The gateway only makes outbound requests; it never listens on a public port.
Control, telemetry and evidence are separate paths on the same credential so a
future transport (WebSocket/gRPC) can replace HTTP without changing the domain
objects.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol


class ControlPlaneError(RuntimeError):
    def __init__(self, status: int, code: str, detail: Any = None) -> None:
        super().__init__(f"control plane error {status}: {code}")
        self.status = status
        self.code = code
        self.detail = detail


class Transport(Protocol):
    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        ...


class UrllibTransport:
    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self.timeout = timeout_seconds

    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        raw = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=raw, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        if raw is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
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
                  agent_version: str, health: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("POST", f"/v1/gateways/{self.gateway_id}/heartbeat", {
            "status": status,
            "protocol_version": "v1",
            "agent_version": agent_version,
            "adapter_inventory": adapter_inventory,
            "health": health or {},
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
