"""MindOS-side provider for Device Control.

This is the consumer boundary: MindOS keeps Task/TaskRun, maps its legacy
``DeviceCommandIntent`` into a Device Control command, and treats Device
Control status as authoritative. It never calls ADB or the gateway.

Retry policy: transport/5xx failures may be retried with the same idempotency
key. ``uncertain`` outcomes and non-idempotent 4xx responses are never retried.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

LEGACY_STATUS_MAP = {
    "created": "queued",
    "validated": "queued",
    "authorized": "queued",
    "queued": "queued",
    "dispatched": "running",
    "received": "running",
    "accepted": "running",
    "executing": "running",
    "verifying": "running",
    "succeeded": "succeeded",
    "rejected": "rejected",
    "failed": "failed",
    "timed_out": "failed",
    "uncertain": "uncertain",
    "cancelled": "cancelled",
    "expired": "cancelled",
}


class ProviderError(RuntimeError):
    def __init__(self, code: str, status: int = 0, detail: Any = None) -> None:
        super().__init__(f"{status} {code}")
        self.code = code
        self.status = status
        self.detail = detail


class Transport(Protocol):
    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        ...


@dataclass
class UrllibTransport:
    timeout_seconds: float = 15.0

    def request(self, method: str, url: str, body: dict[str, Any] | None,
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read() or b"{}")
            return exc.code, payload
        except urllib.error.URLError as exc:
            raise ProviderError("transport_unavailable", detail=str(exc.reason)) from exc


@dataclass
class MindOSDeviceControlProvider:
    base_url: str
    tenant: str
    subject: str
    token_provider: Callable[[], str]
    endpoint_for_device: Callable[[str], str]
    transport: Transport | None = None
    max_transport_retries: int = 2

    def __post_init__(self) -> None:
        object.__setattr__(self, "transport", self.transport or UrllibTransport())

    # -- mapping --------------------------------------------------------

    def build_command(self, intent: dict[str, Any], *, lease_id: str,
                      approval_id: str | None = None, approval_nonce: str | None = None,
                      state_hash: str | None = None, state_version: str | None = None,
                      task_ref: str | None = None, run_ref: str | None = None) -> dict[str, Any]:
        self._validate_intent(intent)
        timeout = float(intent.get("timeout_seconds") or 30.0)
        if timeout <= 0 or timeout > 3600:
            raise ProviderError("invalid_timeout")
        endpoint_id = self.endpoint_for_device(str(intent["device_id"]))
        return {
            "endpoint_id": endpoint_id,
            "capability_id": str(intent["capability"]),
            "capability_version": str(intent.get("capability_version") or "1.0.0"),
            "input": dict(intent.get("parameters") or {}),
            "intent": str(intent.get("intent") or intent.get("operation") or "Device action"),
            "deadline": (datetime.now(timezone.utc) + timedelta(seconds=timeout)).isoformat(),
            "idempotency_key": str(intent.get("idempotency_key") or intent["command_id"]),
            "lease_id": lease_id,
            "approval_id": approval_id or intent.get("approval_ref"),
            "approval_nonce": approval_nonce,
            "state_hash": state_hash,
            "state_version": state_version,
            "task_ref": task_ref,
            "run_ref": run_ref,
            "correlation_id": str(intent["command_id"]),
        }

    def submit(self, intent: dict[str, Any], *, lease_id: str,
               approval_id: str | None = None, approval_nonce: str | None = None,
               state_hash: str | None = None, state_version: str | None = None,
               task_ref: str | None = None, run_ref: str | None = None) -> dict[str, Any]:
        body = self.build_command(
            intent, lease_id=lease_id, approval_id=approval_id,
            approval_nonce=approval_nonce, state_hash=state_hash,
            state_version=state_version, task_ref=task_ref, run_ref=run_ref,
        )
        response = self._request("POST", "/v1/commands", body, retry=True)
        return {
            "provider_command_id": response["command_id"],
            "status": LEGACY_STATUS_MAP.get(response["status"], "unknown"),
            "raw_status": response["status"],
            "correlation_id": response.get("correlation_id"),
            "deduplicated": bool(response.get("deduplicated")),
        }

    def get(self, command_id: str) -> dict[str, Any]:
        response = self._request("GET", f"/v1/commands/{command_id}", None, retry=True)
        return {
            "provider_command_id": command_id,
            "status": LEGACY_STATUS_MAP.get(response["status"], "unknown"),
            "raw_status": response["status"],
            "verification": response.get("verification"),
            "evidence_refs": response.get("evidence_refs", []),
        }

    def cancel(self, command_id: str, reason: str) -> dict[str, Any]:
        response = self._request("POST", f"/v1/commands/{command_id}/cancel",
                                 {"reason": reason}, retry=False)
        return {"provider_command_id": command_id,
                "status": LEGACY_STATUS_MAP.get(response["status"], "unknown"),
                "raw_status": response["status"]}

    def evidence(self, command_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/commands/{command_id}/evidence", None, retry=True)

    # -- plumbing -------------------------------------------------------

    def _validate_intent(self, intent: dict[str, Any]) -> None:
        if not intent.get("command_id") or not intent.get("capability"):
            raise ProviderError("invalid_intent")
        if str(intent.get("tenant") or "") != self.tenant:
            raise ProviderError("tenant_mismatch")
        requested_by = str(intent.get("requested_by") or self.subject)
        if requested_by != self.subject:
            raise ProviderError("actor_mismatch")
        if not intent.get("device_id"):
            raise ProviderError("device_id_required")

    def _request(self, method: str, path: str, body: dict[str, Any] | None,
                 *, retry: bool) -> dict[str, Any]:
        attempts = (self.max_transport_retries + 1) if retry else 1
        last: ProviderError | None = None
        for attempt in range(attempts):
            try:
                status, payload = (self.transport or UrllibTransport()).request(
                    method, f"{self.base_url.rstrip('/')}{path}", body,
                    {"Authorization": f"Bearer {self.token_provider()}"},
                )
            except ProviderError as exc:
                last = exc
                if attempt + 1 == attempts:
                    raise
                time.sleep(0.2 * (attempt + 1))
                continue
            if status < 400:
                return payload
            code = str(payload.get("code") or "http_error")
            if status >= 500 and retry and attempt + 1 < attempts:
                last = ProviderError(code, status, payload)
                time.sleep(0.2 * (attempt + 1))
                continue
            raise ProviderError(code, status, payload)
        raise last or ProviderError("transport_unavailable")
