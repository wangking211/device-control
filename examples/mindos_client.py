"""Dependency-free MindOS → Device Control client example.

MindOS stores the returned command id on its TaskRun as an external reference.
It never calls ADB or the gateway. Replace ``token_provider`` with the caller's
normal bearer-token source (user session or scoped service token).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


class DeviceControlError(RuntimeError):
    def __init__(self, status: int, code: str, detail: Any = None) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code
        self.detail = detail


@dataclass
class MindOSDeviceClient:
    base_url: str
    token_provider: Callable[[], str]

    def submit(self, *, endpoint_id: str, lease_id: str, capability_id: str,
               capability_version: str, input_payload: dict[str, Any], intent: str,
               deadline: str, idempotency_key: str, task_ref: str, run_ref: str,
               correlation_id: str, approval_id: str | None = None,
               state_hash: str | None = None) -> dict[str, Any]:
        return self._request("POST", "/v1/commands", {
            "endpoint_id": endpoint_id,
            "lease_id": lease_id,
            "capability_id": capability_id,
            "capability_version": capability_version,
            "input": input_payload,
            "intent": intent,
            "deadline": deadline,
            "idempotency_key": idempotency_key,
            "approval_id": approval_id,
            "state_hash": state_hash,
            "task_ref": task_ref,
            "run_ref": run_ref,
            "correlation_id": correlation_id,
        })

    def status(self, command_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/commands/{command_id}?include=transitions")

    def evidence(self, command_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/commands/{command_id}/evidence")

    def cancel(self, command_id: str, reason: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/commands/{command_id}/cancel",
                             {"reason": reason})

    def poll_until_terminal(self, command_id: str, *, timeout_seconds: float = 60,
                            interval_seconds: float = 1.0) -> dict[str, Any]:
        terminal = {"succeeded", "rejected", "failed", "timed_out", "cancelled",
                    "uncertain", "expired"}
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            command = self.status(command_id)
            if command["status"] in terminal:
                return command
            time.sleep(interval_seconds)
        raise TimeoutError(f"command {command_id} did not reach a terminal state")

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"{self.base_url.rstrip('/')}{path}",
                                         data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token_provider()}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read() or b"{}")
            raise DeviceControlError(exc.code, payload.get("code", "http_error"),
                                     payload.get("detail")) from exc


def example(token_provider: Callable[[], str]) -> None:
    client = MindOSDeviceClient("https://device-control.internal", token_provider)
    submitted = client.submit(
        endpoint_id="phone-1",
        lease_id="lease_...",
        capability_id="app.launch",
        capability_version="1.0.0",
        input_payload={"app_id": "com.example.notes"},
        intent="Open the notes app",
        deadline="2026-11-26T12:00:00+00:00",
        idempotency_key="task-1-run-1-step-1",
        task_ref="task-1",
        run_ref="run-1",
        correlation_id="corr-1",
    )
    command = client.poll_until_terminal(submitted["command_id"])
    print(command["status"], client.evidence(submitted["command_id"]))
