"""Deterministic in-process adapter for tests, demos and emulator CI.

It models a tiny phone UI: a home screen and one allowlisted app. It can be
told to fail, time out, change state, or simulate user takeover so the worker
and control plane can be tested without hardware. It is never selected by
default in production.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .base import ActionResult, AdapterError, AdapterTimeout


class FakeAndroidAdapter:
    adapter_id = "fake-android"
    version = "1.0.0"

    def __init__(self, *, allowed_apps: set[str] | None = None) -> None:
        self.allowed_apps = allowed_apps or {"com.example.notes"}
        self.state: dict[str, Any] = {
            "screen": "home",
            "foreground_app": None,
            "text": "",
            "last_action": None,
        }
        self.fail_next: str | None = None
        self.timeout_next: bool = False
        self.change_state_after_preflight: bool = False
        self.takeover: bool = False
        self.disconnect_after_action: bool = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    # -- port -----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return {"status": "degraded" if self.takeover else "ok",
                "takeover": self.takeover, "allowed_apps": sorted(self.allowed_apps)}

    def observe_state(self) -> dict[str, Any]:
        payload = {
            "screen": self.state["screen"],
            "foreground_app": self.state["foreground_app"],
            "takeover": self.takeover,
        }
        payload["state_hash"] = self._hash(payload)
        return payload

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        self.calls.append((capability_id, dict(parameters)))
        if self.timeout_next:
            self.timeout_next = False
            raise AdapterTimeout()
        if self.fail_next:
            reason = self.fail_next
            self.fail_next = None
            raise AdapterError(reason, uncertain=True)
        if self.takeover:
            return ActionResult(status="failed", error_class="user_takeover",
                                reason="user_takeover", retryable=False)

        if capability_id == "observe.screenshot":
            raw = json.dumps(self.state, sort_keys=True).encode()
            return ActionResult(
                status="succeeded",
                output={"screenshot_sha256": hashlib.sha256(raw).hexdigest(),
                        "bytes": len(raw), "redacted": True},
                verification=self._verify("screenshot_predicate"),
            )
        if capability_id == "observe.foreground_app":
            return ActionResult(
                status="succeeded",
                output={"foreground_app": self.state["foreground_app"]},
                verification=self._verify("read_after_write"),
            )
        if capability_id == "app.launch":
            app_id = parameters["app_id"]
            if app_id not in self.allowed_apps:
                return ActionResult(status="rejected", error_class="policy",
                                    reason="app_not_allowlisted")
            self.state.update(screen="app", foreground_app=app_id,
                              last_action=capability_id)
            return ActionResult(status="succeeded",
                                output={"foreground_app": app_id},
                                verification=self._verify("ui_state"))
        if capability_id == "ui.tap":
            self.state["screen"] = f"app:{parameters['target_ref']}"
            self.state["last_action"] = capability_id
            return self._maybe_disconnect(
                ActionResult(status="succeeded", output={"screen": self.state["screen"]},
                             verification=self._verify("ui_state"))
            )
        if capability_id == "ui.type_text":
            if str(parameters.get("target_type") or "") in {"password", "otp", "secret"}:
                return ActionResult(status="rejected", error_class="policy",
                                    reason="secret_field_blocked")
            self.state["text"] = parameters["text"]
            self.state["last_action"] = capability_id
            return ActionResult(status="succeeded", output={"text_len": len(parameters["text"])},
                                verification=self._verify("read_after_write"))
        if capability_id == "ui.back":
            self.state.update(screen="home", foreground_app=None, last_action=capability_id)
            return ActionResult(status="succeeded", output={"screen": "home"},
                                verification=self._verify("ui_state"))
        if capability_id == "ui.home":
            self.state.update(screen="home", foreground_app=None, last_action=capability_id)
            return ActionResult(status="succeeded", output={"screen": "home"},
                                verification=self._verify("ui_state"))
        if capability_id == "ui.wait_for":
            expected = parameters["expected_app"]
            success = self.state["foreground_app"] == expected
            return ActionResult(status="succeeded" if success else "uncertain",
                                output={"foreground_app": self.state["foreground_app"]},
                                verification=self._verify("ui_state") if success else None,
                                reason=None if success else "expected_state_not_reached")
        return ActionResult(status="rejected", error_class="validation",
                            reason="unsupported_capability")

    def close(self) -> None:
        return None

    # -- test controls --------------------------------------------------

    def mutate_state(self) -> None:
        self.state["screen"] = "changed"
        self.state["foreground_app"] = "com.example.other"

    def _maybe_disconnect(self, result: ActionResult) -> ActionResult:
        if self.disconnect_after_action:
            self.disconnect_after_action = False
            return ActionResult(status="uncertain", output=result.output,
                                verification=None, error_class="transport",
                                reason="disconnected_after_action", retryable=False)
        return result

    @staticmethod
    def _hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @staticmethod
    def _verify(method: str) -> dict[str, Any]:
        from datetime import datetime, timezone

        return {
            "method": method,
            "verified": True,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "quality": "high",
            **({"adapter_guarantee": True} if method == "adapter_ack" else {}),
        }
