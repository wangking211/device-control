"""Deterministic in-process adapter for tests, demos and emulator CI.

Models a tiny phone UI with a search field, a password field and a continue
button. It can be told to fail, hang, change state, or simulate user takeover
so the worker and control plane can be tested without hardware. It reports
Accessibility-like node summaries, never screen text.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

from .base import ActionResult, AdapterError, AdapterTimeout


class FakeAndroidAdapter:
    adapter_id = "fake-android"
    version = "1.1.0"

    def __init__(self, *, allowed_apps: set[str] | None = None,
                 device_fingerprint: str = "fake-device-fingerprint") -> None:
        self.allowed_apps = allowed_apps or {"com.example.notes"}
        self.device_fingerprint = device_fingerprint
        self.state: dict[str, Any] = {
            "screen": "home",
            "foreground_app": None,
            "text_len": 0,
            "last_action": None,
            "revision": 0,
        }
        self.nodes: dict[str, dict[str, Any]] = {
            "field-search": {
                "resource_id": "field-search", "class_name": "android.widget.EditText",
                "bounds": [20, 100, 700, 180], "clickable": True, "editable": True,
                "sensitive": False, "input_type": "text", "depth": 5, "visible": True,
                "text_length": 0,
            },
            "field-password": {
                "resource_id": "field-password", "class_name": "android.widget.EditText",
                "bounds": [20, 220, 700, 300], "clickable": True, "editable": True,
                "sensitive": True, "input_type": "textPassword", "depth": 5, "visible": True,
                "text_length": 0,
            },
            "button-continue": {
                "resource_id": "button-continue", "class_name": "android.widget.Button",
                "bounds": [20, 340, 700, 420], "clickable": True, "editable": False,
                "sensitive": False, "input_type": "", "depth": 5, "visible": True,
                "text_length": 0,
            },
        }
        self.fail_next: str | None = None
        self.timeout_next: bool = False
        self.hang: bool = False
        self.change_state_after_preflight: bool = False
        self.takeover: bool = False
        self.disconnect_after_action: bool = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    # -- port -----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return {
            "status": "degraded" if self.takeover else "ok",
            "takeover": self.takeover,
            "device_fingerprint": self.device_fingerprint,
            "allowed_apps": sorted(self.allowed_apps),
        }

    def device_fingerprint_value(self) -> str:
        return self.device_fingerprint

    def observe_state(self) -> dict[str, Any]:
        observed_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "foreground_app": self.state["foreground_app"],
            "screen": self.state["screen"],
            "revision": self.state["revision"],
            "nodes": [dict(self.nodes[key]) for key in sorted(self.nodes)],
        }
        state_hash = self._hash(payload)
        return {
            **payload,
            "source": "fake-uiautomator",
            "quality": "high",
            "observed_at": observed_at,
            "state_hash": state_hash,
            "state_version": f"v1:{state_hash[:16]}",
            "device_fingerprint": self.device_fingerprint,
        }

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        self.calls.append((capability_id, dict(parameters)))
        if self.hang:
            time.sleep(3600)
        if self.timeout_next:
            self.timeout_next = False
            raise AdapterTimeout()
        if self.fail_next:
            reason = self.fail_next
            self.fail_next = None
            raise AdapterError(reason, uncertain=True)
        if self.takeover:
            return ActionResult(status="failed", error_class="user_takeover",
                                reason="user_takeover", executed=False)

        if capability_id == "device.observe":
            state = self.observe_state()
            return ActionResult(status="succeeded", executed=False,
                                output={"state": state}, verification=self._verify("ui_state"))
        if capability_id == "device.screenshot":
            raw = json.dumps(self.state, sort_keys=True).encode()
            png = b"\x89PNG\r\n\x1a\n" + raw
            return ActionResult(
                status="succeeded", executed=True,
                output={"screenshot_sha256": hashlib.sha256(png).hexdigest(),
                        "bytes": len(png), "mime_type": "image/png", "redacted": True},
                verification=self._verify("artifact"),
                evidence_refs=[f"sha256:{hashlib.sha256(png).hexdigest()}"],
                artifact_bytes=png,
            )
        if capability_id == "app.launch":
            app_id = parameters["app_id"]
            if app_id not in self.allowed_apps:
                return ActionResult(status="rejected", error_class="policy",
                                    reason="app_not_allowlisted")
            self._mutate(foreground_app=app_id, screen="app")
            return ActionResult(status="succeeded", executed=True,
                                output={"foreground_app": app_id},
                                verification=self._verify("ui_state"))
        if capability_id == "ui.tap":
            node = self._node(parameters)
            if node is None:
                return ActionResult(status="rejected", error_class="validation",
                                    reason="target_unverified")
            before = self.observe_state()["state_hash"]
            self._mutate(screen=f"app:{node['resource_id']}")
            after_state = self.observe_state()
            verified = after_state["state_hash"] != before
            result = ActionResult(
                status="succeeded" if verified else "executed_unverified",
                executed=True,
                output={"target_ref": node["resource_id"], "state_changed": verified},
                verification=self._verify("ui_change") if verified else None,
                reason=None if verified else "no_ui_change",
                post_state={"state_hash": after_state["state_hash"]},
            )
            return self._maybe_disconnect(result)
        if capability_id == "ui.type_text":
            node = self._node(parameters)
            if node is None:
                return ActionResult(status="rejected", error_class="validation",
                                    reason="target_unverified")
            if node.get("sensitive") or "password" in str(node.get("input_type") or ""):
                return ActionResult(status="rejected", error_class="policy",
                                    reason="sensitive_control_blocked")
            if not node.get("editable"):
                return ActionResult(status="rejected", error_class="validation",
                                    reason="target_not_editable")
            before_len = int(node.get("text_length") or 0)
            node["text_length"] = len(str(parameters.get("text") or ""))
            self._mutate(text_len=node["text_length"])
            verified = node["text_length"] != before_len
            return ActionResult(
                status="succeeded" if verified else "executed_unverified",
                executed=True,
                output={"target_ref": node["resource_id"], "text_length": node["text_length"],
                        "value_changed": verified},
                verification=self._verify("field_state") if verified else None,
                reason=None if verified else "field_value_unchanged",
            )
        if capability_id == "ui.swipe":
            before = self.observe_state()["state_hash"]
            self._mutate(screen="swiped")
            after = self.observe_state()
            verified = after["state_hash"] != before
            return ActionResult(
                status="succeeded" if verified else "executed_unverified", executed=True,
                output={"state_changed": verified},
                verification=self._verify("ui_change") if verified else None,
            )
        if capability_id in {"ui.press_back", "ui.press_home"}:
            before = self.observe_state()["state_hash"]
            self._mutate(screen="home", foreground_app=None)
            after = self.observe_state()
            verified = after["state_hash"] != before
            return ActionResult(
                status="succeeded" if verified else "executed_unverified", executed=True,
                output={"screen": "home", "state_changed": verified},
                verification=self._verify("ui_change") if verified else None,
            )
        if capability_id == "ui.wait_for":
            expected = parameters["expected_app"]
            success = self.state["foreground_app"] == expected
            return ActionResult(status="succeeded" if success else "executed_unverified",
                                executed=True,
                                output={"foreground_app": self.state["foreground_app"]},
                                verification=self._verify("ui_state") if success else None,
                                reason=None if success else "expected_state_not_reached")
        return ActionResult(status="rejected", error_class="validation",
                            reason="unsupported_capability")

    def close(self) -> None:
        return None

    # -- test controls --------------------------------------------------

    def mutate_state(self) -> None:
        self._mutate(screen="changed", foreground_app="com.example.other")

    def _mutate(self, **changes: Any) -> None:
        self.state.update(changes)
        self.state["revision"] = int(self.state.get("revision") or 0) + 1

    def _node(self, parameters: dict[str, Any]) -> dict[str, Any] | None:
        target = str(parameters.get("target_ref") or "")
        bounds = parameters.get("bounds")
        for node in self.nodes.values():
            if bounds and node["bounds"] == bounds:
                return node
            if target and node["resource_id"] == target:
                return node
        return None

    def _maybe_disconnect(self, result: ActionResult) -> ActionResult:
        if self.disconnect_after_action:
            self.disconnect_after_action = False
            return ActionResult(status="executed_unverified", executed=True,
                                output=result.output, verification=None,
                                error_class="transport",
                                reason="disconnected_after_action", retryable=False)
        return result

    @staticmethod
    def _hash(payload: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @staticmethod
    def _verify(method: str) -> dict[str, Any]:
        mapped = {"ui_change": "ui_state", "field_state": "read_after_write",
                  "artifact": "screenshot_predicate"}.get(method, method)
        return {
            "method": mapped,
            "verified": True,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "quality": "high",
            **({"adapter_guarantee": True} if method == "adapter_ack" else {}),
        }
