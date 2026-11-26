"""Android adapter driven by the platform-tools ``adb`` binary.

Security properties:

* ``adb_path`` and ``serial`` come from trusted operator configuration. They
  are never accepted from a command envelope or model output.
* Every subprocess call uses an argument array with ``shell=False``; no string
  concatenation reaches a shell.
* Every call has a timeout and bounded captured output. Screenshots are hashed,
  validated and discarded; raw frames never reach the control plane.
* UI state comes from UIAutomator node summaries: text/content-desc are omitted,
  only structural/security attributes and text length are exposed.
* Target sensitivity is derived from the node (password/editability/resource
  id), never from a caller-supplied label.
* App ids and text are validated; arbitrary shell commands are impossible.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from defusedxml import ElementTree as ET

from .base import ActionResult, AdapterError, AdapterTimeout, AdapterUnavailable

APP_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9._%\-@:/ ]{0,500}$")
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024
MAX_NODES = 200
SENSITIVE_MARKERS = ("password", "otp", "pin", "card", "cvv", "credential", "secret")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class AdbSettings:
    adb_path: str
    serial: str
    allowed_apps: frozenset[str]
    command_timeout_seconds: float = 15.0
    max_output_bytes: int = MAX_CAPTURE_BYTES


class AndroidAdbAdapter:
    adapter_id = "android-adb"
    version = "1.1.0"

    def __init__(self, settings: AdbSettings) -> None:
        if not settings.adb_path:
            raise ValueError("adb_path is required")
        if not settings.serial or any(ch in settings.serial for ch in (" ", ";", "&", "|", "`", "$")):
            raise ValueError("serial must be an operator-configured device serial")
        self.settings = settings
        self._closed = False
        self._fingerprint_cache: str | None = None

    # -- port -----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        try:
            output = self._run(["get-state"], timeout=5.0)
        except AdapterError as exc:
            return {"status": "unavailable", "reason": exc.error_class}
        state = output.strip()
        return {
            "status": "ok" if state == "device" else "unavailable",
            "state": state,
            "serial_hash": self._hash(self.settings.serial)[:16],
            "device_fingerprint": self.device_fingerprint(),
        }

    def device_fingerprint(self) -> str | None:
        if self._fingerprint_cache:
            return self._fingerprint_cache
        try:
            serial = self._run(["shell", "getprop", "ro.serialno"], timeout=5.0).strip()
            model = self._run(["shell", "getprop", "ro.product.model"], timeout=5.0).strip()
            manufacturer = self._run(
                ["shell", "getprop", "ro.product.manufacturer"], timeout=5.0
            ).strip()
            build = self._run(["shell", "getprop", "ro.build.fingerprint"], timeout=5.0).strip()
        except AdapterError:
            return None
        material = "|".join([serial, manufacturer, model, build])
        if not material.replace("|", "").strip():
            return None
        self._fingerprint_cache = self._hash(material)
        return self._fingerprint_cache

    def observe_state(self) -> dict[str, Any]:
        observed_at = datetime.now(timezone.utc).isoformat()
        foreground = self._foreground_app()
        screen = self._screen_state()
        nodes, quality, source = self._ui_nodes()
        payload = {
            "foreground_app": foreground,
            "screen": screen,
            "nodes": nodes,
        }
        state_hash = self._hash(self._canonical(payload))
        return {
            **payload,
            "source": source,
            "quality": quality,
            "observed_at": observed_at,
            "state_hash": state_hash,
            "state_version": f"v1:{state_hash[:16]}",
            "device_fingerprint": self.device_fingerprint(),
        }

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        if self._closed:
            raise AdapterUnavailable("adapter closed")
        if capability_id == "device.observe":
            return ActionResult(status="succeeded", executed=False,
                                output={"state": self.observe_state()},
                                verification=self._verification("ui_state"))
        if capability_id == "device.screenshot":
            return self._screenshot()
        if capability_id == "app.launch":
            return self._launch(parameters)
        if capability_id == "ui.tap":
            return self._tap(parameters)
        if capability_id == "ui.type_text":
            return self._type_text(parameters)
        if capability_id == "ui.swipe":
            return self._swipe(parameters)
        if capability_id == "ui.press_back":
            return self._keyevent(4, "press_back")
        if capability_id == "ui.press_home":
            return self._keyevent(3, "press_home")
        if capability_id == "ui.wait_for":
            return self._wait_for(parameters)
        return ActionResult(status="rejected", error_class="validation",
                            reason="unsupported_capability")

    def close(self) -> None:
        self._closed = True

    # -- capabilities ---------------------------------------------------

    def _screenshot(self) -> ActionResult:
        raw = self._run_bytes(
            ["exec-out", "screencap", "-p"], timeout=10.0, max_bytes=MAX_SCREENSHOT_BYTES
        )
        if len(raw) > MAX_SCREENSHOT_BYTES:
            raise AdapterError("screenshot exceeds size cap", error_class="validation")
        valid_png = raw.startswith(PNG_SIGNATURE) and len(raw) > 64
        digest = self._hash_bytes(raw)
        if not valid_png:
            return ActionResult(status="executed_unverified", executed=True,
                                output={"screenshot_sha256": digest, "bytes": len(raw)},
                                reason="invalid_screenshot_format")
        return ActionResult(
            status="succeeded",
            executed=True,
            output={"screenshot_sha256": digest, "bytes": len(raw),
                    "mime_type": "image/png", "redacted": True},
            verification=self._verification("artifact"),
            evidence_refs=[f"sha256:{digest}"],
            artifact_bytes=raw,
        )

    def _launch(self, parameters: dict[str, Any]) -> ActionResult:
        app_id = str(parameters.get("app_id") or "")
        if not APP_ID_RE.fullmatch(app_id):
            raise AdapterError("invalid app id", error_class="validation")
        if app_id not in self.settings.allowed_apps:
            return ActionResult(status="rejected", error_class="policy",
                                reason="app_not_allowlisted")
        self._run([
            "shell", "monkey", "-p", app_id,
            "-c", "android.intent.category.LAUNCHER", "1",
        ])
        deadline = time.monotonic() + 5.0
        foreground = None
        while time.monotonic() < deadline:
            foreground = self._foreground_app()
            if foreground == app_id:
                break
            time.sleep(0.25)
        if foreground != app_id:
            return ActionResult(status="executed_unverified", executed=True,
                                output={"foreground_app": foreground},
                                error_class="state_changed",
                                reason="expected_app_not_foreground", retryable=False)
        return ActionResult(status="succeeded", executed=True,
                            output={"foreground_app": foreground},
                            verification=self._verification("ui_state"))

    def _tap(self, parameters: dict[str, Any]) -> ActionResult:
        node = self._resolve_node(parameters)
        if node is None:
            return ActionResult(status="rejected", error_class="validation",
                                reason="target_unverified")
        before = self.observe_state()["state_hash"]
        x, y = self._center(node.get("bounds") or [])
        self._run(["shell", "input", "tap", str(x), str(y)], timeout=10.0)
        time.sleep(0.5)
        after = self.observe_state()
        changed = after["state_hash"] != before
        return ActionResult(
            status="succeeded" if changed else "executed_unverified",
            executed=True,
            output={"target_ref": node.get("resource_id"), "state_changed": changed},
            verification=self._verification("ui_change") if changed else None,
            reason=None if changed else "no_ui_change",
            post_state={"state_hash": after["state_hash"]},
        )

    def _type_text(self, parameters: dict[str, Any]) -> ActionResult:
        text = str(parameters.get("text") or "")
        node = self._resolve_node(parameters)
        if node is None:
            return ActionResult(status="rejected", error_class="validation",
                                reason="target_unverified")
        if node.get("sensitive"):
            return ActionResult(status="rejected", error_class="policy",
                                reason="sensitive_control_blocked")
        if not node.get("editable"):
            return ActionResult(status="rejected", error_class="validation",
                                reason="target_not_editable")
        resource_id = str(node.get("resource_id") or "").lower()
        if any(marker in resource_id for marker in SENSITIVE_MARKERS):
            return ActionResult(status="rejected", error_class="policy",
                                reason="sensitive_control_blocked")
        if not SAFE_TEXT_RE.fullmatch(text):
            raise AdapterError("text contains unsupported characters", error_class="validation")
        before_len = int(node.get("text_length") or 0)
        encoded = text.replace(" ", "%s")
        self._run(["shell", "input", "text", encoded], timeout=15.0)
        after_node = self._resolve_node(parameters)
        after_len = int((after_node or {}).get("text_length") or 0)
        changed = after_len != before_len
        return ActionResult(
            status="succeeded" if changed else "executed_unverified",
            executed=True,
            output={"target_ref": node.get("resource_id"), "text_length": after_len,
                    "value_changed": changed},
            verification=self._verification("field_state") if changed else None,
            reason=None if changed else "field_value_unchanged",
        )

    def _swipe(self, parameters: dict[str, Any]) -> ActionResult:
        start = self._point(parameters.get("start"))
        end = self._point(parameters.get("end"))
        duration = int(parameters.get("duration_ms") or 300)
        before = self.observe_state()["state_hash"]
        self._run([
            "shell", "input", "swipe", str(start[0]), str(start[1]),
            str(end[0]), str(end[1]), str(max(50, min(2000, duration))),
        ], timeout=15.0)
        time.sleep(0.5)
        after = self.observe_state()
        changed = after["state_hash"] != before
        return ActionResult(
            status="succeeded" if changed else "executed_unverified", executed=True,
            output={"state_changed": changed},
            verification=self._verification("ui_change") if changed else None,
            reason=None if changed else "no_ui_change",
        )

    def _keyevent(self, keycode: int, operation: str) -> ActionResult:
        before = self.observe_state()["state_hash"]
        self._run(["shell", "input", "keyevent", str(keycode)], timeout=10.0)
        time.sleep(0.4)
        after = self.observe_state()
        changed = after["state_hash"] != before
        return ActionResult(
            status="succeeded" if changed else "executed_unverified", executed=True,
            output={"operation": operation, "state_changed": changed},
            verification=self._verification("ui_change") if changed else None,
            reason=None if changed else "no_ui_change",
        )

    def _wait_for(self, parameters: dict[str, Any]) -> ActionResult:
        expected = str(parameters.get("expected_app") or "")
        timeout_ms = int(parameters.get("timeout_ms") or 5000)
        timeout_ms = max(100, min(15000, timeout_ms))
        deadline = time.monotonic() + timeout_ms / 1000
        foreground = None
        while time.monotonic() < deadline:
            foreground = self._foreground_app()
            if foreground == expected:
                return ActionResult(status="succeeded", executed=False,
                                    output={"foreground_app": foreground},
                                    verification=self._verification("ui_state"))
            time.sleep(0.25)
        return ActionResult(status="executed_unverified", executed=False,
                            output={"foreground_app": foreground},
                            error_class="timeout", reason="expected_state_not_reached")

    # -- device observation --------------------------------------------

    def _foreground_app(self) -> str | None:
        output = self._run(["shell", "dumpsys", "window"], timeout=10.0)
        for line in output.splitlines():
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                match = re.search(r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/", line)
                if match:
                    return match.group(1)
        return None

    def _screen_state(self) -> str:
        try:
            output = self._run(["shell", "dumpsys", "power"], timeout=5.0)
        except AdapterError:
            return "unknown"
        if "mWakefulness=Awake" in output:
            return "awake"
        if "mWakefulness=" in output:
            return "asleep"
        return "unknown"

    def _ui_nodes(self) -> tuple[list[dict[str, Any]], str, str]:
        try:
            self._run(["shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], timeout=10.0)
            xml_text = self._run(["exec-out", "cat", "/sdcard/window_dump.xml"], timeout=10.0)
            root = ET.fromstring(xml_text)
        except (AdapterError, ET.ParseError):
            return [], "low", "uiautomator-unavailable"
        nodes: list[dict[str, Any]] = []

        def walk(element: ET.Element, depth: int) -> None:
            if len(nodes) >= MAX_NODES:
                return
            for child in list(element):
                attributes = child.attrib
                text = attributes.get("text") or ""
                node = {
                    "resource_id": attributes.get("resource-id") or "",
                    "class_name": attributes.get("class") or "",
                    "bounds": self._parse_bounds(attributes.get("bounds", "")) or [],
                    "clickable": attributes.get("clickable") == "true",
                    "editable": "EditText" in (attributes.get("class") or ""),
                    "sensitive": attributes.get("password") == "true",
                    "input_type": self._input_type(attributes),
                    "depth": depth,
                    "visible": attributes.get("visible-to-user") == "true",
                    "text_length": len(text),
                }
                nodes.append(node)
                walk(child, depth + 1)

        walk(root, 0)
        quality = "high" if nodes else "low"
        return nodes, quality, "uiautomator"

    @staticmethod
    def _input_type(attributes: dict[str, str]) -> str:
        # UIAutomator does not expose inputType directly; the class/password
        # attributes are the only reliable structural signals in the dump.
        klass = attributes.get("class") or ""
        if attributes.get("password") == "true":
            return "textPassword"
        if "EditText" in klass:
            return "text"
        return ""

    def _resolve_node(self, parameters: dict[str, Any]) -> dict[str, Any] | None:
        nodes, _, _ = self._ui_nodes()
        target = str(parameters.get("target_ref") or "")
        bounds = parameters.get("bounds")
        for node in nodes:
            if bounds and node.get("bounds") == bounds:
                return node
            if target and node.get("resource_id") == target:
                return node
        return None

    @staticmethod
    def _parse_bounds(value: str) -> list[int] | None:
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", value)
        if not match:
            return None
        return [int(part) for part in match.groups()]

    @staticmethod
    def _center(bounds: Sequence[int]) -> tuple[int, int]:
        if len(bounds) != 4:
            raise AdapterError("bounds must have four integers", error_class="validation")
        values = [int(item) for item in bounds]
        if any(item < 0 or item > 10000 for item in values):
            raise AdapterError("bounds out of range", error_class="validation")
        x1, y1, x2, y2 = values
        if x2 <= x1 or y2 <= y1:
            raise AdapterError("bounds are empty", error_class="validation")
        return (x1 + x2) // 2, (y1 + y2) // 2

    @staticmethod
    def _point(value: Any) -> tuple[int, int]:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise AdapterError("swipe point must be [x, y]", error_class="validation")
        x, y = int(value[0]), int(value[1])
        if x < 0 or y < 0 or x > 10000 or y > 10000:
            raise AdapterError("swipe point out of range", error_class="validation")
        return x, y

    # -- subprocess -----------------------------------------------------

    def _command(self, args: Sequence[str]) -> list[str]:
        return [self.settings.adb_path, "-s", self.settings.serial, *args]

    def _run(self, args: Sequence[str], timeout: float | None = None) -> str:
        raw = self._run_bytes(args, timeout=timeout, max_bytes=self.settings.max_output_bytes)
        return raw.decode("utf-8", errors="replace")

    def _run_bytes(self, args: Sequence[str], *, timeout: float | None = None,
                   max_bytes: int | None = None) -> bytes:
        effective_timeout = min(
            float(timeout or self.settings.command_timeout_seconds),
            float(self.settings.command_timeout_seconds),
        )
        command = self._command(args)
        try:
            completed = subprocess.run(  # nosec B603
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=effective_timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterTimeout(f"adb timed out after {effective_timeout}s") from exc
        except FileNotFoundError as exc:
            raise AdapterUnavailable("adb binary not found") from exc
        limit = max_bytes or self.settings.max_output_bytes
        if len(completed.stdout) > limit or len(completed.stderr) > limit:
            raise AdapterError("adb output exceeded cap", error_class="validation")
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise AdapterError(f"adb failed: {message}", error_class="adapter",
                               uncertain=False, retryable=True)
        return completed.stdout

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _verification(method: str) -> dict[str, Any]:
        mapped = {"ui_change": "ui_state", "field_state": "read_after_write",
                  "artifact": "screenshot_predicate"}.get(method, method)
        return {
            "method": mapped,
            "verified": True,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "quality": "medium",
            **({"adapter_guarantee": True} if method == "adapter_ack" else {}),
        }

    @staticmethod
    def _canonical(value: dict[str, Any]) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _hash(cls, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _hash_bytes(cls, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()


def discover_devices(adb_path: str, *, timeout: float = 10.0) -> list[dict[str, Any]]:
    """Operator utility: list attached devices without trusting model input."""

    if not adb_path or not shutil.which(adb_path):
        raise AdapterUnavailable("adb binary not found")
    completed = subprocess.run(  # nosec B603
        [adb_path, "devices", "-l"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise AdapterError("adb devices failed", error_class="adapter")
    devices: list[dict[str, Any]] = []
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            state = parts[1]
            devices.append({"serial": parts[0], "state": state,
                            "authorized": state == "device",
                            "description": " ".join(parts[2:])})
    return devices
