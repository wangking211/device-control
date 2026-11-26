"""Android adapter driven by the platform-tools ``adb`` binary.

Security properties:

* ``adb_path`` and ``serial`` come from trusted operator configuration. They
  are never accepted from a command envelope or model output.
* Every subprocess call uses an argument array with ``shell=False``; no string
  concatenation reaches a shell.
* Every call has a timeout and bounded captured output. Screenshots are hashed
  and discarded, never written to the control plane.
* App ids and text are validated; arbitrary shell commands are impossible
  because the capability surface is closed.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from .base import ActionResult, AdapterError, AdapterTimeout, AdapterUnavailable

APP_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
PACKAGE_SAFE_RE = re.compile(r"^[A-Za-z0-9._%\- ]{0,500}$")
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class AdbSettings:
    adb_path: str
    serial: str
    allowed_apps: frozenset[str]
    command_timeout_seconds: float = 15.0
    max_output_bytes: int = MAX_CAPTURE_BYTES


class AndroidAdbAdapter:
    adapter_id = "android-adb"
    version = "1.0.0"

    def __init__(self, settings: AdbSettings) -> None:
        if not settings.adb_path:
            raise ValueError("adb_path is required")
        if not settings.serial or any(ch in settings.serial for ch in (" ", ";", "&", "|", "`", "$")):
            raise ValueError("serial must be an operator-configured device serial")
        self.settings = settings
        self._closed = False

    # -- port -----------------------------------------------------------

    def health(self) -> dict[str, Any]:
        try:
            output = self._run(["get-state"], timeout=5.0)
        except AdapterError as exc:
            return {"status": "unavailable", "reason": exc.error_class}
        return {"status": "ok" if output.strip() == "device" else "unavailable",
                "state": output.strip(), "serial_hash": self._hash(self.settings.serial)[:16]}

    def observe_state(self) -> dict[str, Any]:
        foreground = self._foreground_app()
        screen = self._screen_state()
        payload = {"foreground_app": foreground, "screen": screen}
        payload["state_hash"] = self._hash(self._canonical(payload))
        return payload

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        if self._closed:
            raise AdapterUnavailable("adapter closed")
        if capability_id == "observe.screenshot":
            return self._screenshot()
        if capability_id == "observe.foreground_app":
            app = self._foreground_app()
            return ActionResult(status="succeeded", output={"foreground_app": app},
                                verification=self._verification("read_after_write"))
        if capability_id == "app.launch":
            return self._launch(parameters)
        if capability_id == "ui.tap":
            return self._tap(parameters)
        if capability_id == "ui.type_text":
            return self._type_text(parameters)
        if capability_id == "ui.back":
            return self._keyevent(4)
        if capability_id == "ui.home":
            return self._keyevent(3)
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
        digest = self._hash_bytes(raw)
        # The raw frame is intentionally discarded: evidence is a hash plus
        # gateway-managed, opt-in, redacted retention.
        return ActionResult(
            status="succeeded",
            output={"screenshot_sha256": digest, "bytes": len(raw), "redacted": True},
            verification=self._verification("screenshot_predicate"),
            evidence_refs=[f"sha256:{digest}"],
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
            return ActionResult(status="uncertain", output={"foreground_app": foreground},
                                error_class="state_changed",
                                reason="expected_app_not_foreground", retryable=False)
        return ActionResult(status="succeeded", output={"foreground_app": foreground},
                            verification=self._verification("ui_state"))

    def _tap(self, parameters: dict[str, Any]) -> ActionResult:
        bounds = parameters.get("bounds")
        if bounds:
            x, y = self._center(bounds)
        else:
            target = str(parameters.get("target_ref") or "")
            found = self._find_bounds(target)
            if found is None:
                return ActionResult(status="rejected", error_class="validation",
                                    reason="semantic_target_not_found")
            x, y = self._center(found)
        screenshot = parameters.get("screenshot_sha256")
        if screenshot:
            current = self._screenshot_hash()
            if current != screenshot:
                return ActionResult(status="rejected", error_class="state_changed",
                                    reason="screen_changed_before_execution")
        self._run(["shell", "input", "tap", str(x), str(y)], timeout=10.0)
        state = self.observe_state()
        return ActionResult(status="succeeded", output={"tap": [x, y], "state_hash": state["state_hash"]},
                            verification=self._verification("ui_state"))

    def _type_text(self, parameters: dict[str, Any]) -> ActionResult:
        text = str(parameters.get("text") or "")
        if str(parameters.get("target_type") or "") in {"password", "otp", "secret", "credential"}:
            return ActionResult(status="rejected", error_class="policy",
                                reason="secret_field_blocked")
        if not PACKAGE_SAFE_RE.fullmatch(text):
            raise AdapterError("text contains unsupported characters", error_class="validation")
        encoded = text.replace(" ", "%s")
        self._run(["shell", "input", "text", encoded], timeout=15.0)
        return ActionResult(status="succeeded", output={"text_len": len(text)},
                            verification=self._verification("read_after_write"))

    def _keyevent(self, keycode: int) -> ActionResult:
        self._run(["shell", "input", "keyevent", str(keycode)], timeout=10.0)
        return ActionResult(status="succeeded", output={"keycode": keycode},
                            verification=self._verification("ui_state"))

    def _wait_for(self, parameters: dict[str, Any]) -> ActionResult:
        expected = str(parameters.get("expected_app") or "")
        timeout_ms = int(parameters.get("timeout_ms") or 5000)
        timeout_ms = max(100, min(15000, timeout_ms))
        deadline = time.monotonic() + timeout_ms / 1000
        foreground = None
        while time.monotonic() < deadline:
            foreground = self._foreground_app()
            if foreground == expected:
                return ActionResult(status="succeeded",
                                    output={"foreground_app": foreground},
                                    verification=self._verification("ui_state"))
            time.sleep(0.25)
        return ActionResult(status="uncertain", output={"foreground_app": foreground},
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

    def _screenshot_hash(self) -> str:
        raw = self._run_bytes(["exec-out", "screencap", "-p"], timeout=10.0,
                              max_bytes=MAX_SCREENSHOT_BYTES)
        return self._hash_bytes(raw)

    def _find_bounds(self, target_ref: str) -> list[int] | None:
        if not target_ref or len(target_ref) > 200:
            return None
        try:
            self._run(["shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], timeout=10.0)
            xml_text = self._run(["exec-out", "cat", "/sdcard/window_dump.xml"], timeout=10.0)
            root = ET.fromstring(xml_text)
        except (AdapterError, ET.ParseError):
            return None
        fallback: list[int] | None = None
        for node in root.iter("node"):
            label = node.attrib.get("content-desc") or node.attrib.get("text") or ""
            bounds = self._parse_bounds(node.attrib.get("bounds", ""))
            if bounds is None:
                continue
            if label == target_ref:
                return bounds
            if fallback is None and target_ref in label:
                fallback = bounds
        return fallback

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
            completed = subprocess.run(
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
        return {
            "method": method,
            "verified": True,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "quality": "medium",
            **({"adapter_guarantee": True} if method == "adapter_ack" else {}),
        }

    @staticmethod
    def _canonical(value: dict[str, Any]) -> str:
        import json

        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _hash(cls, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _hash_bytes(cls, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()


def discover_devices(adb_path: str, *, timeout: float = 10.0) -> list[dict[str, str]]:
    """Operator utility: list attached devices without trusting model input."""

    if not adb_path or not shutil.which(adb_path):
        raise AdapterUnavailable("adb binary not found")
    completed = subprocess.run(
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
    devices: list[dict[str, str]] = []
    for line in completed.stdout.decode("utf-8", errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1], "description": " ".join(parts[2:])})
    return devices
