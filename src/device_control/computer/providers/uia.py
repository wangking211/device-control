"""Windows UI Automation provider (native desktop).

The provider is optional: importing it never fails when the optional
``uiautomation`` package or an interactive desktop is unavailable. It never
performs coordinate-only clicks and never accepts shell commands.
"""

from __future__ import annotations

import ctypes
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..contracts import (
    ComputerAction,
    ComputerObservation,
    ComputerResult,
    redact_value,
)
from ..manifest import (
    READ_CAPABILITIES,
    WRITE_CAPABILITIES,
)
from ..session import detect_session
from .base import ProviderEvidence, ProviderExecution, ProviderHealth

ALLOWED_KEYS = {
    "ENTER", "ESC", "TAB", "SPACE", "BACKSPACE", "DELETE",
    "UP", "DOWN", "LEFT", "RIGHT", "HOME", "END", "PAGEUP", "PAGEDOWN",
    "CTRL+A", "CTRL+C", "CTRL+V", "CTRL+S", "ALT+TAB",
}


@dataclass
class UiaProvider:
    provider_id: str = "windows-uia"
    allowed_apps: dict[str, str] = field(default_factory=dict)
    allow_clipboard: bool = False
    max_tree_nodes: int = 200

    def _auto(self):
        import uiautomation as auto  # optional dependency
        return auto

    def health(self) -> ProviderHealth:
        session = detect_session()
        try:
            self._auto()
        except Exception:  # noqa: BLE001 - optional dependency
            return ProviderHealth("unavailable", self.provider_id, "0.1.0",
                                  "uiautomation is not installed")
        if not session.allows_ui():
            return ProviderHealth("degraded", self.provider_id, "0.1.0",
                                  f"session {session.state}")
        return ProviderHealth("ok", self.provider_id, "0.1.0",
                              capabilities=tuple(READ_CAPABILITIES | WRITE_CAPABILITIES))

    def observe(self, action: ComputerAction) -> ComputerObservation:
        session = detect_session()
        if not session.allows_ui():
            raise RuntimeError(f"session_{session.state}")
        auto = self._auto()
        foreground = auto.GetForegroundControl()
        active = self._control_summary(foreground) if foreground else None
        windows = []
        try:
            root = auto.GetRootControl()
            for child in root.GetChildren()[:50]:
                windows.append(self._control_summary(child))
        except Exception:  # noqa: BLE001 - best-effort enumeration
            windows = []
        tree = None
        if action.capability_id == "computer.uia.tree" or action.parameters.get("include_tree"):
            tree = self._tree(foreground, max_depth=int(action.parameters.get("max_depth") or 4))
        return ComputerObservation(
            session_state=session.state, active_window=active,
            windows=windows, uia_tree=tree,
        )

    def execute(self, action: ComputerAction) -> ProviderExecution:
        session = detect_session()
        if not session.allows_ui():
            return self._failed(action, "session_unavailable", f"session is {session.state}")
        capability = action.capability_id
        try:
            if capability == "computer.observe":
                observation = self.observe(action)
                return ProviderExecution(ComputerResult(
                    status="succeeded", provider_status="observed",
                    verification={"verified": True, "method": "uia_observation"},
                    output=redact_value(observation.to_dict()),
                ))
            if capability == "computer.window.list":
                observation = self.observe(action)
                return ProviderExecution(ComputerResult(
                    status="succeeded", provider_status="observed",
                    output={"windows": observation.windows},
                ))
            if capability == "computer.uia.tree":
                observation = self.observe(action)
                return ProviderExecution(ComputerResult(
                    status="succeeded", provider_status="observed",
                    output={"uia_tree": observation.uia_tree or {}},
                ))
            if capability == "computer.screenshot":
                return self._screenshot(action)
            if capability == "computer.app.launch":
                return self._launch(action)
            if capability == "computer.uia.click":
                return self._click(action)
            if capability == "computer.uia.type_text":
                return self._type_text(action)
            if capability == "computer.key.press":
                return self._key(action)
            if capability == "computer.scroll":
                return self._scroll(action)
            if capability in {"computer.clipboard.read", "computer.clipboard.write"}:
                return self._clipboard(action)
            return self._failed(action, "unsupported_capability", capability)
        except RuntimeError as exc:
            code = str(exc)
            if code.startswith("session_"):
                return self._failed(action, code, "interactive session unavailable")
            return self._failed(action, "uia_error", type(exc).__name__)
        except Exception as exc:  # noqa: BLE001 - provider isolation
            if capability in WRITE_CAPABILITIES:
                return ProviderExecution(ComputerResult(
                    status="uncertain", provider_status="uia_exception_after_dispatch",
                    error_code=type(exc).__name__,
                    error_message="UIA failed after possible dispatch; reconcile",
                    reconcile_required=True,
                ))
            return self._failed(action, "uia_error", f"{type(exc).__name__}")

    def cancel(self, command_id: str) -> dict[str, Any]:
        # UI Automation calls are short and not interruptible once invoked.
        return {"accepted": False, "too_late": True, "command_id": command_id}

    def close(self) -> None:
        return None

    # -- actions ------------------------------------------------------

    def _launch(self, action: ComputerAction) -> ProviderExecution:
        app_id = str(action.parameters.get("app_id") or "")
        executable = self.allowed_apps.get(app_id)
        if not executable:
            return self._failed(action, "app_not_allowlisted", "app is not operator allowlisted")
        if not os.path.isfile(executable):
            return self._failed(action, "app_executable_missing", "allowlisted executable is missing")
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "open", executable, None, str(Path(executable).parent), 1,
        )
        if int(result) <= 32:
            return self._failed(action, "app_launch_failed", "Windows rejected the launch")
        expected = str(action.parameters.get("expected_window") or "")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            auto = self._auto()
            foreground = auto.GetForegroundControl()
            title = str(getattr(foreground, "Name", "") or "") if foreground else ""
            if not expected or expected in title:
                return ProviderExecution(ComputerResult(
                    status="succeeded", provider_status="launched",
                    verification={"verified": True, "method": "window_observed",
                                  "window": redact_value(title)},
                    output={"app_id": app_id, "window": redact_value(title)},
                ))
            time.sleep(0.25)
        return self._failed(action, "window_not_verified", "expected window did not appear")

    def _find_control(self, selector: dict[str, Any]):
        auto = self._auto()
        foreground = auto.GetForegroundControl()
        if foreground is None:
            raise RuntimeError("session_no_foreground")
        target = str(selector.get("window_title") or "")
        if target and target not in str(getattr(foreground, "Name", "") or ""):
            raise RuntimeError("window_mismatch")
        matches = []
        stack = [(foreground, 0)]
        visited = 0
        while stack and visited < self.max_tree_nodes:
            control, depth = stack.pop()
            visited += 1
            if self._matches(control, selector):
                matches.append(control)
                if len(matches) > 1:
                    raise RuntimeError("target_ambiguous")
            if depth < 8:
                stack.extend((child, depth + 1) for child in self._children(control))
        if not matches:
            raise RuntimeError("target_missing")
        return matches[0]

    @staticmethod
    def _children(control: Any) -> list[Any]:
        try:
            return list(control.GetChildren())
        except Exception:  # noqa: BLE001 - stale/unsupported UIA node
            return []

    @staticmethod
    def _matches(control: Any, selector: dict[str, Any]) -> bool:
        if selector.get("automation_id") and str(getattr(control, "AutomationId", "")) != selector["automation_id"]:
            return False
        if selector.get("name") and str(getattr(control, "Name", "")) != selector["name"]:
            return False
        if selector.get("control_type") and str(getattr(control, "ControlTypeName", "")) != selector["control_type"]:
            return False
        return True

    def _click(self, action: ComputerAction) -> ProviderExecution:
        selector = dict(action.parameters.get("selector") or {})
        control = self._find_control(selector)
        if control.IsEnabled is False:
            return self._failed(action, "target_disabled", "target is disabled")
        try:
            control.Click()
        except Exception:  # noqa: BLE001 - fall back to invoke pattern
            pattern = control.GetInvokePattern()
            pattern.Invoke()
        expected = str(action.parameters.get("expected_name") or "")
        verified = not expected or expected in str(getattr(control, "Name", "") or "")
        return ProviderExecution(ComputerResult(
            status="succeeded" if verified else "executed_unverified",
            provider_status="clicked",
            verification={"verified": verified, "method": "uia_post_check"},
            output={"target": redact_value(self._control_summary(control))},
        ))

    def _type_text(self, action: ComputerAction) -> ProviderExecution:
        selector = dict(action.parameters.get("selector") or {})
        control = self._find_control(selector)
        if bool(getattr(control, "IsPassword", False)):
            return self._failed(action, "sensitive_field_blocked", "password controls are never driven")
        if action.parameters.get("sensitive") is True:
            return self._failed(action, "sensitive_text_blocked", "sensitive text is not supported in v1")
        text = str(action.parameters.get("text") or "")
        if not text:
            return self._failed(action, "invalid_text", "text is required")
        control.SetFocus()
        try:
            control.GetValuePattern().SetValue(text)
        except Exception:  # noqa: BLE001 - fallback to keyboard input
            control.SendKeys(text, waitTime=0.01)
        value = ""
        try:
            value = str(control.GetValuePattern().Value or "")
        except Exception:  # noqa: BLE001 - value pattern unavailable
            value = ""
        verified = value == text or not value
        return ProviderExecution(ComputerResult(
            status="succeeded" if verified else "executed_unverified",
            provider_status="typed",
            verification={"verified": verified, "method": "uia_value_check"},
            output={"target": redact_value(self._control_summary(control)),
                    "length": len(text)},
        ))

    def _key(self, action: ComputerAction) -> ProviderExecution:
        key = str(action.parameters.get("key") or "").upper()
        if key not in ALLOWED_KEYS:
            return self._failed(action, "key_not_allowlisted", key)
        auto = self._auto()
        auto.SendKeys("{" + key.lower().replace("+", "}(") + "}" if "+" in key else "{" + key.lower() + "}")
        return ProviderExecution(ComputerResult(
            status="succeeded", provider_status="key_sent",
            verification={"verified": True, "method": "key_dispatched"},
            output={"key": key},
        ))

    def _scroll(self, action: ComputerAction) -> ProviderExecution:
        clicks = int(action.parameters.get("clicks") or 0)
        auto = self._auto()
        for _ in range(abs(clicks)):
            auto.WheelDown() if clicks > 0 else auto.WheelUp()
        return ProviderExecution(ComputerResult(
            status="succeeded", provider_status="scrolled",
            verification={"verified": True, "method": "wheel_dispatched"},
            output={"clicks": clicks},
        ))

    def _screenshot(self, action: ComputerAction) -> ProviderExecution:
        from PIL import ImageGrab

        from ..redaction import redact_image

        image = ImageGrab.grab(all_screens=True)
        content = redact_image(image, action.parameters.get("redact_regions") or [])
        return ProviderExecution(
            ComputerResult(status="succeeded", provider_status="captured",
                           verification={"verified": True, "method": "screenshot"}),
            [ProviderEvidence("screenshot", "image/png", content)],
        )

    def _clipboard(self, action: ComputerAction) -> ProviderExecution:
        if not self.allow_clipboard:
            return self._failed(action, "clipboard_disabled", "clipboard capability is disabled")
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        try:
            if action.capability_id == "computer.clipboard.read":
                value = root.clipboard_get()
                return ProviderExecution(ComputerResult(
                    status="succeeded", provider_status="clipboard_read",
                    output={"text": "[REDACTED]", "length": len(value)},
                ))
            root.clipboard_clear()
            root.clipboard_append(str(action.parameters.get("text") or ""))
            root.update()
            return ProviderExecution(ComputerResult(
                status="succeeded", provider_status="clipboard_written",
                output={"length": len(str(action.parameters.get("text") or ""))},
            ))
        finally:
            root.destroy()

    # -- helpers ------------------------------------------------------

    @staticmethod
    def _control_summary(control: Any) -> dict[str, Any]:
        return redact_value({
            "name": str(getattr(control, "Name", "") or "")[:200],
            "automation_id": str(getattr(control, "AutomationId", "") or "")[:200],
            "control_type": str(getattr(control, "ControlTypeName", "") or "")[:100],
            "enabled": bool(getattr(control, "IsEnabled", True)),
            "password": bool(getattr(control, "IsPassword", False)),
        })

    def _tree(self, control: Any, *, max_depth: int = 4) -> dict[str, Any]:
        nodes = 0

        def walk(node: Any, depth: int) -> dict[str, Any]:
            nonlocal nodes
            nodes += 1
            item = self._control_summary(node)
            if depth < max_depth and nodes < self.max_tree_nodes:
                children = []
                for child in self._children(node):
                    if nodes >= self.max_tree_nodes:
                        break
                    children.append(walk(child, depth + 1))
                if children:
                    item["children"] = children
            return item

        return walk(control, 0) if control is not None else {}

    @staticmethod
    def _failed(action: ComputerAction, code: str, message: str) -> ProviderExecution:
        return ProviderExecution(ComputerResult(
            status="failed", provider_status=code.lower(),
            error_code=code, error_message=message[:240],
        ))


__all__ = ["ALLOWED_KEYS", "UiaProvider"]
