"""Windows Computer Control capability manifest.

The manifest is registered through the existing gateway manifest flow; it does
not create a second registry. Risk tiers are authoritative here and are used by
Device Control policy/lease/approval decisions.
"""

from __future__ import annotations

from typing import Any

MANIFEST_ID = "computer-control"
MANIFEST_VERSION = "1.0.0"
CAPABILITY_IDS = (
    "computer.observe",
    "computer.window.list",
    "computer.uia.tree",
    "computer.screenshot",
    "computer.app.launch",
    "computer.uia.click",
    "computer.uia.type_text",
    "computer.key.press",
    "computer.scroll",
    "computer.clipboard.read",
    "computer.clipboard.write",
    "browser.navigate",
    "browser.inspect",
    "browser.fill",
    "browser.submit",
)
READ_CAPABILITIES = {
    "computer.observe",
    "computer.window.list",
    "computer.uia.tree",
    "computer.screenshot",
    "browser.inspect",
}
WRITE_CAPABILITIES = {
    "computer.app.launch", "computer.uia.click", "computer.uia.type_text",
    "computer.key.press", "computer.scroll", "computer.clipboard.read",
    "computer.clipboard.write", "browser.navigate", "browser.fill",
}
EXTERNAL_SIDE_EFFECT_CAPABILITIES = {"browser.submit"}
SHELL_CAPABILITIES: frozenset[str] = frozenset()

_SELECTOR = {
    "type": "object",
    "properties": {
        "automation_id": {"type": "string", "minLength": 1, "maxLength": 200},
        "name": {"type": "string", "minLength": 1, "maxLength": 200},
        "control_type": {"type": "string", "minLength": 1, "maxLength": 100},
        "window_title": {"type": "string", "minLength": 1, "maxLength": 300},
        "index": {"type": "integer", "minimum": 0, "maximum": 1000},
    },
    "additionalProperties": False,
}


def _capability(capability_id: str, operation: str, risk: str, schema: dict[str, Any],
                *, requires_change: bool = False, timeout_ms: int = 30_000,
                evidence: str | None = None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "id": capability_id,
        "version": "1.0.0",
        "operation": operation,
        "risk_tier": risk,
        "input_schema": schema,
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": timeout_ms,
        "supports_idempotency": True,
        "requires_state": False,
        "verification": {"type": "ui_state", "require_change": requires_change},
    }
    if evidence:
        document["evidence"] = {"capture": evidence, "redaction": "required"}
    return document


def manifest_document() -> dict[str, Any]:
    return {
        "manifest_id": MANIFEST_ID,
        "manifest_version": MANIFEST_VERSION,
        "protocol_version": "v1",
        "capabilities": [
            _capability("computer.observe", "observe", "read", {
                "type": "object", "properties": {
                    "include_tree": {"type": "boolean", "default": False},
                }, "additionalProperties": False,
            }),
            _capability("computer.window.list", "list_windows", "read", {
                "type": "object", "properties": {}, "additionalProperties": False,
            }),
            _capability("computer.uia.tree", "inspect_tree", "read", {
                "type": "object", "properties": {
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": 8, "default": 4},
                    "max_nodes": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200},
                }, "additionalProperties": False,
            }),
            _capability("computer.screenshot", "screenshot", "read", {
                "type": "object", "properties": {
                    "redact_regions": {"type": "array", "maxItems": 64,
                                       "items": {"type": "array", "minItems": 4, "maxItems": 4,
                                                 "items": {"type": "integer", "minimum": 0}}},
                }, "additionalProperties": False,
            }, evidence="screenshot"),
            _capability("computer.app.launch", "launch", "write", {
                "type": "object", "required": ["app_id"],
                "properties": {
                    "app_id": {"type": "string", "minLength": 1, "maxLength": 200},
                    "expected_window": {"type": "string", "maxLength": 300},
                }, "additionalProperties": False,
            }, requires_change=True),
            _capability("computer.uia.click", "click", "write", {
                "type": "object", "required": ["selector"],
                "properties": {"selector": _SELECTOR,
                               "expected_name": {"type": "string", "maxLength": 200}},
                "additionalProperties": False,
            }, requires_change=True),
            _capability("computer.uia.type_text", "type_text", "write", {
                "type": "object", "required": ["selector", "text"],
                "properties": {"selector": _SELECTOR,
                               "text": {"type": "string", "minLength": 1, "maxLength": 4000},
                               "sensitive": {"type": "boolean", "default": False}},
                "additionalProperties": False,
            }, requires_change=True),
            _capability("computer.key.press", "key_press", "write", {
                "type": "object", "required": ["key"],
                "properties": {"key": {"type": "string", "enum": [
                    "ENTER", "ESC", "TAB", "SPACE", "BACKSPACE", "DELETE",
                    "UP", "DOWN", "LEFT", "RIGHT", "HOME", "END", "PAGEUP", "PAGEDOWN",
                    "CTRL+A", "CTRL+C", "CTRL+V", "CTRL+S", "ALT+TAB",
                ]}}, "additionalProperties": False,
            }, requires_change=True),
            _capability("computer.scroll", "scroll", "write", {
                "type": "object", "required": ["clicks"],
                "properties": {"clicks": {"type": "integer", "minimum": -20, "maximum": 20}},
                "additionalProperties": False,
            }, requires_change=True),
            _capability("computer.clipboard.read", "clipboard_read", "write", {
                "type": "object", "properties": {}, "additionalProperties": False,
            }),
            _capability("computer.clipboard.write", "clipboard_write", "write", {
                "type": "object", "required": ["text"],
                "properties": {"text": {"type": "string", "maxLength": 4000}},
                "additionalProperties": False,
            }),
            _capability("browser.navigate", "navigate", "write", {
                "type": "object", "required": ["url"],
                "properties": {"url": {"type": "string", "format": "uri",
                                       "pattern": "^https?://"}},
                "additionalProperties": False,
            }, requires_change=True),
            _capability("browser.inspect", "inspect", "read", {
                "type": "object", "properties": {
                    "locator": {"type": "object", "additionalProperties": True},
                }, "additionalProperties": False,
            }),
            _capability("browser.fill", "fill", "write", {
                "type": "object", "required": ["locator", "value"],
                "properties": {"locator": {"type": "object", "additionalProperties": True},
                               "value": {"type": "string", "maxLength": 4000},
                               "sensitive": {"type": "boolean", "default": False}},
                "additionalProperties": False,
            }, requires_change=True),
            _capability("browser.submit", "submit", "write", {
                "type": "object", "required": ["locator"],
                "properties": {"locator": {"type": "object", "additionalProperties": True}},
                "additionalProperties": False,
            }, requires_change=True),
        ],
    }


def endpoint_capability(capability_id: str) -> dict[str, Any] | None:
    for capability in manifest_document()["capabilities"]:
        if capability["id"] == capability_id:
            return {
                "id": capability["id"],
                "version": capability["version"],
                "input_schema": capability["input_schema"],
                "output_schema": capability["output_schema"],
                "risk_tier": capability["risk_tier"],
                "execution_locality": "local",
                "supports_idempotency": True,
                "max_timeout_ms": capability["timeout_ms"],
            }
    return None


def endpoint_capabilities(capability_ids: set[str]) -> list[dict[str, Any]]:
    result = []
    for capability_id in CAPABILITY_IDS:
        if capability_id in capability_ids:
            item = endpoint_capability(capability_id)
            if item:
                result.append(item)
    return result


__all__ = [
    "CAPABILITY_IDS",
    "EXTERNAL_SIDE_EFFECT_CAPABILITIES",
    "MANIFEST_ID",
    "MANIFEST_VERSION",
    "READ_CAPABILITIES",
    "SHELL_CAPABILITIES",
    "WRITE_CAPABILITIES",
    "endpoint_capabilities",
    "endpoint_capability",
    "manifest_document",
]
