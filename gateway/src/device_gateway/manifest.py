"""Capability manifest exposed by the gateway.

The manifest is operator-deployed configuration, not model input. Every
capability declares its typed input, risk tier, idempotency and verification
strategy so the control plane and gateway can reject anything undeclared.
"""

from __future__ import annotations

from typing import Any

PROTOCOL_VERSION = "v1"

CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "id": "observe.screenshot",
        "version": "1.0.0",
        "risk_tier": "read",
        "input_schema": {
            "type": "object",
            "properties": {"redact": {"type": "boolean", "default": True}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "required": ["screenshot_sha256", "bytes", "redacted"],
            "properties": {
                "screenshot_sha256": {"type": "string"},
                "bytes": {"type": "integer"},
                "redacted": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "supports_idempotency": True,
        "max_timeout_ms": 15000,
        "verification": "screenshot_predicate",
        "requires_state_hash": False,
    },
    {
        "id": "observe.foreground_app",
        "version": "1.0.0",
        "risk_tier": "read",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {
            "type": "object",
            "properties": {"foreground_app": {"type": ["string", "null"]}},
            "additionalProperties": False,
        },
        "supports_idempotency": True,
        "max_timeout_ms": 10000,
        "verification": "read_after_write",
        "requires_state_hash": False,
    },
    {
        "id": "app.launch",
        "version": "1.0.0",
        "risk_tier": "read",
        "input_schema": {
            "type": "object",
            "required": ["app_id"],
            "properties": {"app_id": {"type": "string", "minLength": 1, "maxLength": 200}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "properties": {"foreground_app": {"type": ["string", "null"]}},
            "additionalProperties": False,
        },
        "supports_idempotency": True,
        "max_timeout_ms": 15000,
        "verification": "ui_state",
        "requires_state_hash": False,
        "allowlist": True,
    },
    {
        "id": "ui.tap",
        "version": "1.0.0",
        "risk_tier": "write",
        "input_schema": {
            "type": "object",
            "required": ["target_ref"],
            "properties": {
                "target_ref": {"type": "string", "minLength": 1, "maxLength": 200},
                "bounds": {
                    "type": ["array", "null"],
                    "items": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "minItems": 4,
                    "maxItems": 4,
                },
                "screenshot_sha256": {"type": ["string", "null"], "maxLength": 200},
                "target_type": {"type": ["string", "null"], "maxLength": 50},
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "supports_idempotency": False,
        "max_timeout_ms": 10000,
        "verification": "ui_state",
        "requires_state_hash": True,
    },
    {
        "id": "ui.type_text",
        "version": "1.0.0",
        "risk_tier": "write",
        "input_schema": {
            "type": "object",
            "required": ["target_ref", "text"],
            "properties": {
                "target_ref": {"type": "string", "minLength": 1, "maxLength": 200},
                "text": {"type": "string", "maxLength": 500},
                "target_type": {"type": ["string", "null"], "maxLength": 50},
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "supports_idempotency": False,
        "max_timeout_ms": 15000,
        "verification": "read_after_write",
        "requires_state_hash": True,
    },
    {
        "id": "ui.back",
        "version": "1.0.0",
        "risk_tier": "write",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": True},
        "supports_idempotency": False,
        "max_timeout_ms": 10000,
        "verification": "ui_state",
        "requires_state_hash": True,
    },
    {
        "id": "ui.home",
        "version": "1.0.0",
        "risk_tier": "write",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": True},
        "supports_idempotency": False,
        "max_timeout_ms": 10000,
        "verification": "ui_state",
        "requires_state_hash": True,
    },
    {
        "id": "ui.wait_for",
        "version": "1.0.0",
        "risk_tier": "read",
        "input_schema": {
            "type": "object",
            "required": ["expected_app"],
            "properties": {
                "expected_app": {"type": "string", "minLength": 1, "maxLength": 200},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 15000},
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "supports_idempotency": True,
        "max_timeout_ms": 20000,
        "verification": "ui_state",
        "requires_state_hash": False,
    },
)

CAPABILITY_IDS = tuple(item["id"] for item in CAPABILITIES)


def capability(capability_id: str, version: str) -> dict[str, Any] | None:
    for item in CAPABILITIES:
        if item["id"] == capability_id and item["version"] == version:
            return item
    return None


def inventory(adapter_id: str, adapter_version: str, platform: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return [
        {
            "adapter_id": adapter_id,
            "version": adapter_version,
            "capabilities": list(CAPABILITY_IDS),
            "platform": platform or {},
        }
    ]


def manifest_document() -> dict[str, Any]:
    return {"protocol_version": PROTOCOL_VERSION, "capabilities": list(CAPABILITIES)}
