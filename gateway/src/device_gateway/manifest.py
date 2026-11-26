"""Trusted, versioned capability manifest.

Risk, operation, state requirements and verification semantics are defined
here. A command envelope may only repeat these values; it can never lower them.
The digest is computed over the canonical manifest payload and an optional
HMAC signature lets the operator pin the exact manifest at the control plane.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

PROTOCOL_VERSION = "v1"
MANIFEST_ID = "android-adb-standard"
MANIFEST_VERSION = "1.1.0"

CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "id": "device.observe",
        "version": "1.0.0",
        "operation": "observe",
        "risk_tier": "read",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 15000,
        "supports_idempotency": True,
        "requires_state": False,
        "verification": {"type": "ui_state", "require_change": False},
        "evidence": {"capture": "node_summary", "redaction": "required", "retention_seconds": 3600},
    },
    {
        "id": "device.screenshot",
        "version": "1.0.0",
        "operation": "screenshot",
        "risk_tier": "read",
        "input_schema": {
            "type": "object",
            "properties": {"redact": {"type": "boolean", "default": True}},
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 15000,
        "supports_idempotency": True,
        "requires_state": False,
        "verification": {"type": "artifact", "require_change": False},
        "evidence": {"capture": "screenshot", "redaction": "required", "retention_seconds": 86400},
    },
    {
        "id": "app.launch",
        "version": "1.0.0",
        "operation": "launch",
        "risk_tier": "read",
        "input_schema": {
            "type": "object",
            "required": ["app_id"],
            "properties": {"app_id": {"type": "string", "minLength": 1, "maxLength": 200}},
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 15000,
        "supports_idempotency": True,
        "requires_state": False,
        "verification": {"type": "ui_state", "require_change": False},
        "allowlist": True,
        "evidence": {"capture": "none", "redaction": "required"},
    },
    {
        "id": "ui.tap",
        "version": "1.0.0",
        "operation": "tap",
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
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 10000,
        "supports_idempotency": False,
        "requires_state": True,
        "state_max_age_ms": 15000,
        "verification": {"type": "ui_change", "require_change": True},
        "evidence": {"capture": "node_summary", "redaction": "required"},
    },
    {
        "id": "ui.type_text",
        "version": "1.0.0",
        "operation": "type_text",
        "risk_tier": "write",
        "input_schema": {
            "type": "object",
            "required": ["target_ref", "text"],
            "properties": {
                "target_ref": {"type": "string", "minLength": 1, "maxLength": 200},
                "text": {"type": "string", "maxLength": 500},
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 15000,
        "supports_idempotency": False,
        "requires_state": True,
        "state_max_age_ms": 15000,
        "verification": {"type": "field_state", "require_change": True},
        "evidence": {"capture": "none", "redaction": "required"},
    },
    {
        "id": "ui.swipe",
        "version": "1.0.0",
        "operation": "swipe",
        "risk_tier": "write",
        "input_schema": {
            "type": "object",
            "required": ["start", "end"],
            "properties": {
                "start": {
                    "type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "minItems": 2, "maxItems": 2,
                },
                "end": {
                    "type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "minItems": 2, "maxItems": 2,
                },
                "duration_ms": {"type": "integer", "minimum": 50, "maximum": 2000},
            },
            "additionalProperties": False,
        },
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 15000,
        "supports_idempotency": False,
        "requires_state": True,
        "state_max_age_ms": 15000,
        "verification": {"type": "ui_change", "require_change": True},
        "evidence": {"capture": "node_summary", "redaction": "required"},
    },
    {
        "id": "ui.press_back",
        "version": "1.0.0",
        "operation": "press_back",
        "risk_tier": "write",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 10000,
        "supports_idempotency": False,
        "requires_state": True,
        "state_max_age_ms": 15000,
        "verification": {"type": "ui_change", "require_change": True},
        "evidence": {"capture": "node_summary", "redaction": "required"},
    },
    {
        "id": "ui.press_home",
        "version": "1.0.0",
        "operation": "press_home",
        "risk_tier": "write",
        "input_schema": {"type": "object", "additionalProperties": False},
        "output_schema": {"type": "object", "additionalProperties": True},
        "timeout_ms": 10000,
        "supports_idempotency": False,
        "requires_state": True,
        "state_max_age_ms": 15000,
        "verification": {"type": "ui_change", "require_change": True},
        "evidence": {"capture": "node_summary", "redaction": "required"},
    },
    {
        "id": "ui.wait_for",
        "version": "1.0.0",
        "operation": "wait_for",
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
        "timeout_ms": 20000,
        "supports_idempotency": True,
        "requires_state": False,
        "verification": {"type": "ui_state", "require_change": False},
        "evidence": {"capture": "none", "redaction": "required"},
    },
)

CAPABILITY_IDS = tuple(item["id"] for item in CAPABILITIES)
DENY_RISK = {"destructive", "safety_critical"}


def _payload(manifest: dict[str, Any]) -> dict[str, Any]:
    fields = ("manifest_id", "manifest_version", "protocol_version", "endpoint_id",
              "device_id", "device_fingerprint", "capabilities")
    return {field: manifest[field] for field in fields if field in manifest}


def digest(manifest: dict[str, Any]) -> str:
    raw = json.dumps(_payload(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sign(manifest_digest: str, key: str) -> str:
    if len(key.encode("utf-8")) < 32:
        raise ValueError("manifest signing key must be at least 32 bytes")
    return hmac.new(key.encode("utf-8"), manifest_digest.encode("ascii"), hashlib.sha256).hexdigest()


def verify(manifest_digest: str, signature: str | None, key: str) -> bool:
    if not signature or len(key.encode("utf-8")) < 32:
        return False
    return hmac.compare_digest(sign(manifest_digest, key), signature)


def default_document() -> dict[str, Any]:
    document: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "manifest_version": MANIFEST_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "capabilities": [dict(item) for item in CAPABILITIES],
    }
    key = os.environ.get("DEVICE_GATEWAY_MANIFEST_HMAC_KEY", "")
    if len(key.encode("utf-8")) >= 32:
        document["signature"] = sign(digest(document), key)
    return document


def load(path: str | None = None) -> dict[str, Any]:
    """Load the operator manifest, defaulting to the built-in document."""

    if not path:
        return default_document()
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("manifest file must contain a JSON object")
    return document


def capability(manifest: dict[str, Any], capability_id: str,
               version: str) -> dict[str, Any] | None:
    for item in manifest.get("capabilities") or []:
        if item.get("id") == capability_id and item.get("version") == version:
            return item
    return None


def inventory(adapter_id: str, adapter_version: str,
              platform: dict[str, Any] | None = None,
              manifest: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    manifest = manifest or default_document()
    return [
        {
            "adapter_id": adapter_id,
            "version": adapter_version,
            "capabilities": [item["id"] for item in manifest.get("capabilities") or []],
            "platform": platform or {},
        }
    ]


def manifest_document(manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    document = manifest or default_document()
    return {**document, "digest": digest(document)}
