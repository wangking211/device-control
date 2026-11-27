"""Home Assistant pilot manifest, capability conversion and native mapping."""

from __future__ import annotations

from typing import Any

MANIFEST_ID = "home-assistant-pilot"
MANIFEST_VERSION = "1.0.0"
CAPABILITY_IDS = ("device.observe", "light.turn_on", "light.turn_off", "light.set_brightness")
READ_CAPABILITIES = {"device.observe"}
NATIVE_SERVICE = {
    "light.turn_on": "light.turn_on",
    "light.turn_off": "light.turn_off",
    "light.set_brightness": "light.turn_on",
}


def manifest_document() -> dict[str, Any]:
    return {
        "manifest_id": MANIFEST_ID,
        "manifest_version": MANIFEST_VERSION,
        "protocol_version": "v1",
        "capabilities": [
            {
                "id": "device.observe",
                "version": "1.0.0",
                "operation": "observe",
                "risk_tier": "read",
                "input_schema": {
                    "type": "object", "required": ["entity_id"],
                    "properties": {"entity_id": {"type": "string", "minLength": 1}},
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "additionalProperties": True},
                "timeout_ms": 15000,
                "supports_idempotency": True,
                "requires_state": False,
                "verification": {"type": "ui_state", "require_change": False},
            },
            {
                "id": "light.turn_on",
                "version": "1.0.0",
                "operation": "turn_on",
                "risk_tier": "write",
                "input_schema": {
                    "type": "object", "required": ["entity_id"],
                    "properties": {
                        "entity_id": {"type": "string", "minLength": 1},
                        "expected_state": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "additionalProperties": True},
                "timeout_ms": 15000,
                "supports_idempotency": False,
                "requires_state": True,
                "state_max_age_ms": 15000,
                "verification": {"type": "ui_state", "require_change": True},
            },
            {
                "id": "light.turn_off",
                "version": "1.0.0",
                "operation": "turn_off",
                "risk_tier": "write",
                "input_schema": {
                    "type": "object", "required": ["entity_id"],
                    "properties": {
                        "entity_id": {"type": "string", "minLength": 1},
                        "expected_state": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "additionalProperties": True},
                "timeout_ms": 15000,
                "supports_idempotency": False,
                "requires_state": True,
                "state_max_age_ms": 15000,
                "verification": {"type": "ui_state", "require_change": True},
            },
            {
                "id": "light.set_brightness",
                "version": "1.0.0",
                "operation": "set_brightness",
                "risk_tier": "write",
                "input_schema": {
                    "type": "object", "required": ["entity_id", "brightness"],
                    "properties": {
                        "entity_id": {"type": "string", "minLength": 1},
                        "brightness": {"type": "integer", "minimum": 0, "maximum": 255},
                        "expected_state": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                "output_schema": {"type": "object", "additionalProperties": True},
                "timeout_ms": 15000,
                "supports_idempotency": False,
                "requires_state": True,
                "state_max_age_ms": 15000,
                "verification": {"type": "ui_state", "require_change": True},
            },
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
                "execution_locality": "edge",
                "supports_idempotency": capability["supports_idempotency"],
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


def default_claim_capabilities() -> set[str]:
    return set(READ_CAPABILITIES)


def native_command(capability_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if capability_id not in CAPABILITY_IDS:
        raise ValueError("unsupported capability")
    if capability_id in READ_CAPABILITIES:
        return {"native_id": parameters["entity_id"], "read_only": True}
    service = NATIVE_SERVICE[capability_id]
    payload = {"entity_id": parameters["entity_id"]}
    if capability_id == "light.set_brightness":
        brightness = int(parameters["brightness"])
        if brightness < 0 or brightness > 255:
            raise ValueError("brightness out of range")
        payload["brightness"] = brightness
    return {
        "native_id": parameters["entity_id"],
        "native_operation": service,
        "parameters": payload,
        "expected_state": parameters.get("expected_state")
        or ("on" if capability_id == "light.turn_on" else "off"),
        "read_only": False,
    }
