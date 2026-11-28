"""Versioned wire-contract loading and validation.

The v1 files under ``contracts/v1`` are vendored from
``ai-platform/platform/contracts/device``. Validation is used for transport
shapes only; authorization is never inferred from a schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "contracts" / "v1"

SCHEMAS: dict[str, str] = {
    "endpoint": "device-endpoint.schema.json",
    "enrollment": "endpoint-enrollment.schema.json",
    "heartbeat": "endpoint-heartbeat.schema.json",
    "enrollment_receipt": "endpoint-receipt.schema.json",
    "invocation": "device-invocation.schema.json",
    "result": "device-result.schema.json",
    "gateway_enrollment": "gateway-enrollment.schema.json",
    "gateway_activation": "gateway-activation.schema.json",
    "gateway_receipt": "gateway-receipt.schema.json",
    "gateway_heartbeat": "gateway-heartbeat.schema.json",
    "command": "device-command.schema.json",
    "command_state": "device-command-status.schema.json",
    "gateway_command": "gateway-command.schema.json",
    "gateway_command_result": "gateway-command-result.schema.json",
    "event": "device-event.schema.json",
    "manifest": "device-manifest.schema.json",
    "adapter_manifest": "adapter-plugin-manifest.schema.json",
    "canonical_device": "canonical-device.schema.json",
    "telemetry": "device-telemetry.schema.json",
    "twin": "device-twin.schema.json",
}


def load_schema(name: str) -> dict[str, Any]:
    filename = SCHEMAS.get(name)
    if filename is None:
        raise KeyError(name)
    return json.loads((CONTRACT_DIR / filename).read_text(encoding="utf-8"))


def load_all() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for name, filename in SCHEMAS.items():
        path = CONTRACT_DIR / filename
        if path.is_file():
            loaded[name] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def missing_contracts() -> list[str]:
    return [filename for filename in SCHEMAS.values() if not (CONTRACT_DIR / filename).is_file()]


def _registry() -> Registry:
    """Register each schema under its ``$id``, file URI and public filename.

    A relative ``$ref`` in a document with an ``$id`` resolves against that
    ``$id``, so the filename alias keeps the vendored layout working exactly
    like the canonical monorepo copy.
    """

    resources: list[tuple[str, Resource]] = []
    for name, schema in load_all().items():
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        filename = SCHEMAS[name]
        resources.append(((CONTRACT_DIR / filename).resolve().as_uri(), resource))
        resources.append((f"https://ai-platform.local/contracts/device/{filename}", resource))
        if isinstance(schema.get("$id"), str):
            resources.append((schema["$id"], resource))
    return Registry().with_resources(resources)


def validate_contract(name: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    validator = Draft202012Validator(
        load_schema(name),
        registry=_registry(),
        format_checker=FormatChecker(),
    )
    return _errors(validator, payload)


def validate_instance(schema: dict[str, Any], payload: Any) -> list[dict[str, str]]:
    """Validate a capability's declared input schema (already trusted config)."""

    if not isinstance(schema, dict) or not schema:
        return []
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return _errors(validator, payload)


def _errors(validator: Draft202012Validator, payload: Any) -> list[dict[str, str]]:
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.absolute_path))
    return [
        {"path": "/" + "/".join(map(str, error.absolute_path)), "message": error.message}
        for error in errors
    ]
