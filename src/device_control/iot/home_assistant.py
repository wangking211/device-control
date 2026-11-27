"""Home Assistant mapping helpers (specification + test fixtures).

Discovery maps HA entities to untrusted canonical devices; nothing becomes
executable until Device Control claim/authorization. Service calls become
Device Control commands and are verified by re-reading state, not by the HTTP
service response alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

HA_PLATFORM = "homeassistant"
READ_ONLY_DOMAINS = {"sensor", "binary_sensor", "weather", "sun", "person"}
WRITE_DOMAINS = {"light", "switch", "fan", "cover", "climate", "scene", "script"}


@dataclass(frozen=True)
class HADevice:
    native_id: str
    device_id: str
    display_name: str
    device_type: str
    area: str | None
    capabilities: tuple[dict[str, Any], ...]
    trust_state: str = "pending"


def canonical_device_id(tenant_id: str, entity_id: str) -> str:
    safe = entity_id.replace(".", ":").replace("/", "_")
    return f"ha:{tenant_id}:{safe}"


def map_entity(tenant_id: str, state: dict[str, Any],
               area: str | None = None) -> HADevice:
    entity_id = str(state["entity_id"])
    domain = entity_id.split(".", 1)[0]
    attributes = state.get("attributes") or {}
    name = str(attributes.get("friendly_name") or entity_id)
    capabilities: list[dict[str, Any]] = [
        {
            "capability_id": "device.observe",
            "version": "1.0.0",
            "native_operation": "GET /api/states/{entity_id}",
            "risk_tier": "read",
            "requires_state": False,
            "idempotent": True,
            "verification": "read_after_write",
        }
    ]
    if domain in WRITE_DOMAINS:
        capabilities.append({
            "capability_id": f"{domain}.set_state",
            "version": "1.0.0",
            "native_operation": f"{domain}.turn_on" if domain == "light" else f"{domain}.toggle",
            "risk_tier": "write",
            "requires_state": True,
            "idempotent": False,
            "verification": "read_after_write",
        })
    return HADevice(
        native_id=entity_id,
        device_id=canonical_device_id(tenant_id, entity_id),
        display_name=name,
        device_type=domain,
        area=area,
        capabilities=tuple(capabilities),
    )


def build_command(intent: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Map a Device Control command to an HA service call (no HA auth here)."""

    entity_id = str(intent["native_id"])
    domain = entity_id.split(".", 1)[0]
    operation = str(intent.get("native_operation") or "")
    if operation not in {f"{domain}.turn_on", f"{domain}.toggle", f"{domain}.turn_off"}:
        raise ValueError("unsupported Home Assistant operation")
    data = dict(intent.get("parameters") or {})
    payload = {"entity_id": entity_id, **data}
    return {
        "service": operation,
        "endpoint": f"/api/services/{operation.replace('.', '/')}",
        "payload": payload,
        "expected_state": intent.get("expected_state"),
        "state_before": state.get("state"),
    }


def verify_state(expected: Any, observed: Any) -> bool:
    if expected is None:
        return False
    return str(expected) == str(observed)


def compare_native_mapping(existing: dict[str, Any], incoming: dict[str, Any]) -> str:
    """Return a conflict policy decision for a duplicate native mapping."""

    if existing.get("native_id") != incoming.get("native_id"):
        return "different_native"
    if existing.get("device_id") != incoming.get("device_id"):
        return "conflict"
    return "same"
