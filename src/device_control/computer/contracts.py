"""Typed Windows Computer Control action/observation contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

ACTION_SCHEMA = "dc.computer-action/v1"
OBSERVATION_SCHEMA = "dc.computer-observation/v1"
RESULT_SCHEMA = "dc.computer-result/v1"
MAX_PARAMETER_BYTES = 16 * 1024

SENSITIVE_KEY_MARKERS = (
    "password", "passwd", "secret", "token", "credential", "cookie",
    "authorization", "card_number", "cvv", "otp", "sessionid",
)


class ComputerActionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ComputerAction:
    schema: str
    command_id: str
    tenant_ref: str
    endpoint_id: str
    device_id: str
    task_ref: str | None
    run_ref: str | None
    capability_id: str
    capability_version: str
    operation: str
    parameters: Mapping[str, Any]
    idempotency_key: str
    deadline: str
    approval_ref: str | None = None
    expected_state: Mapping[str, Any] | None = None

    @classmethod
    def from_envelope(cls, envelope: Mapping[str, Any]) -> "ComputerAction":
        if str(envelope.get("protocol_version") or "") != "v1":
            raise ComputerActionError("protocol_mismatch", "unsupported protocol version")
        parameters = envelope.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ComputerActionError("invalid_parameters", "parameters must be an object")
        try:
            size = len(json.dumps(dict(parameters), ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ComputerActionError("invalid_parameters", "parameters are not JSON") from exc
        if size > MAX_PARAMETER_BYTES:
            raise ComputerActionError("parameters_too_large", "parameters exceed 16 KiB")
        action = cls(
            schema=ACTION_SCHEMA,
            command_id=str(envelope.get("command_id") or ""),
            tenant_ref=str(envelope.get("tenant_ref") or ""),
            endpoint_id=str(envelope.get("endpoint_id") or ""),
            device_id=str(envelope.get("device_id") or ""),
            task_ref=envelope.get("task_ref"),
            run_ref=envelope.get("run_ref"),
            capability_id=str(envelope.get("capability_id") or ""),
            capability_version=str(envelope.get("capability_version") or ""),
            operation=str(envelope.get("operation") or ""),
            parameters=dict(parameters),
            idempotency_key=str(envelope.get("idempotency_key") or ""),
            deadline=str(envelope.get("deadline") or ""),
            approval_ref=envelope.get("approval_id"),
            expected_state=envelope.get("expected_state")
            if isinstance(envelope.get("expected_state"), Mapping) else None,
        )
        action.validate()
        return action

    def validate(self) -> None:
        for name in ("command_id", "tenant_ref", "endpoint_id", "device_id",
                     "capability_id", "capability_version", "operation",
                     "idempotency_key", "deadline"):
            if not str(getattr(self, name) or "").strip():
                raise ComputerActionError("action_incomplete", f"{name} is required")
        try:
            deadline = datetime.fromisoformat(self.deadline.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ComputerActionError("invalid_deadline", "deadline is not ISO-8601") from exc
        if deadline.tzinfo is None:
            raise ComputerActionError("invalid_deadline", "deadline must be timezone-aware")

    def fingerprint(self) -> str:
        payload = {
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "operation": self.operation,
            "parameters": dict(self.parameters),
            "expected_state": dict(self.expected_state or {}),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def ledger_key(self) -> str:
        return "|".join((self.tenant_ref, self.endpoint_id,
                         str(self.task_ref or ""), str(self.run_ref or ""),
                         self.idempotency_key))


@dataclass
class ComputerObservation:
    schema: str = OBSERVATION_SCHEMA
    session_state: str = "unknown"
    active_window: dict[str, Any] | None = None
    windows: list[dict[str, Any]] = field(default_factory=list)
    uia_tree: dict[str, Any] | None = None
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComputerResult:
    schema: str = RESULT_SCHEMA
    status: str = "failed"
    provider_status: str = ""
    verification: dict[str, Any] | None = None
    output: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    reconcile_required: bool = False
    occurred_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def redact_value(value: Any, *, key: str = "") -> Any:
    """Recursively redact secrets from observations/logs before persistence."""

    if key and is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): redact_value(item, key=str(item_key))
                for item_key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        for marker in ("password=", "token=", "bearer ", "authorization:"):
            if marker in lowered:
                return "[REDACTED]"
    return value


__all__ = [
    "ACTION_SCHEMA",
    "ComputerAction",
    "ComputerActionError",
    "ComputerObservation",
    "ComputerResult",
    "OBSERVATION_SCHEMA",
    "RESULT_SCHEMA",
    "is_sensitive_key",
    "redact_value",
]
