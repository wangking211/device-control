"""Adapter port and result types.

Adapters are the only code allowed to touch a device. They run in the gateway
process (or a dedicated adapter container), never inside the FastAPI control
plane. A crashing adapter is isolated by the worker: it produces a failed or
uncertain result, not a control-plane crash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class AdapterError(RuntimeError):
    """Adapter failure with an explicit uncertainty flag."""

    def __init__(self, message: str, *, error_class: str = "adapter",
                 uncertain: bool = False, retryable: bool = False) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.uncertain = uncertain
        self.retryable = retryable


class AdapterTimeout(AdapterError):
    def __init__(self, message: str = "adapter timeout") -> None:
        super().__init__(message, error_class="timeout", uncertain=True, retryable=False)


class AdapterUnavailable(AdapterError):
    def __init__(self, message: str = "device unavailable") -> None:
        super().__init__(message, error_class="unavailable", uncertain=False, retryable=True)


@dataclass
class ActionResult:
    status: str
    output: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] | None = None
    evidence_refs: list[str] = field(default_factory=list)
    error_class: str | None = None
    retryable: bool = False
    reason: str | None = None
    executed: bool = False
    post_state: dict[str, Any] | None = None
    artifact_bytes: bytes | None = None
    redaction: dict[str, Any] | None = None


@runtime_checkable
class DeviceAdapter(Protocol):
    adapter_id: str
    version: str

    def health(self) -> dict[str, Any]:
        ...

    def observe_state(self) -> dict[str, Any]:
        """Return the current device state, including a state hash."""

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        ...

    def close(self) -> None:
        ...


class NullAdapter:
    """Adapter used when no hardware driver is configured (fails closed)."""

    adapter_id = "null"
    version = "0.0.0"

    def health(self) -> dict[str, Any]:
        return {"status": "unavailable", "reason": "no_adapter_configured"}

    def observe_state(self) -> dict[str, Any]:
        raise AdapterUnavailable("no adapter configured")

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> ActionResult:
        raise AdapterUnavailable("no adapter configured")

    def close(self) -> None:
        return None
