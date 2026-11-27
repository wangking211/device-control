"""Adapter SPI contracts and value objects (platform-neutral)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence


class AdapterError(RuntimeError):
    def __init__(self, code: str, message: str = "", *, retryable: bool = False,
                 native_id: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.retryable = retryable
        self.native_id = native_id


@dataclass(frozen=True)
class AdapterHealth:
    status: str  # ok | degraded | unavailable
    version: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    checked_at: str = ""


@dataclass(frozen=True)
class PlatformConfig:
    platform_instance_id: str
    tenant_id: str
    adapter_id: str
    endpoint: str
    platform_version: str = ""
    secret_refs: dict[str, str] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityMapping:
    capability_id: str
    version: str
    native_operation: str
    risk_tier: str  # read | write | destructive | safety_critical
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    requires_state: bool = False
    idempotent: bool = False
    verification: str = "read_after_write"


@dataclass(frozen=True)
class DiscoveredDevice:
    native_id: str
    native_type: str
    display_name: str
    capabilities: tuple[CapabilityMapping, ...] = ()
    manufacturer: str | None = None
    model: str | None = None
    area: str | None = None
    native_ref: dict[str, Any] = field(default_factory=dict)
    trusted: bool = False  # discovery never grants control authority


@dataclass(frozen=True)
class DiscoveryPage:
    devices: tuple[DiscoveredDevice, ...]
    cursor: str | None = None


@dataclass(frozen=True)
class Observation:
    native_id: str
    observed_at: str
    properties: dict[str, Any] = field(default_factory=dict)
    connectivity: str = "unknown"
    quality: str = "medium"
    state_hash: str = ""
    native_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TelemetryPoint:
    native_id: str
    metric: str
    value: Any
    unit: str | None
    source_timestamp: str
    ingest_timestamp: str
    sequence: int | None = None
    quality: str = "good"
    schema_version: str = "1"


@dataclass(frozen=True)
class ExecutionResult:
    native_id: str
    accepted: bool
    executed: bool = False
    verified: bool = False
    status: str = "accepted"
    observed: Observation | None = None
    error: str | None = None
    evidence_refs: tuple[str, ...] = ()
    native_response: dict[str, Any] = field(default_factory=dict)


class AdapterPlugin(Protocol):
    """Stable adapter port. All methods are platform-neutral.

    ``validate_config`` and ``health`` must not mutate platform state. Discovery
    returns untrusted devices; only Device Control claim/activation grants
    control authority. ``execute`` is only called after policy/lease/approval
    checks and must report execution separately from physical verification.
    """

    adapter_id: str
    api_version: str

    def validate_config(self, config: PlatformConfig) -> list[str]:
        ...

    def connect(self, config: PlatformConfig, resolve_secret: Any) -> None:
        ...

    def disconnect(self) -> None:
        ...

    def health(self) -> AdapterHealth:
        ...

    def discover(self, cursor: str | None = None,
                 filters: dict[str, Any] | None = None) -> DiscoveryPage:
        ...

    def get_device(self, native_id: str) -> DiscoveredDevice | None:
        ...

    def get_capabilities(self, native_id: str) -> Sequence[CapabilityMapping]:
        ...

    def observe(self, native_id: str) -> Observation:
        ...

    def execute(self, command: dict[str, Any]) -> ExecutionResult:
        ...

    def subscribe(self, event_types: Sequence[str], cursor: str | None = None
                  ) -> tuple[list[dict[str, Any]], str | None]:
        ...

    def get_telemetry(self, native_id: str, cursor: str | None = None,
                      limit: int = 100) -> tuple[list[TelemetryPoint], str | None]:
        ...

    def reconcile(self, mapping_state: dict[str, Any]) -> dict[str, Any]:
        ...
