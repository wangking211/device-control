"""Replaceable Computer Control provider contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..contracts import ComputerAction, ComputerObservation, ComputerResult


@dataclass(frozen=True)
class ProviderHealth:
    status: str
    provider: str
    version: str
    detail: str = ""
    capabilities: tuple[str, ...] = ()


@dataclass
class ProviderEvidence:
    evidence_type: str
    mime_type: str
    content: bytes
    redaction_status: str = "redacted"
    captured_at: str | None = None


@dataclass
class ProviderExecution:
    result: ComputerResult
    evidence: list[ProviderEvidence] = field(default_factory=list)


class ComputerProvider(Protocol):
    provider_id: str

    def health(self) -> ProviderHealth:
        ...

    def observe(self, action: ComputerAction) -> ComputerObservation:
        ...

    def execute(self, action: ComputerAction) -> ProviderExecution:
        ...

    def cancel(self, command_id: str) -> dict[str, Any]:
        ...

    def close(self) -> None:
        ...


__all__ = [
    "ComputerProvider",
    "ProviderEvidence",
    "ProviderExecution",
    "ProviderHealth",
]
