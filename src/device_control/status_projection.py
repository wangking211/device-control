"""Canonical device-command status projection.

Device Control keeps its authoritative, fine-grained internal status machine
(``created`` … ``uncertain``). Consumers such as MindOS must not re-invent a
second mapping, so this module is the single projection contract:

* the raw provider status is always preserved;
* unknown values project to ``unknown`` instead of guessing;
* ``executed_unverified`` can never project to ``succeeded``;
* terminal status changes remain the control plane's authority.

The mapping is deliberately a pure function; it never mutates command state.
"""

from __future__ import annotations

from typing import Any, Mapping

CONTRACT_VERSION = "dc-command-state/v1"

CANONICAL_STATUSES = frozenset({
    "queued",
    "waiting_approval",
    "running",
    "verifying",
    "succeeded",
    "failed",
    "unknown",
    "cancelled",
    "expired",
})

CANONICAL_TERMINAL = frozenset({
    "succeeded", "failed", "unknown", "cancelled", "expired",
})

# Internal/provider status -> canonical status. Keys that do not appear here
# project to ``unknown``.
STATUS_MAP: dict[str, str] = {
    "created": "queued",
    "validated": "queued",
    "authorized": "queued",
    "queued": "queued",
    "waiting_approval": "waiting_approval",
    "approval_required": "waiting_approval",
    "dispatched": "running",
    "received": "running",
    "accepted": "running",
    "executing": "running",
    "verifying": "running",
    "executed_unverified": "verifying",
    "succeeded": "succeeded",
    "rejected": "failed",
    "failed": "failed",
    "timed_out": "failed",
    "uncertain": "unknown",
    "cancelled": "cancelled",
    "expired": "expired",
}


def canonical_status(provider_status: Any) -> str:
    """Project a raw status; unknown or non-string values fail to ``unknown``."""

    if not isinstance(provider_status, str):
        return "unknown"
    return STATUS_MAP.get(provider_status.strip().lower(), "unknown")


def normalize_canonical(value: Any) -> str:
    """Accept an already-canonical value or project a raw status."""

    if isinstance(value, str) and value.strip().lower() in CANONICAL_STATUSES:
        return value.strip().lower()
    return canonical_status(value)


def is_canonical_terminal(status: str) -> bool:
    return status in CANONICAL_TERMINAL


def project_status(command: Mapping[str, Any]) -> str:
    """Canonical status for a stored command, preserving raw ambiguity."""

    provider_status = command.get("provider_status") or command.get("status")
    canonical = canonical_status(command.get("status"))
    # The authoritative machine may collapse ``executed_unverified`` into
    # ``uncertain`` (unknown physical outcome) while the raw adapter result is
    # retained. The contract requires that raw value to project to
    # ``verifying`` — never ``succeeded``.
    if canonical == "unknown" and str(provider_status).strip().lower() == "executed_unverified":
        canonical = "verifying"
    return canonical


def project(command: Mapping[str, Any]) -> dict[str, Any]:
    """Build the cross-repo command status projection.

    ``provider_status`` is the authoritative Device Control status. Consumers
    store this projection as a read model; they never write Device Control
    status back from it.
    """

    provider_status = command.get("provider_status") or command.get("status")
    canonical = project_status(command)
    return {
        "contract_version": CONTRACT_VERSION,
        "command_id": command.get("command_id"),
        "tenant_id": command.get("tenant_ref"),
        "device_id": command.get("device_id"),
        "endpoint_id": command.get("endpoint_id"),
        "platform_instance_id": command.get("platform_instance_id"),
        "task_ref": command.get("task_ref"),
        "run_ref": command.get("run_ref"),
        "correlation_id": command.get("correlation_id"),
        "idempotency_key": command.get("idempotency_key"),
        "provider_status": provider_status,
        "canonical_status": canonical,
        "status_reason": command.get("status_reason"),
        "verification": command.get("verification"),
        "evidence_refs": command.get("evidence_refs") or [],
        "created_at": command.get("created_at"),
        "updated_at": command.get("updated_at"),
        "completed_at": command.get("completed_at"),
    }


__all__ = [
    "CANONICAL_STATUSES",
    "CANONICAL_TERMINAL",
    "CONTRACT_VERSION",
    "STATUS_MAP",
    "canonical_status",
    "is_canonical_terminal",
    "normalize_canonical",
    "project",
    "project_status",
]
