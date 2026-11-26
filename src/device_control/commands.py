"""Command state machine and gateway status mapping.

``succeeded`` requires verification evidence. A transport acknowledgement
(``received``/``accepted``) is never success, and ``uncertain`` is a terminal
answer meaning "the action may have happened but cannot be verified".
"""

from __future__ import annotations

from typing import Any

ACTIVE_STATES = frozenset(
    {
        "created",
        "validated",
        "authorized",
        "queued",
        "dispatched",
        "received",
        "accepted",
        "executing",
        "verifying",
    }
)

TERMINAL_STATES = frozenset(
    {"succeeded", "rejected", "failed", "timed_out", "cancelled", "uncertain", "expired"}
)

TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"validated", "rejected", "expired"}),
    "validated": frozenset({"authorized", "rejected", "expired"}),
    "authorized": frozenset({"queued", "cancelled", "expired"}),
    "queued": frozenset({"dispatched", "cancelled", "expired"}),
    "dispatched": frozenset({"received", "cancelled", "timed_out", "uncertain", "failed"}),
    "received": frozenset({"accepted", "rejected", "timed_out", "uncertain", "failed"}),
    "accepted": frozenset({"executing", "rejected", "timed_out", "cancelled", "failed", "uncertain"}),
    "executing": frozenset({"verifying", "succeeded", "failed", "timed_out", "uncertain", "cancelled"}),
    "verifying": frozenset({"succeeded", "failed", "uncertain"}),
}

# Gateway-reported statuses, in the order a healthy command produces them.
GATEWAY_PROGRESS_STATUSES = ("received", "accepted", "executing")

RESULT_STATUSES = (
    "succeeded",
    "failed",
    "rejected",
    "timed_out",
    "cancelled",
    "uncertain",
)

VERIFICATION_METHODS = frozenset(
    {"adapter_ack", "read_after_write", "ui_state", "screenshot_predicate", "sensor_observation", "manual_confirmation"}
)

EVIDENCE_RETENTION_LIMIT = 20


def can_transition(current: str, target: str) -> bool:
    if current in TERMINAL_STATES:
        return False
    return target in TRANSITIONS.get(current, frozenset())


def is_terminal(status: str) -> bool:
    return status in TERMINAL_STATES


def verification_is_sufficient(verification: Any) -> bool:
    if not isinstance(verification, dict):
        return False
    if verification.get("method") not in VERIFICATION_METHODS:
        return False
    if verification.get("verified") is not True:
        return False
    if not str(verification.get("observed_at") or "").strip():
        return False
    # An adapter guarantee is a documented capability property, not a free-text
    # claim invented per result.
    if verification.get("method") == "adapter_ack" and verification.get("adapter_guarantee") is not True:
        return False
    return True


def redact_evidence(evidence_refs: list[str] | None) -> list[str]:
    """Evidence references only; raw screenshots never enter the control plane."""

    refs = [str(ref) for ref in (evidence_refs or []) if str(ref).strip()]
    return refs[:EVIDENCE_RETENTION_LIMIT]
