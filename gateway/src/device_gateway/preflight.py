"""Execution-side revalidation.

The control plane is authoritative, but a command envelope is rechecked at the
gateway boundary immediately before execution: binding, deadline, capability,
typed parameters, risk, secret fields, allowlist and observed state hash. A
stale approval or a changed screen must not execute.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from jsonschema import Draft202012Validator

from . import manifest

DENY_RISK = {"destructive", "safety_critical"}
SECRET_TARGETS = {"password", "otp", "secret", "credential", "card_number", "cvv"}
BLOCKED_APP_MARKERS = ("bank", "wallet", "password", "authenticator", "1password", "lastpass")


class Rejected(Exception):
    def __init__(self, code: str, reason: str, error_class: str = "validation") -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.error_class = error_class


@dataclass(frozen=True)
class Context:
    tenant_ref: str
    gateway_id: str
    now: datetime
    observed_state_hash: str | None
    allowed_apps: frozenset[str]


def revalidate(command: dict[str, Any], context: Context) -> dict[str, Any]:
    if command.get("protocol_version") != manifest.PROTOCOL_VERSION:
        raise Rejected("protocol_mismatch", "unsupported protocol version", "validation")
    if str(command.get("tenant_ref") or "") != context.tenant_ref:
        raise Rejected("tenant_mismatch", "command tenant does not match gateway", "policy")
    if str(command.get("gateway_id") or "") != context.gateway_id:
        raise Rejected("gateway_mismatch", "command targets another gateway", "policy")

    deadline = _parse(command.get("deadline"))
    if deadline is None or deadline <= context.now:
        raise Rejected("expired", "command deadline has elapsed", "timeout")

    risk = str(command.get("risk_tier") or "")
    if risk in DENY_RISK:
        raise Rejected("risk_blocked", f"risk tier {risk} is not executable by this gateway", "policy")

    capability = manifest.capability(
        str(command.get("capability_id") or ""), str(command.get("capability_version") or "")
    )
    if capability is None:
        raise Rejected("unsupported_capability", "capability is not in the gateway manifest", "validation")

    parameters = command.get("parameters")
    if not isinstance(parameters, dict):
        raise Rejected("invalid_parameters", "parameters must be an object", "validation")

    target_type = str(parameters.get("target_type") or "").lower()
    if target_type in SECRET_TARGETS:
        raise Rejected("secret_field_blocked", "secret fields are never typed", "policy")
    app_id = str(parameters.get("app_id") or "").lower()
    if any(marker in app_id for marker in BLOCKED_APP_MARKERS):
        raise Rejected("sensitive_app_blocked", "sensitive apps are never controlled", "policy")

    errors = sorted(
        Draft202012Validator(capability["input_schema"]).iter_errors(parameters),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise Rejected("invalid_parameters", errors[0].message, "validation")

    if capability.get("allowlist"):
        requested = str(parameters.get("app_id") or "")
        if context.allowed_apps and requested not in context.allowed_apps:
            raise Rejected("app_not_allowlisted", "app is not operator-allowlisted", "policy")

    if capability.get("requires_state_hash"):
        expected = command.get("state_hash")
        if expected and context.observed_state_hash and str(expected) != str(context.observed_state_hash):
            raise Rejected("state_changed", "device state changed after approval", "state_changed")

    if risk == "write" and not command.get("lease_id"):
        raise Rejected("lease_missing", "write capability requires a lease", "policy")
    if command.get("policy_decision") == "ask" and not command.get("approval_id"):
        raise Rejected("approval_missing", "approval is required for this action", "policy")
    return capability


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
