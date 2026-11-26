"""Execution-side revalidation against the trusted manifest.

The control plane is authoritative, but a command envelope is rechecked at the
gateway boundary immediately before execution: manifest digest, capability,
operation, risk, typed parameters, device/endpoint identity, lease, approval,
state freshness and sensitive-control semantics. Envelope claims are compared
to the manifest; they are never trusted as the source of risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from jsonschema import Draft202012Validator

from . import manifest as manifest_rules

DENY_RISK = {"destructive", "safety_critical"}
SECRET_TARGETS = {"password", "otp", "secret", "credential", "card_number", "cvv"}
BLOCKED_APP_MARKERS = ("bank", "wallet", "password", "authenticator", "1password", "lastpass")
SENSITIVE_RESOURCE_MARKERS = ("password", "otp", "pin", "card", "cvv", "credential", "secret")


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
    endpoint_id: str
    now: datetime
    observed_state_hash: str | None
    observed_state_version: str | None
    observed_at: str | None
    device_id: str | None
    device_fingerprint: str | None
    allowed_apps: frozenset[str]
    nodes: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def revalidate(command: dict[str, Any], context: Context,
               manifest: dict[str, Any]) -> dict[str, Any]:
    if command.get("protocol_version") != manifest_rules.PROTOCOL_VERSION:
        raise Rejected("protocol_mismatch", "unsupported protocol version", "validation")
    if str(command.get("tenant_ref") or "") != context.tenant_ref:
        raise Rejected("tenant_mismatch", "command tenant does not match gateway", "policy")
    if str(command.get("gateway_id") or "") != context.gateway_id:
        raise Rejected("gateway_mismatch", "command targets another gateway", "policy")
    if str(command.get("endpoint_id") or "") != context.endpoint_id:
        raise Rejected("endpoint_mismatch", "command targets another endpoint", "policy")

    expected_digest = manifest_rules.digest(manifest)
    if str(command.get("manifest_digest") or "") != expected_digest:
        raise Rejected("manifest_mismatch", "manifest digest does not match", "policy")

    deadline = _parse(command.get("deadline"))
    if deadline is None or deadline <= context.now:
        raise Rejected("expired", "command deadline has elapsed", "timeout")

    capability = manifest_rules.capability(
        manifest,
        str(command.get("capability_id") or ""),
        str(command.get("capability_version") or ""),
    )
    if capability is None:
        raise Rejected("unsupported_capability", "capability is not in the trusted manifest", "validation")

    operation = str(capability.get("operation") or capability.get("id"))
    risk = str(capability.get("risk_tier") or "")
    if str(command.get("operation") or "") != operation:
        raise Rejected("operation_mismatch", "operation does not match manifest", "policy")
    if str(command.get("risk_tier") or "") != risk:
        raise Rejected("risk_tier_mismatch", "risk tier does not match manifest", "policy")
    if risk in DENY_RISK:
        raise Rejected("risk_blocked", f"risk tier {risk} is not executable by this gateway", "policy")

    parameters = command.get("parameters")
    if not isinstance(parameters, dict):
        raise Rejected("invalid_parameters", "parameters must be an object", "validation")

    target_type = str(parameters.get("target_type") or "").lower()
    if target_type in SECRET_TARGETS:
        raise Rejected("secret_field_blocked", "secret controls are never driven", "policy")
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
        if requested not in context.allowed_apps:
            raise Rejected("app_not_allowlisted", "app is not operator-allowlisted", "policy")

    if operation == "type_text":
        _reject_sensitive_text_target(parameters, context.nodes)

    if capability.get("requires_state"):
        _check_state(command, context, capability)

    if risk == "write" and not command.get("lease_id"):
        raise Rejected("lease_missing", "write capability requires a lease", "policy")
    if command.get("policy_decision") == "ask" and not (
        command.get("approval_id") and command.get("approval_nonce")
    ):
        raise Rejected("approval_missing", "approval and nonce are required for this action", "policy")
    return capability


def _check_state(command: dict[str, Any], context: Context,
                 capability: dict[str, Any]) -> None:
    state_hash = command.get("state_hash")
    state_version = command.get("state_version")
    if not state_hash or not state_version:
        raise Rejected("state_missing", "state hash and version are required", "policy")
    if context.observed_state_hash != state_hash:
        raise Rejected("state_changed", "device state hash changed", "state_changed")
    if context.observed_state_version != state_version:
        raise Rejected("state_changed", "device state version changed", "state_changed")
    if command.get("device_fingerprint") and context.device_fingerprint != command.get("device_fingerprint"):
        raise Rejected("device_identity_mismatch", "device fingerprint changed", "policy")
    if context.observed_at:
        observed = _parse(context.observed_at)
        max_age_ms = int(capability.get("state_max_age_ms") or 15000)
        if observed is None or (context.now - observed).total_seconds() * 1000 > max_age_ms:
            raise Rejected("state_expired", "state observation is stale", "state_changed")


def _reject_sensitive_text_target(parameters: dict[str, Any],
                                  nodes: tuple[dict[str, Any], ...]) -> None:
    node = _find_node(parameters, nodes)
    if node is None:
        # Cannot prove the target is a non-sensitive editable field.
        raise Rejected("target_unverified", "target control could not be identified", "policy")
    if node.get("sensitive"):
        raise Rejected("sensitive_control_blocked", "password control detected", "policy")
    if not node.get("editable"):
        raise Rejected("target_not_editable", "target is not an editable control", "policy")
    resource_id = str(node.get("resource_id") or "").lower()
    input_type = str(node.get("input_type") or "").lower()
    if any(marker in resource_id for marker in SENSITIVE_RESOURCE_MARKERS):
        raise Rejected("sensitive_control_blocked", "sensitive control id detected", "policy")
    if "password" in input_type or "numberpassword" in input_type:
        raise Rejected("sensitive_control_blocked", "sensitive input type detected", "policy")


def _find_node(parameters: dict[str, Any],
               nodes: tuple[dict[str, Any], ...]) -> dict[str, Any] | None:
    target = str(parameters.get("target_ref") or "")
    bounds = parameters.get("bounds")
    for node in nodes:
        if bounds and node.get("bounds") == bounds:
            return node
        if target and node.get("resource_id") == target:
            return node
    return None


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
