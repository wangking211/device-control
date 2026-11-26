"""Deterministic device policy.

This is the preflight decision. It is advisory for ``allow`` and final for
``deny``; ``ask`` requires a human approval bound to the exact action. The
gateway re-runs the same rules at execution time, because a control-plane
decision is not proof that the device state still matches.

R3 (``safety_critical``) capabilities default-deny for general agents. A
principal must carry the dedicated ``device.safety_critical`` scope, and even
then the capability must be present in the endpoint's reported catalogue.
"""

from __future__ import annotations

from typing import Any, Iterable

POLICY_VERSION = "device-policy/2026-11-26.2"

BLOCKED_APP_MARKERS = ("bank", "wallet", "password", "authenticator", "1password", "lastpass")
ASK_ACTIONS = {
    "send", "post", "message", "purchase", "payment", "transfer", "booking",
    "delete", "install", "uninstall", "call", "security_settings", "external_link",
}
READ_ACTIONS = {"observe", "read", "search", "navigate", "wait_for", "read_list", "screenshot", "foreground_app"}
LOW_RISK_ACTIONS = {"launch", "tap", "type", "type_text", "back", "home", "wait_and_verify"}
DESTRUCTIVE_ACTIONS = {"factory_reset", "wipe", "uninstall", "revoke_certificate", "change_lock"}
SECRET_TARGETS = {"password", "otp", "secret", "credential", "card_number", "cvv"}

SAFETY_SCOPE = "device.safety_critical"
RISK_TIERS = frozenset({"read", "write", "destructive", "safety_critical"})


def policy_version() -> str:
    return POLICY_VERSION


def evaluate(
    action: dict[str, Any],
    *,
    lease_mode: str,
    principal_scopes: Iterable[str] = (),
    risk_tier: str | None = None,
) -> dict[str, str]:
    app = str(action.get("app_id", "")).lower()
    field_type = str(action.get("target_type", "")).lower()
    action_type = str(action.get("action_type", "")).lower()
    scopes = set(principal_scopes)

    if any(marker in app for marker in BLOCKED_APP_MARKERS):
        return _deny("sensitive_app_blocked")
    if field_type in SECRET_TARGETS:
        return _deny("secret_field_blocked")
    if action_type in DESTRUCTIVE_ACTIONS:
        return _deny("destructive_action_requires_dedicated_workflow")
    if risk_tier == "safety_critical":
        if SAFETY_SCOPE in scopes or "*" in scopes:
            return _ask("safety_critical_action_requires_human_approval")
        return _deny("r3_safety_critical_default_deny")
    if risk_tier == "destructive":
        return _deny("destructive_capability_not_available_to_general_agents")
    if lease_mode == "read_only" and action_type not in READ_ACTIONS:
        return _deny("read_only_lease")
    if action_type in READ_ACTIONS or action_type in LOW_RISK_ACTIONS:
        return _allow("scoped_low_risk_action" if action_type in LOW_RISK_ACTIONS else "scoped_read_action")
    if action_type in ASK_ACTIONS:
        return _ask("high_risk_action_requires_human_approval")
    return _ask("unclassified_mutation_requires_human_approval")


def _allow(reason: str) -> dict[str, str]:
    return {"decision": "allow", "reason": reason, "policy_version": POLICY_VERSION}


def _ask(reason: str) -> dict[str, str]:
    return {"decision": "ask", "reason": reason, "policy_version": POLICY_VERSION}


def _deny(reason: str) -> dict[str, str]:
    return {"decision": "deny", "reason": reason, "policy_version": POLICY_VERSION}
