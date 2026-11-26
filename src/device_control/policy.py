from __future__ import annotations

from typing import Any

BLOCKED_APP_MARKERS = ("bank", "wallet", "password", "authenticator", "1password", "lastpass")
ASK_ACTIONS = {"send", "post", "message", "purchase", "payment", "transfer", "booking", "delete", "install", "uninstall", "call", "security_settings", "external_link"}
READ_ACTIONS = {"observe", "read", "search", "navigate", "wait_for", "read_list"}


def evaluate(action: dict[str, Any], *, lease_mode: str) -> dict[str, str]:
    app = str(action.get("app_id", "")).lower()
    field_type = str(action.get("target_type", "")).lower()
    action_type = str(action.get("action_type", "")).lower()
    if any(marker in app for marker in BLOCKED_APP_MARKERS):
        return {"decision": "deny", "reason": "sensitive_app_blocked"}
    if field_type in {"password", "otp", "secret", "credential"}:
        return {"decision": "deny", "reason": "secret_field_blocked"}
    if lease_mode == "read_only" and action_type not in READ_ACTIONS:
        return {"decision": "deny", "reason": "read_only_lease"}
    if action_type in READ_ACTIONS:
        return {"decision": "allow", "reason": "scoped_read_action"}
    if action_type in ASK_ACTIONS:
        return {"decision": "ask", "reason": "high_risk_action_requires_human_approval"}
    return {"decision": "ask", "reason": "unclassified_mutation_requires_human_approval"}
