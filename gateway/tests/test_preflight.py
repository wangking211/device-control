from datetime import datetime, timedelta, timezone

import pytest
from device_gateway.preflight import Context, Rejected, revalidate


def envelope(**overrides):
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    payload = {
        "command_id": "cmd-1",
        "tenant_ref": "tenant-a",
        "gateway_id": "gw-1",
        "endpoint_id": "phone-1",
        "capability_id": "app.launch",
        "capability_version": "1.0.0",
        "parameters": {"app_id": "com.example.notes"},
        "intent": "open",
        "deadline": deadline,
        "idempotency_key": "idem-1",
        "lease_id": "lease-1",
        "approval_id": None,
        "policy_version": "device-policy/1",
        "policy_decision": "allow",
        "risk_tier": "read",
        "state_hash": None,
        "protocol_version": "v1",
    }
    payload.update(overrides)
    return payload


def context(**overrides):
    payload = {
        "tenant_ref": "tenant-a",
        "gateway_id": "gw-1",
        "now": datetime.now(timezone.utc),
        "observed_state_hash": None,
        "allowed_apps": frozenset({"com.example.notes"}),
    }
    payload.update(overrides)
    return Context(**payload)


def test_manifest_rejects_unknown_and_accepts_declared_capability():
    revalidate(envelope(), context())
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(capability_id="adb.shell"), context())
    assert exc.value.code == "unsupported_capability"


def test_binding_deadline_and_risk_are_enforced():
    with pytest.raises(Rejected, match="tenant"):
        revalidate(envelope(tenant_ref="tenant-b"), context())
    with pytest.raises(Rejected, match="gateway"):
        revalidate(envelope(gateway_id="gw-2"), context())
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(Rejected) as expired:
        revalidate(envelope(deadline=past), context())
    assert expired.value.code == "expired"
    with pytest.raises(Rejected) as risk:
        revalidate(envelope(risk_tier="safety_critical"), context())
    assert risk.value.code == "risk_blocked"


def test_secret_fields_allowlist_and_state_hash_are_enforced():
    with pytest.raises(Rejected) as secret:
        revalidate(envelope(parameters={"app_id": "com.example.notes", "target_type": "password"}),
                   context())
    assert secret.value.code == "secret_field_blocked"
    with pytest.raises(Rejected) as allowlist:
        revalidate(envelope(parameters={"app_id": "com.evil.app"}), context())
    assert allowlist.value.code == "app_not_allowlisted"

    tap = {
        "capability_id": "ui.tap", "capability_version": "1.0.0", "risk_tier": "write",
        "parameters": {"target_ref": "Continue", "bounds": [0, 0, 100, 100]},
        "state_hash": "old-state",
    }
    with pytest.raises(Rejected) as changed:
        revalidate(envelope(**tap), context(observed_state_hash="new-state"))
    assert changed.value.code == "state_changed"


def test_ask_without_approval_is_rejected():
    ask = {
        "capability_id": "ui.type_text", "capability_version": "1.0.0", "risk_tier": "write",
        "parameters": {"target_ref": "field", "text": "hello"},
        "policy_decision": "ask", "approval_id": None,
    }
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**ask), context())
    assert exc.value.code == "approval_missing"


def test_typed_parameters_are_validated():
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(parameters={}), context())
    assert exc.value.code == "invalid_parameters"
