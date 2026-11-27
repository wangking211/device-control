from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from device_gateway import manifest as manifest_rules
from device_gateway.preflight import Context, Rejected, revalidate

MANIFEST = manifest_rules.default_document()
DIGEST = manifest_rules.digest(MANIFEST)
STATE_HASH = "state-hash"
STATE_VERSION = "v1:state-hash"


def envelope(**overrides):
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    payload = {
        "command_id": "cmd-1",
        "tenant_ref": "tenant-a",
        "gateway_id": "gw-1",
        "endpoint_id": "phone-1",
        "capability_id": "app.launch",
        "capability_version": "1.0.0",
        "operation": "launch",
        "parameters": {"app_id": "com.example.notes"},
        "intent": "open",
        "deadline": deadline,
        "idempotency_key": "idem-1",
        "lease_id": "lease-1",
        "approval_id": None,
        "approval_nonce": None,
        "policy_version": "device-policy/1",
        "policy_decision": "allow",
        "risk_tier": "read",
        "state_hash": None,
        "state_version": None,
        "manifest_digest": DIGEST,
        "device_id": "device-1",
        "device_fingerprint": "fp-1",
        "protocol_version": "v1",
    }
    payload.update(overrides)
    return payload


def context(**overrides):
    payload = {
        "tenant_ref": "tenant-a",
        "gateway_id": "gw-1",
        "endpoint_id": "phone-1",
        "now": datetime.now(timezone.utc),
        "observed_state_hash": STATE_HASH,
        "observed_state_version": STATE_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "device_id": "device-1",
        "device_fingerprint": "fp-1",
        "allowed_apps": frozenset({"com.example.notes"}),
        "nodes": (
            {"resource_id": "field-search", "bounds": [0, 0, 10, 10], "editable": True,
             "sensitive": False, "input_type": "text", "text_length": 0},
            {"resource_id": "field-password", "bounds": [0, 20, 10, 30], "editable": True,
             "sensitive": True, "input_type": "textPassword", "text_length": 0},
            {"resource_id": "button-continue", "bounds": [0, 40, 10, 50], "editable": False,
             "sensitive": False, "input_type": "", "text_length": 0},
        ),
    }
    payload.update(overrides)
    return Context(**payload)


def test_manifest_rejects_unknown_and_accepts_declared_capability():
    revalidate(envelope(), context(), MANIFEST)
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(capability_id="adb.shell", operation="shell"), context(), MANIFEST)
    assert exc.value.code == "unsupported_capability"


def test_manifest_digest_operation_and_risk_cannot_be_downgraded():
    with pytest.raises(Rejected) as digest:
        revalidate(envelope(manifest_digest="tampered"), context(), MANIFEST)
    assert digest.value.code == "manifest_mismatch"
    with pytest.raises(Rejected) as operation:
        revalidate(envelope(operation="shell"), context(), MANIFEST)
    assert operation.value.code == "operation_mismatch"
    with pytest.raises(Rejected) as risk:
        revalidate(envelope(risk_tier="safety_critical"), context(), MANIFEST)
    assert risk.value.code == "risk_tier_mismatch"


def test_manifest_risk_is_authoritative_even_if_envelope_downgrades():
    strict = deepcopy(MANIFEST)
    for capability in strict["capabilities"]:
        if capability["id"] == "app.launch":
            capability["risk_tier"] = "safety_critical"
    strict_digest = manifest_rules.digest(strict)
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(manifest_digest=strict_digest), context(), strict)
    assert exc.value.code == "risk_tier_mismatch"


def test_binding_deadline_and_endpoint_are_enforced():
    with pytest.raises(Rejected, match="tenant"):
        revalidate(envelope(tenant_ref="tenant-b"), context(), MANIFEST)
    with pytest.raises(Rejected, match="gateway"):
        revalidate(envelope(gateway_id="gw-2"), context(), MANIFEST)
    with pytest.raises(Rejected, match="endpoint"):
        revalidate(envelope(endpoint_id="phone-2"), context(), MANIFEST)
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(Rejected) as expired:
        revalidate(envelope(deadline=past), context(), MANIFEST)
    assert expired.value.code == "expired"


def test_secret_fields_allowlist_and_state_are_enforced():
    with pytest.raises(Rejected) as secret:
        revalidate(envelope(
            capability_id="ui.type_text", operation="type_text", risk_tier="write",
            parameters={"target_ref": "field-password", "text": "1234"},
            state_hash=STATE_HASH, state_version=STATE_VERSION,
            policy_decision="ask", approval_id="apr-1", approval_nonce="nonce-1",
        ), context(), MANIFEST)
    assert secret.value.code == "sensitive_control_blocked"

    with pytest.raises(Rejected) as allowlist:
        revalidate(envelope(parameters={"app_id": "com.evil.app"}), context(), MANIFEST)
    assert allowlist.value.code == "app_not_allowlisted"

    tap = {
        "capability_id": "ui.tap", "operation": "tap", "risk_tier": "write",
        "parameters": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "state_hash": STATE_HASH, "state_version": STATE_VERSION,
        "policy_decision": "ask", "approval_id": "apr-1", "approval_nonce": "nonce-1",
    }
    with pytest.raises(Rejected) as changed:
        revalidate(envelope(**tap), context(observed_state_hash="other"), MANIFEST)
    assert changed.value.code == "state_changed"


def test_state_missing_or_stale_is_rejected():
    tap = {
        "capability_id": "ui.tap", "operation": "tap", "risk_tier": "write",
        "parameters": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "state_hash": None, "state_version": None,
        "policy_decision": "ask", "approval_id": "apr-1", "approval_nonce": "nonce-1",
    }
    with pytest.raises(Rejected) as missing:
        revalidate(envelope(**tap), context(), MANIFEST)
    assert missing.value.code == "state_missing"

    stale = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    tap.update(state_hash=STATE_HASH, state_version=STATE_VERSION)
    with pytest.raises(Rejected) as expired:
        revalidate(envelope(**tap), context(observed_at=stale), MANIFEST)
    assert expired.value.code == "state_expired"


def test_state_time_future_quality_and_fingerprint_fail_closed():
    tap = {
        "capability_id": "ui.tap", "operation": "tap", "risk_tier": "write",
        "parameters": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "state_hash": STATE_HASH, "state_version": STATE_VERSION,
        "policy_decision": "ask", "approval_id": "apr-1", "approval_nonce": "nonce-1",
    }
    future = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**tap), context(observed_at=future), MANIFEST)
    assert exc.value.code == "state_time_in_future"

    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**tap), context(ui_quality="low"), MANIFEST)
    assert exc.value.code == "state_quality_insufficient"

    no_fingerprint = {**tap, "device_fingerprint": None}
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**no_fingerprint), context(device_fingerprint=None), MANIFEST)
    assert exc.value.code == "fingerprint_unavailable"


def test_ambiguous_target_is_rejected():
    duplicate = (
        {"resource_id": "button-continue", "bounds": [0, 40, 10, 50], "editable": False,
         "sensitive": False, "input_type": "", "visible": True},
        {"resource_id": "button-continue", "bounds": [0, 60, 10, 70], "editable": False,
         "sensitive": False, "input_type": "", "visible": True},
    )
    tap = {
        "capability_id": "ui.tap", "operation": "tap", "risk_tier": "write",
        "parameters": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "state_hash": STATE_HASH, "state_version": STATE_VERSION,
        "policy_decision": "ask", "approval_id": "apr-1", "approval_nonce": "nonce-1",
    }
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**tap), context(nodes=duplicate), MANIFEST)
    assert exc.value.code == "target_ambiguous"


def test_upstream_policy_allow_cannot_authorize_a_write():
    tap = {
        "capability_id": "ui.tap", "operation": "tap", "risk_tier": "write",
        "parameters": {"target_ref": "button-continue", "bounds": [0, 40, 10, 50]},
        "state_hash": STATE_HASH, "state_version": STATE_VERSION,
        "policy_decision": "allow", "approval_id": None, "approval_nonce": None,
    }
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**tap), context(), MANIFEST)
    assert exc.value.code == "policy_decision_mismatch"


def test_ask_without_approval_nonce_is_rejected():
    ask = {
        "capability_id": "ui.type_text", "operation": "type_text", "risk_tier": "write",
        "parameters": {"target_ref": "field-search", "text": "hello"},
        "state_hash": STATE_HASH, "state_version": STATE_VERSION,
        "policy_decision": "ask", "approval_id": "apr-1", "approval_nonce": None,
    }
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(**ask), context(), MANIFEST)
    assert exc.value.code == "approval_missing"


def test_typed_parameters_are_validated():
    with pytest.raises(Rejected) as exc:
        revalidate(envelope(parameters={}), context(), MANIFEST)
    assert exc.value.code == "invalid_parameters"
